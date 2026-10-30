"""Adversarial adapter controls; no application mutation or campaign is run."""
import copy
import json
import os
import py_compile
from pathlib import Path
import sys
import textwrap
import subprocess

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'qualification'))
import run_pytest_evidence as runner


def case(tmp_path, body='assert VALUE == 1', *, target='VALUE = 1\n', prefix='', args=''):
    root = tmp_path / 'workspace'
    (root / 'tests').mkdir(parents=True)
    (root / 'target.py').write_text(target)
    (root / 'pytest.ini').write_text('[pytest]\nasyncio_mode = auto\nasyncio_default_fixture_loop_scope = function\nasyncio_default_test_loop_scope = function\n')
    (root / 'tests/test_case.py').write_text('import pytest\nfrom target import *\n' + textwrap.dedent(prefix) +
                                          f'\ndef test_case({args}):\n' + textwrap.indent(textwrap.dedent(body), '    ') + '\n')
    lock = tmp_path / 'tool.lock'
    lock.write_text('synthetic adapter control; no mutation producer\n')
    manifest = runner.make_manifest(root, 'a' * 40, ['target.py', 'pytest.ini', 'tests/test_case.py'],
        ['tests/test_case.py'], ['target'], ['tests/test_case.py::test_case'], lock, sys.executable)
    return root, manifest


def execute(tmp_path, body='assert VALUE == 1', **kwargs):
    root, manifest = case(tmp_path, body, **kwargs)
    output = tmp_path / 'evidence'
    result = runner.run_evidence(manifest, output, timeout=20)
    return root, manifest, output, result


def test_real_positive_assertions_are_measured_in_call_phase(tmp_path):
    _, _, output, result = execute(tmp_path, 'for number in range(3):\n    assert VALUE == 1\nassert True')
    assert result['outcome'] == 'passed' and result['clean_baseline']
    assert result['call_assertions'] == 4
    assert result['qualification_credit'] is False
    facts = json.loads((output / 'summary.json').read_text())
    assert facts['assertion_passes'] == {'setup': 0, 'call': 4, 'teardown': 0}


@pytest.mark.parametrize('body', ['assert VALUE == 2', 'with pytest.raises(ValueError):\n    pass', 'pytest.fail("explicit contract")'])
def test_only_genuine_call_assertion_or_verified_pytest_contract_failure_is_eligible(tmp_path, body):
    _, _, _, result = execute(tmp_path, body)
    assert result['outcome'] == 'assertion_failure'
    assert result['assertion_failure'] and not result['clean_baseline']
    assert result['qualification_credit'] is False


@pytest.mark.parametrize('body', ['raise RuntimeError("runtime control")', '1 + None',
                                 'with pytest.raises(ValueError):\n    raise RuntimeError("wrong exception")'])
def test_call_phase_runtime_failures_never_become_assertion_kills(tmp_path, body):
    _, _, _, result = execute(tmp_path, body)
    assert result['outcome'] == 'runtime_error'
    assert result['assertion_failure'] is False


def test_application_internal_assertion_is_not_a_test_assertion(tmp_path):
    _, _, _, result = execute(tmp_path, 'explode()', target='VALUE=1\ndef explode():\n    assert False\n')
    assert result['outcome'] == 'runtime_error'
    assert not result['assertion_failure']


def test_setup_assertion_error_is_not_a_test_phase_kill(tmp_path):
    _, _, _, result = execute(tmp_path, 'assert True', args='broken', prefix='''
        @pytest.fixture
        def broken():
            assert False
    ''')
    assert result['outcome'] == 'setup_or_teardown_error'
    assert not result['assertion_failure']


def test_teardown_error_invalidates_a_real_call_assertion_failure(tmp_path):
    _, _, _, result = execute(tmp_path, 'assert False', args='broken', prefix='''
        @pytest.fixture
        def broken():
            yield
            raise RuntimeError("teardown control")
    ''')
    assert result['outcome'] == 'setup_or_teardown_error'
    assert not result['assertion_failure']


@pytest.mark.parametrize('target', ['raise ImportError("collection control")\n', 'VALUE = (\n'])
def test_import_and_compiler_errors_are_collection_failures_not_kills(tmp_path, target):
    _, _, _, result = execute(tmp_path, target=target)
    assert result['outcome'] == 'collection_error'
    assert not result['assertion_failure']


@pytest.mark.parametrize('body', ['import warnings\nwarnings.warn("warning control", UserWarning)\nassert False',
                                 'import atexit,warnings\natexit.register(lambda: warnings.warn("late warning", UserWarning))\nassert True'])
def test_warnings_deny_clean_baseline_and_assertion_credit_including_after_sessionfinish(tmp_path, body):
    _, _, _, result = execute(tmp_path, body)
    assert result['outcome'] == 'warning_or_unstructured_stderr'
    assert not result['assertion_failure'] and not result['clean_baseline']


def test_timeout_never_earns_credit_even_if_native_mutation_tool_would_say_killed(tmp_path):
    _, manifest = case(tmp_path, 'import time\ntime.sleep(60)\nassert True')
    output = tmp_path / 'evidence'
    result = runner.run_evidence(manifest, output, timeout=1)
    assert result['outcome'] == 'timed_out' and not result['assertion_failure']
    assert (output / 'stdout.bin').exists() and (output / 'stderr.bin').exists()


def test_raw_output_limit_denies_credit_and_retains_both_streams(tmp_path):
    _, manifest = case(tmp_path, 'import os\nwith capfd.disabled():\n    os.write(1,b"x"*100000)\nassert True', args='capfd')
    output = tmp_path / 'evidence'
    result = runner.run_evidence(manifest, output, output_limit=4096)
    assert result['outcome'] == 'output_limit' and not result['assertion_failure']
    assert (output / 'stdout.bin').stat().st_size > 4096


@pytest.mark.parametrize('body', ['import os\nos._exit(1)',
    'import json,os\nfrom pathlib import Path\nPath(os.environ["CLOUD_PYTEST_SUMMARY"]).write_text(json.dumps({"assertions":999,"killed":True}))\nos._exit(1)'])
def test_missing_or_forged_summary_never_earns_credit(tmp_path, body):
    _, _, _, result = execute(tmp_path, body)
    assert result['outcome'] == 'evidence_error' and not result['assertion_failure']


def test_source_changed_before_execution_cannot_use_a_frozen_manifest(tmp_path):
    root, manifest = case(tmp_path)
    (root / 'target.py').write_text('VALUE=2\n')
    result = runner.run_evidence(manifest, tmp_path / 'evidence')
    assert result['outcome'] == 'custody_error' and not result['assertion_failure']


def test_source_changed_during_execution_cannot_earn_kill_credit(tmp_path):
    _, _, _, result = execute(tmp_path, 'from pathlib import Path\nPath("target.py").write_text("VALUE=2\\n")\nassert False')
    assert result['outcome'] == 'custody_error' and not result['assertion_failure']


def test_wrong_import_origin_cannot_earn_assertion_credit(tmp_path):
    _, _, _, result = execute(tmp_path, 'import target\ntarget.__file__="/not/the/admitted/source.py"\nassert False')
    assert result['outcome'] == 'custody_error' and not result['assertion_failure']


@pytest.mark.parametrize('field', ['producer_hashes', 'runtime_identity'])
def test_producer_or_runtime_tool_identity_drift_refuses_before_execution(tmp_path, field):
    _, manifest = case(tmp_path)
    if field == 'producer_hashes':
        manifest[field]['pytest_evidence.py'] = '0' * 64
    else:
        manifest[field]['packages']['pytest']['version'] = 'forged'
    result = runner.run_evidence(manifest, tmp_path / 'evidence')
    assert result['outcome'] == 'custody_error' and not result['assertion_failure']


def test_tool_lock_drift_refuses_before_execution(tmp_path):
    _, manifest = case(tmp_path)
    Path(manifest['tool_lock']['path']).write_text('changed')
    result = runner.run_evidence(manifest, tmp_path / 'evidence')
    assert result['outcome'] == 'custody_error'


def test_postrun_summary_and_parent_envelope_forgery_are_detected(tmp_path):
    _, manifest, output, result = execute(tmp_path)
    (output / 'summary.json').write_text('{"forged":true}')
    assert runner.assess(output, manifest, result['execution_sha256'])['outcome'] == 'evidence_error'
    (output / 'execution.json').write_text('{"forged":true}')
    assert runner.assess(output, manifest, result['execution_sha256'])['outcome'] == 'evidence_error'


def test_malformed_counters_or_duplicate_reports_fail_even_with_parent_bound_bytes(tmp_path):
    _, manifest, output, _ = execute(tmp_path)
    original = json.loads((output / 'summary.json').read_text())
    envelope = json.loads((output / 'execution.json').read_text())
    for change in ('bool_counter', 'duplicate_report', 'bad_warnings'):
        facts = copy.deepcopy(original)
        if change == 'bool_counter':
            facts['assertion_passes']['call'] = True
        elif change == 'duplicate_report':
            facts['reports'].append(facts['reports'][0])
        else:
            facts['warnings'] = None
        raw = runner.encoded(facts)
        (output / 'summary.json').write_bytes(raw)
        envelope['summary_sha256'] = runner.sha(raw)
        parent_raw = runner.encoded(envelope)
        (output / 'execution.json').write_bytes(parent_raw)
        result = runner.assess(output, manifest, runner.sha(parent_raw))
        assert result['outcome'] == 'evidence_error' and not result['assertion_failure']


def test_fresh_prefix_ignores_same_size_same_mtime_stale_application_pyc(tmp_path):
    root, _ = case(tmp_path, 'assert VALUE == 2', target='VALUE=1\n')
    target = root / 'target.py'
    (root / '__pycache__').mkdir()
    py_compile.compile(str(target), cfile=str(root / '__pycache__' / ('target.' + sys.implementation.cache_tag + '.pyc')), doraise=True)
    assert list((root / '__pycache__').glob('target.*.pyc'))
    original = target.stat()
    target.write_text('VALUE=2\n')
    os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))
    manifest = runner.make_manifest(root, 'a' * 40, ['target.py', 'pytest.ini', 'tests/test_case.py'],
        ['tests/test_case.py'], ['target'], ['tests/test_case.py::test_case'], tmp_path / 'tool.lock', sys.executable)
    result = runner.run_evidence(manifest, tmp_path / 'evidence')
    assert result['clean_baseline'] and result['call_assertions'] == 1


def test_fresh_prefix_rewrites_tests_previously_cached_without_assertion_pass_hooks(tmp_path):
    root, manifest = case(tmp_path, 'assert VALUE == 1\nassert True')
    env = runner.clean_env(tmp_path)
    env['PYTHONDONTWRITEBYTECODE'] = '0'
    warm = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'pytest_asyncio.plugin',
                           '-o', 'enable_assertion_pass_hook=false', 'tests/test_case.py'],
                          cwd=root, env=env, capture_output=True, timeout=20)
    (tmp_path / 'warm-stdout.bin').write_bytes(warm.stdout)
    (tmp_path / 'warm-stderr.bin').write_bytes(warm.stderr)
    assert warm.returncode == 0
    assert list((root / 'tests/__pycache__').glob('test_case.*pytest*.pyc'))
    result = runner.run_evidence(manifest, tmp_path / 'evidence')
    assert result['clean_baseline'] and result['call_assertions'] == 2


@pytest.mark.parametrize('missing', ['teardown', 'other_node'])
def test_incomplete_phase_or_node_summary_never_earns_assertion_credit(tmp_path, missing):
    root, manifest = case(tmp_path, 'assert False', prefix='def test_other():\n    assert True\n')
    manifest['expected_nodeids'] = ['tests/test_case.py::test_case', 'tests/test_case.py::test_other']
    output = tmp_path / 'evidence'
    genuine = runner.run_evidence(manifest, output)
    assert genuine['assertion_failure']
    facts = json.loads((output / 'summary.json').read_text())
    if missing == 'teardown':
        facts['reports'] = [r for r in facts['reports'] if not (r['nodeid'].endswith('test_case') and r['when'] == 'teardown')]
    else:
        facts['reports'] = [r for r in facts['reports'] if not r['nodeid'].endswith('test_other')]
    raw = runner.encoded(facts)
    (output / 'summary.json').write_bytes(raw)
    envelope = json.loads((output / 'execution.json').read_text())
    envelope['summary_sha256'] = runner.sha(raw)
    parent = runner.encoded(envelope)
    (output / 'execution.json').write_bytes(parent)
    result = runner.assess(output, manifest, runner.sha(parent))
    assert result['outcome'] == 'evidence_error' and not result['assertion_failure']


def test_skip_and_unexpected_collection_selection_never_supply_credit(tmp_path):
    _, manifest = case(tmp_path, 'pytest.skip("no execution evidence")')
    result = runner.run_evidence(manifest, tmp_path / 'skipped')
    assert result['outcome'] == 'skipped' and not result['assertion_failure'] and not result['clean_baseline']
    manifest['expected_nodeids'] = ['tests/test_case.py::uncollected']
    result = runner.run_evidence(manifest, tmp_path / 'wrong-selection')
    assert result['outcome'] == 'collection_error' and not result['assertion_failure']


def test_no_tests_never_becomes_a_clean_baseline(tmp_path):
    root, manifest = case(tmp_path)
    raw = b'from target import VALUE\ndef helper():\n    pass\n'
    (root / 'tests/test_case.py').write_bytes(raw)
    manifest['files']['tests/test_case.py'] = runner.sha(raw)
    result = runner.run_evidence(manifest, tmp_path / 'evidence')
    assert result['outcome'] == 'collection_error' and not result['assertion_failure'] and not result['clean_baseline']


@pytest.mark.parametrize('phase', ['collection', 'setup', 'call', 'teardown'])
def test_logged_warning_in_every_pytest_phase_denies_clean_baseline_and_kill(tmp_path, phase):
    """Captured logs cannot qualify in any pytest execution phase."""
    prefix, body, args = 'import logging\n', 'assert True', ''
    if phase == 'collection':
        prefix += 'logging.warning("synthetic collection warning")\n'
    elif phase == 'call':
        body = 'logging.warning("synthetic call warning")\nassert True'
    else:
        args = 'noisy'
        prefix += ('@pytest.fixture\ndef noisy():\n' +
            ('    logging.warning("synthetic setup warning")\n    return 1\n' if phase == 'setup'
             else '    yield 1\n    logging.warning("synthetic teardown warning")\n'))
    _, _, _, result = execute(tmp_path, body, prefix=prefix, args=args)
    assert result['outcome'] == 'warning_or_unstructured_stderr'
    assert not result['clean_baseline'] and not result['assertion_failure']
    assert any(w['category'] == 'logging.WARNING' for w in result['warnings'])


def test_logged_warning_after_sessionfinish_is_observed_even_with_no_output_handler(tmp_path):
    """A quiet handler cannot hide a warning emitted during process exit."""
    _, _, output, result = execute(tmp_path, '''
        import atexit, logging
        logger = logging.getLogger('synthetic-late-warning')
        logger.propagate = False
        logger.addHandler(logging.NullHandler())
        atexit.register(lambda: logger.warning('synthetic late warning'))
        assert True
    ''')
    assert (output / 'stderr.bin').stat().st_size == 0
    assert result['outcome'] == 'warning_or_unstructured_stderr'
    assert any(w['category'] == 'logging.WARNING' for w in result['warnings'])
    assert not result['clean_baseline'] and not result['assertion_failure']


def test_unconsumed_pytest_captured_stderr_from_passing_test_denies_clean_baseline(tmp_path):
    """Passing assertions do not erase captured diagnostic output."""
    _, _, _, result = execute(tmp_path, 'import sys\nprint("synthetic diagnostic",file=sys.stderr)\nassert True')
    assert result['outcome'] == 'warning_or_unstructured_stderr'
    assert any(w['category'] == 'pytest.CapturedStderr' for w in result['warnings'])
    assert not result['clean_baseline'] and not result['assertion_failure']


def test_logging_shutdown_after_summary_cannot_supply_a_clean_baseline(tmp_path):
    """The parent journal includes handlers closed after summary creation."""
    _, _, output, result = execute(tmp_path, '''
        import logging
        logger = logging.getLogger('synthetic-shutdown-warning')
        logger.propagate = False
        logger.addHandler(logging.NullHandler())
        class WarningOnClose(logging.Handler):
            def close(self):
                logger.warning('synthetic warning after summary')
                super().close()
        keeper = WarningOnClose()
        logging.getLogger('synthetic-kept-handler').addHandler(keeper)
        assert True
    ''')
    assert (output / 'stderr.bin').stat().st_size == 0
    assert result['outcome'] == 'warning_or_unstructured_stderr'
    assert any(w['category'] == 'logging.WARNING' for w in result['warnings'])
    assert not result['clean_baseline'] and not result['assertion_failure']
    journal = [json.loads(line) for line in (output / 'log-records.jsonl').read_text().splitlines()]
    assert journal and all(row['nonce'] for row in journal)


def test_changed_warning_journal_invalidates_parent_execution(tmp_path):
    """The assessor cannot consume a journal changed after parent sealing."""
    _, manifest, output, result = execute(tmp_path, 'assert True')
    assert result['clean_baseline']
    with (output / 'log-records.jsonl').open('ab') as target:
        target.write(b'{}\n')
    assessed = runner.assess(output, manifest, result['execution_sha256'])
    assert assessed['outcome'] == 'evidence_error'
    assert not assessed['clean_baseline'] and not assessed['assertion_failure']


@pytest.mark.parametrize('fixture', ['capsys', 'capfd', 'capsysbinary', 'capfdbinary'])
def test_consumed_capture_stderr_remains_observed_without_changing_the_read(tmp_path, fixture):
    """All four public capture fixtures retain their normal return value."""
    _, _, output, result = execute(tmp_path, f'''
        import sys
        sys.stderr.write('synthetic consumed diagnostic')
        captured = {fixture}.readouterr()
        assert captured.err == {'b' if fixture.endswith('binary') else ''}'synthetic consumed diagnostic'
        assert not {fixture}.readouterr().err
    ''', args=fixture)
    assert result['outcome'] == 'warning_or_unstructured_stderr'
    assert not result['clean_baseline'] and not result['assertion_failure']
    assert any(row['category'] == 'pytest.CaptureFixtureStderr' for row in result['warnings'])
    facts = json.loads((output/'summary.json').read_text())
    assert all(row['outcome'] == 'passed' for row in facts['reports'])


def test_null_handler_logging_does_not_format_lazy_arguments(tmp_path):
    """The observer leaves argument formatting exclusively to handlers."""
    _, _, output, result = execute(tmp_path, '''
        import logging
        calls = []
        class Lazy:
            def __str__(self):
                calls.append('formatted')
                return 'synthetic lazy argument'
        logger = logging.getLogger('synthetic-lazy')
        logger.propagate = False
        logger.addHandler(logging.NullHandler())
        logger.warning('%s', Lazy())
        assert calls == []
    ''')
    assert result['outcome'] == 'warning_or_unstructured_stderr'
    assert all(row['outcome'] == 'passed' for row in json.loads((output/'summary.json').read_text())['reports'])


def test_make_log_record_preserves_reconstruction_and_observes_final_warning(tmp_path):
    """Factory level=None is valid before the supplied dictionary is applied."""
    _, _, output, result = execute(tmp_path, '''
        import logging
        record = logging.makeLogRecord({'name': 'synthetic-receiver', 'levelno': logging.WARNING,
            'levelname': 'WARNING', 'msg': 'synthetic reconstructed warning', 'args': (), 'lineno': 37})
        assert record.levelno == logging.WARNING
        assert record.lineno == 37
        assert record.getMessage() == 'synthetic reconstructed warning'
    ''')
    assert result['outcome'] == 'warning_or_unstructured_stderr'
    assert any(row['category'] == 'logging.WARNING' for row in result['warnings'])
    assert all(row['outcome'] == 'passed' for row in json.loads((output/'summary.json').read_text())['reports'])
