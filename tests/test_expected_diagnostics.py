"""Exact diagnostic contracts never excuse an unknown runtime failure."""
import json

import pytest

from test_pytest_evidence import execute


PREFIX = 'from expected_diagnostics import capture_expected_logs\n'
TARGET = '''
import logging
VALUE = 1
def emit():
    try:
        raise ValueError("injected fixture fault")
    except Exception:
        logging.getLogger("fixture.operation").exception("Operation failed")
'''
BODY = '''
with capture_expected_logs(caplog, "fixture") as diagnostics:
    emit()
    diagnostics.expect(logger="fixture.operation", level=40, message="Operation failed",
                       exception=ValueError("injected fixture fault"))
assert VALUE == 1
'''


def test_exact_injected_fault_is_preserved_and_acknowledged_after_contract(tmp_path):
    _, _, output, result = execute(tmp_path, BODY, target=TARGET, prefix=PREFIX, args='caplog')
    assert result['clean_baseline'] and result['outcome'] == 'passed'
    assert result['warnings'] == [] and result['qualification_credit'] is False
    assert len(result['diagnostics']) == len(result['expected_diagnostics']) == 1
    acknowledged = result['expected_diagnostics'][0]
    assert acknowledged['observation'] == result['diagnostics'][0]
    assert acknowledged['acknowledgement']['test_site'][0] == 'tests/test_case.py'
    events = [json.loads(line) for line in (output / 'log-records.jsonl').read_text().splitlines()]
    assert [row['event'] for row in events] == ['observed', 'acknowledged']
    assert len({row['nonce'] for row in events}) == 1


@pytest.mark.parametrize('replacement', ['RuntimeError("unexpected internal fault")',
    'ValueError("different internal fault")', 'TypeError("injected fixture fault")'])
def test_generic_logging_site_never_acknowledges_an_unknown_internal_exception(tmp_path, replacement):
    _, _, _, result = execute(tmp_path, BODY, target=TARGET.replace('ValueError("injected fixture fault")', replacement),
                               prefix=PREFIX, args='caplog')
    assert not result['clean_baseline'] and not result['assertion_failure']
    assert result['expected_diagnostics'] == []
    assert result['warnings'] and result['qualification_credit'] is False


@pytest.mark.parametrize(('old', 'new'), [('fixture.operation', 'another.logger'),
    ('level=40', 'level=30'), ('message="Operation failed"', 'message="Another message"')])
def test_exact_logger_level_and_rendered_message_are_required(tmp_path, old, new):
    _, _, _, result = execute(tmp_path, BODY.replace(old, new), target=TARGET, prefix=PREFIX, args='caplog')
    assert not result['clean_baseline'] and not result['assertion_failure']
    assert result['expected_diagnostics'] == [] and result['warnings']


def test_duplicate_extra_event_is_not_excused_by_one_exact_contract(tmp_path):
    _, _, _, result = execute(tmp_path, BODY.replace('    emit()', '    emit()\n    emit()'),
                               target=TARGET, prefix=PREFIX, args='caplog')
    assert not result['clean_baseline'] and not result['assertion_failure']
    assert len(result['expected_diagnostics']) == 1 and len(result['warnings']) == 1


def test_missing_event_is_a_contract_runtime_error_never_an_assertion_kill(tmp_path):
    _, _, _, result = execute(tmp_path, BODY.replace('    emit()', '    pass'),
                               target=TARGET, prefix=PREFIX, args='caplog')
    assert result['outcome'] == 'runtime_error' and not result['assertion_failure']
    assert result['expected_diagnostics'] == []


def test_expected_record_does_not_hide_a_separate_genuine_test_assertion(tmp_path):
    _, _, _, result = execute(tmp_path, BODY.replace('assert VALUE == 1', 'assert VALUE == 2'),
                               target=TARGET, prefix=PREFIX, args='caplog')
    assert result['outcome'] == 'assertion_failure' and result['assertion_failure']
    assert len(result['expected_diagnostics']) == 1 and result['warnings'] == []


def test_acknowledged_record_never_excuses_consumed_or_unconsumed_stderr(tmp_path):
    body = BODY + '\nimport sys\nprint("unexpected stderr", file=sys.stderr)\ncapsys.readouterr()\n'
    _, _, _, result = execute(tmp_path, body, target=TARGET, prefix=PREFIX, args='caplog,capsys')
    assert result['outcome'] == 'warning_or_unstructured_stderr'
    assert not result['assertion_failure'] and not result['clean_baseline']
    assert any(row['category'] == 'pytest.CaptureFixtureStderr' for row in result['warnings'])


def test_late_shutdown_record_at_same_generic_site_stays_unacknowledged(tmp_path):
    body = BODY + '\nimport atexit\natexit.register(emit)\n'
    _, _, _, result = execute(tmp_path, body, target=TARGET, prefix=PREFIX, args='caplog')
    assert result['outcome'] == 'warning_or_unstructured_stderr'
    assert len(result['expected_diagnostics']) == 1 and result['warnings']
    assert not result['clean_baseline'] and not result['assertion_failure']


def test_exact_cause_and_context_graph_are_required(tmp_path):
    target = TARGET.replace('raise ValueError("injected fixture fault")',
        'try:\n            raise OSError("injected cause")\n        except OSError as cause:\n            raise ValueError("injected fixture fault") from cause')
    _, _, _, rejected = execute(tmp_path / 'missing-chain', BODY, target=target, prefix=PREFIX, args='caplog')
    assert rejected['warnings'] and not rejected['assertion_failure'] and not rejected['clean_baseline']
    body = BODY.replace('    diagnostics.expect(',
        '    expected = ValueError("injected fixture fault")\n'
        '    expected.__cause__ = expected.__context__ = OSError("injected cause")\n'
        '    expected.__suppress_context__ = True\n    diagnostics.expect(').replace(
        'exception=ValueError("injected fixture fault"))', 'exception=expected)')
    _, _, _, accepted = execute(tmp_path / 'exact-chain', body, target=target, prefix=PREFIX, args='caplog')
    assert accepted['clean_baseline'] and len(accepted['expected_diagnostics']) == 1


def test_dynamic_non_test_site_cannot_acknowledge_a_real_record(tmp_path):
    body = BODY.replace('    diagnostics.expect(logger="fixture.operation", level=40, message="Operation failed",\n'
                        '                       exception=ValueError("injected fixture fault"))',
                        '    eval(\'diagnostics.expect(logger="fixture.operation", level=40, message="Operation failed", exception=ValueError("injected fixture fault"))\')')
    _, _, _, result = execute(tmp_path, body, target=TARGET, prefix=PREFIX, args='caplog')
    assert result['warnings'] and result['expected_diagnostics'] == []
    assert not result['clean_baseline'] and not result['assertion_failure']


@pytest.mark.parametrize('field', ['nonce', 'record_id'])
def test_journal_acknowledgement_requires_parent_nonce_and_original_record_identity(tmp_path, field):
    body = BODY + '''
import json,os
from pathlib import Path
path=Path(os.environ["CLOUD_PYTEST_LOG_JOURNAL"])
events=[json.loads(line) for line in path.read_text().splitlines()]
'''
    body += ('events[-1]["nonce"]="0"*64\n' if field == 'nonce' else
             'events[-1]["payload"]["record_id"]="0"*32\n')
    body += 'path.write_text("".join(json.dumps(event)+"\\n" for event in events))\n'
    _, _, _, result = execute(tmp_path, body, target=TARGET, prefix=PREFIX, args='caplog')
    assert result['outcome'] == 'evidence_error'
    assert not result['clean_baseline'] and not result['assertion_failure']


@pytest.mark.parametrize('substitution', ['exception', 'message', 'exception_arguments', 'format_arguments'])
def test_mutating_a_captured_record_cannot_replace_the_observed_diagnostic(tmp_path, substitution):
    target = TARGET.replace('ValueError("injected fixture fault")', 'TypeError("unexpected internal fault")')
    edit = ('    record = caplog.records[-1]\n'
            '    record.exc_info = (ValueError, ValueError("injected fixture fault"), record.exc_info[2])\n')
    if substitution == 'message':
        target = TARGET.replace('"Operation failed"', '"Unexpected operation failure"')
        edit = '    caplog.records[-1].msg = "Operation failed"\n'
    elif substitution == 'exception_arguments':
        target = TARGET.replace('ValueError("injected fixture fault")', 'ValueError("unexpected internal fault")')
        edit = '    caplog.records[-1].exc_info[1].args = ("injected fixture fault",)\n'
    body = BODY.replace('    diagnostics.expect(', edit + '    diagnostics.expect(')
    if substitution == 'format_arguments':
        target = TARGET.replace('exception("Operation failed")', 'exception("Operation %s failed", "internal")')
        body = BODY.replace(edit, '    caplog.records[-1].args = ("fixture",)\n').replace(
            'message="Operation failed"', 'message="Operation fixture failed"')
    _, _, _, result = execute(tmp_path, body, target=target, prefix=PREFIX, args='caplog')
    assert not result['clean_baseline'] and not result['assertion_failure']
    assert result['expected_diagnostics'] == [] and result['warnings']


def test_passive_exception_snapshot_never_formats_opaque_lazy_arguments(tmp_path):
    body = '''
import logging
class LazyArgument:
    def __str__(self):
        raise RuntimeError("passive observer formatted a lazy argument")
logger=logging.getLogger("fixture.lazy-exception")
logger.handlers=[logging.NullHandler()]
logger.propagate=False
try:
    raise ValueError(LazyArgument())
except ValueError:
    logger.exception("Generic operation failure")
assert True
'''
    _, _, _, result = execute(tmp_path, body)
    assert result['outcome'] == 'warning_or_unstructured_stderr'
    assert result['warnings'] and result['expected_diagnostics'] == []
    assert not result['clean_baseline'] and not result['assertion_failure']


def test_custom_exception_renderer_cannot_replace_the_message_observed_at_log_time(tmp_path):
    target = '''
import logging
VALUE=1
class MutableRenderingError(ValueError):
    def __init__(self, rendered):
        super().__init__("stable primitive argument")
        self.rendered=rendered
    def __str__(self):
        return self.rendered
def emit():
    error=MutableRenderingError("unexpected observed message")
    try:
        raise error
    except MutableRenderingError:
        logging.getLogger("fixture.operation").exception("Operation failed")
    error.rendered="expected message"
'''
    body = BODY.replace('exception=ValueError("injected fixture fault"))',
                        'exception=MutableRenderingError("expected message"))')
    _, _, _, result = execute(tmp_path, body, target=target, prefix=PREFIX, args='caplog')
    assert not result['clean_baseline'] and not result['assertion_failure']
    assert result['expected_diagnostics'] == [] and result['warnings']
