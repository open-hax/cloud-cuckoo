# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic executor controls; these never supply application mutation credit."""
import copy
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_executor as executor
import native_inventory as inventory


def source(tmp_path, *, call_prefix=''):
    root = tmp_path / 'application'
    module = root / 'src/knoxx_colab_mcp/example.py'
    module.parent.mkdir(parents=True)
    module.write_text('VALUE = 1\n')
    tests = root / 'tests/test_example.py'
    tests.parent.mkdir()
    tests.write_text('from knoxx_colab_mcp import example\n'
        'def test_real_assertion():\n' + call_prefix + '    assert example.VALUE == 1\n')
    for args in (['init', '-q'], ['config', 'user.name', 'Synthetic Fixture'],
            ['config', 'user.email', 'fixture@example.invalid'], ['add', 'src', 'tests'],
            ['-c', 'core.hooksPath=/dev/null', 'commit', '--no-gpg-sign', '-qm', 'synthetic executor control']):
        subprocess.run(['git', *args], cwd=root, check=True, capture_output=True)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    files = inventory.source_custody(root, revision)
    lock = tmp_path / 'tools.lock'
    lock.write_text('explicit synthetic lock, no application admission\n')
    return root, revision, files, lock


def request(root, revision, files, lock, output, **extra):
    return {'schema': 'cloud-native-invocation/v1', 'producer_hashes': executor.producer_identity(),
        'root': str(root), 'source_sha': revision, 'files': files, 'tool_lock': str(lock),
        'tool_lock_sha256': executor.sha(lock.read_bytes()), 'result': str(output / 'result.json'), **extra}


def worker(value, output, *, cwd):
    output.mkdir()
    path = output / 'request.json'
    path.write_bytes(executor.encoded(value))
    result = subprocess.run([sys.executable, '-I', '-B', '-X', 'pycache_prefix=' + str(output / 'fresh-cache'),
        str(executor.HERE / 'native_executor.py'), '_worker', '--request', str(path)], cwd=cwd,
        env=executor.clean_environment(output), capture_output=True, timeout=30)
    (output / 'stdout').write_bytes(result.stdout)
    (output / 'stderr').write_bytes(result.stderr)
    return result


@pytest.mark.parametrize('relative', ['pytest.py', 'pluggy.py', 'sitecustomize.py',
    'pytest/__init__.py', '.ignored/cache.py', 'tests/__pycache__/old.pyc'])
def test_actual_untracked_shadow_modules_refuse_before_execution(tmp_path, relative):
    root, revision, files, lock = source(tmp_path)
    shadow = root / relative
    shadow.parent.mkdir(parents=True, exist_ok=True)
    sentinel = tmp_path / 'untrusted-code-executed'
    shadow.write_text('from pathlib import Path\nPath(' + repr(str(sentinel)) + ').touch()\n')
    output = tmp_path / 'worker'
    result = worker(request(root, revision, files, lock, output, mode='collection',
        tests=['tests/test_example.py']), output, cwd=root)
    assert result.returncode == 2
    assert not sentinel.exists()
    assert not (output / 'result.json').exists()
    assert json.loads(result.stdout)['outcome'] == 'qualification_refused'


def test_real_collection_returns_only_actual_nodeids_without_kill_credit(tmp_path):
    root, revision, files, lock = source(tmp_path)
    output = tmp_path / 'worker'
    result = worker(request(root, revision, files, lock, output, mode='collection',
        tests=['tests/test_example.py']), output, cwd=tmp_path)
    assert result.returncode == 0, (result.stdout, result.stderr)
    facts = executor.read_json(output / 'result.json')
    assert facts['nodeids'] == ['tests/test_example.py::test_real_assertion']
    assert facts['warnings'] == [] and facts['collection_errors'] == []
    assert 'genuine_assertion_kills' not in facts
    executor.verify_tree(root, revision, files)


@pytest.mark.parametrize('mode', ['changed', 'missing', 'symlink', 'hardlink', 'empty_directory', 'wrong_head'])
def test_complete_source_refuses_every_unadmitted_entry(tmp_path, mode):
    root, revision, files, _ = source(tmp_path)
    executor.verify_tree(root, revision, files)
    target = root / 'src/knoxx_colab_mcp/example.py'
    if mode == 'changed': target.write_text('VALUE = 2\n')
    if mode == 'missing': target.unlink()
    if mode == 'symlink':
        content = target.read_bytes()
        target.unlink()
        (tmp_path / 'outside').write_bytes(content)
        target.symlink_to(tmp_path / 'outside')
    if mode == 'hardlink': os.link(target, tmp_path / 'outside')
    if mode == 'empty_directory': (root / 'unused').mkdir()
    with pytest.raises(executor.Refusal):
        executor.verify_tree(root, 'f' * 40 if mode == 'wrong_head' else revision, files)


@pytest.mark.parametrize('native,assessment,containment,restored,expected', [
    ({'worker_outcome': 'normal', 'test_outcome': 'killed'},
        {'outcome': 'assertion_failure', 'assertion_failure': True}, {'cgroup_empty': True}, True, 'genuine_assertion_kill'),
    ({'worker_outcome': 'normal', 'test_outcome': 'survived'},
        {'outcome': 'passed', 'clean_baseline': True}, {'cgroup_empty': True}, True, 'survived'),
    *[({'worker_outcome': 'normal', 'test_outcome': 'killed'}, {'outcome': reason},
        {'cgroup_empty': True}, True, reason) for reason in ('runtime_error', 'collection_error',
        'setup_or_teardown_error', 'warning_or_unstructured_stderr', 'evidence_error', 'skipped', 'custody_error')],
    ({'worker_outcome': 'normal', 'test_outcome': 'killed'}, {'outcome': 'passed', 'clean_baseline': True},
        {'cgroup_empty': True}, True, 'native_evidence_disagreement'),
    ({'worker_outcome': 'exception', 'test_outcome': 'killed'}, {'assertion_failure': True},
        {'cgroup_empty': True}, True, 'native_worker_error'),
    ({'worker_outcome': 'normal', 'test_outcome': 'killed'}, {'assertion_failure': True},
        {'cgroup_empty': False}, True, 'containment_error'),
    ({'worker_outcome': 'normal', 'test_outcome': 'killed'}, {'assertion_failure': True},
        {'cgroup_empty': True, 'timed_out': True}, True, 'timed_out'),
    ({'worker_outcome': 'normal', 'test_outcome': 'killed'}, {'assertion_failure': True},
        {'cgroup_empty': True}, False, 'restoration_error'),
])
def test_native_killed_never_substitutes_for_genuine_evidence(native, assessment, containment, restored, expected):
    assert executor.classify(native, assessment, containment, restored) == expected


def test_official_native_result_persists_and_restores_even_runtime_exit_failure(tmp_path):
    root, revision, files, lock = source(tmp_path)
    frozen = tmp_path / 'inventory'
    manifest = inventory.freeze(root, revision, lock, frozen)
    _, entries, mapping = executor.read_inventory(frozen, root, revision, lock)
    entry = next(entry for entry in entries if entry['proposal_status'] == 'compile_valid')
    output = tmp_path / 'native'
    session = tmp_path / 'session.sqlite'
    session.write_bytes((frozen / 'session.sqlite').read_bytes())
    job_id = mapping[executor.native_spec_key(entry['native_spec'])]
    value = request(root, revision, files, lock, output, mode='native', entry=entry,
        native_tool_identity=manifest['tool_identity'], session=str(session),
        session_before_sha256=executor.sha(session.read_bytes()), job_id=job_id,
        test_command=shlex.join([sys.executable, '-I', '-B', '-c', 'raise RuntimeError("synthetic runtime error")']),
        test_timeout=10, native_result=str(tmp_path / 'native-result.json'))
    result = worker(value, output, cwd=tmp_path)
    assert result.returncode == 0, (result.stdout, result.stderr)
    persisted = executor.read_json(tmp_path / 'native-result.json')
    assert persisted['worker_outcome'] == 'normal' and persisted['test_outcome'] == 'killed'
    executor.verify_native_result(session, job_id, persisted)
    executor.verify_tree(root, revision, files)
    assert executor.classify(persisted, {'outcome': 'runtime_error'}, {'cgroup_empty': True}, True) == 'runtime_error'
    # A native job may not be evaluated a second time or overwrite its first result.
    value['session_before_sha256'] = executor.sha(session.read_bytes())
    second = tmp_path / 'second'
    value['result'] = str(second / 'result.json')
    assert worker(value, second, cwd=tmp_path).returncode == 2


@pytest.mark.parametrize('field', ['native_dump_sha256', 'native_session_sha256', 'inventory_sha256',
    'tool_lock_sha256', 'producer_sha256'])
def test_inventory_custody_tampering_refuses_before_tests(tmp_path, field):
    root, revision, _, lock = source(tmp_path)
    frozen = tmp_path / 'inventory'
    manifest = inventory.freeze(root, revision, lock, frozen)
    manifest[field] = '0' * 64
    (frozen / 'manifest.json').write_bytes(executor.encoded(manifest))
    with pytest.raises(executor.Refusal): executor.read_inventory(frozen, root, revision, lock)


def test_native_full_spec_mapping_rejects_duplicate_or_partial_match(tmp_path):
    root, revision, _, lock = source(tmp_path)
    frozen = tmp_path / 'inventory'
    manifest = inventory.freeze(root, revision, lock, frozen)
    lines = (frozen / 'dump.stdout').read_bytes().splitlines()
    rows = [json.loads(line) for line in lines]
    rows[1][0]['mutations'] = rows[0][0]['mutations']
    raw = b''.join(executor.encoded(row) for row in rows)
    (frozen / 'dump.stdout').write_bytes(raw)
    manifest['native_dump_sha256'] = executor.sha(raw)
    (frozen / 'manifest.json').write_bytes(executor.encoded(manifest))
    with pytest.raises(executor.Refusal): executor.read_inventory(frozen, root, revision, lock)


@pytest.mark.parametrize('mode', ['known_mutant', 'unknown_bytes', 'unrelated_change'])
def test_post_timeout_recovery_only_restores_exact_owned_mutant(tmp_path, mode):
    root, revision, files, _ = source(tmp_path)
    target = root / 'src/knoxx_colab_mcp/example.py'
    mutant = b'VALUE = 2\n'
    entry = {'module_path': str(target.relative_to(root)), 'original_sha256': executor.sha(target.read_bytes()),
        'mutated_sha256': executor.sha(mutant)}
    target.write_bytes(b'UNKNOWN\n' if mode == 'unknown_bytes' else mutant)
    if mode == 'unrelated_change': (root / 'tests/test_example.py').write_text('WRONG = True\n')
    if mode == 'known_mutant':
        executor.restore_owned_target(root, revision, files, entry)
        executor.verify_tree(root, revision, files)
    else:
        with pytest.raises(executor.Refusal): executor.restore_owned_target(root, revision, files, entry)


def test_external_venv_and_evidence_may_not_live_in_source_or_redirected_ancestry(tmp_path):
    root, _, _, _ = source(tmp_path)
    with pytest.raises(executor.Refusal): executor.safe_external(root / '.venv/bin/python', root)
    (tmp_path / 'redirect').symlink_to(root)
    with pytest.raises(executor.Refusal): executor.safe_external(tmp_path / 'redirect/output', root)
    assert executor.safe_external(tmp_path / 'external', root) == tmp_path / 'external'


def test_request_producer_or_tool_drift_refuses(tmp_path):
    root, revision, files, lock = source(tmp_path)
    value = request(root, revision, files, lock, tmp_path)
    executor.request_custody(value)
    changed = copy.deepcopy(value)
    changed['producer_hashes']['native_executor.py'] = '0' * 64
    with pytest.raises(executor.Refusal): executor.request_custody(changed)
    lock.write_text('changed tool lock\n')
    with pytest.raises(executor.Refusal): executor.request_custody(value)


def test_json_duplicate_and_redirected_summary_refuse(tmp_path):
    path = tmp_path / 'duplicate.json'
    path.write_text('{"complete":true,"complete":false}')
    with pytest.raises(executor.Refusal): executor.read_json(path)
    link = tmp_path / 'link.json'
    link.symlink_to(path)
    with pytest.raises(executor.Refusal): executor.read_json(link)


class SyntheticProcessBoundary:
    """Test-only dependency injection; never a kernel containment claim."""
    def __init__(self, *, late_journal=False):
        self.late_journal = late_journal
        self.invocations = []

    def run(self, arguments, *, output, environment, cwd, timeout):
        result = subprocess.run(arguments, cwd=cwd, env=environment, capture_output=True, timeout=timeout)
        (output / 'unit.stdout').write_bytes(result.stdout)
        (output / 'unit.stderr').write_bytes(result.stderr)
        value = executor.read_json(output / 'request.json')
        self.invocations.append(value['mode'])
        if self.late_journal and value['mode'] == 'evidence':
            with (Path(value['evidence']) / 'log-records.jsonl').open('ab') as stream:
                stream.write(b'{}\n')
        return {'cgroup_empty': True, 'timed_out': False, 'synthetic_control_only': True}


@pytest.mark.parametrize('mode', ['clean', 'warning', 'late_journal'])
def test_actual_synthetic_baseline_and_late_diagnostics_reassessment(tmp_path, monkeypatch, mode):
    prefix = '    import logging\n    logging.warning("unmatched synthetic warning")\n' if mode == 'warning' else ''
    root, revision, files, lock = source(tmp_path, call_prefix=prefix)
    monkeypatch.setattr(executor, 'APPLICATION_TESTS', ('tests/test_example.py',))
    monkeypatch.setattr(executor, 'E2E_FUNCTIONS', frozenset({'test_real_assertion'}))
    output = tmp_path / 'baseline'
    output.mkdir()
    boundary = SyntheticProcessBoundary(late_journal=mode == 'late_journal')
    if mode == 'clean':
        result = executor.baseline(root, revision, files, lock, sys.executable, output, boundary)
        assert result['integration']['assessment']['clean_baseline'] is True
        assert result['e2e']['assessment']['clean_baseline'] is True
        assert result['integration']['assessment']['call_assertions'] == 1
        assert boundary.invocations == ['collection', 'evidence', 'evidence']
    else:
        with pytest.raises(executor.Refusal):
            executor.baseline(root, revision, files, lock, sys.executable, output, boundary)
        assert boundary.invocations == ['collection', 'evidence']
        initial = executor.read_json(output / 'integration/worker-result.json')
        if mode == 'late_journal':
            assert initial['clean_baseline'] is True
            assert initial['execution_sha256']
        else:
            assert initial['clean_baseline'] is False
            assert initial['outcome'] == 'warning_or_unstructured_stderr'
    executor.verify_tree(root, revision, files)


def test_ordinary_venv_interpreter_symlink_is_supported_but_not_redirected_parent(tmp_path):
    root, _, _, _ = source(tmp_path)
    interpreter = tmp_path / 'python'
    interpreter.symlink_to(Path(sys.executable).resolve())
    assert executor.external_python(interpreter, root) == interpreter
    parent = tmp_path / 'venv-alias'
    parent.symlink_to(tmp_path)
    with pytest.raises(executor.Refusal): executor.external_python(parent / 'python', root)


@pytest.mark.parametrize('mode', ['overlap', 'missing_result', 'changed_inventory', 'wrong_source', 'clean'])
def test_four_group_collection_requires_exact_frozen_coverage_without_admitting_production(tmp_path, mode):
    groups = [[str(index) * 64] for index in range(4)]
    source_sha = 'a' * 40
    for index in range(4):
        frozen = {'source_sha': source_sha, 'inventory_sha256': 'b' * 64, 'seed': 'frozen seed',
            'partitions': groups, 'producer_sha256': executor.producer_identity()['native_inventory.py'],
            'tool_lock_sha256': executor.sha((executor.HERE / 'tools.lock').read_bytes())}
        inventory_dir = tmp_path / ('inventory-' + str(index))
        inventory_dir.mkdir()
        (inventory_dir / 'manifest.json').write_bytes(executor.encoded(frozen))
        assessment = {'assessment': {'clean_baseline': True, 'call_assertions': index + 1}}
        result = {'schema': 'cloud-native-partition/v1', 'source_sha': source_sha, 'partition': index,
            'qualification_credit': False, 'production_admitted': False, 'producer_hashes': executor.producer_identity(),
            'application_runtime': {'synthetic_control_only': True},
            'inventory_sha256': 'b' * 64, 'seed': 'frozen seed', 'selected': groups[index],
            'native_inventory_manifest_sha256': executor.sha(executor.encoded(frozen)), 'evaluated_mutants': 1,
            'genuine_assertion_kills': 0, 'outcomes': {'survived': 1},
            'baseline_before': {'integration': assessment, 'e2e': assessment},
            'baseline_after': {'integration': assessment, 'e2e': assessment},
            'results': [{'fingerprint': groups[index][0], 'outcome': 'survived'}]}
        if index == 3:
            if mode == 'overlap': result['selected'] = groups[0]
            if mode == 'missing_result': result['results'] = []
            if mode == 'changed_inventory': result['inventory_sha256'] = 'c' * 64
            if mode == 'wrong_source': result['source_sha'] = 'd' * 40
        partition_dir = tmp_path / ('partition-' + str(index))
        partition_dir.mkdir()
        (partition_dir / 'partition.json').write_bytes(executor.encoded(result))
    if mode == 'clean':
        result = executor.aggregate(tmp_path, source_sha, tmp_path / 'campaign.json')
        assert result['all_partitions_measured'] is True
        assert result['qualification_credit'] is False and result['production_admitted'] is False
        assert len(result['partitions']) == 4
        assert sum(part['genuine_assertion_kills'] for part in result['partitions']) == 0
    else:
        with pytest.raises(executor.Refusal): executor.aggregate(tmp_path, source_sha, tmp_path / 'campaign.json')


def test_uncertain_boundary_stops_owned_unit_retains_hold_and_never_advances(tmp_path, monkeypatch):
    boundary = executor.SystemdBoundary()
    calls = []
    def fail(*args, **kwargs):
        boundary.active_unit = 'cloud-cuckoo-invocation-synthetic.service'
        raise executor.Refusal('synthetic unavailable cgroup metadata')
    def command(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, b'', b'')
    monkeypatch.setattr(boundary, '_run', fail)
    monkeypatch.setattr(boundary, 'command', command)
    arguments = dict(output=tmp_path, environment={}, cwd=tmp_path, timeout=1)
    with pytest.raises(executor.Refusal): boundary.run(['synthetic'], **arguments)
    assert calls == [('systemctl', 'stop', 'cloud-cuckoo-invocation-synthetic.service')]
    assert executor.read_json(tmp_path / 'containment-error.json')['cgroup_empty'] is False
    with pytest.raises(executor.Refusal): boundary.run(['synthetic'], **arguments)
    assert len(calls) == 1


def test_actual_tiny_synthetic_campaign_runs_official_mutation_and_restored_measured_baselines(tmp_path, monkeypatch):
    root, revision, files, lock = source(tmp_path)
    frozen = tmp_path / 'inventory'
    manifest = inventory.freeze(root, revision, lock, frozen)
    monkeypatch.setattr(executor, 'APPLICATION_TESTS', ('tests/test_example.py',))
    monkeypatch.setattr(executor, 'E2E_FUNCTIONS', frozenset({'test_real_assertion'}))
    result = executor.campaign(root, revision, frozen, lock, sys.executable, tmp_path / 'campaign', 0,
        boundary=SyntheticProcessBoundary())
    assert result['selected'] == manifest['partitions'][0]
    assert result['evaluated_mutants'] == len(result['selected']) > 0
    # These are deliberately tiny synthetic fixture assertions, not application
    # qualification credit. The release CLI has no synthetic boundary override.
    assert result['genuine_assertion_kills'] == result['evaluated_mutants']
    assert result['qualification_credit'] is False and result['production_admitted'] is False
    assert result['baseline_before']['integration']['assessment']['call_assertions'] == 1
    assert result['baseline_after']['integration']['assessment']['call_assertions'] == 1
    assert all(row['restored'] and row['assessment']['assertion_failure'] for row in result['results'])
    executor.verify_tree(root, revision, files)
