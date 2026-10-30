"""Native inventory laws; synthetic sources supply no application qualification."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import warnings
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_inventory as inventory


def setup_source(tmp_path):
    root = tmp_path/'source'
    module = root/inventory.MODULE/'example.py'
    module.parent.mkdir(parents=True)
    module.write_text('VALUE = 1\n')
    for args in (['init', '-q'], ['config', 'user.name', 'Synthetic Fixture'],
                 ['config', 'user.email', 'fixture@example.invalid'], ['add', 'src'],
                 ['-c', 'core.hooksPath=/dev/null', 'commit', '--no-gpg-sign', '-qm', 'explicit synthetic source']):
        subprocess.run(['git', *args], cwd=root, check=True, capture_output=True)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    lock = tmp_path/'tools.lock'
    lock.write_text('synthetic native-inventory control, not an admitted tool lock\n')
    return root, revision, module, lock


def test_git_source_custody_rejects_dirty_bytes_wrong_revision_and_symlink(tmp_path):
    root, revision, module, _ = setup_source(tmp_path)
    original = module.read_bytes()
    actual = inventory.source_custody(root, revision)
    assert actual[str(module.relative_to(root))] == hashlib.sha256(original).hexdigest()
    for mode in ('dirty', 'wrong_revision', 'redirected'):
        if mode == 'dirty':
            module.write_bytes(original + b'VALUE=2\n')
        if mode == 'redirected':
            target = tmp_path/'redirected.py'
            target.write_bytes(original)
            module.unlink()
            module.symlink_to(target)
        with pytest.raises(inventory.Refusal):
            inventory.source_custody(root, 'f'*40 if mode == 'wrong_revision' else revision)
        if module.is_symlink():
            module.unlink()
        module.write_bytes(original)


def test_native_proposal_negatives_and_duplicate_bytes_are_retained_without_kill_credit(tmp_path):
    root, revision, module, _ = setup_source(tmp_path)
    source = inventory.source_custody(root, revision)
    destination = tmp_path/'mutants'
    destination.mkdir()
    spec = {'module_path': str(module.relative_to(root)), 'operator_name': 'core/SyntheticControl',
            'operator_args': {}, 'occurrence': 0, 'start_pos': [1, 0], 'end_pos': [1, 9]}
    seen = set()
    def run(change):
        return inventory.materialize(copy.deepcopy(spec), root=root, revision=revision, source=source,
            mutate=change, operator=lambda name: lambda: object(), seen=seen, output=destination)
    good = run(lambda *args: 'VALUE = 2\n')
    assert good['proposal_status'] == 'compile_valid'
    assert run(lambda *args: 'VALUE = 2\n')['proposal_status'] == 'duplicate_mutated_bytes'
    assert run(lambda *args: 'VALUE = 1\n')['proposal_status'] == 'inapplicable_or_noop'
    assert run(lambda *args: 'VALUE = (\n')['proposal_status'] == 'syntax_error'
    def fail(*args):
        raise RuntimeError('synthetic native operator failure')
    assert run(fail)['proposal_status'] == 'operator_error'
    def warn(*args):
        warnings.warn('synthetic operator warning')
        return 'VALUE = 3\n'
    assert run(warn)['proposal_status'] == 'compile_or_operator_warning'
    assert not any('kill' in key for key in good)
    assert inventory.sha((destination/(good['fingerprint']+'.py')).read_bytes()) == good['mutated_sha256']


def test_out_of_scope_and_non_native_specs_refuse(tmp_path):
    root, revision, _, _ = setup_source(tmp_path)
    spec = {'module_path': 'tests/test_fake.py', 'operator_name': 'external/Fake',
            'operator_args': {}, 'occurrence': 0}
    with pytest.raises(inventory.Refusal):
        inventory.materialize(spec, root=root, revision=revision,
            source=inventory.source_custody(root, revision), mutate=None, operator=None, seen=set(), output=tmp_path)


def test_frozen_partition_is_deterministic_disjoint_and_has_no_negative_proposals():
    entries = [{'fingerprint': hashlib.sha256(str(n).encode()).hexdigest(),
                'proposal_status': 'compile_valid' if n < 21 else 'syntax_error'} for n in range(25)]
    actual = inventory.partition(entries)
    assert actual == inventory.partition(list(reversed(entries)))
    assert sorted(map(len, actual)) == [5, 5, 5, 6]
    assert len({value for batch in actual for value in batch}) == 21


def test_actual_native_init_dump_and_mutation_api_never_execute_test_jobs(tmp_path):
    root, revision, _, lock = setup_source(tmp_path)
    before = inventory.source_custody(root, revision)
    result = inventory.freeze(root, revision, lock, tmp_path/'inventory')
    assert result['source_files'] == before == inventory.source_custody(root, revision)
    assert result['proposal_count'] > 0
    assert result['evaluated_mutants'] == result['genuine_assertion_kills'] == 0
    assert result['qualification_credit'] is result['production_admitted'] is False
    output = tmp_path/'inventory'
    assert result['inventory_sha256'] == inventory.sha((output/'inventory.json').read_bytes())
    assert json.loads((output/'manifest.json').read_text()) == result
    with pytest.raises(inventory.Refusal):
        inventory.freeze(root, revision, lock, output)


def test_output_parent_alias_and_dot_dot_refuse_before_native_commands_or_writes(tmp_path):
    root, revision, _, lock = setup_source(tmp_path)
    alias = tmp_path/'outside-alias'
    alias.symlink_to(root/inventory.MODULE, target_is_directory=True)
    before = inventory.source_custody(root, revision)
    for destination in (alias/'injected', tmp_path/'outside-alias/../injected', root/'injected'):
        with patch.object(inventory, 'tool_identity') as identity, patch.object(inventory.subprocess, 'run') as native:
            with pytest.raises(inventory.Refusal):
                inventory.freeze(root, revision, lock, destination)
            identity.assert_not_called()
            native.assert_not_called()
        assert not destination.exists()
        assert not (root/inventory.MODULE/'injected').exists()
    assert inventory.source_custody(root, revision) == before
