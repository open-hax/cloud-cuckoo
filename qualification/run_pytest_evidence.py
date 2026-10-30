# SPDX-License-Identifier: GPL-3.0-or-later
"""Parent-observed pytest execution, never a standalone promotion authority.

Source admission must supply the frozen manifest. Native CI custody must bind
the returned execution digest; accepting an attacker-supplied digest is not
authentication. This adapter never creates mutation proposals or awards release
qualification credit, and never trusts Cosmic Ray's exit-code kill scoreboard.
"""
import json
import hashlib
import argparse
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import time
import tempfile

from pytest_evidence import encoded, producer_hashes, relative_file, sha, source_hashes, valid_test_site


class EvidenceError(ValueError):
    pass


def require(value):
    if not value:
        raise EvidenceError('Evidence or custody refused')


def clean_env(home, extra=None):
    return {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(home),
            'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
            'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1', **(extra or {})}


def target_runtime(python, home):
    directory = str(Path(__file__).resolve().parent)
    code = 'import json,pytest_evidence; print(json.dumps(pytest_evidence.runtime_identity(),sort_keys=True))'
    with tempfile.TemporaryDirectory(prefix='cloud-pytest-runtime-cache-') as cache:
        result = subprocess.run([str(python), '-B', '-X', 'pycache_prefix=' + cache, '-P', '-c', code],
                                capture_output=True, timeout=20,
                                env=clean_env(home, {'PYTHONPATH': directory}), check=False)
    require(result.returncode == 0 and not result.stderr)
    return json.loads(result.stdout)


def make_manifest(root, source_sha, files, tests, imports, expected_nodeids, tool_lock, python, *, phase='adapter_control'):
    root, tool_lock, python = Path(root).resolve(), Path(tool_lock).resolve(), Path(python).absolute()
    require(re.fullmatch(r'[0-9a-f]{40}', source_sha or '') and files and tests and imports and expected_nodeids)
    names = sorted(set(files))
    require(len(names) == len(files) and all(value.split('::', 1)[0] in names for value in tests))
    require(len(set(expected_nodeids)) == len(expected_nodeids))
    require(phase in {'adapter_control', 'integration', 'e2e'})
    return {'schema': 'cloud-pytest-manifest/v1', 'root': str(root), 'source_sha': source_sha, 'phase': phase,
            'files': {name: sha(relative_file(root, name).read_bytes()) for name in names},
            'tests': list(tests), 'imports': list(imports), 'expected_nodeids': sorted(expected_nodeids),
            'producer_hashes': producer_hashes(), 'tool_lock': {'path': str(tool_lock), 'sha256': sha(tool_lock.read_bytes())},
            'python': str(python), 'runtime_identity': target_runtime(python, root)}


def custody(manifest):
    require(manifest.get('schema') == 'cloud-pytest-manifest/v1')
    require(source_hashes(manifest) == manifest['files'] and producer_hashes() == manifest['producer_hashes'])
    lock = Path(manifest['tool_lock']['path'])
    require(not lock.is_symlink() and sha(lock.read_bytes()) == manifest['tool_lock']['sha256'])


def _write(path, raw):
    with path.open('xb') as target:
        os.chmod(path, 0o600)
        target.write(raw)
    return sha(raw)


def file_sha(path):
    require(path.is_file() and not path.is_symlink())
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def _stop(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=10)


def run_evidence(manifest, output, *, timeout=90, output_limit=16 * 1024 * 1024):
    output = Path(output)
    require(timeout > 0 and output_limit > 0)
    output.mkdir(mode=0o700)
    cache = output / 'python-cache'
    cache.mkdir(mode=0o700)
    manifest_raw = encoded(manifest)
    _write(output / 'manifest.json', manifest_raw)
    nonce = secrets.token_hex(32)
    envelope = {'schema': 'cloud-pytest-execution/v1', 'manifest_sha256': sha(manifest_raw),
                'nonce': nonce, 'observed_exit': None, 'timed_out': False, 'output_limit': False,
                'custody_before': False, 'custody_after': False, 'summary_sha256': None}
    envelope['pycache_prefix'] = str(cache.resolve())
    for name in ('stdout.bin', 'stderr.bin', 'log-records.jsonl'):
        _write(output / name, b'')
    process = None
    try:
        custody(manifest)
        require(target_runtime(manifest['python'], output) == manifest['runtime_identity'])
        envelope['custody_before'] = True
        root = Path(manifest['root'])
        package_paths = [str(root / 'src'), str(root)]
        env = clean_env(output, {'PYTHONPATH': os.pathsep.join([str(Path(__file__).resolve().parent), *package_paths]),
            'CLOUD_PYTEST_MANIFEST': str((output / 'manifest.json').resolve()),
            'CLOUD_PYTEST_CACHE': str(cache.resolve()),
            'CLOUD_PYTEST_LOG_JOURNAL': str((output / 'log-records.jsonl').resolve()),
            'CLOUD_PYTEST_SUMMARY': str((output / 'summary.json').resolve()), 'CLOUD_PYTEST_NONCE': nonce})
        args = [manifest['python'], '-B', '-X', 'pycache_prefix=' + str(cache.resolve()), '-P', '-m', 'pytest',
                '-q', '-p', 'pytest_evidence', '-p', 'pytest_asyncio.plugin',
                '-p', 'no:cacheprovider', '-o', 'enable_assertion_pass_hook=true', '--rootdir', str(root),
                '--confcutdir', str(root), *manifest['tests']]
        with (output / 'stdout.bin').open('wb') as stdout, (output / 'stderr.bin').open('wb') as stderr:
            process = subprocess.Popen(args, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    envelope['timed_out'] = True
                    _stop(process)
                    break
                if sum((output / name).stat().st_size for name in ('stdout.bin', 'stderr.bin', 'log-records.jsonl')) > output_limit:
                    envelope['output_limit'] = True
                    _stop(process)
                    break
                time.sleep(0.025)
            envelope['observed_exit'] = process.wait(timeout=10)
            if sum((output / name).stat().st_size for name in ('stdout.bin', 'stderr.bin', 'log-records.jsonl')) > output_limit:
                envelope['output_limit'] = True
        custody(manifest)
        require(target_runtime(manifest['python'], output) == manifest['runtime_identity'])
        envelope['custody_after'] = True
    except Exception:
        # Static flags plus raw files preserve failure without echoing source,
        # test operands or private exception payloads into the public result.
        pass
    finally:
        if process is not None:
            if process.poll() is None:
                _stop(process)
            # Clean descendants that retained this invocation's owned group.
            # The outer producer must also own a cgroup for children that
            # create new sessions, and verify its emptiness before another job.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    summary = output / 'summary.json'
    if summary.is_file() and not summary.is_symlink() and summary.stat().st_size <= 2 * 1024 * 1024:
        envelope['summary_sha256'] = sha(summary.read_bytes())
    envelope['stdout_sha256'] = file_sha(output / 'stdout.bin')
    envelope['stderr_sha256'] = file_sha(output / 'stderr.bin')
    envelope['log_records_sha256'] = file_sha(output / 'log-records.jsonl')
    digest = _write(output / 'execution.json', encoded(envelope))
    result = assess(output, manifest, digest)
    return {**result, 'execution_sha256': digest}


def assess(output, manifest, expected_execution_sha256):
    """Assess only parent/native-custody-bound bytes, never a pasted summary."""
    output = Path(output)
    result = {'schema': 'cloud-pytest-assessment/v1', 'source_sha': manifest.get('source_sha'),
              'phase': manifest.get('phase'),
              'outcome': 'evidence_error', 'call_assertions': 0, 'warnings': [],
              'assertion_failure': False, 'clean_baseline': False, 'qualification_credit': False}
    try:
        execution = output / 'execution.json'
        require(not execution.is_symlink() and sha(execution.read_bytes()) == expected_execution_sha256)
        envelope = json.loads(execution.read_bytes())
        require(envelope['schema'] == 'cloud-pytest-execution/v1' and
                envelope['manifest_sha256'] == sha(encoded(manifest)) and
                sha((output / 'manifest.json').read_bytes()) == envelope['manifest_sha256'])
        for name in ('stdout', 'stderr'):
            path = output / (name + '.bin')
            require(file_sha(path) == envelope[name + '_sha256'])
        journal = output / 'log-records.jsonl'
        require(file_sha(journal) == envelope['log_records_sha256']
                and journal.stat().st_size <= 16 * 1024 * 1024)
        logged = [json.loads(line) for line in journal.read_bytes().splitlines()]
        require(all(isinstance(row, dict)
                and set(row) == {'schema', 'nonce', 'category', 'message_sha256', 'when', 'nodeid'}
                and row['schema'] == 'cloud-pytest-log-record/v1' and row['nonce'] == envelope['nonce']
                and isinstance(row['category'], str) and row['category'].startswith('logging.')
                and isinstance(row['message_sha256'], str) and re.fullmatch('[0-9a-f]{64}', row['message_sha256'])
                and row['when'] == 'process' and row['nodeid'] is None for row in logged))
        if not envelope['custody_before'] or not envelope['custody_after']:
            result['outcome'] = 'custody_error'
            return result
        if envelope['timed_out'] or envelope['output_limit']:
            result['outcome'] = 'timed_out' if envelope['timed_out'] else 'output_limit'
            return result
        path = output / 'summary.json'
        require(path.stat().st_size <= 2 * 1024 * 1024 and file_sha(path) == envelope['summary_sha256'])
        facts = json.loads(path.read_bytes())
        require(facts['schema'] == 'cloud-pytest-facts/v1' and facts['complete'] is True and
                facts['nonce'] == envelope['nonce'] and facts['manifest_sha256'] == envelope['manifest_sha256'] and
                facts['exit_code'] == envelope['observed_exit'] and
                facts['producer_hashes'] == manifest['producer_hashes'] and
                facts['runtime_identity'] == manifest['runtime_identity'] and
                facts['pycache_prefix'] == envelope['pycache_prefix'] and facts['dont_write_bytecode'] is True)
        if facts['source_before'] != manifest['files'] or facts['source_after'] != manifest['files']:
            result['outcome'] = 'custody_error'
            return result
        require(set(facts['assertion_passes']) == {'setup', 'call', 'teardown'} and
                all(type(value) is int and value >= 0 for value in facts['assertion_passes'].values()) and
                isinstance(facts['warnings'], list) and isinstance(facts['collected'], list) and
                type(facts['exit_code']) is int and type(facts['collection_failed']) is bool and
                isinstance(facts['collection_errors'], list))
        result['call_assertions'] = facts['assertion_passes']['call']
        result['warnings'] = facts['warnings'] + [
            {key: value for key, value in row.items() if key not in {'schema', 'nonce'}} for row in logged]
        if result['warnings'] or (output / 'stderr.bin').stat().st_size:
            result['outcome'] = 'warning_or_unstructured_stderr'
            return result
        if sorted(facts['collected']) != manifest['expected_nodeids'] or facts['collection_failed']:
            result['outcome'] = 'collection_error'
            return result
        if not facts['imports'] or any(not value.get('valid') or
                value.get('sha256') != manifest['files'].get(value.get('path')) for value in facts['imports'].values()):
            result['outcome'] = 'custody_error'
            return result
        reports = facts['reports']
        require(isinstance(reports, list) and reports and all(
            isinstance(r, dict) and set(r) == {'nodeid', 'when', 'outcome', 'exception_type', 'failure_kind', 'test_site'} and
            r['nodeid'] in facts['collected'] and r['when'] in {'setup', 'call', 'teardown'} and
            r['outcome'] in {'passed', 'failed', 'skipped'} for r in reports) and
            len({(r['nodeid'], r['when']) for r in reports}) == len(reports))
        if any(r['outcome'] == 'skipped' for r in reports):
            result['outcome'] = 'skipped'
        elif any(r['outcome'] != 'passed' and r['when'] != 'call' for r in reports):
            result['outcome'] = 'setup_or_teardown_error'
        else:
            phases = {(r['nodeid'], r['when']) for r in reports}
            require(all((node, phase) in phases for node in facts['collected'] for phase in ('setup', 'call', 'teardown')))
            failed = [r for r in reports if r['when'] == 'call' and r['outcome'] == 'failed']
            if failed:
                genuine = all(r['failure_kind'] in {'assertion', 'expected_exception', 'explicit_fail'} and
                    r['exception_type'] == ('builtins.AssertionError' if r['failure_kind'] == 'assertion'
                                            else manifest['runtime_identity']['pytest_failure_type']) and
                    valid_test_site(manifest, r['test_site'], r['failure_kind']) for r in failed)
                result['outcome'] = 'assertion_failure' if genuine and facts['exit_code'] == 1 else 'runtime_error'
                result['assertion_failure'] = result['outcome'] == 'assertion_failure'
            elif facts['exit_code'] == 0 and result['call_assertions'] > 0:
                phases = {(r['nodeid'], r['when']) for r in reports if r['outcome'] == 'passed'}
                if all((node, phase) in phases for node in facts['collected'] for phase in ('setup', 'call', 'teardown')):
                    result.update(outcome='passed', clean_baseline=True)
    except Exception:
        pass
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--timeout', type=float, default=90)
    args = parser.parse_args()
    try:
        manifest = json.loads(Path(args.manifest).read_bytes())
        result = run_evidence(manifest, Path(args.output), timeout=args.timeout)
        print(json.dumps(result, sort_keys=True))
        return 0 if result['clean_baseline'] else 1 if result['assertion_failure'] else 2
    except Exception:
        print(json.dumps({'outcome': 'evidence_error', 'qualification_credit': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
