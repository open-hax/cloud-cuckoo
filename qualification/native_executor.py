# SPDX-License-Identifier: GPL-3.0-or-later
"""Execute frozen native proposals with measured tests and real containment.

This is an admitted-source release path, not a sandbox for arbitrary Python.
The application checkout is exclusive and exactly matches Git; dependencies,
cache and evidence live outside it. Native outcomes never grant assertion or
production qualification by themselves. No application campaign is started by
importing this module or running its synthetic controls.
"""
import argparse
from collections import Counter
from contextlib import closing
import hashlib
import importlib.util
import importlib.metadata
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
APPLICATION_TESTS = (
    'tests/test_compute.py', 'tests/test_oauth.py', 'tests/test_transport.py',
    'tests/test_revocation_retry.py', 'tests/test_production_binding.py',
    'tests/test_transport_stage.py', 'tests/test_dependency_compatibility.py',
)
E2E_FUNCTIONS = frozenset({
    'test_typed_http_gateway_remote_job_and_cleanup', 'test_real_http_and_official_browser_transport',
    'test_real_gateway_forwards_to_dedicated_mcp_fixtures_and_preserves_errors',
    'test_oauth_authenticates_real_stage_forwarding_and_denies_replay_and_revocation',
    'test_proxy_http_mcp_identity_revocation_and_client_boundaries',
})


class Refusal(ValueError):
    pass


def require(value, reason='Native qualification custody refused'):
    if not value: raise Refusal(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    with path.open('xb') as target:
        path.chmod(0o600)
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def read_json(path, maximum=16 * 1024 * 1024):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum)
    def unique(pairs):
        result = {}
        for name, value in pairs:
            require(name not in result, 'Duplicate evidence field')
            result[name] = value
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def helper(name):
    """Load the accepted producer file explicitly, never from application cwd."""
    path = HERE / (name + '.py')
    require(path.is_file() and not path.is_symlink())
    if name in sys.modules:
        require(Path(sys.modules[name].__file__).resolve() == path)
        return sys.modules[name]
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def helpers():
    if (HERE / 'expected_diagnostics.py').exists(): helper('expected_diagnostics')
    helper('pytest_evidence')
    return helper('native_inventory'), helper('run_pytest_evidence')


def producer_identity():
    names = ['native_executor.py', 'native_inventory.py', 'pytest_evidence.py', 'run_pytest_evidence.py']
    if (HERE / 'expected_diagnostics.py').exists(): names.append('expected_diagnostics.py')
    return {name: sha((HERE / name).read_bytes()) for name in names}


def verify_tree(root, revision, expected):
    """Refuse untracked/ignored shadow code as well as missing or changed bytes."""
    require(root.is_absolute() and root.is_dir() and not any(p.is_symlink() for p in (root, *root.parents)))
    require((root / '.git').is_dir() and not (root / '.git').is_symlink(), 'Use an exclusive Git clone')
    require(re.fullmatch(r'[0-9a-f]{40}', revision or ''))
    actual_head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root).decode().strip()
    require(actual_head == revision, 'Application revision changed')
    files, directories = set(), set()
    for name in expected:
        value = Path(name)
        require(not value.is_absolute() and '..' not in value.parts)
        directories.update(str(parent) for parent in value.parents if str(parent) != '.')
    for path in root.rglob('*'):
        relative = path.relative_to(root)
        if relative.parts[0] == '.git': continue
        require(not path.is_symlink(), 'Redirected application entry')
        if path.is_dir():
            require(str(relative) in directories, 'Unexpected application directory')
        else:
            require(path.is_file() and path.stat().st_nlink == 1 and str(relative) in expected,
                    'Unexpected application file')
            files.add(str(relative))
            require(sha(path.read_bytes()) == expected[str(relative)], 'Application bytes changed')
    require(files == set(expected), 'Application source is incomplete')


def native_spec_key(spec):
    return encoded(spec)


def read_inventory(directory, root, revision, tool_lock):
    native, _ = helpers()
    manifest = read_json(directory / 'manifest.json')
    require(manifest.get('schema') == 'cloud-cuckoo-native-inventory/v1' and manifest.get('source_sha') == revision
        and manifest.get('evaluated_mutants') == 0 and manifest.get('qualification_credit') is False)
    require(manifest['producer_sha256'] == sha((HERE / 'native_inventory.py').read_bytes())
        and manifest['tool_lock_sha256'] == sha(tool_lock.read_bytes())
        and manifest['tool_identity'] == native.tool_identity(), 'Native tool or producer drift')
    for name, field in [('inventory.json', 'inventory_sha256'), ('dump.stdout', 'native_dump_sha256'),
                        ('session.sqlite', 'native_session_sha256')]:
        require((directory / name).is_file() and not (directory / name).is_symlink()
            and sha((directory / name).read_bytes()) == manifest[field])
    entries = read_json(directory / 'inventory.json', maximum=64 * 1024 * 1024)
    rows = [json.loads(line) for line in (directory / 'dump.stdout').read_bytes().splitlines()]
    mapping = {}
    for work, result in rows:
        require(result is None and isinstance(work, dict) and len(work.get('mutations', [])) == 1)
        key = native_spec_key(work['mutations'][0])
        require(key not in mapping and isinstance(work.get('job_id'), str) and work['job_id'])
        mapping[key] = work['job_id']
    require(len(mapping) == len(entries) == manifest['proposal_count']
        and len(set(mapping.values())) == len(mapping)
        and set(mapping) == {native_spec_key(entry['native_spec']) for entry in entries})
    require(dict(Counter(entry['proposal_status'] for entry in entries)) == manifest['proposal_statuses'])
    require(native.partition(entries) == manifest['partitions'], 'Frozen native partition selection changed')
    for entry in entries:
        require(entry['source_sha'] == revision and entry['original_sha256'] == manifest['source_files'][entry['module_path']])
        if 'fingerprint' in entry:
            fingerprint = entry['fingerprint']
            require(fingerprint == native.fingerprint(revision, entry['module_path'], entry['original_sha256'], entry['mutated_sha256']))
            path = directory / 'mutants' / (fingerprint + '.py')
            require(path.is_file() and not path.is_symlink() and sha(path.read_bytes()) == entry['mutated_sha256'])
    require(native.source_custody(root, revision) == manifest['source_files'], 'Inventory source differs from Git')
    verify_tree(root, revision, manifest['source_files'])
    return manifest, entries, mapping


def safe_external(path, root):
    path = Path(path).absolute()
    require('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents))
        and not path.is_relative_to(root), 'Evidence, dependencies and caches must be outside application source')
    return path


def external_python(path, root):
    """An ordinary venv interpreter leaf symlink is required on uv/POSIX."""
    path = Path(path).absolute()
    require(path.is_file() and os.access(path, os.X_OK) and not path.is_relative_to(root)
        and not path.resolve().is_relative_to(root) and '..' not in path.parts
        and not any(parent.is_symlink() for parent in path.parents), 'Unadmitted application interpreter')
    return path


def installed_identity():
    packages = {}
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata['Name'].lower().replace('_', '-')
        require(name not in packages)
        files = {}
        for entry in distribution.files or []:
            if not str(entry).endswith('.pyc'):
                path = Path(distribution.locate_file(entry))
                require(path.is_file() and not path.is_symlink())
                files[str(entry)] = sha(path.read_bytes())
        packages[name] = {'version': distribution.version, 'installed_files_sha256': sha(encoded(files))}
    return {'python': sys.version, 'python_sha256': sha(Path(sys.executable).resolve().read_bytes()),
            'packages': packages}


def application_identity(python, output):
    cache = output / ('runtime-cache-' + secrets.token_hex(16))
    cache.mkdir(mode=0o700)
    result = subprocess.run([str(python), '-I', '-B', '-X', 'pycache_prefix=' + str(cache),
        str(HERE / 'native_executor.py'), '_runtime'],
        cwd=output, env=clean_environment(output), capture_output=True, timeout=30, check=False)
    require(result.returncode == 0 and not result.stderr, 'Application dependency identity unavailable')
    return json.loads(result.stdout)


def clean_environment(home):
    return {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(home), 'LANG': 'C.UTF-8',
            'PYTHONDONTWRITEBYTECODE': '1', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}


def source_imports(source):
    return ['knoxx_colab_mcp.' + Path(name).stem for name in sorted(source)
            if name.startswith('src/knoxx_colab_mcp/') and name.endswith('.py')
            and name.count('/') == 2 and Path(name).stem != '__init__']


def classify(native, assessment, containment, restored):
    """Native KILLED is retained even when the real cause is not an assertion."""
    if not restored: return 'restoration_error'
    if not containment.get('cgroup_empty'): return 'containment_error'
    if containment.get('timed_out'): return 'timed_out'
    if containment.get('output_limit'): return 'output_limit'
    if containment.get('unstructured_diagnostics'): return 'native_tool_diagnostics'
    if native.get('worker_outcome') != 'normal': return 'native_worker_error'
    if native.get('test_outcome') == 'killed' and assessment.get('assertion_failure') is True \
            and assessment.get('outcome') == 'assertion_failure':
        return 'genuine_assertion_kill'
    if native.get('test_outcome') == 'survived' and assessment.get('clean_baseline') is True:
        return 'survived'
    return assessment.get('outcome', 'evidence_error') if assessment.get('outcome') not in \
        {'passed', 'assertion_failure'} else 'native_evidence_disagreement'


def request_custody(request):
    require(request.get('schema') == 'cloud-native-invocation/v1'
        and request.get('producer_hashes') == producer_identity(), 'Invocation producer changed')
    root = Path(request['root'])
    require(sha(Path(request['tool_lock']).read_bytes()) == request['tool_lock_sha256'])
    verify_tree(root, request['source_sha'], request['files'])
    return root


def collect_worker(request):
    """Native pytest collection supplies real node IDs, never assertion credit."""
    root = request_custody(request)
    # -I starts from installed tools, then these are the already admitted exact
    # application paths. No checkout-local pytest/pluggy/sitecustomize is allowed.
    import pytest
    sys.path[:0] = [str(root / 'src'), str(root)]
    state = {'nodeids': [], 'warnings': [], 'collection_errors': []}
    class Collector:
        def pytest_collection_finish(self, session):
            state['nodeids'] = [item.nodeid for item in session.items]
        def pytest_warning_recorded(self, warning_message, when, nodeid, location):
            state['warnings'].append({'category': warning_message.category.__name__,
                'message_sha256': sha(str(warning_message.message).encode())})
        def pytest_collectreport(self, report):
            if report.failed: state['collection_errors'].append(report.nodeid)
    os.chdir(root)
    result = pytest.main(['--collect-only', '-q', '-p', 'pytest_asyncio.plugin', '-p', 'no:cacheprovider',
        '--rootdir', str(root), '--confcutdir', str(root), *request['tests']], plugins=[Collector()])
    verify_tree(root, request['source_sha'], request['files'])
    write_new(Path(request['result']), encoded({'schema': 'cloud-native-collection/v1',
        'exit_code': int(result), 'producer_hashes': producer_identity(), **state}))
    return 0 if result == 0 and state['nodeids'] and not state['warnings'] else 2


def evidence_worker(request):
    request_custody(request)
    _, runner = helpers()
    result = runner.run_evidence(request['manifest'], Path(request['evidence']), timeout=request['test_timeout'])
    request_custody(request)
    write_new(Path(request['result']), encoded(result))
    return 0 if result['clean_baseline'] else 1 if result['assertion_failure'] else 2


def native_worker(request):
    # Official installed APIs are loaded before application cwd is introduced.
    from cosmic_ray.mutating import mutate_and_test
    from cosmic_ray.work_item import MutationSpec
    from cosmic_ray.work_db import use_db, WorkDB
    native, _ = helpers()
    require(native.tool_identity() == request['native_tool_identity'])
    root = request_custody(request)
    arguments = dict(request['entry']['native_spec'])
    arguments.update(start_pos=tuple(arguments['start_pos']), end_pos=tuple(arguments['end_pos']))
    spec = MutationSpec(**arguments)
    session = Path(request['session'])
    require(sha(session.read_bytes()) == request['session_before_sha256'])
    with use_db(session, mode=WorkDB.Mode.open) as database:
        work = [item for item in database.work_items if item.job_id == request['job_id']]
        require(len(work) == 1 and len(work[0].mutations) == 1 and work[0].mutations[0] == spec
            and request['job_id'] not in dict(database.results), 'Native job/session mismatch')
    os.chdir(root)
    result = mutate_and_test([spec], request['test_command'], timeout=request['test_timeout'] + 20)
    # Preserve the actual native WorkResult with the official API, including all
    # its negative statuses. No conversion to the native is_killed convenience.
    with use_db(session, mode=WorkDB.Mode.open) as database:
        database.set_result(request['job_id'], result)
    verify_tree(root, request['source_sha'], request['files'])
    require(native.tool_identity() == request['native_tool_identity'], 'Native tool changed during execution')
    native_result = {'worker_outcome': result.worker_outcome.value,
        'test_outcome': result.test_outcome.value if result.test_outcome is not None else None,
        'output': result.output, 'diff': result.diff}
    write_new(Path(request['native_result']), encoded(native_result))
    write_new(Path(request['result']), encoded({'restored': True, 'native': native_result,
        'session_sha256': sha(session.read_bytes()), 'producer_hashes': producer_identity()}))
    return 0


def invocation(request, output, *, python, boundary, timeout):
    output.mkdir(mode=0o700)
    request = {**request, 'schema': 'cloud-native-invocation/v1', 'producer_hashes': producer_identity(),
        'result': str(output / 'worker-result.json')}
    write_new(output / 'request.json', encoded(request))
    proof = boundary.run([str(python), '-I', '-B', '-X', 'pycache_prefix=' + str(output / 'fresh-cache'),
        str(HERE / 'native_executor.py'), '_worker', '--request', str(output / 'request.json')],
        output=output, environment=clean_environment(output), cwd=output, timeout=timeout)
    require(proof.get('cgroup_empty'), 'Invocation containment is not proven')
    result = read_json(output / 'worker-result.json') if (output / 'worker-result.json').is_file() else None
    return result, proof


def baseline(root, revision, source, tool_lock, python, output, boundary):
    _, runner = helpers()
    base = {'root': str(root), 'source_sha': revision, 'files': source,
        'tool_lock': str(tool_lock), 'tool_lock_sha256': sha(tool_lock.read_bytes())}
    runtime = application_identity(python, output)
    require(all(name in source for name in APPLICATION_TESTS), 'The frozen application test plan is incomplete')
    collection, proof = invocation({**base, 'mode': 'collection', 'tests': APPLICATION_TESTS}, output / 'collection',
        python=python, boundary=boundary, timeout=90)
    require(isinstance(collection, dict) and not proof['timed_out'] and not proof.get('output_limit')
        and not proof.get('unstructured_diagnostics') and collection['exit_code'] == 0 and not collection['warnings']
        and not collection['collection_errors'] and collection['nodeids']
        and len(set(collection['nodeids'])) == len(collection['nodeids']), 'Real collection was not clean and complete')
    require(not (output / 'collection' / 'unit.stderr').stat().st_size, 'Collection emitted stderr')
    verify_tree(root, revision, source)
    require(application_identity(python, output) == runtime)
    selected = collection['nodeids']
    require(all(node.split('::', 1)[0] in APPLICATION_TESTS for node in selected))
    e2e = [node for node in selected if node.split('::', 1)[-1].split('[', 1)[0] in E2E_FUNCTIONS]
    require({node.split('::', 1)[-1].split('[', 1)[0] for node in e2e} == E2E_FUNCTIONS,
        'The predeclared actual HTTP/OAuth test group is incomplete')
    result = {}
    for phase, tests, nodes in [('integration', list(APPLICATION_TESTS), selected), ('e2e', e2e, e2e)]:
        require(application_identity(python, output) == runtime)
        manifest = runner.make_manifest(root, revision, list(source), tests, source_imports(source), nodes,
            tool_lock, python, phase=phase)
        value, contained = invocation({**base, 'mode': 'evidence', 'manifest': manifest,
            'evidence': str(output / (phase + '-evidence')), 'test_timeout': 150}, output / phase,
            python=sys.executable, boundary=boundary, timeout=180)
        require(isinstance(value, dict) and 'execution_sha256' in value, 'Baseline worker did not seal evidence')
        assessed = runner.assess(output / (phase + '-evidence'), manifest, value['execution_sha256'])
        require(not contained['timed_out'] and not contained.get('output_limit')
            and not contained.get('unstructured_diagnostics') and assessed['clean_baseline'] and assessed['call_assertions'] > 0,
            'Warning/error-bearing baseline is denied')
        verify_tree(root, revision, source)
        require(application_identity(python, output) == runtime)
        result[phase] = {'manifest': manifest, 'assessment': assessed,
                        'execution_sha256': value['execution_sha256']}
    write_new(output / 'baseline.json', encoded(result))
    return result


def verify_native_result(session, job_id, expected):
    from cosmic_ray.work_db import use_db, WorkDB
    with use_db(session, mode=WorkDB.Mode.open) as database:
        result = dict(database.results).get(job_id)
        require(result is not None and expected == {'worker_outcome': result.worker_outcome.value,
            'test_outcome': result.test_outcome.value if result.test_outcome else None,
            'output': result.output, 'diff': result.diff}, 'Native result persistence changed')


def restore_owned_target(root, revision, source, entry):
    """Only the exact admitted original/mutant target can be recovered after timeout."""
    target = root / entry['module_path']
    current = sha(target.read_bytes())
    require(current in {entry['original_sha256'], entry['mutated_sha256']}, 'Unknown target bytes retained')
    expected = dict(source)
    expected[entry['module_path']] = current
    verify_tree(root, revision, expected)
    if current != entry['original_sha256']:
        original = subprocess.check_output(['git', 'show', revision + ':' + entry['module_path']], cwd=root)
        require(sha(original) == entry['original_sha256'])
        target.write_bytes(original)
        with target.open('rb') as stream: os.fsync(stream.fileno())
    verify_tree(root, revision, source)


def campaign(root, revision, inventory_directory, tool_lock, python, output, partition, *, boundary=None):
    """Evaluate one entire frozen disjoint group; stop on unsafe custody/containment."""
    from cosmic_ray.work_db import use_db, WorkDB  # import before app cwd
    del use_db, WorkDB
    boundary = boundary or SystemdBoundary()
    root = Path(root).absolute()
    output, python = safe_external(output, root), external_python(python, root)
    tool_lock, inventory_directory = Path(tool_lock).absolute(), safe_external(inventory_directory, root)
    require(type(partition) is int and 0 <= partition < 4 and not output.exists())
    output.mkdir(mode=0o700)
    manifest, entries, jobs = read_inventory(inventory_directory, root, revision, tool_lock)
    source = manifest['source_files']
    application_runtime = application_identity(python, output)
    write_new(output / 'application-runtime.json', encoded(application_runtime))
    write_new(output / 'producer.json', encoded({'source_sha': revision, 'producer_hashes': producer_identity(),
        'inventory_manifest_sha256': sha((inventory_directory / 'manifest.json').read_bytes()),
        'partition': partition, 'selected': manifest['partitions'][partition]}))
    before_dir = output / 'baseline-before'
    before_dir.mkdir(mode=0o700)
    before = baseline(root, revision, source, tool_lock, python, before_dir, boundary)
    require(application_identity(python, output) == application_runtime)
    session = output / 'session.sqlite'
    shutil.copyfile(inventory_directory / 'session.sqlite', session)
    session.chmod(0o600)
    by_fingerprint = {entry['fingerprint']: entry for entry in entries if entry['proposal_status'] == 'compile_valid'}
    results = []
    for fingerprint in manifest['partitions'][partition]:
        verify_tree(root, revision, source)
        entry = by_fingerprint[fingerprint]
        trial = output / fingerprint
        trial.mkdir(mode=0o700)
        mutant_manifest = json.loads(json.dumps(before['integration']['manifest']))
        mutant_manifest['files'][entry['module_path']] = entry['mutated_sha256']
        test_request = {'schema': 'cloud-native-invocation/v1', 'mode': 'evidence',
            'producer_hashes': producer_identity(), 'root': str(root), 'source_sha': revision,
            'files': mutant_manifest['files'], 'tool_lock': str(tool_lock),
            'tool_lock_sha256': sha(tool_lock.read_bytes()), 'manifest': mutant_manifest,
            'evidence': str(trial / 'evidence'), 'test_timeout': 150, 'result': str(trial / 'assessment-initial.json')}
        write_new(trial / 'test-request.json', encoded(test_request))
        (trial / 'test-driver-cache').mkdir(mode=0o700)
        command = shlex.join([sys.executable, '-I', '-B', '-X', 'pycache_prefix=' + str(trial / 'test-driver-cache'),
            str(HERE / 'native_executor.py'),
            '_worker', '--request', str(trial / 'test-request.json')])
        request = {'mode': 'native', 'root': str(root), 'source_sha': revision, 'files': source,
            'tool_lock': str(tool_lock), 'tool_lock_sha256': sha(tool_lock.read_bytes()),
            'entry': entry, 'native_tool_identity': manifest['tool_identity'], 'session': str(session),
            'session_before_sha256': sha(session.read_bytes()), 'job_id': jobs[native_spec_key(entry['native_spec'])],
            'test_command': command, 'test_timeout': 150, 'native_result': str(trial / 'native-result.json')}
        value, contained = invocation(request, trial / 'invocation', python=sys.executable,
            boundary=boundary, timeout=200)
        restore_owned_target(root, revision, source, entry)
        require(application_identity(python, output) == application_runtime, 'Application dependencies changed')
        if not isinstance(value, dict) or 'native' not in value:
            write_new(trial / 'result.json', encoded({'fingerprint': fingerprint, 'outcome':
                'timed_out' if contained['timed_out'] else 'native_worker_missing_result',
                'containment': contained, 'restored': True, 'genuine_assertion_kill': False}))
            raise Refusal('Missing native result retained after containment and exact restoration')
        native_result = value['native']
        verify_native_result(session, request['job_id'], native_result)
        _, runner = helpers()
        if not (trial / 'assessment-initial.json').is_file():
            write_new(trial / 'result.json', encoded({'fingerprint': fingerprint,
                'outcome': 'native_test_missing_measured_evidence', 'native': native_result,
                'containment': contained, 'restored': True, 'genuine_assertion_kill': False}))
            raise Refusal('Missing measured evidence retained after containment and exact restoration')
        initial = read_json(trial / 'assessment-initial.json')
        assessed = runner.assess(trial / 'evidence', mutant_manifest, initial['execution_sha256'])
        outcome = classify(native_result, assessed, contained, True)
        row = {'fingerprint': fingerprint, 'job_id': request['job_id'], 'outcome': outcome,
            'native_worker_outcome': native_result['worker_outcome'], 'native_test_outcome': native_result['test_outcome'],
            'assessment': assessed, 'execution_sha256': initial['execution_sha256'],
            'restored': True, 'containment': contained}
        write_new(trial / 'result.json', encoded(row))
        results.append(row)
        require(not contained['timed_out'], 'Contained timeout retained; campaign stops after restoration')
    dumped = subprocess.run([sys.executable, '-I', '-B', '-m', 'cosmic_ray.cli', 'dump', str(session)],
        cwd=output, env=clean_environment(output), capture_output=True, timeout=30, check=False)
    write_new(output / 'native-results.stdout', dumped.stdout)
    write_new(output / 'native-results.stderr', dumped.stderr)
    require(dumped.returncode == 0 and not dumped.stderr, 'Native final result dump did not complete cleanly')
    after_dir = output / 'baseline-after'
    after_dir.mkdir(mode=0o700)
    after = baseline(root, revision, source, tool_lock, python, after_dir, boundary)
    require(application_identity(python, output) == application_runtime)
    counts = dict(Counter(row['outcome'] for row in results))
    result = {'schema': 'cloud-native-partition/v1', 'source_sha': revision, 'partition': partition,
        'producer_hashes': producer_identity(), 'native_inventory_manifest_sha256': sha((inventory_directory / 'manifest.json').read_bytes()),
        'inventory_sha256': manifest['inventory_sha256'], 'seed': manifest['seed'],
        'selected': manifest['partitions'][partition], 'evaluated_mutants': len(results),
        'genuine_assertion_kills': counts.get('genuine_assertion_kill', 0), 'outcomes': counts,
        'baseline_before': before, 'baseline_after': after, 'results': results,
        'session_sha256': sha(session.read_bytes()), 'qualification_credit': False, 'production_admitted': False}
    result['application_runtime'] = application_runtime
    write_new(output / 'partition.json', encoded(result))
    return result


def aggregate(directory, revision, output):
    """Collect four native evidence groups; production policy remains Services-owned."""
    parts = [read_json(directory / ('partition-' + str(index)) / 'partition.json', maximum=128 * 1024 * 1024)
             for index in range(4)]
    first = parts[0]
    selected = []
    frozen_partitions = None
    for index, part in enumerate(parts):
        frozen_path = directory / ('inventory-' + str(index)) / 'manifest.json'
        frozen = read_json(frozen_path)
        require(sha(frozen_path.read_bytes()) == part['native_inventory_manifest_sha256']
            and frozen['source_sha'] == revision and frozen['inventory_sha256'] == part['inventory_sha256']
            and frozen['seed'] == part['seed'] and frozen['partitions'][index] == part['selected']
            and frozen['producer_sha256'] == producer_identity()['native_inventory.py']
            and frozen['tool_lock_sha256'] == sha((HERE / 'tools.lock').read_bytes()))
        if frozen_partitions is None: frozen_partitions = frozen['partitions']
        require(frozen_partitions == frozen['partitions'], 'Frozen disjoint inventories disagree')
        require(part['schema'] == 'cloud-native-partition/v1' and part['source_sha'] == revision
            and part['partition'] == index and part['qualification_credit'] is False
            and part['production_admitted'] is False and part['producer_hashes'] == producer_identity()
            and part['inventory_sha256'] == first['inventory_sha256'] and part['seed'] == first['seed'])
        require(part.get('application_runtime') == first.get('application_runtime')
            and part.get('application_runtime'), 'Application environments differ between disjoint groups')
        require(part['evaluated_mutants'] == len(part['selected']) == len(part['results'])
            and part['selected'] == [row['fingerprint'] for row in part['results']]
            and part['outcomes'] == dict(Counter(row['outcome'] for row in part['results']))
            and part['genuine_assertion_kills'] == part['outcomes'].get('genuine_assertion_kill', 0))
        for phase in ('integration', 'e2e'):
            for when in ('baseline_before', 'baseline_after'):
                assessment = part[when][phase]['assessment']
                require(assessment['clean_baseline'] and assessment['call_assertions'] > 0)
        selected.extend(part['selected'])
    require(selected and len(selected) == len(set(selected)), 'Groups are not complete and disjoint')
    result = {'schema': 'cloud-native-campaign-evidence/v1', 'source_sha': revision,
        'producer_hashes': producer_identity(), 'inventory_sha256': first['inventory_sha256'], 'seed': first['seed'],
        'partition_receipt_sha256': [sha((directory / ('partition-' + str(i)) / 'partition.json').read_bytes()) for i in range(4)],
        'partitions': [{'partition': part['partition'], 'evaluated_mutants': part['evaluated_mutants'],
            'genuine_assertion_kills': part['genuine_assertion_kills'], 'outcomes': part['outcomes']} for part in parts],
        'all_partitions_measured': True, 'qualification_credit': False, 'production_admitted': False}
    write_new(output, encoded(result))
    return result


class SystemdBoundary:
    """One existing OS control-group primitive per invocation, never process groups alone."""
    def __init__(self, *, system=True):
        self.system = system
        self.active_unit = None

    def command(self, tool, *args, timeout=15):
        prefix = ['sudo', '-n'] if self.system else []
        user = [] if self.system else ['--user']
        return subprocess.run([*prefix, tool, *user, *args], stdin=subprocess.DEVNULL,
            capture_output=True, timeout=timeout, check=False)

    def show(self, unit):
        result = self.command('systemctl', 'show', unit, '--property=Id,LoadState,ActiveState,SubState,ControlGroup,MainPID,ExecMainStatus,Result,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax')
        require(result.returncode == 0, 'Owned unit metadata unavailable')
        values = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
        require(values.get('Id') == unit and values.get('LoadState') == 'loaded')
        return values

    def run(self, arguments, *, output, environment, cwd, timeout):
        require(self.active_unit is None, 'An earlier invocation has not been settled')
        try:
            return self._run(arguments, output=output, environment=environment, cwd=cwd, timeout=timeout)
        except Exception:
            if self.active_unit is not None:
                stopped = self.command('systemctl', 'stop', self.active_unit, timeout=15)
                write_new(output / 'containment-error.json', encoded({'unit': self.active_unit,
                    'stop_exit': stopped.returncode, 'cgroup_empty': False,
                    'qualification_credit': False, 'production_admitted': False}))
            # Do not guess missing cgroup metadata or advance another invocation.
            raise

    def _run(self, arguments, *, output, environment, cwd, timeout):
        unit = 'cloud-cuckoo-invocation-' + secrets.token_hex(16) + '.service'
        self.active_unit = unit
        require(output.is_absolute() and output.is_dir() and timeout > 0)
        options = ['--unit=' + unit, '--property=RemainAfterExit=yes', '--property=KillMode=control-group',
            '--property=MemoryMax=1610612736', '--property=MemorySwapMax=0', '--property=CPUQuota=100%',
            '--property=TasksMax=128', '--property=RuntimeMaxSec=' + str(timeout + 30),
            '--property=NoNewPrivileges=yes', '--working-directory=' + str(cwd),
            '--property=StandardOutput=file:' + str(output / 'unit.stdout'),
            '--property=StandardError=file:' + str(output / 'unit.stderr')]
        if self.system:
            options += ['--uid=' + str(os.getuid()), '--gid=' + str(os.getgid()),
                        '--property=ProtectControlGroups=yes', '--property=CapabilityBoundingSet=']
        started = self.command('systemd-run', *options, '/usr/bin/env', '-i',
            *[key + '=' + value for key, value in environment.items()], *arguments)
        write_new(output / 'unit-start.stdout', started.stdout)
        write_new(output / 'unit-start.stderr', started.stderr)
        require(started.returncode == 0, 'Owned invocation could not start')
        group, observed, deadline = None, None, time.monotonic() + timeout
        timed_out, output_limit = False, False
        while True:
            observed = self.show(unit)
            if observed.get('ControlGroup'):
                value = observed['ControlGroup']
                require(value.startswith('/') and '..' not in Path(value).parts and value.endswith('/' + unit))
                group = Path('/sys/fs/cgroup') / value.lstrip('/')
            require(observed.get('MemoryMax') == '1610612736' and observed.get('MemorySwapMax') == '0'
                and observed.get('CPUQuotaPerSecUSec') == '1s' and observed.get('TasksMax') == '128')
            if observed.get('MainPID') == '0' and observed.get('SubState') in {'exited', 'failed', 'dead'}: break
            if time.monotonic() >= deadline:
                timed_out = True
                break
            if sum(path.stat().st_size for path in (output / 'unit.stdout', output / 'unit.stderr') if path.exists()) > 16 * 1024 * 1024:
                output_limit = True
                break
            time.sleep(0.1)
        require(group is not None, 'No authoritative invocation cgroup was observed')
        naturally_empty = group.is_dir() and (group / 'cgroup.procs').read_text().strip() == '' \
            and 'populated 0' in (group / 'cgroup.events').read_text().splitlines()
        stopped = self.command('systemctl', 'stop', unit, timeout=15)
        require(stopped.returncode == 0, 'Owned cgroup could not be stopped; preserve all evidence')
        deadline = time.monotonic() + 10
        while group.exists():
            if not (group / 'cgroup.procs').read_text().strip() and 'populated 0' in (group / 'cgroup.events').read_text().splitlines(): break
            require(time.monotonic() < deadline, 'Owned cgroup is not empty')
            time.sleep(0.1)
        # cgroup v2 cannot remove a populated group. The manager's successful
        # stop plus disappearance of this previously observed unique group is
        # also a kernel emptiness observation, not a guessed missing selector.
        empty = not group.exists() or (not (group / 'cgroup.procs').read_text().strip()
            and 'populated 0' in (group / 'cgroup.events').read_text().splitlines())
        require(empty, 'Containment not established')
        proof = {'unit': unit, 'control_group': str(group), 'timed_out': timed_out,
            'output_limit': output_limit,
            'naturally_empty': naturally_empty, 'cgroup_empty': True, 'observed_exit': observed.get('ExecMainStatus'),
            'unit_result': observed.get('Result'), 'memory_max': 1610612736, 'swap_max': 0, 'cpu_quota_percent': 100}
        proof['unstructured_diagnostics'] = bool((output / 'unit.stderr').stat().st_size)
        proof['stdout_sha256'] = sha((output / 'unit.stdout').read_bytes())
        proof['stderr_sha256'] = sha((output / 'unit.stderr').read_bytes())
        write_new(output / 'containment.json', encoded(proof))
        self.command('systemctl', 'reset-failed', unit)
        self.active_unit = None
        return proof


def containment_control(output):
    """Create a session-escaped synthetic descendant and prove cgroup cleanup."""
    output.mkdir(mode=0o700)
    code = ('import os,time\nreader,writer=os.pipe()\npid=os.fork()\n'
        'if pid:\n os.close(writer)\n os.read(reader,1)\n os._exit(0)\n'
        'os.close(reader)\nos.setsid()\nos.write(writer,b"1")\nos.close(writer)\ntime.sleep(60)\n')
    proof = SystemdBoundary().run([sys.executable, '-I', '-B', '-c', code], output=output,
        environment=clean_environment(output), cwd=output, timeout=15)
    require(proof['cgroup_empty'] and not proof['naturally_empty'] and not proof['timed_out'])
    timeout_output = output / 'timeout'
    timeout_output.mkdir(mode=0o700)
    expired = SystemdBoundary().run([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(60)'],
        output=timeout_output, environment=clean_environment(timeout_output), cwd=timeout_output, timeout=0.2)
    require(expired['cgroup_empty'] and expired['timed_out'])
    write_new(output / 'control.json', encoded({'synthetic_descendant_cleaned': True,
        'synthetic_timeout_cleaned': True,
        'qualification_credit': False, 'production_admitted': False}))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    sub.add_parser('_runtime')
    worker = sub.add_parser('_worker')
    worker.add_argument('--request', type=Path, required=True)
    execute = sub.add_parser('partition')
    for name in ('root', 'inventory', 'tool-lock', 'python', 'output'):
        execute.add_argument('--' + name, type=Path, required=True)
    execute.add_argument('--source-sha', required=True)
    execute.add_argument('--partition', type=int, choices=range(4), required=True)
    control = sub.add_parser('containment-control')
    control.add_argument('--output', type=Path, required=True)
    collect = sub.add_parser('aggregate')
    collect.add_argument('--directory', type=Path, required=True)
    collect.add_argument('--source-sha', required=True)
    collect.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(sys.flags.isolated and sys.dont_write_bytecode, 'Launch the controller with Python -I -B')
        if args.mode == '_runtime':
            print(json.dumps(installed_identity(), sort_keys=True))
            return 0
        if args.mode == 'containment-control':
            containment_control(args.output)
            return 0
        if args.mode == 'aggregate':
            aggregate(args.directory, args.source_sha, args.output)
            return 0
        if args.mode == '_worker':
            request = read_json(args.request)
            handlers = {'collection': collect_worker, 'evidence': evidence_worker, 'native': native_worker}
            require(request.get('mode') in handlers)
            return handlers[request['mode']](request)
        result = campaign(args.root, args.source_sha, args.inventory, args.tool_lock, args.python,
            args.output, args.partition)
        print(json.dumps({key: result[key] for key in ('source_sha', 'partition', 'evaluated_mutants',
            'genuine_assertion_kills', 'qualification_credit', 'production_admitted')}, sort_keys=True))
        return 0
    except Exception as error:
        # Full native/test streams remain private in the invocation directory;
        # public control output contains no exception payload or operands.
        print(json.dumps({'outcome': 'qualification_refused', 'exception_type': type(error).__name__,
            'qualification_credit': False, 'production_admitted': False}, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
