# SPDX-License-Identifier: GPL-3.0-or-later
"""Freeze native Cosmic Ray proposals. This module never executes test jobs."""
import argparse
from collections import Counter
import hashlib
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import warnings

SEED = 'cloud-cuckoo-full-qualification-v1'
MODULE = 'src/knoxx_colab_mcp'
HERE = Path(__file__).resolve().parent


class Refusal(ValueError):
    pass


def require(value, message):
    if not value:
        raise Refusal(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    with path.open('xb') as target:
        os.chmod(path, 0o600)
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def checked_file(root, relative):
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute()
            and '..' not in Path(relative).parts, 'Unbounded source path')
    path = root / relative
    require(not any(p.is_symlink() for p in (path, *path.parents))
            and path.is_file(), 'Redirected or absent source file')
    return path


def absolute_unredirected(value):
    """Reject redirected ancestry before a native command or output write."""
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts
            and not any(parent.is_symlink() for parent in (path, *path.parents)),
            'Use absolute paths without redirected or dot-dot ancestry')
    return path


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root)


def source_custody(root, revision):
    require(re.fullmatch('[0-9a-f]{40}', revision or ''), 'Immutable source revision required')
    require(git(root, 'rev-parse', 'HEAD').decode().strip() == revision,
            'Application checkout differs from source revision')
    require(not git(root, 'status', '--porcelain', '--untracked-files=no'), 'Tracked source is dirty')
    names = git(root, 'ls-tree', '-r', '-z', '--name-only', revision).decode().split('\0')[:-1]
    require(names and len(names) == len(set(names)), 'Source inventory is unavailable')
    result = {}
    for name in names:
        raw = checked_file(root, name).read_bytes()
        require(raw == git(root, 'show', revision + ':' + name), 'Source bytes differ from Git')
        result[name] = sha(raw)
    require(any(name.startswith(MODULE + '/') and name.endswith('.py') for name in names),
            'Application scope is absent')
    return result


def tool_identity():
    require(metadata.version('cosmic-ray') == '8.7.0', 'Unadmitted Cosmic Ray version')
    providers = list(metadata.entry_points(group='cosmic_ray.operator_providers'))
    require(len(providers) == 1 and providers[0].name == 'core'
            and providers[0].value == 'cosmic_ray.operators.provider:OperatorProvider'
            and providers[0].dist.metadata['Name'].lower().replace('_', '-') == 'cosmic-ray',
            'Only the native Cosmic Ray core provider is admitted')
    packages = {}
    for distribution in metadata.distributions():
        name = distribution.metadata['Name'].lower().replace('_', '-')
        files = {}
        for entry in distribution.files or []:
            if str(entry).endswith('.py'):
                path = Path(distribution.locate_file(entry))
                require(path.is_file() and not path.is_symlink(), 'Tool code custody is unavailable')
                files[str(entry)] = sha(path.read_bytes())
        require(name not in packages, 'Duplicate installed distribution identity')
        packages[name] = {'version': distribution.version, 'python_files_sha256': sha(encoded(files))}
    return {'python': sys.version, 'python_sha256': sha(Path(sys.executable).resolve().read_bytes()),
            'packages': packages, 'operator_provider': 'cosmic_ray.operators.provider:OperatorProvider'}


def fingerprint(revision, path, original_sha, mutated_sha):
    return sha(('cloud-cuckoo-mutant/v1\0' + revision + '\0' + path + '\0'
                + original_sha + '\0' + mutated_sha).encode())


def materialize(spec, *, root, revision, source, mutate, operator, seen, output):
    name = spec.get('module_path')
    require(name in source and name.startswith(MODULE + '/') and name.endswith('.py'),
            'Native proposal is outside the complete application scope')
    require(isinstance(spec.get('operator_args'), dict)
            and type(spec.get('occurrence')) is int and spec['occurrence'] >= 0
            and isinstance(spec.get('operator_name'), str) and spec['operator_name'].startswith('core/'),
            'Malformed or nonnative proposal')
    path = checked_file(root, name)
    original = path.read_text(encoding='utf-8')
    entry = {'native_spec': spec, 'module_path': name, 'source_sha': revision,
             'original_sha256': source[name]}
    try:
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter('always')
            changed = mutate(original, operator(spec['operator_name'])(**spec['operator_args']), spec['occurrence'])
        entry['operator_warnings'] = [{'category': w.category.__name__,
            'message_sha256': sha(str(w.message).encode())} for w in captured]
    except Exception as error:
        return {**entry, 'proposal_status': 'operator_error', 'exception_type': type(error).__name__}
    if changed is None or changed == original:
        return {**entry, 'proposal_status': 'inapplicable_or_noop'}
    require(isinstance(changed, str), 'Native mutation returned an unknown representation')
    raw = changed.encode()
    mutated_sha = sha(raw)
    value = fingerprint(revision, name, source[name], mutated_sha)
    entry.update(mutated_sha256=mutated_sha, fingerprint=value)
    if value in seen:
        return {**entry, 'proposal_status': 'duplicate_mutated_bytes'}
    seen.add(value)
    write_new(output / (value + '.py'), raw)
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter('always')
        try:
            compile(changed, name, 'exec', dont_inherit=True)
            status = 'compile_valid'
        except SyntaxError:
            status = 'syntax_error'
        except Exception as error:
            status = 'compile_error'
            entry['exception_type'] = type(error).__name__
    entry['compile_warnings'] = [{'category': w.category.__name__,
        'message_sha256': sha(str(w.message).encode()), 'lineno': w.lineno} for w in captured]
    if status == 'compile_valid' and (captured or entry['operator_warnings']):
        status = 'compile_or_operator_warning'
    return {**entry, 'proposal_status': status}


def partition(entries):
    candidates = [entry for entry in entries if entry['proposal_status'] == 'compile_valid']
    candidates.sort(key=lambda value: (sha((SEED + '\0' + value['fingerprint']).encode()), value['fingerprint']))
    return [[value['fingerprint'] for value in candidates[index::4]] for index in range(4)]


def freeze(root, source_sha, tool_lock, output):
    """Return an immutable inventory; native init/dump must contain no results."""
    root, tool_lock, output = map(absolute_unredirected, (root, tool_lock, output))
    require(not output.exists() and output.parent.is_dir() and output.parent.stat().st_uid == os.getuid()
            and not output.resolve().is_relative_to(root.resolve()),
            'Use a fresh inventory directory outside the application checkout')
    source = source_custody(root, source_sha)
    require(tool_lock.is_file() and not tool_lock.is_symlink(), 'Pinned tool lock required')
    lock_sha = sha(tool_lock.read_bytes())
    producer_sha = sha(Path(__file__).read_bytes())
    identity = tool_identity()
    output.mkdir(mode=0o700)
    (output / 'home').mkdir(mode=0o700)
    (output / 'mutants').mkdir(mode=0o700)
    configuration = ('[cosmic-ray]\nmodule-path = ' + json.dumps(MODULE) + '\n'
                     'timeout = 90\nexcluded-modules = []\n'
                     'test-command = "false"\n[cosmic-ray.distributor]\nname = "local"\n').encode()
    write_new(output / 'cosmic-ray.toml', configuration)
    environment = {'PATH': str(Path(sys.executable).parent) + ':/usr/bin:/bin',
                   'HOME': str(output / 'home'), 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
    for operation, args in [('init', [str(output/'cosmic-ray.toml'), str(output/'session.sqlite')]),
                            ('dump', [str(output/'session.sqlite')])]:
        process = subprocess.run([sys.executable, '-B', '-m', 'cosmic_ray.cli', operation, *args],
            cwd=root, env=environment, capture_output=True, timeout=180, check=False)
        write_new(output / (operation + '.stdout'), process.stdout)
        write_new(output / (operation + '.stderr'), process.stderr)
        require(process.returncode == 0 and not process.stderr, 'Native inventory command failed or warned')
    session = output / 'session.sqlite'
    with sqlite3.connect('file:' + str(session) + '?mode=ro', uri=True) as database:
        require(database.execute('SELECT COUNT(*) FROM work_results').fetchone()[0] == 0,
                'A native session already contains executed results')
    native = [json.loads(line) for line in (output / 'dump.stdout').read_bytes().splitlines()]
    require(native and all(isinstance(row, list) and len(row) == 2 and row[1] is None
            and isinstance(row[0], dict) and len(row[0].get('mutations', [])) == 1 for row in native),
            'Native proposal/session shape is unexpected')
    native.sort(key=lambda row: (row[0]['mutations'][0]['module_path'], row[0]['mutations'][0]['start_pos'],
                                row[0]['mutations'][0]['operator_name'], row[0]['mutations'][0]['occurrence']))
    from cosmic_ray.mutating import mutate_code
    from cosmic_ray.plugins import get_operator
    entries, seen = [], set()
    for work, _ in native:
        entries.append(materialize(work['mutations'][0], root=root, revision=source_sha, source=source,
            mutate=mutate_code, operator=get_operator, seen=seen, output=output/'mutants'))
    require(source_custody(root, source_sha) == source and tool_identity() == identity
            and sha(tool_lock.read_bytes()) == lock_sha
            and sha(Path(__file__).read_bytes()) == producer_sha,
            'Source or native tool changed while freezing proposals')
    inventory_bytes = encoded(entries)
    write_new(output/'inventory.json', inventory_bytes)
    result = {'schema': 'cloud-cuckoo-native-inventory/v1', 'source_sha': source_sha,
        'source_files': source, 'module_scope': MODULE, 'tool_identity': identity,
        'tool_lock_sha256': lock_sha,
        'producer_sha256': producer_sha, 'seed': SEED,
        'native_session_sha256': sha(session.read_bytes()), 'native_dump_sha256': sha((output/'dump.stdout').read_bytes()),
        'inventory_sha256': sha(inventory_bytes), 'proposal_count': len(entries),
        'proposal_statuses': dict(sorted(Counter(e['proposal_status'] for e in entries).items())),
        'partitions': partition(entries), 'evaluated_mutants': 0, 'genuine_assertion_kills': 0,
        'qualification_credit': False, 'production_admitted': False}
    write_new(output/'manifest.json', encoded(result))
    descriptor = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--tool-lock', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = freeze(args.root, args.source_sha, args.tool_lock, args.output)
    print(json.dumps({'frozen': True, 'proposals': result['proposal_count'],
                      'partitions': [len(rows) for rows in result['partitions']], 'qualification_credit': False}))


if __name__ == '__main__':
    main()
