# SPDX-License-Identifier: GPL-3.0-or-later
"""Measured pytest facts. The admitted producer/harness is the trust boundary.

This hook is not an authentication boundary against malicious test code running
in its own process. The parent seals observed execution and an outer native CI
collector must authenticate that producer artifact before qualification.
"""
import ast
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys

import pytest
from _pytest.outcomes import Failed


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def runtime_identity():
    import _pytest
    import pluggy
    import pytest_asyncio
    packages = {}
    for name, module in [('pytest', _pytest), ('pluggy', pluggy), ('pytest-asyncio', pytest_asyncio)]:
        root = Path(module.__file__).resolve().parent
        files = {str(p.relative_to(root)): sha(p.read_bytes()) for p in sorted(root.rglob('*.py'))}
        packages[name] = {'version': importlib.metadata.version(name), 'files_sha256': sha(encoded(files))}
    return {'python': sys.version, 'python_sha256': sha(Path(sys.executable).resolve().read_bytes()),
            'packages': packages, 'pytest_failure_type': Failed.__module__ + '.' + Failed.__qualname__}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def relative_file(root, value):
    path = root / value
    if (not isinstance(value, str) or Path(value).is_absolute() or '..' in Path(value).parts or
            any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file()):
        raise ValueError('Uncontrolled evidence input')
    return path


def source_hashes(manifest):
    root = Path(manifest['root'])
    return {name: sha(relative_file(root, name).read_bytes()) for name in manifest['files']}


def producer_hashes():
    root = Path(__file__).resolve().parent
    return {name: sha((root / name).read_bytes()) for name in ('pytest_evidence.py', 'run_pytest_evidence.py')}


def valid_test_site(manifest, site, kind):
    if not isinstance(site, (list, tuple)) or len(site) != 2 or type(site[1]) is not int or site[1] <= 0:
        return False
    root = Path(manifest['root'])
    declared = {str(relative_file(root, value.split('::', 1)[0]).resolve())
                for value in manifest['tests']}
    path = relative_file(root, site[0]).resolve()
    if str(path) not in declared:
        return False
    for node in ast.walk(ast.parse(path.read_text())):
        if not hasattr(node, 'lineno') or not node.lineno <= site[1] <= getattr(node, 'end_lineno', node.lineno):
            continue
        if kind == 'assertion' and isinstance(node, ast.Assert):
            return True
        if kind == 'explicit_fail' and isinstance(node, ast.Call):
            call = node.func
            if isinstance(call, ast.Attribute) and isinstance(call.value, ast.Name) and call.value.id == 'pytest' and call.attr == 'fail':
                return True
        if kind == 'expected_exception' and isinstance(node, ast.With):
            for context in node.items:
                call = context.context_expr
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and
                        isinstance(call.func.value, ast.Name) and call.func.value.id == 'pytest' and call.func.attr == 'raises'):
                    return True
    return False


def _test_site(item, traceback, kind):
    """Verify a failing assertion/contract callsite in a declared test file."""
    manifest = item.config._evidence['manifest']
    root = Path(manifest['root'])
    for entry in reversed(list(traceback)):
        path = Path(str(entry.path)).resolve()
        if path.is_relative_to(root):
            site = (str(path.relative_to(root)), entry.lineno + 1)
            if valid_test_site(manifest, site, kind):
                return site
    return None


def pytest_configure(config):
    global _STATE
    raw = Path(os.environ['CLOUD_PYTEST_MANIFEST']).read_bytes()
    manifest = json.loads(raw)
    if config.getini('enable_assertion_pass_hook') is not True:
        raise ValueError('Real assertion-pass rewriting is required')
    cache = Path(os.environ['CLOUD_PYTEST_CACHE']).resolve()
    if (not sys.dont_write_bytecode or sys.pycache_prefix is None or Path(sys.pycache_prefix).resolve() != cache or
            not cache.is_dir() or any(cache.iterdir())):
        raise ValueError('An exclusive empty cache prefix is required for fresh source and assertion reads')
    config._evidence = {'schema': 'cloud-pytest-facts/v1', 'nonce': os.environ['CLOUD_PYTEST_NONCE'],
        'manifest_sha256': sha(raw), 'manifest': manifest, 'producer_hashes': producer_hashes(),
        'runtime_identity': runtime_identity(), 'source_before': source_hashes(manifest),
        'pycache_prefix': str(cache), 'dont_write_bytecode': sys.dont_write_bytecode,
        'collected': [], 'collection_errors': [], 'reports': [], 'warnings': [],
        'assertion_passes': {'setup': 0, 'call': 0, 'teardown': 0}, 'complete': False}
    _STATE = config._evidence


def pytest_collection_finish(session):
    session.config._evidence['collected'] = [item.nodeid for item in session.items]


def pytest_collectreport(report):
    if report.failed and _STATE is not None:
        _STATE['collection_errors'].append(report.nodeid)


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_setup(item):
    item._evidence_phase = 'setup'
    yield


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_call(item):
    item._evidence_phase = 'call'
    yield


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_teardown(item):
    item._evidence_phase = 'teardown'
    yield


def pytest_assertion_pass(item, lineno, orig, expl):
    item.config._evidence['assertion_passes'][getattr(item, '_evidence_phase', 'setup')] += 1


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    record = {'nodeid': item.nodeid, 'when': report.when, 'outcome': report.outcome,
              'exception_type': None, 'failure_kind': None, 'test_site': None}
    if call.excinfo is not None:
        error = call.excinfo.value
        record['exception_type'] = type(error).__module__ + '.' + type(error).__qualname__
        record['failure_kind'] = 'runtime_exception'
        leaf = call.excinfo.traceback[-1]
        leaf_path = Path(str(leaf.path)).resolve()
        if report.when == 'call' and isinstance(error, AssertionError):
            site = _test_site(item, [leaf], 'assertion')
            if site:
                record.update(failure_kind='assertion', test_site=site)
        elif report.when == 'call' and isinstance(error, Failed):
            pytest_root = Path(pytest.__file__).resolve().parent.parent / '_pytest'
            if leaf_path.is_relative_to(pytest_root):
                kind = 'expected_exception' if str(error).startswith('DID NOT RAISE') else 'explicit_fail'
                site = _test_site(item, call.excinfo.traceback, kind)
                if site:
                    record.update(failure_kind=kind, test_site=site)
    item.config._evidence['reports'].append(record)


def pytest_warning_recorded(warning_message, when, nodeid, location):
    # Called before pytest_configure for some configuration warnings. Keep one
    # process-local list and attach it at sessionfinish, including those early events.
    _WARNINGS.append({'category': warning_message.category.__module__ + '.' + warning_message.category.__name__,
                      'message_sha256': sha(str(warning_message.message).encode()), 'when': when, 'nodeid': nodeid})


_WARNINGS = []
_STATE = None


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    state = session.config._evidence
    state['warnings'] = _WARNINGS
    state['source_after'] = source_hashes(state['manifest'])
    state['exit_code'] = int(exitstatus)
    state['collection_failed'] = bool(state['collection_errors'])
    state['imports'] = {}
    root = Path(state['manifest']['root'])
    for name, module in tuple(sys.modules.items()):
        if not any(name == prefix or name.startswith(prefix + '.') for prefix in state['manifest']['imports']):
            continue
        raw_path = getattr(module, '__file__', None)
        path = Path(raw_path).resolve() if raw_path else None
        if path is None or not path.is_relative_to(root):
            state['imports'][name] = {'valid': False}
            continue
        relative = str(path.relative_to(root))
        state['imports'][name] = {'valid': relative in state['manifest']['files'],
                                  'path': relative, 'sha256': sha(path.read_bytes())}
    state['complete'] = True
    # No exception text, assert operands, bearer token or protocol payload is
    # copied into this structured projection. Full raw streams stay private.
    del state['manifest']
    path = Path(os.environ['CLOUD_PYTEST_SUMMARY'])
    with path.open('x') as target:
        os.chmod(path, 0o600)
        target.write(json.dumps(state, sort_keys=True) + '\n')
