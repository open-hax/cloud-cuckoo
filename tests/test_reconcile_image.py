"""Reconcile native, already-pushed image evidence without publication effects."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location('reconcile_release_image', Path(__file__).parents[1] / 'scripts/release_image.py')
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
SOURCE = 'a' * 40
CURRENT = 'b' * 40
PUBLISHER = 'c' * 40
IMAGE_ID = 'sha256:' + 'd' * 64
IMAGE_DIGEST = 'sha256:' + 'e' * 64
BUILD_DIGEST = 'sha256:' + 'f' * 64
RELEASE_DIGEST = 'sha256:' + '1' * 64
RUN, ATTEMPT, RELEASE_ARTIFACT, BUILD_ARTIFACT = 67890, 2, 321, 654
PRIVATE_PACKAGE = {'name': 'cloud-cuckoo', 'package_type': 'container',
                   'owner': {'login': 'open-hax'}, 'visibility': 'private'}


@pytest.fixture(autouse=True)
def current_native_context(monkeypatch):
    values = {'GITHUB_REPOSITORY': release.REPOSITORY, 'GITHUB_REF': 'refs/heads/main',
              'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_SHA': CURRENT,
              'GITHUB_RUN_ID': '12345', 'GITHUB_RUN_ATTEMPT': '1',
              'GITHUB_ACTOR': 'fixture-reconciler', 'GH_TOKEN': 'fixture-ephemeral-token',
              'GITHUB_TOKEN': 'fixture-ephemeral-token'}
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv('GITHUB_OUTPUT', raising=False)


def merged(sha):
    return {'number': 7 if sha == SOURCE else 8, 'merged_at': '2026-10-28T00:00:00Z',
            'merge_commit_sha': sha, 'base': {'ref': 'main', 'repo': {'full_name': release.REPOSITORY}}}


class Native:
    """Only fake read-only GitHub responses; unknown routes fail the test."""
    def __init__(self):
        now = datetime.now(timezone.utc)
        self.repository = {'id': 22, 'full_name': release.REPOSITORY, 'private': True, 'default_branch': 'main'}
        self.publisher = {'id': RUN, 'run_attempt': ATTEMPT, 'event': 'workflow_dispatch',
                          'path': '.github/workflows/publish-image.yml', 'head_branch': 'main',
                          'head_sha': PUBLISHER, 'status': 'completed', 'conclusion': 'failure',
                          'repository': copy.deepcopy(self.repository), 'head_repository': copy.deepcopy(self.repository)}
        common = {'expired': False, 'created_at': (now - timedelta(hours=1)).isoformat(),
                  'expires_at': (now + timedelta(days=7)).isoformat(), 'size_in_bytes': 123,
                  'workflow_run': {'id': RUN, 'head_sha': PUBLISHER, 'repository_id': 22, 'head_repository_id': 22}}
        self.release = {**copy.deepcopy(common), 'id': RELEASE_ARTIFACT,
                        'name': f'cloud-cuckoo-release-{RUN}-{ATTEMPT}', 'digest': RELEASE_DIGEST}
        self.build = {**copy.deepcopy(common), 'id': BUILD_ARTIFACT,
                      'name': f'cloud-cuckoo-build-{RUN}-{ATTEMPT}', 'digest': BUILD_DIGEST}
        self.artifacts = [self.release, self.build]
        self.package = copy.deepcopy(PRIVATE_PACKAGE)
        self.package_after = None
        self.package_calls = 0
        self.pulls = {SOURCE: [merged(SOURCE)], PUBLISHER: [merged(PUBLISHER)]}
        self.calls = []

    def __call__(self, path, **kwargs):
        self.calls.append((path, kwargs))
        if path == 'repos/' + release.REPOSITORY:
            return copy.deepcopy(self.repository)
        if path == f'repos/{release.REPOSITORY}/actions/runs/{RUN}/attempts/{ATTEMPT}':
            return copy.deepcopy(self.publisher)
        if path.startswith(f'repos/{release.REPOSITORY}/actions/runs/{RUN}/artifacts?'):
            return {'total_count': len(self.artifacts), 'artifacts': copy.deepcopy(self.artifacts)}
        if path == f'repos/{release.REPOSITORY}/actions/artifacts/{RELEASE_ARTIFACT}':
            return copy.deepcopy(self.release)
        if path == f'repos/{release.REPOSITORY}/actions/artifacts/{BUILD_ARTIFACT}':
            return copy.deepcopy(self.build)
        for sha, pulls in self.pulls.items():
            if path == f'repos/{release.REPOSITORY}/commits/{sha}/pulls?per_page=100':
                return copy.deepcopy(pulls)
        if path == 'orgs/open-hax/packages/container/cloud-cuckoo':
            self.package_calls += 1
            return copy.deepcopy(self.package_after if self.package_calls > 1 and self.package_after is not None else self.package)
        raise AssertionError('Unexpected fake native route: ' + path)


class Commands:
    def __init__(self):
        self.calls = []
        self.head = CURRENT
        self.unrelated = None
        self.image = {'Id': IMAGE_ID, 'Config': {'User': '1000:1000', 'Labels': {
            'org.opencontainers.image.source': 'https://github.com/' + release.REPOSITORY,
            'org.opencontainers.image.licenses': 'GPL-3.0-or-later',
            'org.opencontainers.image.revision': SOURCE}}}

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[0] == 'git':
            if args[-2:] == ['rev-parse', 'HEAD']:
                return (self.head + '\n').encode()
            if 'merge-base' in args and self.unrelated in args[args.index('--is-ancestor') + 1:]:
                raise release.Refusal('Fixture source is not accepted ancestry')
            if 'show' in args:
                return (Path(__file__).parents[1] / 'LICENSE').read_bytes()
            assert 'cat-file' in args or 'merge-base' in args
            return b''
        assert args[0] == 'docker'
        assert args[1] in {'login', 'pull', 'image', 'logout', 'run'}, 'Reconciliation invoked a publication or host effect'
        if args[1:3] == ['image', 'inspect']:
            return json.dumps([self.image]).encode()
        return b''


def draft_receipt():
    return {'schema': 'cloud-cuckoo-image/v1', 'repository': release.REPOSITORY,
            'workflow_sha': PUBLISHER, 'run_id': RUN, 'run_attempt': ATTEMPT,
            'source_sha': SOURCE, 'source_pr': 7, 'source_archive_sha256': '2' * 64,
            'docker_archive_sha256': '3' * 64, 'image_id': IMAGE_ID,
            'image_tag': f'{release.IMAGE}:source-{SOURCE}-run-{RUN}-attempt-{ATTEMPT}',
            'image_digest': IMAGE_DIGEST, 'image_reference': release.IMAGE + '@' + IMAGE_DIGEST,
            'build_artifact_id': BUILD_ARTIFACT, 'build_artifact_digest': BUILD_DIGEST,
            'tests': {'tests': 22, 'failures': 0, 'errors': 0, 'skipped': 0},
            'pending_smoke': 'passed', 'metadata_verified': False,
            'published_at': '2026-10-28T00:00:00+00:00'}


def admit(tmp_path, native=None, commands=None):
    native, commands = native or Native(), commands or Commands()
    receipt = tmp_path / 'reconciliation-input.json'
    release.reconcile_admit(str(RUN), str(ATTEMPT), tmp_path / 'checkout', receipt,
                            api=native, command=commands)
    return receipt, native, commands


def reconcile(tmp_path, *, native=None, commands=None, mutate=None, mutate_admission=None):
    admission, native, commands = admit(tmp_path, native, commands)
    if mutate_admission:
        data = json.loads(admission.read_text());mutate_admission(data);admission.write_text(json.dumps(data))
    directory = tmp_path / 'release'
    directory.mkdir()
    draft = draft_receipt()
    if mutate:
        mutate(draft)
    (directory / 'release-receipt.json').write_text(json.dumps(draft))
    output = tmp_path / 'reconciled.json'
    release.reconcile(directory, admission, tmp_path / 'checkout', output, api=native, command=commands)
    return json.loads(output.read_text()), native, commands


def test_completed_failed_publisher_can_be_admitted_without_publication_commands(tmp_path):
    path, _, commands = admit(tmp_path)
    data = json.loads(path.read_text())
    assert data == {'schema': 'cloud-cuckoo-reconciliation-input/v1', **release.context(),
                    'publisher_run_id': RUN, 'publisher_run_attempt': ATTEMPT,
                    'publisher_workflow_sha': PUBLISHER, 'release_artifact_id': RELEASE_ARTIFACT,
                    'release_artifact_digest': RELEASE_DIGEST}
    assert all(args[0] == 'git' for args, _ in commands.calls)


@pytest.mark.parametrize(('key', 'value'), [('event', 'pull_request'), ('head_branch', 'topic'),
    ('path', '.github/workflows/other.yml'), ('status', 'in_progress'), ('id', RUN + 1),
    ('run_attempt', ATTEMPT + 1), ('repository', {'full_name': 'another/repository'}),
    ('head_repository', {'full_name': 'fork/cloud-cuckoo'})])
def test_admission_refuses_foreign_or_unfinished_publisher(tmp_path, key, value):
    native = Native();native.publisher[key] = value
    with pytest.raises(release.Refusal):
        admit(tmp_path, native=native)
    assert not (tmp_path / 'reconciliation-input.json').exists()


@pytest.mark.parametrize('change', ['duplicate', 'expired', 'wrong_name', 'wrong_run', 'wrong_sha', 'bad_digest'])
def test_admission_requires_one_exact_native_release_artifact(tmp_path, change):
    native = Native()
    if change == 'duplicate':
        native.artifacts.append({**native.release, 'id': RELEASE_ARTIFACT + 1})
    elif change == 'expired':native.release['expired'] = True
    elif change == 'wrong_name':native.release['name'] = 'other-artifact'
    elif change == 'wrong_run':native.release['workflow_run']['id'] += 1
    elif change == 'wrong_sha':native.release['workflow_run']['head_sha'] = '0' * 40
    else:native.release['digest'] = 'sha256:unknown'
    with pytest.raises(release.Refusal):
        admit(tmp_path, native=native)


def test_publisher_must_be_an_accepted_main_merge_and_current_ancestor(tmp_path):
    native = Native();native.pulls[PUBLISHER] = []
    with pytest.raises(release.Refusal):admit(tmp_path, native=native)
    commands = Commands();commands.unrelated = PUBLISHER
    with pytest.raises(release.Refusal):admit(tmp_path, commands=commands)


def test_admission_refuses_wrong_current_checkout_and_nonmain_context(tmp_path, monkeypatch):
    commands = Commands();commands.head = '0' * 40
    with pytest.raises(release.Refusal):admit(tmp_path, commands=commands)
    monkeypatch.setenv('GITHUB_REF', 'refs/heads/topic')
    native = Native()
    with pytest.raises(release.Refusal):admit(tmp_path, native=native)
    assert not native.calls


def test_reconcile_proves_private_exact_image_without_build_push_save_or_token_environment(tmp_path):
    data, native, commands = reconcile(tmp_path)
    assert data['metadata_verified'] is True and data['image_provenance_verified'] is True
    assert data['package_visibility'] == 'private'
    assert data['package_ui_repository_link'] == 'unknown'
    assert data['image_reference'] == release.IMAGE + '@' + IMAGE_DIGEST
    assert native.package_calls == 2
    docker = [(args, kwargs) for args, kwargs in commands.calls if args[0] == 'docker']
    assert sum(args == ['docker', 'pull', release.IMAGE + '@' + IMAGE_DIGEST] for args, _ in docker) == 1
    assert any(args[1] == 'login' for args, _ in docker) and any(args[1] == 'logout' for args, _ in docker)
    for args, kwargs in docker:
        assert 'GH_TOKEN' not in kwargs['env'] and 'GITHUB_TOKEN' not in kwargs['env']
        assert 'fixture-ephemeral-token' not in ' '.join(args)
        assert not Path(kwargs['env']['DOCKER_CONFIG']).exists()
        if args[1] == 'login':assert kwargs['input'] == b'fixture-ephemeral-token'


@pytest.mark.parametrize(('key', 'value'), [('source_sha', '0' * 40), ('workflow_sha', '0' * 40),
    ('run_id', RUN + 1), ('run_attempt', ATTEMPT + 1), ('image_id', 'sha256:' + '0' * 64),
    ('image_reference', release.IMAGE + ':mutable-tag'), ('image_tag', release.IMAGE + ':other'),
    ('build_artifact_digest', 'sha256:' + '0' * 64), ('pending_smoke', 'unknown')])
def test_tampered_release_evidence_never_yields_a_verified_receipt(tmp_path, key, value):
    with pytest.raises(release.Refusal):reconcile(tmp_path, mutate=lambda d:d.update({key: value}))
    assert not (tmp_path / 'reconciled.json').exists()


@pytest.mark.parametrize(('key', 'value'), [('tests', 21), ('failures', 1), ('errors', 1), ('skipped', 1)])
def test_only_complete_source_suite_supplies_test_evidence(tmp_path, key, value):
    with pytest.raises(release.Refusal):reconcile(tmp_path, mutate=lambda d:d['tests'].update({key: value}))


@pytest.mark.parametrize(('key', 'value'), [('visibility', 'internal'), ('name', 'other'),
    ('package_type', 'npm'), ('owner', {'login': 'another-owner'})])
def test_supported_package_identity_is_required_before_pull(tmp_path, key, value):
    native, commands = Native(), Commands();native.package[key] = value
    with pytest.raises(release.Refusal):reconcile(tmp_path, native=native, commands=commands)
    assert not any(args[:2] == ['docker', 'pull'] for args, _ in commands.calls)


def test_postpull_visibility_drift_refuses_and_cleans_up_auth(tmp_path):
    native, commands = Native(), Commands();native.package_after = {**PRIVATE_PACKAGE, 'visibility': 'internal'}
    with pytest.raises(release.Refusal):reconcile(tmp_path, native=native, commands=commands)
    assert not (tmp_path / 'reconciled.json').exists()
    assert any(args[:2] == ['docker', 'logout'] for args, _ in commands.calls)


def test_public_reconcile_checks_license_and_anonymous_access(tmp_path):
    native, commands = Native(), Commands()
    native.repository['private'] = False
    native.package['visibility'] = 'public'
    data, _, _ = reconcile(tmp_path, native=native, commands=commands)
    assert data['publication_target'] == 'public' and data['public_release_complete'] is True
    assert data['license_verified'] is True
    assert data['license_sha256'] == release.sha256(Path(__file__).parents[1] / 'LICENSE')
    assert any(args[:2] == ['docker', 'run'] and release.LICENSE_PATH.encode() in options.get('input', b'')
               for args, options in commands.calls)
    assert any(args[:2] == ['docker', 'pull'] and set(options['env']) == {'PATH', 'HOME', 'DOCKER_CONFIG'}
               for args, options in commands.calls)


@pytest.mark.parametrize('change', ['id', 'user', 'revision', 'source'])
def test_freshly_pulled_image_identity_and_nonroot_labels_are_required(tmp_path, change):
    commands = Commands()
    if change == 'id':commands.image['Id'] = 'sha256:' + '0' * 64
    elif change == 'user':commands.image['Config']['User'] = 'root'
    elif change == 'revision':commands.image['Config']['Labels']['org.opencontainers.image.revision'] = '0' * 40
    else:commands.image['Config']['Labels']['org.opencontainers.image.source'] = 'https://github.com/another/repo'
    with pytest.raises(release.Refusal):reconcile(tmp_path, commands=commands)
    assert not (tmp_path / 'reconciled.json').exists()


def test_current_admission_context_cannot_be_replaced_by_publisher_context(tmp_path):
    with pytest.raises(release.Refusal):
        reconcile(tmp_path, mutate_admission=lambda d:d.update(workflow_sha=PUBLISHER))


def test_undocumented_repository_field_does_not_supply_package_ui_link(tmp_path):
    native = Native();native.package['repository'] = {'full_name': 'unrelated/claim'}
    data, _, _ = reconcile(tmp_path, native=native)
    assert data['package_ui_repository_link'] == 'unknown'


@pytest.mark.parametrize('change', ['expired', 'id', 'name', 'digest', 'run', 'head'])
def test_native_build_artifact_is_bound_independently_of_downloaded_receipt(tmp_path, change):
    native, commands = Native(), Commands()
    if change == 'expired':native.build['expired'] = True
    elif change == 'id':native.build['id'] += 1
    elif change == 'name':native.build['name'] = 'unrelated-build'
    elif change == 'digest':native.build['digest'] = 'sha256:' + '0' * 64
    elif change == 'run':native.build['workflow_run']['id'] += 1
    else:native.build['workflow_run']['head_sha'] = '0' * 40
    with pytest.raises(release.Refusal):reconcile(tmp_path, native=native, commands=commands)
    assert not (tmp_path / 'reconciled.json').exists()
    assert not any(args[:2] == ['docker', 'pull'] for args, _ in commands.calls)


def test_source_is_itself_an_accepted_main_merge_and_current_ancestor(tmp_path):
    native = Native();native.pulls[SOURCE] = []
    with pytest.raises(release.Refusal):reconcile(tmp_path, native=native)
    commands = Commands();commands.unrelated = SOURCE
    other = tmp_path / 'unrelated';other.mkdir()
    with pytest.raises(release.Refusal):reconcile(other, commands=commands)


def test_source_pr_number_is_bound_to_native_merged_pull(tmp_path):
    with pytest.raises(release.Refusal):reconcile(tmp_path, mutate=lambda d:d.update(source_pr=99))


def test_registry_token_absence_does_not_become_successful_reconciliation(tmp_path, monkeypatch):
    monkeypatch.delenv('GH_TOKEN')
    commands = Commands()
    with pytest.raises(release.Refusal):reconcile(tmp_path, commands=commands)
    assert not any(args[:2] == ['docker', 'pull'] for args, _ in commands.calls)
    assert not (tmp_path / 'reconciled.json').exists()

