"""Publication boundary fixtures; these tests never publish or deploy an image."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile

import pytest

SPEC = importlib.util.spec_from_file_location('release_image', Path(__file__).parents[1] / 'scripts/release_image.py')
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
SOURCE = 'a' * 40
WORKFLOW = 'b' * 40
IMAGE_ID = 'sha256:' + 'c' * 64
ARTIFACT_DIGEST = 'd' * 64
REGISTRY_DIGEST = 'sha256:' + 'e' * 64
PRIVATE_PACKAGE = {'visibility': 'private', 'repository': {'full_name': release.REPOSITORY}}
PRIVATE_REPO = {'full_name': release.REPOSITORY, 'private': True, 'default_branch': 'main'}


@pytest.fixture(autouse=True)
def native_context(monkeypatch):
    for key, value in {'GITHUB_REPOSITORY': release.REPOSITORY, 'GITHUB_REF': 'refs/heads/main',
                       'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_SHA': WORKFLOW,
                       'GITHUB_RUN_ID': '12345', 'GITHUB_RUN_ATTEMPT': '1',
                       'GITHUB_ACTOR': 'fixture-publisher', 'GH_TOKEN': 'fixture-ephemeral-secret'}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv('GITHUB_OUTPUT', raising=False)


def image_record(source=SOURCE, image_id=IMAGE_ID):
    return {'Id': image_id, 'Config': {'User': '1000:1000', 'Labels': {
        'org.opencontainers.image.source': 'https://github.com/' + release.REPOSITORY,
        'org.opencontainers.image.revision': source}}}


def merged_pull(source):
    return {'number': 7, 'merged_at': '2026-10-29T00:00:00Z', 'merge_commit_sha': source,
            'base': {'ref': 'main', 'repo': {'full_name': release.REPOSITORY}}}


@pytest.mark.parametrize(('key', 'value'), [('GITHUB_REF', 'refs/heads/topic'),
    ('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_REPOSITORY', 'fork/cloud-cuckoo'),
    ('GITHUB_SHA', 'main'), ('GITHUB_RUN_ATTEMPT', '0')])
def test_native_gate_refuses_other_contexts(monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(release.Refusal):
        release.context()


def test_admission_archives_only_merged_tracked_bytes(tmp_path, monkeypatch):
    checkout = tmp_path / 'checkout'
    checkout.mkdir()
    git = lambda *args, **kwargs: release.run(['git', '-C', str(checkout), *args], **kwargs)
    git('init', '-q')
    git('config', 'user.name', 'Fixture')
    git('config', 'user.email', 'fixture@example.invalid')
    git('config', 'core.hooksPath', '/dev/null')
    (checkout / 'Dockerfile').write_text('FROM scratch\n')
    git('add', 'Dockerfile')
    git('commit', '--no-gpg-sign', '-qm', 'fixture source')
    source = git('rev-parse', 'HEAD').decode().strip()
    monkeypatch.setenv('GITHUB_SHA', source)
    (checkout / '.env').write_text('fixture-untracked-private-value')
    api = lambda path: PRIVATE_REPO if path == 'repos/' + release.REPOSITORY else [merged_pull(source)]
    release.admit(source, checkout, tmp_path / 'source.tar', tmp_path / 'tests', tmp_path / 'admit.json', api=api)
    assert sorted(p.name for p in (tmp_path / 'tests').iterdir()) == ['Dockerfile']
    receipt = json.loads((tmp_path / 'admit.json').read_text())
    assert receipt['source_sha'] == source and receipt['source_pr'] == 7
    assert receipt['source_archive_sha256'] == release.sha256(tmp_path / 'source.tar')


@pytest.mark.parametrize('proof', [[], [merged_pull('f' * 40)],
    [{**merged_pull(SOURCE), 'merged_at': None}], [merged_pull(SOURCE), merged_pull(SOURCE)]])
def test_admission_requires_actual_unambiguous_main_merge(tmp_path, proof):
    commands = []
    def command(args, **kwargs):
        commands.append(args)
        return (WORKFLOW + '\n').encode() if args[-2:] == ['rev-parse', 'HEAD'] else b''
    api = lambda path: PRIVATE_REPO if path == 'repos/' + release.REPOSITORY else proof
    with pytest.raises(release.Refusal):
        release.admit(SOURCE, tmp_path, tmp_path / 'source.tar', tmp_path / 'tests', tmp_path / 'admit.json', api=api, command=command)
    assert not (tmp_path / 'source.tar').exists()
    assert not any('archive' in args for args in commands)


@pytest.mark.parametrize('source', ['main', 'a' * 39, 'A' * 40, 'a' * 40 + ';false'])
def test_admission_rejects_unpinned_input_before_api(tmp_path, source):
    def forbidden(*args, **kwargs):
        pytest.fail('Unpinned input reached external metadata')
    with pytest.raises(release.Refusal):
        release.admit(source, tmp_path, tmp_path / 'a', tmp_path / 'b', tmp_path / 'c', api=forbidden)


@pytest.mark.parametrize('report', ['<testsuites><testsuite tests="21"/></testsuites>',
    '<testsuites><testsuite tests="22" failures="1"/></testsuites>',
    '<testsuites><testsuite tests="22" skipped="1"/></testsuites>',
    '<testsuites><testsuite tests="22" errors="1"/></testsuites>'])
def test_test_gate_requires_complete_passing_suite(tmp_path, report):
    path = tmp_path / 'tests.xml'
    path.write_text(report)
    with pytest.raises(release.Refusal):
        release.tests_passed(path)


@pytest.mark.parametrize('metadata', [None, {'visibility': 'public', 'repository': {'full_name': release.REPOSITORY}},
    {'visibility': 'private', 'repository': None}, {'visibility': 'private', 'repository': {'full_name': 'another/repo'}}])
def test_package_privacy_and_source_are_verified(metadata):
    with pytest.raises(release.Refusal):
        release.private_package(metadata)
    if metadata is not None:
        with pytest.raises(release.Refusal):
            release.private_package(metadata, permit_missing=True)
    release.private_package(None, permit_missing=True)  # Absent-or-inaccessible, never a claim of absence.
    release.private_package(PRIVATE_PACKAGE)


@pytest.mark.parametrize('change', ['revision', 'source', 'user', 'image'])
def test_loaded_image_rejects_label_user_and_identity_drift(change):
    record = image_record()
    if change == 'revision':
        record['Config']['Labels']['org.opencontainers.image.revision'] = 'f' * 40
    elif change == 'source':
        record['Config']['Labels']['org.opencontainers.image.source'] = 'https://github.com/another/repo'
    elif change == 'user':
        record['Config']['User'] = 'root'
    else:
        record['Id'] = 'sha256:' + 'f' * 64
    with pytest.raises(release.Refusal):
        release.validate_image(record, SOURCE, IMAGE_ID)


class Docker:
    def __init__(self, source=SOURCE):
        self.calls = []
        self.source = source

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[1:3] == ['image', 'inspect']:
            return json.dumps([image_record(self.source)]).encode()
        if args[1] == 'save':
            Path(args[args.index('--output') + 1]).write_bytes(b'fixture-docker-archive')
        if args[1] == 'push':
            return b'tag: digest: ' + REGISTRY_DIGEST.encode() + b' size: 123\n'
        return b''


def make_build(tmp_path):
    archive = tmp_path / 'source.tar'
    with tarfile.open(archive, 'w') as tar:
        info = tarfile.TarInfo('Dockerfile')
        content = b'FROM scratch\n'
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    data = {'schema': 'cloud-cuckoo-image/v1', **release.context(), 'source_sha': SOURCE,
            'source_pr': 7, 'source_archive_sha256': release.sha256(archive)}
    receipt = tmp_path / 'admit.json'
    release.write_json(receipt, data)
    report = tmp_path / 'tests.xml'
    report.write_text('<testsuites><testsuite tests="22" failures="0" errors="0" skipped="0"/></testsuites>')
    docker = Docker()
    output = tmp_path / 'artifact'
    release.build(archive, receipt, report, tmp_path / 'fresh-build', output, command=docker)
    return docker, output


def test_build_checks_actual_image_in_restricted_container(tmp_path):
    docker, output = make_build(tmp_path)
    smoke = next((args, kwargs) for args, kwargs in docker.calls if args[1] == 'run')
    args, kwargs = smoke
    for option, value in [('--pull', 'never'), ('--network', 'none'), ('--user', '1000:1000'),
                           ('--cap-drop', 'ALL'), ('--security-opt', 'no-new-privileges')]:
        assert args[args.index(option) + 1] == value
    assert '--read-only' in args and args[-3:] == [IMAGE_ID, 'python', '-']
    assert kwargs['input'] == release.SMOKE.encode()
    assert (output / 'image.tar').exists()
    data = json.loads((output / 'build.json').read_text())
    assert data['pending_smoke'] == 'passed' and data['tests']['tests'] == 22
    assert data['image_tag'] == release.IMAGE + ':source-' + SOURCE + '-run-12345-attempt-1'


def publication_api(*, pre=PRIVATE_PACKAGE, post=PRIVATE_PACKAGE, artifact=None):
    calls = []
    def api(path, **kwargs):
        calls.append(path)
        if path == 'repos/' + release.REPOSITORY:
            return PRIVATE_REPO
        if '/actions/artifacts/' in path:
            return artifact or {'expired': False, 'digest': 'sha256:' + ARTIFACT_DIGEST,
                'workflow_run': {'id': 12345, 'head_sha': WORKFLOW}}
        return pre if calls.count(path) == 1 else post
    return api


def publish(tmp_path, directory, docker, api):
    data = json.loads((directory / 'build.json').read_text())
    receipt = tmp_path / 'published.json'
    release.publish(directory, '67890', ARTIFACT_DIGEST, data['docker_archive_sha256'], IMAGE_ID,
                    receipt, api=api, command=docker, pause=lambda seconds: None)
    return receipt


def test_publish_binds_artifact_and_verifies_digest_with_ephemeral_credentials(tmp_path):
    _, directory = make_build(tmp_path)
    docker = Docker()
    receipt = publish(tmp_path, directory, docker, publication_api(pre=None))
    data = json.loads(receipt.read_text())
    assert data['image_reference'] == release.IMAGE + '@' + REGISTRY_DIGEST
    assert data['package_visibility'] == 'private' and data['metadata_verified'] is True
    login = next((args, kwargs) for args, kwargs in docker.calls if args[1] == 'login')
    assert login[1]['input'] == b'fixture-ephemeral-secret'
    for args, kwargs in docker.calls:
        if args[1] in {'login', 'push', 'pull', 'logout'}:
            assert 'fixture-ephemeral-secret' not in ' '.join(args)
            assert 'GH_TOKEN' not in kwargs['env'] and 'GITHUB_TOKEN' not in kwargs['env']
            assert not Path(kwargs['env']['DOCKER_CONFIG']).exists()
    assert any(args == ['docker', 'pull', release.IMAGE + '@' + REGISTRY_DIGEST] for args, _ in docker.calls)
    assert any(args[1] == 'logout' for args, _ in docker.calls)


@pytest.mark.parametrize('artifact', [
    {'expired': True, 'digest': 'sha256:' + ARTIFACT_DIGEST, 'workflow_run': {'id': 12345, 'head_sha': WORKFLOW}},
    {'expired': False, 'digest': 'sha256:' + 'f' * 64, 'workflow_run': {'id': 12345, 'head_sha': WORKFLOW}},
    {'expired': False, 'digest': 'sha256:' + ARTIFACT_DIGEST, 'workflow_run': {'id': 999, 'head_sha': WORKFLOW}}])
def test_publish_refuses_other_or_expired_artifact_before_docker(tmp_path, artifact):
    _, directory = make_build(tmp_path)
    docker = Docker()
    with pytest.raises(release.Refusal):
        publish(tmp_path, directory, docker, publication_api(artifact=artifact))
    assert not docker.calls


def test_publish_refuses_changed_image_archive_before_docker(tmp_path):
    _, directory = make_build(tmp_path)
    (directory / 'image.tar').write_bytes(b'tampered fixture')
    docker = Docker()
    with pytest.raises(release.Refusal):
        publish(tmp_path, directory, docker, publication_api())
    assert not docker.calls


def test_publish_refuses_public_package_before_registry_login(tmp_path):
    _, directory = make_build(tmp_path)
    docker = Docker()
    with pytest.raises(release.Refusal):
        publish(tmp_path, directory, docker, publication_api(pre={**PRIVATE_PACKAGE, 'visibility': 'public'}))
    assert not docker.calls


def test_publish_never_claims_private_when_postpublication_metadata_is_unavailable(tmp_path):
    _, directory = make_build(tmp_path)
    docker = Docker()
    with pytest.raises(release.Refusal):
        publish(tmp_path, directory, docker, publication_api(post=None))
    receipt = json.loads((tmp_path / 'published.json').read_text())
    assert receipt['metadata_verified'] is False and 'package_visibility' not in receipt
    assert any(args[1] == 'logout' for args, _ in docker.calls)


def test_main_failure_never_logs_captured_secret(monkeypatch, capsys):
    monkeypatch.setattr('sys.argv', ['release_image.py', 'admit', '--source-sha', SOURCE,
        '--checkout', 'unused', '--archive', 'unused', '--test-directory', 'unused', '--receipt', 'unused'])
    def failed(**kwargs):
        raise release.Refusal('fixture-sensitive-subprocess-output')
    monkeypatch.setattr(release, 'admit', failed)
    assert release.main() == 1
    assert 'fixture-sensitive-subprocess-output' not in capsys.readouterr().out
