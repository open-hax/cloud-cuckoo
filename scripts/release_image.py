#!/usr/bin/env python3
"""Build and publish a private source-bound image; never deploy a host."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

REPOSITORY = 'open-hax/cloud-cuckoo'
IMAGE = 'ghcr.io/' + REPOSITORY
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')

SMOKE = r'''
import asyncio
import httpx
from knoxx_colab_mcp.oauth import IdentityUnavailable, PUBLIC_BASE, SCOPES
from knoxx_colab_mcp.server import make_server
class Backend:
    def status(self): return {'mode':'image-check','browser_connected':False}
async def main():
    app=make_server(Backend(),'fixture-denied-'+'x'*40,IdentityUnavailable()).http_app(stateless_http=True,json_response=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://image-check') as c:
        for path in ['/.well-known/oauth-authorization-server','/.well-known/oauth-authorization-server/colab']:
            response=await c.get(path)
            assert response.status_code==200 and response.headers['cache-control']=='no-store'
            data=response.json()
            assert data['issuer']==PUBLIC_BASE and data['scopes_supported']==SCOPES
            assert data['code_challenge_methods_supported']==['S256']
        for path in ['/authorize','/consent','/register','/token','/revoke','/auth/callback']:
            assert (await c.post(path,data={})).status_code==503
        for key in ['', 'wrong', 'fixture-denied-'+'x'*40]:
            headers={'Authorization':'Bearer '+key} if key else {}
            assert (await c.post('/mcp',headers=headers,json={})).status_code==401
        assert (await c.get('/health')).json()['identity_available'] is False
    print('pending contract verified')
asyncio.run(main())
'''


class Refusal(Exception):
    pass


class MetadataUnavailable(Refusal):
    def __init__(self, status):
        super().__init__('Required GitHub metadata is unavailable')
        self.status = status


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def run(command, *, input=None, env=None, timeout=900, stdout=subprocess.PIPE):
    result = subprocess.run(command, input=input, env=env, stdout=stdout,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode:
        raise Refusal('A bounded build or publication command failed')
    return result.stdout or b''


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def github(path, *, missing=False, api_version='2022-11-28'):
    token = os.environ.get('GH_TOKEN')
    if not token:
        raise Refusal('The job-scoped GitHub token is unavailable')
    request = urllib.request.Request('https://api.github.com/' + path, headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': api_version, 'User-Agent': 'cloud-cuckoo-image-builder'})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
            payload = response.read(2 * 1024 * 1024 + 1)
            if len(payload) > 2 * 1024 * 1024:
                raise Refusal('GitHub metadata exceeded its bound')
            return json.loads(payload)
    except urllib.error.HTTPError as error:
        if missing and error.code == 404:
            return None
        raise MetadataUnavailable(error.code) from None


def context():
    if (os.environ.get('GITHUB_REPOSITORY') != REPOSITORY or
            os.environ.get('GITHUB_REF') != 'refs/heads/main' or
            os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'):
        raise Refusal('Only a manual main-branch run of the private source repository is supported')
    workflow_sha = os.environ.get('GITHUB_SHA', '')
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '')
    if not HEX40.fullmatch(workflow_sha) or not run_id.isdecimal() or not attempt.isdecimal() or min(int(run_id), int(attempt)) < 1:
        raise Refusal('The native workflow identity is invalid')
    return {'repository': REPOSITORY, 'workflow_sha': workflow_sha,
            'run_id': int(run_id), 'run_attempt': int(attempt)}


def private_repository(api):
    data = api('repos/' + REPOSITORY)
    if (data.get('full_name') != REPOSITORY or data.get('private') is not True or
            data.get('default_branch') != 'main'):
        raise Refusal('The source repository must remain private with main as its default')


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    Path(path).chmod(0o600)


def emit(name, value):
    if output := os.environ.get('GITHUB_OUTPUT'):
        with Path(output).open('a') as stream:
            stream.write(name + '=' + str(value) + '\n')


def extract(archive, directory):
    Path(directory).mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as source:
        source.extractall(directory, filter='data')


def accepted_merge(source_sha, checkout, *, api, command):
    if not isinstance(source_sha, str) or not HEX40.fullmatch(source_sha):
        raise Refusal('An explicit full lowercase merged source SHA is required')
    head = command(['git', '-C', str(checkout), 'rev-parse', 'HEAD']).decode().strip()
    if head != context()['workflow_sha']:
        raise Refusal('The builder checkout differs from the native workflow revision')
    command(['git', '-C', str(checkout), 'cat-file', '-e', source_sha + '^{commit}'])
    command(['git', '-C', str(checkout), 'merge-base', '--is-ancestor', source_sha, head])
    print('Tracked source ancestry verified', flush=True)
    pulls = api(f'repos/{REPOSITORY}/commits/{source_sha}/pulls?per_page=100')
    matching = [p for p in pulls if p.get('merged_at') and p.get('merge_commit_sha') == source_sha and
                p.get('base', {}).get('ref') == 'main' and p.get('base', {}).get('repo', {}).get('full_name') == REPOSITORY]
    if len(matching) != 1 or type(matching[0].get('number')) is not int:
        raise Refusal('Source must be the actual merge commit of one accepted main PR')
    print('Native merged PR evidence verified', flush=True)
    return matching[0]['number']


def admit(source_sha, checkout, archive, test_directory, receipt, *, api=github, command=run):
    native = context()
    if not HEX40.fullmatch(source_sha):
        raise Refusal('An explicit full lowercase merged source SHA is required')
    private_repository(api)
    print('Private source repository metadata verified', flush=True)
    source_pr = accepted_merge(source_sha, checkout, api=api, command=command)
    with Path(archive).open('xb') as stream:
        command(['git', '-C', str(checkout), 'archive', '--format=tar', source_sha], stdout=stream)
    Path(archive).chmod(0o600)
    data = {'schema': 'cloud-cuckoo-image/v1', **native, 'source_sha': source_sha,
            'source_pr': source_pr, 'source_archive_sha256': sha256(archive)}
    write_json(receipt, data)
    extract(archive, test_directory)


def tests_passed(report):
    root = ET.parse(report).getroot()
    suites = [node for node in root.iter('testsuite') if not node.findall('testsuite')]
    counts = {key: sum(int(node.get(key, '0')) for node in suites) for key in ['tests', 'failures', 'errors', 'skipped']}
    if counts['tests'] < 22 or any(counts[key] for key in ['failures', 'errors', 'skipped']):
        raise Refusal('The complete source suite must pass at least 22 tests without errors or skips')
    return counts


def image_record(image, command):
    record = json.loads(command(['docker', 'image', 'inspect', image]))
    if not isinstance(record, list) or len(record) != 1:
        raise Refusal('Image identity could not be resolved')
    return record[0]


def validate_image(record, source_sha, expected_id=None):
    image_id = record.get('Id', '')
    config = record.get('Config', {})
    labels = config.get('Labels', {})
    if (not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id) or
            (expected_id is not None and image_id != expected_id) or config.get('User') != '1000:1000' or
            labels.get('org.opencontainers.image.source') != 'https://github.com/' + REPOSITORY or
            labels.get('org.opencontainers.image.revision') != source_sha):
        raise Refusal('The image does not match the selected source and nonroot contract')
    return image_id


def image_tag(data):
    return f"{IMAGE}:source-{data['source_sha']}-run-{data['run_id']}-attempt-{data['run_attempt']}"


def build(archive, receipt, report, build_directory, output, *, command=run):
    data = json.loads(Path(receipt).read_text())
    if any(data.get(key) != value for key, value in context().items()) or sha256(archive) != data['source_archive_sha256']:
        raise Refusal('Source archive or native build identity changed')
    counts = tests_passed(report)
    extract(archive, build_directory)  # Fresh context: test caches/venv never enter the build.
    tag = image_tag(data)
    command(['docker', 'build', '--build-arg', 'SOURCE_REVISION=' + data['source_sha'], '--tag', tag, str(build_directory)])
    image_id = validate_image(image_record(tag, command), data['source_sha'])
    command(['docker', 'run', '--rm', '-i', '--pull', 'never', '--network', 'none', '--read-only',
             '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
             '--pids-limit', '64', '--memory', '512m', '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
             image_id, 'python', '-'], input=SMOKE.encode(), timeout=180)
    Path(output).mkdir(parents=True, exist_ok=False)
    image_archive = Path(output) / 'image.tar'
    command(['docker', 'save', '--output', str(image_archive), tag])
    data.update({'image_id': image_id, 'image_tag': tag, 'docker_archive_sha256': sha256(image_archive),
                 'tests': counts, 'pending_smoke': 'passed'})
    write_json(Path(output) / 'build.json', data)
    emit('image_id', image_id)
    emit('docker_archive_sha256', data['docker_archive_sha256'])


def private_package(data, *, permit_missing=False):
    # GitHub documents first publication as private. A 404 is retained as
    # absent-or-inaccessible, never asserted to prove absence. Existing visible
    # packages must have the exact registry identity and private visibility.
    # GHCR REST has no documented repository-link field; image origin is bound
    # separately by native run/artifact custody and the pulled OCI image.
    if data is None and permit_missing:
        return
    if (not isinstance(data, dict) or data.get('visibility') != 'private' or
            data.get('name') != 'cloud-cuckoo' or data.get('package_type') != 'container' or
            not isinstance(data.get('owner'), dict) or data['owner'].get('login') != 'open-hax'):
        raise Refusal('Package privacy and exact registry identity are not verified')


def probe(output, *, api=github):
    """Observe native package metadata without building, pushing or qualifying it."""
    native = context()
    private_repository(api)
    observations = []
    for version in ['2022-11-28', '2026-03-10']:
        try:
            data = api('orgs/open-hax/packages/container/cloud-cuckoo', api_version=version)
        except MetadataUnavailable as error:
            observations.append({'api_version': version, 'http_status': error.status,
                                 'visibility': None, 'linked_repository': None})
            continue
        if not isinstance(data, dict):
            raise Refusal('Package metadata shape is unavailable')
        repository = data.get('repository')
        linked = repository.get('full_name') if isinstance(repository, dict) else None
        if not isinstance(linked, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', linked):
            linked = None
        visibility = data.get('visibility')
        if visibility not in ['private', 'public', 'internal']:
            visibility = None
        observations.append({'api_version': version, 'http_status': 200,
                             'visibility': visibility, 'linked_repository': linked})
    data = {'schema': 'cloud-cuckoo-package-probe/v1', **native,
            'metadata_verified': False, 'observations': observations}
    write_json(output, data)
    print(json.dumps(data, sort_keys=True), flush=True)


def publish(directory, artifact_id, artifact_digest, expected_archive_sha, expected_image_id, output,
            *, api=github, command=run, pause=time.sleep):
    native = context()
    private_repository(api)
    if not artifact_id.isdecimal() or not HEX64.fullmatch(artifact_digest):
        raise Refusal('The native build artifact identity is invalid')
    artifact = api(f'repos/{REPOSITORY}/actions/artifacts/{artifact_id}')
    if (artifact.get('expired') is not False or artifact.get('digest') != 'sha256:' + artifact_digest or
            artifact.get('workflow_run', {}).get('id') != native['run_id'] or
            artifact.get('workflow_run', {}).get('head_sha') != native['workflow_sha']):
        raise Refusal('The downloaded artifact is not bound to this builder run')
    data = json.loads((Path(directory) / 'build.json').read_text())
    if (data.get('schema') != 'cloud-cuckoo-image/v1' or
            any(data.get(key) != value for key, value in native.items()) or
            not HEX40.fullmatch(data.get('source_sha', '')) or data.get('pending_smoke') != 'passed' or
            data.get('image_id') != expected_image_id or data.get('docker_archive_sha256') != expected_archive_sha or
            data.get('image_tag') != image_tag(data) or
            sha256(Path(directory) / 'image.tar') != expected_archive_sha):
        raise Refusal('The build artifact content or source receipt changed')
    private_package(api('orgs/open-hax/packages/container/cloud-cuckoo', missing=True), permit_missing=True)
    command(['docker', 'load', '--input', str(Path(directory) / 'image.tar')])
    validate_image(image_record(expected_image_id, command), data['source_sha'], expected_image_id)
    tag = image_tag(data)
    command(['docker', 'tag', expected_image_id, tag])
    token = os.environ.get('GH_TOKEN', '')
    actor = os.environ.get('GITHUB_ACTOR', '')
    if not token or not actor:
        raise Refusal('The ephemeral publishing identity is unavailable')
    with tempfile.TemporaryDirectory(prefix='cloud-cuckoo-ghcr-') as auth:
        docker_env = {key: value for key, value in os.environ.items() if key not in {'GH_TOKEN', 'GITHUB_TOKEN'}}
        docker_env['DOCKER_CONFIG'] = auth
        try:
            command(['docker', 'login', 'ghcr.io', '--username', actor, '--password-stdin'], input=token.encode(), env=docker_env, timeout=60)
            result = command(['docker', 'push', tag], env=docker_env)
            digests = set(re.findall(rb'\bdigest: (sha256:[0-9a-f]{64})\b', result))
            if len(digests) != 1:
                raise Refusal('The registry did not return exactly one image digest')
            digest = digests.pop().decode()
            reference = IMAGE + '@' + digest
            command(['docker', 'pull', reference], env=docker_env)
            validate_image(image_record(reference, lambda args: command(args, env=docker_env)), data['source_sha'], expected_image_id)
            data.update({'image_digest': digest, 'image_reference': reference,
                         'build_artifact_id': int(artifact_id), 'build_artifact_digest': 'sha256:' + artifact_digest,
                         'published_at': datetime.now(timezone.utc).isoformat(), 'metadata_verified': False})
            write_json(output, data)
            for attempt in range(3):
                package = api('orgs/open-hax/packages/container/cloud-cuckoo', missing=True)
                if package is not None:
                    private_package(package)
                    break
                if attempt == 2:
                    raise Refusal('Published package metadata remains unavailable')
                pause(2)
            data.update({'package_visibility': 'private', 'metadata_verified': True,
                         'image_provenance_verified': True, 'package_ui_repository_link': 'unknown'})
            write_json(output, data)
            emit('image_reference', reference)
        finally:
            try:
                command(['docker', 'logout', 'ghcr.io'], env=docker_env, timeout=30)
            except Refusal:
                pass  # The containing auth directory is removed unconditionally.


def artifact_proof(data, artifact_id, digest, run_id, workflow_sha, name):
    if (type(artifact_id) is not int or artifact_id < 1 or not isinstance(digest, str) or
            not isinstance(data, dict) or data.get('id') != artifact_id or data.get('name') != name or
            data.get('expired') is not False or data.get('digest') != digest or
            not re.fullmatch(r'sha256:[0-9a-f]{64}', digest) or
            data.get('workflow_run', {}).get('id') != run_id or
            data.get('workflow_run', {}).get('head_sha') != workflow_sha):
        raise Refusal('Native publisher artifact custody is unavailable')


def reconcile_admit(publisher_run_id, publisher_run_attempt, checkout, receipt, *, api=github, command=run):
    native = context()
    private_repository(api)
    if (not publisher_run_id.isdecimal() or not publisher_run_attempt.isdecimal() or
            min(int(publisher_run_id), int(publisher_run_attempt)) < 1):
        raise Refusal('An exact native publisher run and attempt are required')
    run_id, attempt = int(publisher_run_id), int(publisher_run_attempt)
    publisher = api(f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}')
    if (publisher.get('id') != run_id or publisher.get('run_attempt') != attempt or
            publisher.get('event') != 'workflow_dispatch' or publisher.get('head_branch') != 'main' or
            publisher.get('path') != '.github/workflows/publish-image.yml' or publisher.get('status') != 'completed' or
            publisher.get('conclusion') not in ['success', 'failure'] or
            publisher.get('repository', {}).get('full_name') != REPOSITORY or
            publisher.get('head_repository', {}).get('full_name') != REPOSITORY):
        raise Refusal('The native source publisher run is not eligible')
    workflow_sha = publisher.get('head_sha')
    accepted_merge(workflow_sha, checkout, api=api, command=command)
    listed = api(f'repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100')
    artifacts = listed.get('artifacts', [])
    name = f'cloud-cuckoo-release-{run_id}-{attempt}'
    matching = [a for a in artifacts if a.get('name') == name]
    if listed.get('total_count') != len(artifacts) or len(matching) != 1:
        raise Refusal('Native release artifact enumeration is incomplete or ambiguous')
    selected = matching[0]
    artifact_proof(selected, selected.get('id'), selected.get('digest', ''), run_id, workflow_sha, name)
    data = {'schema': 'cloud-cuckoo-reconciliation-input/v1', **native,
            'publisher_run_id': run_id, 'publisher_run_attempt': attempt, 'publisher_workflow_sha': workflow_sha,
            'release_artifact_id': selected['id'], 'release_artifact_digest': selected['digest']}
    write_json(receipt, data)
    emit('artifact_id', selected['id'])


def reconcile(directory, admission, checkout, output, *, api=github, command=run):
    native = context()
    proof = json.loads(Path(admission).read_text())
    if (proof.get('schema') != 'cloud-cuckoo-reconciliation-input/v1' or
            any(proof.get(key) != value for key, value in native.items())):
        raise Refusal('The current reconciliation identity changed')
    # Recollect publisher custody now; the downloaded artifact cannot choose it.
    with tempfile.TemporaryDirectory(prefix='cloud-cuckoo-proof-') as temporary:
        refreshed = Path(temporary) / 'admission.json'
        reconcile_admit(str(proof['publisher_run_id']), str(proof['publisher_run_attempt']), checkout,
                        refreshed, api=api, command=command)
        if json.loads(refreshed.read_text()) != proof:
            raise Refusal('Native release artifact custody changed')
    data = json.loads((Path(directory) / 'release-receipt.json').read_text())
    if (data.get('schema') != 'cloud-cuckoo-image/v1' or data.get('repository') != REPOSITORY or
            data.get('run_id') != proof['publisher_run_id'] or data.get('run_attempt') != proof['publisher_run_attempt'] or
            data.get('workflow_sha') != proof['publisher_workflow_sha'] or data.get('pending_smoke') != 'passed' or
            not re.fullmatch(r'sha256:[0-9a-f]{64}', data.get('image_id', '')) or
            not re.fullmatch(r'sha256:[0-9a-f]{64}', data.get('image_digest', '')) or
            data.get('image_reference') != IMAGE + '@' + data.get('image_digest', '') or
            data.get('image_tag') != image_tag(data) or
            not HEX64.fullmatch(data.get('source_archive_sha256', '')) or
            not HEX64.fullmatch(data.get('docker_archive_sha256', ''))):
        raise Refusal('The published image receipt is not source-bound')
    counts = data.get('tests', {})
    if (set(counts) != {'tests', 'failures', 'errors', 'skipped'} or
            any(type(value) is not int for value in counts.values()) or counts['tests'] < 22 or
            any(counts[key] != 0 for key in ['failures', 'errors', 'skipped'])):
        raise Refusal('The native source suite did not completely pass')
    if data.get('source_pr') != accepted_merge(data.get('source_sha'), checkout, api=api, command=command):
        raise Refusal('The image receipt differs from its accepted source PR')
    artifact_id, digest = data.get('build_artifact_id'), data.get('build_artifact_digest', '')
    if type(artifact_id) is not int or artifact_id < 1:
        raise Refusal('Native build artifact identity is unavailable')
    artifact_proof(api(f'repos/{REPOSITORY}/actions/artifacts/{artifact_id}'), artifact_id, digest,
                   data['run_id'], data['workflow_sha'], f"cloud-cuckoo-build-{data['run_id']}-{data['run_attempt']}")
    private_package(api('orgs/open-hax/packages/container/cloud-cuckoo'))
    token, actor = os.environ.get('GH_TOKEN'), os.environ.get('GITHUB_ACTOR')
    if not token or not actor:
        raise Refusal('The ephemeral read-only registry identity is unavailable')
    with tempfile.TemporaryDirectory(prefix='cloud-cuckoo-pull-') as auth:
        docker_env = {key: value for key, value in os.environ.items() if key not in {'GH_TOKEN', 'GITHUB_TOKEN'}}
        docker_env['DOCKER_CONFIG'] = auth
        try:
            command(['docker', 'login', 'ghcr.io', '--username', actor, '--password-stdin'], input=token.encode(), env=docker_env, timeout=60)
            command(['docker', 'pull', data['image_reference']], env=docker_env)
            validate_image(image_record(data['image_reference'], lambda args: command(args, env=docker_env)),
                           data['source_sha'], data['image_id'])
            private_package(api('orgs/open-hax/packages/container/cloud-cuckoo'))
        finally:
            try:
                command(['docker', 'logout', 'ghcr.io'], env=docker_env, timeout=30)
            except Refusal:
                pass
    data.update({'metadata_verified': True, 'image_provenance_verified': True, 'package_visibility': 'private',
                 'package_ui_repository_link': 'unknown', 'reconciled_at': datetime.now(timezone.utc).isoformat(),
                 'reconciliation': {**native, 'release_artifact_id': proof['release_artifact_id'],
                                    'release_artifact_digest': proof['release_artifact_digest']}})
    write_json(output, data)
    emit('image_reference', data['image_reference'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    admit_args = sub.add_parser('admit')
    for name in ['source-sha', 'checkout', 'archive', 'test-directory', 'receipt']:
        admit_args.add_argument('--' + name, required=True)
    build_args = sub.add_parser('build')
    for name in ['archive', 'receipt', 'report', 'build-directory', 'output']:
        build_args.add_argument('--' + name, required=True)
    publish_args = sub.add_parser('publish')
    for name in ['directory', 'artifact-id', 'artifact-digest', 'expected-archive-sha', 'expected-image-id', 'output']:
        publish_args.add_argument('--' + name, required=True)
    probe_args = sub.add_parser('probe')
    probe_args.add_argument('--output', required=True)
    reconcile_admit_args = sub.add_parser('reconcile-admit')
    for name in ['publisher-run-id', 'publisher-run-attempt', 'checkout', 'receipt']:
        reconcile_admit_args.add_argument('--' + name, required=True)
    reconcile_args = sub.add_parser('reconcile')
    for name in ['directory', 'admission', 'checkout', 'output']:
        reconcile_args.add_argument('--' + name, required=True)
    args = vars(parser.parse_args())
    mode = args.pop('mode').replace('-', '_')
    try:
        globals()[mode](**args)
        print('Cloud Cuckoo image step completed: ' + mode)
        return 0
    except (Refusal, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, ET.ParseError, tarfile.TarError):
        print('Cloud Cuckoo image step refused; no credential or captured subprocess output is logged', flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
