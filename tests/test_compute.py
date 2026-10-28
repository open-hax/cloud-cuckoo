"""Prove the CLI boundary never executes submitted Python on the host."""
import asyncio
import json
from pathlib import Path
import sys

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
import pytest

from knoxx_colab_mcp.compute import ComputeCLI, COMPUTE_TOOLS, make_compute_server
from knoxx_colab_mcp.server import Gateway, TOOL_NAMES, make_server
from test_transport import serve, TOKEN, GATEWAY_TOKEN


@pytest.fixture
def compute(tmp_path):
    executable = tmp_path / "fixture-colab"
    executable.write_text("#!" + sys.executable + "\n" + '''
import json,sys,time
from pathlib import Path
args=sys.argv[1:]
idx=args.index('--config')
state=Path(args[idx+1]);state.parent.mkdir(parents=True,exist_ok=True)
cmd=args[idx+2]
data=json.loads(state.read_text()) if state.exists() else {}
if cmd=='usage': print('Compute units available: 12.5')
elif cmd=='sessions': print('\\n'.join(x['endpoint'] for x in data.values()))
elif cmd=='new':
 name=args[args.index('--session')+1]
 data[name]={'endpoint':'endpoint-'+name}
 state.write_text(json.dumps(data));print('fixture allocated')
elif cmd=='exec':
 source=Path(args[args.index('--file')+1]).read_text()
 if 'LONG_TEST' in source:time.sleep(60)
 if 'FAIL_TEST' in source: print('fixture remote traceback');sys.exit(3)
 if 'FLOOD_TEST' in source: print('x'*(11*1024*1024))
 print('fixture remote output; submitted code was not evaluated locally')
elif cmd=='stop':
 data.pop(args[args.index('--session')+1],None)
 state.write_text(json.dumps(data));print('fixture stopped')
else:sys.exit(9)
''')
    executable.chmod(0o700)
    adc = tmp_path / "isolated-adc.json"
    adc.write_text('{}')
    return ComputeCLI(str(executable), tmp_path / 'state', adc, provision_seconds=3, execution_cushion=0)


async def finish(backend, job_id):
    await asyncio.wait_for(backend.tasks[job_id], 10)
    return backend.job(job_id)


async def test_typed_http_gateway_remote_job_and_cleanup(compute, tmp_path):
    async with serve(make_compute_server(compute, TOKEN)) as local:
        gateway = Gateway("http://127.0.0.1:1/mcp", TOKEN, compute_url=local+'/mcp')
        async with serve(make_server(gateway, GATEWAY_TOKEN)) as public:
            async with Client(StreamableHttpTransport(public+'/mcp',auth=GATEWAY_TOKEN)) as client:
                assert {t.name for t in await client.list_tools()} == set(TOOL_NAMES + COMPUTE_TOOLS)
                usage = (await client.call_tool('colab_compute_usage',{})).structured_content
                assert '12.5' in usage['output']
                marker = tmp_path/'host-code-must-never-run'
                submitted = f"from pathlib import Path; Path({str(marker)!r}).write_text('bad')"
                record = (await client.call_tool('colab_compute_start',{'code':submitted})).structured_content
                job = await finish(compute, record['job_id'])
                assert job['status']=='completed'
                assert job['exit_code']==0
                assert 'verified endpoint absent' in job['runtime_cleanup']
                assert not marker.exists()
                assert 'not evaluated locally' in job['output_tail']
                invalid = await client.call_tool('colab_compute_start',{'code':'x','accelerator':'TYPO'},raise_on_error=False)
                assert invalid.is_error


async def test_failure_timeout_cancel_concurrency_and_retained_output(compute):
    failed = await compute.start('FAIL_TEST')
    failed = await finish(compute,failed['job_id'])
    assert failed['status']=='failed' and failed['exit_code']==3
    assert 'traceback' in failed['output_tail']
    long = await compute.start('LONG_TEST',timeout_seconds=1)
    await asyncio.sleep(.05)
    with pytest.raises(ValueError,match='already active'):
        await compute.start('print(1)')
    timed = await finish(compute,long['job_id'])
    assert timed['status']=='timed_out'
    assert 'verified endpoint absent' in timed['runtime_cleanup']
    queued = await compute.start('print(1)')
    await compute.cancel(queued['job_id'])
    await asyncio.gather(compute.tasks[queued['job_id']],return_exceptions=True)
    assert compute.job(queued['job_id'])['status']=='cancelled'
    flood = await compute.start('FLOOD_TEST')
    flood = await finish(compute,flood['job_id'])
    assert flood['status']=='failed'
    assert (compute.state_dir/'jobs'/flood['job_id']/'output.txt').stat().st_size<=10*1024*1024
    assert 'verified endpoint absent' in flood['runtime_cleanup']


async def test_missing_login_and_unknown_ids_fail_closed(compute):
    compute.adc_file.unlink()
    with pytest.raises(ValueError,match='login is pending'):
        await compute.start('print(1)')
    with pytest.raises(ValueError,match='Invalid owned'):
        compute.job('../../other')
    with pytest.raises(ValueError,match='Unknown'):
        compute.job('0'*32)


async def test_uncertain_cleanup_blocks_more_allocations_until_verified(compute):
    flag = compute.state_dir/'refuse-stop'
    source = Path(compute.executable).read_text().replace("elif cmd=='stop':", "elif cmd=='stop':\n if (state.parent/'refuse-stop').exists():sys.exit(4)")
    Path(compute.executable).write_text(source)
    flag.write_text('fixture unassign failure')
    record = await compute.start('print(1)')
    failed_cleanup = await finish(compute,record['job_id'])
    assert failed_cleanup['runtime_cleanup'].startswith('unverified')
    with pytest.raises(ValueError,match='cleanup is unverified'):
        await compute.start('print(2)')
    flag.unlink()
    retried = await compute.cancel(record['job_id'])
    assert 'verified endpoint absent' in retried['runtime_cleanup']


async def test_restart_recovers_only_recorded_owned_session(compute):
    job_id='1'*32
    session='knoxx-mcp-'+job_id
    compute.jobs[job_id]={'job_id':job_id,'session':session,'status':'running',
                          'endpoint':'endpoint-owned','runtime_cleanup':'pending'}
    folder=compute.state_dir/'jobs'/job_id
    folder.mkdir(parents=True)
    compute.save(job_id)
    (compute.state_dir/'sessions.json').write_text(json.dumps({session:{'endpoint':'endpoint-owned'},'user-notebook':{'endpoint':'keep-user-notebook'}}))
    async with compute.lifespan(None):
        recovered=compute.job(job_id)
        assert recovered['status']=='interrupted'
        assert 'verified endpoint absent' in recovered['runtime_cleanup']
        assert 'user-notebook' in json.loads((compute.state_dir/'sessions.json').read_text())
