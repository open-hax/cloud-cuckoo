# Pytest execution evidence

This adapter measures an admitted test plan; it grants no production or mutation
qualification credit by itself. Source admission supplies the frozen manifest.
The outer producer/native CI artifact custody must authenticate the returned
execution digest. An attacker-supplied digest is not authentication, and pytest
hooks inside the test process are not a cryptographic sandbox against arbitrary
malicious accepted harness code.

`make_manifest` binds the application/test file hashes, declared test selectors
and expected collected node IDs, import roots, phase, producer code, tool lock,
Python binary and actual pytest/pluggy/pytest-asyncio code identities. The parent
uses a fresh nonce and stripped environment, observes exit/timeout/output limits,
retains both raw streams, verifies custody before/after, and seals the summary
and execution hashes. All raw files remain private in a new exclusive directory.
Every child and runtime-identity probe uses an exclusive empty Python cache
prefix as well as `-B`; disabling bytecode writes alone does not prevent stale
application imports or reuse of tests cached without assertion-pass rewriting.

Official pytest hooks measure successful assertion executions separately during
setup/call/teardown and capture collection failures, warnings and report phases.
The public logging record factory is chained without changing the returned
record. Warning-level and higher records deny evidence even when pytest captures
them or a logger has only a `NullHandler`. Nonempty captured stderr also denies
evidence, including output consumed through the public `CaptureFixture.readouterr`
method. Public `logging.makeLogRecord` reconstruction is observed after its
dictionary is applied; its initial `level=None` factory call remains valid.
The observer hashes primitive unformatted origin/format fields and never calls
`getMessage`, `str` or `repr` on lazy message arguments. Only hashes and categories enter the structured projection; diagnostic
payloads are not copied there. The parent creates an exclusive warning journal
and hashes it after the child process exits. This includes records emitted by
`logging.shutdown` after the final exclusive summary writer. Each journal row
binds the fresh execution nonce, and the journal shares the output size limit.
Missing, changed, malformed or stale journals and incomplete summaries deny
evidence.
Only call-phase `AssertionError` at a declared test `assert`, missing expected
exceptions at a declared `pytest.raises`, or explicit declared `pytest.fail`
can be an assertion-failure candidate. Runtime exceptions, application-internal
asserts, setup/teardown failures, compiler/import/collection errors, warnings,
timeouts, output limits, skips, missing/bad/stale evidence and custody drift deny
that candidate. In particular, Cosmic Ray's default nonzero-exit/timeout
`KILLED` result supplies no admission.
An assertion-failure candidate requires complete setup/call/teardown coverage
for every declared collected node. Truncated reports cannot supply a kill.

The producer must run each invocation in an independently owned resource cgroup
and verify its complete emptiness before another job. The adapter stops its
owned process group, including timeout descendants; an application may create
new sessions, which requires that outer cgroup boundary. This first slice has
no mutation executor, operator implementation or campaign. Native Cosmic Ray
proposal/session inputs remain separate; no score or selection is fabricated.

`integration` and `e2e` are explicit immutable manifest phases. Actual local
HTTP/WebSocket/OAuth fixture tests may measure those phases with synthetic
upstreams; they do not prove human login or Google execution. Source 19e's two
Authlib warnings must deny a clean baseline even if all tests exit 0. A future
accepted warning-free source requires fresh source/producer/tool/harness custody
and baseline/postrestore evidence before any genuine mutant pilot or campaign.

The source CI workflow installs `uv.lock` with the project test extra, which
contains pytest and pytest-asyncio. Cosmic Ray inventory uses a separate tooling
environment; it is not the application test interpreter. PR/main CI runs both
the adversarial controls and the full source suite on an ephemeral runner with
read-only repository permission, stripped test environments, fresh cache
prefixes and a 2 GiB / 2 CPU systemd resource boundary. It retains raw streams,
JUnit reports and each control invocation. A passing CI test job does not erase
recorded dependency warnings or grant production qualification.
