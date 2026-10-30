# Native proposal inventory

`native_inventory.py` freezes proposals from Cosmic Ray 8.7.0's native core
provider. It invokes native `init` and `dump`, requires an empty results table,
and uses the official `mutate_code` and `get_operator` APIs. No test command,
mutation campaign, kill collection or production admission runs in this slice.

The complete tracked application checkout must equal its immutable Git source.
The full `src/knoxx_colab_mcp` scope, native session and dump, all proposal
statuses, source hashes, installed tool code identities, hash lock, producer
hash and deterministic selection seed remain inspectable. Native job UUIDs are
retained in the raw dump; deterministic proposal and selection identities use
native specifications and actual source/mutated bytes. Duplicate bytes,
operator errors, no-ops, syntax/compile errors and warnings remain negative
inventory entries. They cannot enter the four disjoint candidate partitions.
Output ancestry must be absolute and contain no symlinks or dot-dot segments;
the actual destination must remain outside the source before any output write
or native tool invocation. Materialized bytes are preserved in a fresh private directory. The manifest is
written last. Source/tool/producer custody is checked again before completion.

Install `qualification/tools.lock` in a separate Python 3.13 environment with
`uv pip install --require-hashes`. Native controls run with `-c /dev/null`
because they test independent synthetic tool fixtures, without application
pytest configuration. Native CI retains the actual source, hash lock, raw
streams, JUnit report and synthetic fixture inputs. These five controls include
real native session creation and mutation materialization; they supply zero
application test executions or qualification credit.

An eventual executor must authenticate native accepted source/producer custody,
freeze this inventory before execution, preserve every observed negative and
unexecuted candidate, use the source-owned pytest evidence adapter, and prove
each resource cgroup empty before reassessing retained evidence. Cosmic Ray's
default nonzero/timeout kill classification is not qualifying evidence. A
future four-by-250 collection requires actual genuine test assertion failures,
fresh clean baseline/restoration, published raw custody and the existing
Services admission decision. This inventory does not implement that policy.
