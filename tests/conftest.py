# SPDX-License-Identifier: GPL-3.0-or-later
"""Standard log capture for application contracts; logger levels stay intact."""
import sys

import pytest

if 'pytest_evidence' in sys.modules:
    # Measurement executes the separately admitted producer helper. Collection
    # and ordinary pytest can use this checkout's identical test-support module.
    from expected_diagnostics import capture_expected_logs
else:
    from qualification.expected_diagnostics import capture_expected_logs


APPLICATION_MODULES = frozenset({'test_compute.py', 'test_oauth.py', 'test_transport.py',
    'test_revocation_retry.py', 'test_production_binding.py', 'test_transport_stage.py',
    'test_dependency_compatibility.py'})


@pytest.fixture(autouse=True)
def diagnostics(request, caplog):
    if request.path.name not in APPLICATION_MODULES:
        yield None
        return
    with capture_expected_logs(caplog, 'fastmcp', 'uvicorn') as capture:
        yield capture
