"""Live smoke test against a REAL Jamf Pro tenant.

Skipped unless the JAMF_* env vars are set, so it never runs in the normal
offline suite. Point it at any Jamf Pro tenant (yours, a trial, or a CI secret)
to verify the actual contract the mocked tests can only assume - OAuth, the
Jamf Pro + Classic API call shapes, and idempotent upsert:

    JAMF_BASE_URL=https://<tenant>.jamfcloud.com \
    JAMF_CLIENT_ID=<api-role client id> \
    JAMF_CLIENT_SECRET=<secret> \
    JAMF_SMART_GROUP="<an existing smart group name>" \
    pytest tests/test_jamf_live.py -v

The OAuth role needs script + policy read/write. It creates a synthetic script
and policy scoped to JAMF_SMART_GROUP, proves both upserts are idempotent, reads
status back, then deletes both (best-effort cleanup in a finally).
"""
import os

import httpx
import pytest

from thumper.services.jamf import JamfClient

BASE_URL = os.environ.get("JAMF_BASE_URL")
CLIENT_ID = os.environ.get("JAMF_CLIENT_ID")
CLIENT_SECRET = os.environ.get("JAMF_CLIENT_SECRET")
SMART_GROUP = os.environ.get("JAMF_SMART_GROUP")

pytestmark = pytest.mark.skipif(
    not (BASE_URL and CLIENT_ID and CLIENT_SECRET and SMART_GROUP),
    reason="set JAMF_BASE_URL, JAMF_CLIENT_ID, JAMF_CLIENT_SECRET, JAMF_SMART_GROUP "
           "to run the live Jamf smoke test",
)

_NAME = "Thumper Agent - smoketest-delete-me"
_SCRIPT = "#!/bin/sh\necho thumper-jamf-smoketest\n"


def _delete(client, path):
    """Best-effort teardown using the client's live bearer token."""
    with httpx.Client(base_url=BASE_URL.rstrip("/"), timeout=10) as http:
        http.delete(path, headers={"Authorization": f"Bearer {client._token()}"})


def test_jamf_live_script_policy_upsert_idempotent_and_status():
    client = JamfClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)

    # OAuth + Classic group lookup in one call (raises JamfError if the group is
    # missing or the role lacks read).
    group_id = client.find_smart_group_id(SMART_GROUP)
    assert group_id

    script_id = client.upsert_script(_NAME, _SCRIPT)  # Jamf Pro API create (201)
    policy_id = None
    try:
        assert script_id
        assert client.upsert_script(_NAME, _SCRIPT) == script_id  # idempotent (paginated find)

        policy_id = client.upsert_policy(_NAME, script_id, group_id)  # Classic API XML write
        assert policy_id
        assert client.upsert_policy(_NAME, script_id, group_id) == policy_id  # idempotent

        assert policy_id in client.find_policies_by_prefix("Thumper Agent - ")

        status = client.policy_status(policy_id)
        assert status["name"] == _NAME
        assert status["smart_group"] == SMART_GROUP
        # scope_count is the live member count of the group (>= 0).
        assert isinstance(status["scope_count"], int)
    finally:
        if policy_id:
            _delete(client, f"/JSSResource/policies/id/{policy_id}")
        _delete(client, f"/api/v1/scripts/{script_id}")
