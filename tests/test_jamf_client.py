import httpx
import pytest

from thumper.services.jamf import JamfClient, JamfError


def make_client(handler, **kwargs):
    transport = httpx.MockTransport(handler)
    http = httpx.Client(base_url="https://jss.example.com", transport=transport, timeout=10)
    return JamfClient("https://jss.example.com", "cid", "secret", client=http, **kwargs)


def test_token_fetched_with_client_credentials():
    seen = {}

    def handler(request):
        assert request.url.path == "/api/oauth/token"
        assert request.method == "POST"
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"access_token": "tok-1", "expires_in": 3600})

    client = make_client(handler)
    assert client._token() == "tok-1"
    assert "grant_type=client_credentials" in seen["body"]
    assert "client_id=cid" in seen["body"]
    assert "client_secret=secret" in seen["body"]


def test_token_is_cached_between_calls():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(200, json={"access_token": "tok-1", "expires_in": 3600})

    client = make_client(handler)
    client._token()
    client._token()
    assert calls["n"] == 1


def test_token_refreshes_after_expiry(monkeypatch):
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(200, json={"access_token": f"tok-{calls['n']}", "expires_in": 100})

    fake_now = {"t": 1000.0}
    monkeypatch.setattr("thumper.services.jamf.time.monotonic", lambda: fake_now["t"])
    client = make_client(handler)
    assert client._token() == "tok-1"
    fake_now["t"] = 2000.0  # well past expiry
    assert client._token() == "tok-2"
    assert calls["n"] == 2


def test_token_failure_raises_jamferror():
    def handler(request):
        return httpx.Response(401, text="bad creds")

    client = make_client(handler)
    with pytest.raises(JamfError, match="auth failed"):
        client._token()


def test_token_malformed_body_raises_jamferror():
    def handler(request):
        return httpx.Response(200, json={"no_token": True})

    client = make_client(handler)
    with pytest.raises(JamfError, match="malformed response"):
        client._token()


def _token_ok(request):
    return httpx.Response(200, json={"access_token": "tok-1", "expires_in": 3600})


def test_upsert_script_creates_when_absent():
    seen = {}

    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        if request.url.path == "/api/v1/scripts" and request.method == "GET":
            return httpx.Response(200, json={"results": [{"id": "9", "name": "Other"}]})
        if request.url.path == "/api/v1/scripts" and request.method == "POST":
            seen["body"] = request.read().decode()
            return httpx.Response(201, json={"id": "42"})
        return httpx.Response(500)

    client = make_client(handler)
    assert client.upsert_script("Thumper Agent - tw1", "#!/bin/sh\necho hi\n") == "42"
    assert "Thumper Agent - tw1" in seen["body"]
    assert "echo hi" in seen["body"]


def test_upsert_script_updates_when_present():
    seen = {}

    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        if request.url.path == "/api/v1/scripts" and request.method == "GET":
            return httpx.Response(200, json={"results": [{"id": "7", "name": "Thumper Agent - tw1"}]})
        if request.url.path == "/api/v1/scripts/7" and request.method == "PUT":
            seen["hit"] = True
            return httpx.Response(200, json={"id": "7"})
        return httpx.Response(500)

    client = make_client(handler)
    assert client.upsert_script("Thumper Agent - tw1", "body") == "7"
    assert seen["hit"] is True


def test_upsert_script_create_failure_raises():
    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        if request.method == "GET":
            return httpx.Response(200, json={"results": []})
        return httpx.Response(400, text="nope")

    client = make_client(handler)
    with pytest.raises(JamfError, match="script create failed"):
        client.upsert_script("Thumper Agent - tw1", "body")


def test_find_smart_group_id_returns_id():
    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        if request.url.path == "/JSSResource/computergroups/name/All Macs":
            return httpx.Response(200, json={"computer_group": {"id": 11, "name": "All Macs"}})
        return httpx.Response(500)

    client = make_client(handler)
    assert client.find_smart_group_id("All Macs") == "11"


def test_find_smart_group_id_missing_raises():
    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        return httpx.Response(404, text="not found")

    client = make_client(handler)
    with pytest.raises(JamfError, match="not found in Jamf"):
        client.find_smart_group_id("Ghosts")


def test_smart_group_member_count():
    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        if request.url.path == "/JSSResource/computergroups/id/11":
            return httpx.Response(200, json={"computer_group": {"computers": [{}, {}, {}]}})
        return httpx.Response(500)

    client = make_client(handler)
    assert client.smart_group_member_count("11") == 3


def test_smart_group_member_count_null_computers():
    # Classic API JSON emits "computers": null (not []) for an empty group -
    # `.get("computers", [])` returns None there, so len() must be guarded.
    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        if request.url.path == "/JSSResource/computergroups/id/11":
            return httpx.Response(200, json={"computer_group": {"computers": None}})
        return httpx.Response(500)

    client = make_client(handler)
    assert client.smart_group_member_count("11") == 0


def test_find_script_id_paginates_beyond_one_page():
    # >100 scripts: the match lives on page 1. A single-page lookup would miss it
    # and wrongly CREATE a duplicate instead of updating in place.
    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        if request.url.path == "/api/v1/scripts" and request.method == "GET":
            page = int(request.url.params.get("page"))
            if page == 0:
                return httpx.Response(200, json={"results": [
                    {"id": str(i), "name": f"Other {i}"} for i in range(100)]})
            if page == 1:
                return httpx.Response(200, json={"results": [
                    {"id": "777", "name": "Thumper Agent - tw1"}]})
            return httpx.Response(200, json={"results": []})
        if request.url.path == "/api/v1/scripts/777" and request.method == "PUT":
            return httpx.Response(200, json={"id": "777"})
        return httpx.Response(500)

    client = make_client(handler)
    assert client.upsert_script("Thumper Agent - tw1", "body") == "777"


def test_upsert_policy_creates_with_xml():
    seen = {}

    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        if request.url.path == "/JSSResource/policies/name/Thumper Agent - tw1":
            return httpx.Response(404)
        if request.url.path == "/JSSResource/policies/id/0" and request.method == "POST":
            seen["xml"] = request.read().decode()
            return httpx.Response(201, text="<policy><id>55</id></policy>")
        return httpx.Response(500)

    client = make_client(handler)
    assert client.upsert_policy("Thumper Agent - tw1", "42", "11") == "55"
    assert "<id>42</id>" in seen["xml"]        # script ref
    assert "<id>11</id>" in seen["xml"]        # smart group ref
    assert "<trigger_checkin>true</trigger_checkin>" in seen["xml"]


def test_upsert_policy_updates_existing():
    seen = {}

    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        if request.url.path == "/JSSResource/policies/name/Thumper Agent - tw1":
            return httpx.Response(200, json={"policy": {"general": {"id": 88}}})
        if request.url.path == "/JSSResource/policies/id/88" and request.method == "PUT":
            seen["hit"] = True
            return httpx.Response(201, text="<policy><id>88</id></policy>")
        return httpx.Response(500)

    client = make_client(handler)
    assert client.upsert_policy("Thumper Agent - tw1", "42", "11") == "88"
    assert seen["hit"] is True


def test_find_policies_by_prefix():
    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        if request.url.path == "/JSSResource/policies":
            return httpx.Response(200, json={"policies": [
                {"id": 1, "name": "Thumper Agent - tw1"},
                {"id": 2, "name": "Unrelated"},
                {"id": 3, "name": "Thumper Agent - tw2"},
            ]})
        return httpx.Response(500)

    client = make_client(handler)
    assert client.find_policies_by_prefix("Thumper Agent") == ["1", "3"]


def test_find_policies_by_prefix_missing_id_raises_jamferror():
    # A matching policy with no "id" must raise JamfError, not a bare KeyError
    # that would escape the plugin boundary (consistent with _find_script_id).
    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        if request.url.path == "/JSSResource/policies":
            return httpx.Response(200, json={"policies": [{"name": "Thumper Agent - tw1"}]})
        return httpx.Response(500)

    client = make_client(handler)
    with pytest.raises(JamfError, match="unexpected response shape"):
        client.find_policies_by_prefix("Thumper Agent")


def test_policy_status_reports_scope():
    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        if request.url.path == "/JSSResource/policies/id/55":
            return httpx.Response(200, json={"policy": {
                "general": {"id": 55, "name": "Thumper Agent - tw1", "enabled": True},
                "scope": {"computer_groups": [{"id": 11, "name": "All Macs"}]},
            }})
        if request.url.path == "/JSSResource/computergroups/id/11":
            return httpx.Response(200, json={"computer_group": {"computers": [{}, {}]}})
        return httpx.Response(500)

    client = make_client(handler)
    status = client.policy_status("55")
    assert status == {
        "policy_id": "55", "name": "Thumper Agent - tw1",
        "enabled": True, "smart_group": "All Macs", "scope_count": 2,
    }


def test_policy_status_null_computer_groups():
    # scope present but computer_groups null (empty-group edge) - must not crash.
    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        if request.url.path == "/JSSResource/policies/id/77":
            return httpx.Response(200, json={"policy": {
                "general": {"id": 77, "name": "Thumper Agent - tw9", "enabled": False},
                "scope": {"computer_groups": None},
            }})
        return httpx.Response(500)

    client = make_client(handler)
    assert client.policy_status("77") == {
        "policy_id": "77", "name": "Thumper Agent - tw9",
        "enabled": False, "smart_group": None, "scope_count": 0,
    }


def test_policy_status_no_scope():
    def handler(request):
        if request.url.path == "/api/oauth/token":
            return _token_ok(request)
        if request.url.path == "/JSSResource/policies/id/77":
            return httpx.Response(200, json={"policy": {
                "general": {"id": 77, "name": "Thumper Agent - tw9", "enabled": False},
                "scope": {"computer_groups": []},
            }})
        return httpx.Response(500)

    client = make_client(handler)
    assert client.policy_status("77") == {
        "policy_id": "77", "name": "Thumper Agent - tw9",
        "enabled": False, "smart_group": None, "scope_count": 0,
    }


def _token_then(other):
    """Handler that mints a token on the OAuth path and delegates everything else."""
    def handler(request):
        if request.url.path == "/api/oauth/token":
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        return other(request)
    return handler


def test_transport_error_on_api_call_is_wrapped_as_jamferror():
    # A connection/timeout error on any non-token call must surface as JamfError,
    # never a raw httpx exception (which would escape the plugin unwrapped).
    def boom(request):
        raise httpx.ConnectError("connection reset")

    client = make_client(_token_then(boom))
    with pytest.raises(JamfError, match="request failed"):
        client.find_smart_group_id("All Macs")


def test_non_json_2xx_body_is_wrapped_as_jamferror():
    # A 200 with a non-JSON body (e.g. an HTML proxy/error page) must become a
    # JamfError, not a bare ValueError/JSONDecodeError.
    def html(request):
        return httpx.Response(200, text="<html>not json</html>")

    client = make_client(_token_then(html))
    with pytest.raises(JamfError, match="malformed JSON"):
        client.find_smart_group_id("All Macs")


def test_api_401_remints_token_once_and_retries():
    calls = {"token": 0, "scripts": 0}

    def handler(request):
        if request.url.path == "/api/oauth/token":
            calls["token"] += 1
            return httpx.Response(200, json={"access_token": f"tok-{calls['token']}", "expires_in": 3600})
        calls["scripts"] += 1
        if calls["scripts"] == 1:
            return httpx.Response(401, text="token revoked")  # first try: stale token
        return httpx.Response(200, json={"results": []})       # retry: fresh token works

    client = make_client(handler)
    assert client._find_script_id("X") is None  # succeeds after the transparent retry
    assert calls["token"] == 2   # token re-minted exactly once
    assert calls["scripts"] == 2  # the call was retried once


def test_api_401_is_not_retried_forever():
    # A persistent 401 must give up after one re-mint and surface as JamfError,
    # not loop. (Second 401 is returned, not swallowed.)
    calls = {"token": 0, "scripts": 0}

    def handler(request):
        if request.url.path == "/api/oauth/token":
            calls["token"] += 1
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        calls["scripts"] += 1
        return httpx.Response(401, text="still unauthorized")

    client = make_client(handler)
    with pytest.raises(JamfError, match="401"):
        client.find_smart_group_id("All Macs")
    assert calls["scripts"] == 2  # tried once, retried once, then surfaced
