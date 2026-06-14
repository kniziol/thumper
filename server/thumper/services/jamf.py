"""Jamf Pro API client for the MDM deploy plugin.

Speaks BOTH Jamf surfaces on one base_url: the modern Jamf Pro API
(/api/..., scripts) and the Classic API (/JSSResource/..., policies + smart
groups). Both accept the OAuth bearer token. Independent of the plugin contract:
raises JamfError, which the plugin translates into PluginError.

Every authenticated request goes through `_send_authed`, which is the single
place that (a) attaches the bearer, (b) turns any httpx transport error into a
JamfError so nothing escapes this client unwrapped, and (c) transparently
re-mints the token once on a 401 (revoked/rotated mid-run). Response bodies are
parsed through `_json`/`_dig`, which turn malformed or unexpectedly-shaped
responses into JamfError too.
"""
import time
import urllib.parse
import xml.etree.ElementTree as ET

import httpx

_TOKEN_SKEW = 60  # refresh this many seconds before the token actually expires


class JamfError(Exception):
    """Any Jamf API failure (auth, non-2xx, missing object, transport, parse)."""


class JamfClient:
    def __init__(self, base_url, client_id, client_secret, *, client=None):
        self._base = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._http = client or httpx.Client(base_url=self._base, timeout=10)
        self._token_value = None
        self._token_expiry = 0.0

    def _token(self) -> str:
        if self._token_value and time.monotonic() < self._token_expiry:
            return self._token_value
        try:
            resp = self._http.post(
                "/api/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
        except httpx.HTTPError as exc:
            raise JamfError(f"Jamf auth request failed: {exc}") from exc
        if resp.status_code != 200:
            raise JamfError(f"Jamf auth failed: {resp.status_code} {resp.text[:200]}")
        try:
            body = resp.json()
            self._token_value = body["access_token"]
            expires_in = float(body.get("expires_in", 0))
        except (ValueError, KeyError, TypeError) as exc:
            raise JamfError(f"Jamf auth returned a malformed response: {exc}") from exc
        # Floor the lifetime so a missing/short expires_in still yields a positive
        # cache window instead of an already-past expiry that re-auths every call.
        self._token_expiry = time.monotonic() + max(expires_in, _TOKEN_SKEW + 1) - _TOKEN_SKEW
        return self._token_value

    def _invalidate_token(self):
        self._token_value = None
        self._token_expiry = 0.0

    def _send_authed(self, method, url, *, accept="application/json",
                     content_type=None, **kwargs):
        """Send an authenticated request. Wraps any httpx transport error as a
        JamfError, and on a 401 re-mints the token once and retries (so a token
        revoked/rotated mid-operation self-heals instead of failing the deploy)."""
        for attempt in (1, 2):
            headers = {"Authorization": f"Bearer {self._token()}", "Accept": accept}
            if content_type:
                headers["Content-Type"] = content_type
            try:
                resp = self._http.request(method, url, headers=headers, **kwargs)
            except httpx.HTTPError as exc:
                raise JamfError(f"Jamf {method} {url} request failed: {exc}") from exc
            if resp.status_code == 401 and attempt == 1:
                self._invalidate_token()
                continue
            return resp
        return resp

    @staticmethod
    def _json(resp, label):
        """Decode a JSON body, turning a non-JSON response into JamfError."""
        try:
            return resp.json()
        except ValueError as exc:
            raise JamfError(f"{label}: malformed JSON response: {exc}") from exc

    @staticmethod
    def _dig(data, *keys, label):
        """Walk a nested mapping/list, raising JamfError on any missing key or
        wrong type instead of a bare KeyError/TypeError escaping the client."""
        cur = data
        try:
            for key in keys:
                cur = cur[key]
        except (KeyError, TypeError, IndexError) as exc:
            path = "/".join(str(k) for k in keys)
            raise JamfError(f"{label}: unexpected response shape at {path}: {exc}") from exc
        return cur

    _SCRIPT_PAGE_SIZE = 100

    def _find_script_id(self, name):
        # Page through the full list: a tenant with >100 scripts would otherwise
        # hide an existing one past page 0, so upsert_script would wrongly create
        # a duplicate instead of updating it. Stop at the first short/empty page.
        page = 0
        while True:
            resp = self._send_authed(
                "GET", "/api/v1/scripts",
                params={"page": page, "page-size": self._SCRIPT_PAGE_SIZE},
            )
            if resp.status_code != 200:
                raise JamfError(f"Jamf script list failed: {resp.status_code} {resp.text[:200]}")
            results = self._json(resp, "Jamf script list").get("results", [])
            for item in results:
                if item.get("name") == name:
                    return str(self._dig(item, "id", label="Jamf script list"))
            if len(results) < self._SCRIPT_PAGE_SIZE:
                return None
            page += 1

    def upsert_script(self, name, contents):
        payload = {
            "name": name,
            "priority": "AFTER",
            "info": "Managed by Thumper. Installs the honeytoken agent.",
            "scriptContents": contents,
        }
        existing = self._find_script_id(name)
        if existing:
            resp = self._send_authed("PUT", f"/api/v1/scripts/{existing}", json=payload)
            if resp.status_code not in (200, 201):
                raise JamfError(f"Jamf script update failed: {resp.status_code} {resp.text[:200]}")
            return existing
        resp = self._send_authed("POST", "/api/v1/scripts", json=payload)
        if resp.status_code != 201:
            raise JamfError(f"Jamf script create failed: {resp.status_code} {resp.text[:200]}")
        return str(self._dig(self._json(resp, "Jamf script create"), "id", label="Jamf script create"))

    def find_smart_group_id(self, name):
        resp = self._send_authed(
            "GET", f"/JSSResource/computergroups/name/{urllib.parse.quote(name, safe='')}"
        )
        if resp.status_code == 404:
            raise JamfError(f"smart group {name!r} not found in Jamf")
        if resp.status_code != 200:
            raise JamfError(f"Jamf group lookup failed: {resp.status_code} {resp.text[:200]}")
        return str(self._dig(self._json(resp, "Jamf group lookup"),
                             "computer_group", "id", label="Jamf group lookup"))

    def smart_group_member_count(self, group_id):
        resp = self._send_authed("GET", f"/JSSResource/computergroups/id/{group_id}")
        if resp.status_code != 200:
            raise JamfError(f"Jamf group read failed: {resp.status_code} {resp.text[:200]}")
        # Classic API JSON serializes an empty group as "computers": null (not []),
        # and `.get(default)` only fills a MISSING key - so coerce null → [].
        group = self._dig(self._json(resp, "Jamf group read"), "computer_group",
                          label="Jamf group read")
        return len(group.get("computers") or [])

    @staticmethod
    def _policy_xml(name, script_id, group_id):
        policy = ET.Element("policy")
        general = ET.SubElement(policy, "general")
        ET.SubElement(general, "name").text = name
        ET.SubElement(general, "enabled").text = "true"
        ET.SubElement(general, "trigger_checkin").text = "true"
        ET.SubElement(general, "frequency").text = "Once per computer"
        scope = ET.SubElement(policy, "scope")
        groups = ET.SubElement(scope, "computer_groups")
        grp = ET.SubElement(groups, "computer_group")
        ET.SubElement(grp, "id").text = str(group_id)
        scripts = ET.SubElement(policy, "scripts")
        scr = ET.SubElement(scripts, "script")
        ET.SubElement(scr, "id").text = str(script_id)
        ET.SubElement(scr, "priority").text = "After"
        return ET.tostring(policy, encoding="unicode")

    def _find_policy_id(self, name):
        resp = self._send_authed(
            "GET", f"/JSSResource/policies/name/{urllib.parse.quote(name, safe='')}"
        )
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise JamfError(f"Jamf policy lookup failed: {resp.status_code} {resp.text[:200]}")
        return str(self._dig(self._json(resp, "Jamf policy lookup"),
                             "policy", "general", "id", label="Jamf policy lookup"))

    def upsert_policy(self, name, script_id, group_id):
        xml = self._policy_xml(name, script_id, group_id)
        existing = self._find_policy_id(name)
        if existing:
            resp = self._send_authed("PUT", f"/JSSResource/policies/id/{existing}",
                                     content=xml, content_type="application/xml",
                                     accept="application/xml")
            if resp.status_code not in (200, 201):
                raise JamfError(f"Jamf policy update failed: {resp.status_code} {resp.text[:200]}")
            return existing
        resp = self._send_authed("POST", "/JSSResource/policies/id/0",
                                 content=xml, content_type="application/xml",
                                 accept="application/xml")
        if resp.status_code not in (200, 201):
            raise JamfError(f"Jamf policy create failed: {resp.status_code} {resp.text[:200]}")
        try:
            new_id = ET.fromstring(resp.text).findtext("id")
        except ET.ParseError as exc:
            raise JamfError(f"Jamf policy create returned malformed XML: {exc}") from exc
        if not new_id:
            raise JamfError("Jamf policy create response missing <id>")
        return new_id

    def find_policies_by_prefix(self, prefix):
        resp = self._send_authed("GET", "/JSSResource/policies")
        if resp.status_code != 200:
            raise JamfError(f"Jamf policy list failed: {resp.status_code} {resp.text[:200]}")
        return [
            str(self._dig(policy, "id", label="Jamf policy list"))
            for policy in self._json(resp, "Jamf policy list").get("policies", [])
            if str(policy.get("name", "")).startswith(prefix)
        ]

    def policy_status(self, policy_id):
        resp = self._send_authed("GET", f"/JSSResource/policies/id/{policy_id}")
        if resp.status_code != 200:
            raise JamfError(f"Jamf policy read failed: {resp.status_code} {resp.text[:200]}")
        policy = self._dig(self._json(resp, "Jamf policy read"), "policy", label="Jamf policy read")
        general = self._dig(policy, "general", label="Jamf policy read")
        # `or []` guards the empty-group case where Classic JSON gives null, not [].
        groups = policy.get("scope", {}).get("computer_groups") or []
        group = groups[0] if groups else None
        return {
            "policy_id": str(self._dig(general, "id", label="Jamf policy read")),
            "name": self._dig(general, "name", label="Jamf policy read"),
            "enabled": self._dig(general, "enabled", label="Jamf policy read"),
            "smart_group": group["name"] if group else None,
            "scope_count": self.smart_group_member_count(group["id"]) if group else 0,
        }
