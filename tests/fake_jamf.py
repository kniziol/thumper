"""An in-process fake Jamf Pro server for integration-testing the real plugin
over real HTTP.

This is NOT a Jamf emulator - it's a *contract fake*. It implements only the
endpoints `JamfClient` calls, and returns the response shapes that were verified
against Jamf's documented API (Jamf Pro API for scripts/OAuth, Classic API XML
for policies + smart groups). It's as honest as those documented shapes, so it
exercises the parts a mock can't: the real OAuth round-trip, the bearer token
actually being attached, our hand-built policy XML actually being parsed, real
status codes, and httpx param/content encoding over a socket.

Deliberately reproduces two real-world quirks the unit tests can't:
  - an empty smart group serializes `"computers": null` (not `[]`)
  - the script list is paginated, so >100 scripts span multiple pages
"""
import urllib.parse
import xml.etree.ElementTree as ET

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

_TOKEN = "fake-access-token"
_PAGE_SIZE_DEFAULT = 100


def create_fake_jamf(*, client_id="cid", client_secret="secret",
                     seed_groups=None, filler_scripts=0):
    """Build a fake Jamf Pro FastAPI app.

    seed_groups: {name: computers} where `computers` is a list (members) or None
                 (empty group - exercises the `computers: null` path).
    filler_scripts: number of unrelated scripts to pre-create, to force the
                    script lookup across more than one page.
    """
    app = FastAPI()
    store = {
        "scripts": {},     # id -> payload dict (incl. name)
        "policies": {},    # id -> {"general": {...}, "group_id": int, "script_id": str}
        "groups": {},      # id -> {"id", "name", "is_smart", "computers"}
        "next_script_id": 1,
        "next_policy_id": 1,
        "token_requests": 0,
    }
    app.state.store = store

    gid = 100
    for name, computers in (seed_groups or {}).items():
        store["groups"][gid] = {"id": gid, "name": name, "is_smart": True,
                                "computers": computers}
        gid += 1
    for _ in range(filler_scripts):
        sid = store["next_script_id"]
        store["next_script_id"] += 1
        store["scripts"][str(sid)] = {"id": str(sid), "name": f"Unrelated {sid}"}

    def authed(request: Request) -> bool:
        return request.headers.get("authorization") == f"Bearer {_TOKEN}"

    def group_by_name(name):
        return next((g for g in store["groups"].values() if g["name"] == name), None)

    # ---- Jamf Pro API: OAuth + scripts (JSON) ----

    @app.post("/api/oauth/token")
    async def oauth_token(request: Request):
        store["token_requests"] += 1
        form = {k: v[0] for k, v in
                urllib.parse.parse_qs((await request.body()).decode()).items()}
        if (form.get("grant_type") != "client_credentials"
                or form.get("client_id") != client_id
                or form.get("client_secret") != client_secret):
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        return {"access_token": _TOKEN, "expires_in": 1199, "token_type": "Bearer"}

    @app.get("/api/v1/scripts")
    async def list_scripts(request: Request):
        if not authed(request):
            return JSONResponse({"httpStatus": 401}, status_code=401)
        page = int(request.query_params.get("page", 0))
        size = int(request.query_params.get("page-size", _PAGE_SIZE_DEFAULT))
        items = list(store["scripts"].values())
        chunk = items[page * size:page * size + size]
        return {"totalCount": len(items), "results": chunk}

    @app.post("/api/v1/scripts")
    async def create_script(request: Request):
        if not authed(request):
            return JSONResponse({"httpStatus": 401}, status_code=401)
        payload = await request.json()
        sid = str(store["next_script_id"])
        store["next_script_id"] += 1
        store["scripts"][sid] = {"id": sid, **payload}
        return JSONResponse({"id": sid, "href": f"/api/v1/scripts/{sid}"}, status_code=201)

    @app.put("/api/v1/scripts/{sid}")
    async def update_script(sid: str, request: Request):
        if not authed(request):
            return JSONResponse({"httpStatus": 401}, status_code=401)
        if sid not in store["scripts"]:
            return JSONResponse({"httpStatus": 404}, status_code=404)
        store["scripts"][sid].update(await request.json())
        return {"id": sid, **store["scripts"][sid]}

    # ---- Classic API: computer groups + policies (JSON reads, XML writes) ----

    @app.get("/JSSResource/computergroups/name/{name}")
    async def find_group(name: str, request: Request):
        if not authed(request):
            return Response("unauthorized", status_code=401)
        g = group_by_name(name)
        if not g:
            return Response(status_code=404)
        return {"computer_group": {"id": g["id"], "name": g["name"],
                                   "is_smart": g["is_smart"]}}

    @app.get("/JSSResource/computergroups/id/{group_id}")
    async def read_group(group_id: int, request: Request):
        if not authed(request):
            return Response("unauthorized", status_code=401)
        g = store["groups"].get(group_id)
        if not g:
            return Response(status_code=404)
        # `computers` is intentionally passed through as-is - may be None.
        return {"computer_group": {"id": g["id"], "name": g["name"],
                                   "computers": g["computers"]}}

    @app.get("/JSSResource/policies")
    async def list_policies(request: Request):
        if not authed(request):
            return Response("unauthorized", status_code=401)
        return {"policies": [{"id": int(pid), "name": p["general"]["name"]}
                             for pid, p in store["policies"].items()]}

    @app.get("/JSSResource/policies/name/{name}")
    async def find_policy(name: str, request: Request):
        if not authed(request):
            return Response("unauthorized", status_code=401)
        for pid, p in store["policies"].items():
            if p["general"]["name"] == name:
                return {"policy": {"general": {"id": int(pid), "name": name}}}
        return Response(status_code=404)

    @app.get("/JSSResource/policies/id/{pid}")
    async def read_policy(pid: str, request: Request):
        if not authed(request):
            return Response("unauthorized", status_code=401)
        p = store["policies"].get(pid)
        if not p:
            return Response(status_code=404)
        g = store["groups"].get(p["group_id"]) if p["group_id"] else None
        groups = [{"id": g["id"], "name": g["name"]}] if g else []
        return {"policy": {
            "general": {"id": int(pid), "name": p["general"]["name"],
                        "enabled": p["general"]["enabled"]},
            "scope": {"computer_groups": groups},
        }}

    def _store_policy(pid, xml_body):
        root = ET.fromstring(xml_body)
        gid_text = root.findtext("scope/computer_groups/computer_group/id")
        store["policies"][pid] = {
            "general": {"name": root.findtext("general/name"),
                        "enabled": root.findtext("general/enabled") == "true"},
            "group_id": int(gid_text) if gid_text else None,
            "script_id": root.findtext("scripts/script/id"),
        }
        return Response(f"<policy><id>{pid}</id></policy>",
                        media_type="application/xml", status_code=201)

    @app.post("/JSSResource/policies/id/0")
    async def create_policy(request: Request):
        if not authed(request):
            return Response("unauthorized", status_code=401)
        pid = str(store["next_policy_id"])
        store["next_policy_id"] += 1
        return _store_policy(pid, (await request.body()).decode())

    @app.put("/JSSResource/policies/id/{pid}")
    async def update_policy(pid: str, request: Request):
        if not authed(request):
            return Response("unauthorized", status_code=401)
        if pid not in store["policies"]:
            return Response(status_code=404)
        return _store_policy(pid, (await request.body()).decode())

    return app
