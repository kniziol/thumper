"""POST /api/agent/tripwire-paths - pre-enroll bait-path preview.

The agent fetches its tripwires' bait paths BEFORE enrolling so a path conflict
can abort the install without ever creating an endpoint (issue #29: a refused
install must leave no ghost endpoint in the dashboard). The endpoint returns the
paths as plain text (one per line) and is gated by the enroll token, like
/enroll - but it creates nothing.
"""
from thumper import store
from thumper.db import Tripwire

ENROLL_TOKEN = "dev-enroll-token"


def _mk(db, name, path):
    return store.create_tripwire(db, name=name, token_type="aws", path=path)


def test_returns_paths_for_given_tripwires(client_db):
    tc, db = client_db
    a = _mk(db, "aws", "~/.aws/credentials")
    b = _mk(db, "npm", "~/.npmrc")

    resp = tc.post("/api/agent/tripwire-paths",
                   data={"enroll_token": ENROLL_TOKEN,
                         "tripwire_ids": f"{a.id},{b.id}"})

    assert resp.status_code == 200
    assert resp.text.splitlines() == ["~/.aws/credentials", "~/.npmrc"]


def test_creates_no_endpoint(client_db):
    """The whole point: previewing paths must not register an endpoint."""
    tc, db = client_db
    a = _mk(db, "aws", "~/.aws/credentials")

    tc.post("/api/agent/tripwire-paths",
            data={"enroll_token": ENROLL_TOKEN, "tripwire_ids": a.id})

    assert store.list_endpoints(db) == []


def test_bad_token_is_401(client_db):
    tc, db = client_db
    a = _mk(db, "aws", "~/.aws/credentials")
    resp = tc.post("/api/agent/tripwire-paths",
                   data={"enroll_token": "wrong", "tripwire_ids": a.id})
    assert resp.status_code == 401


def test_unknown_and_inactive_tripwires_are_skipped(client_db):
    tc, db = client_db
    a = _mk(db, "aws", "~/.aws/credentials")
    inactive = _mk(db, "old", "~/.netrc")
    row = db.query(Tripwire).filter(Tripwire.id == inactive.id).first()
    row.active = False
    db.commit()

    resp = tc.post("/api/agent/tripwire-paths",
                   data={"enroll_token": ENROLL_TOKEN,
                         "tripwire_ids": f"{a.id},tw_does_not_exist,{inactive.id}"})

    assert resp.status_code == 200
    assert resp.text.splitlines() == ["~/.aws/credentials"]
