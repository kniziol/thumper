"""POST /api/integrations/{plugin}/test - the connection-test endpoint."""
from thumper import store


def test_test_deploy_integration_returns_400_and_records_nothing(client_db):
    tc, db = client_db
    store.upsert_integration(db, plugin="mdm", kind="deploy",
                             config={"base_url": "https://jss", "client_id": "c",
                                     "client_secret": "s", "smart_group": "All"})

    resp = tc.post("/api/integrations/mdm/test")

    assert resp.status_code == 400
    assert "alert" in resp.json()["detail"]
    db.expire_all()
    row = store.get_integration(db, "mdm")
    assert row.last_test_status is None


def test_test_unknown_plugin_returns_404(client_db):
    tc, _ = client_db
    assert tc.post("/api/integrations/nope/test").status_code == 404


def test_test_unconfigured_alert_integration_returns_400(client_db):
    tc, _ = client_db
    resp = tc.post("/api/integrations/webhook/test")
    assert resp.status_code == 400
    assert "not configured" in resp.json()["detail"]


def test_test_alert_integration_failure_is_200_ok_false_and_persisted(client_db):
    tc, db = client_db
    store.upsert_integration(db, plugin="webhook", kind="alert",
                             config={"url": "http://127.0.0.1:1/hook"})

    resp = tc.post("/api/integrations/webhook/test")

    assert resp.status_code == 200
    assert resp.json()["ok"] is False
    db.expire_all()
    row = store.get_integration(db, "webhook")
    assert row.last_test_status == "failed"
    assert row.last_test_error


def test_delete_integration_removes_the_row(client_db):
    tc, db = client_db
    store.upsert_integration(db, plugin="webhook", kind="alert", config={"url": "http://x"})
    assert store.get_integration(db, "webhook") is not None

    resp = tc.delete("/api/integrations/webhook")

    assert resp.status_code == 200
    db.expire_all()
    assert store.get_integration(db, "webhook") is None


def test_delete_unknown_plugin_returns_404(client_db):
    tc, _ = client_db
    assert tc.delete("/api/integrations/nope").status_code == 404
