"""GET /api/settings - read-only server configuration."""
from unittest.mock import patch, MagicMock


def test_settings_sqlite(client_db):
    tc, _ = client_db
    resp = tc.get("/api/settings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["database"]["backend"] == "sqlite"
    assert "://" not in body["database"]["location"]
    assert body["thresholds"]["stale_minutes"] == 15
    assert body["thresholds"]["inactive_hours"] == 12
    assert body["dashboard"]["refresh_seconds"] == 60


def test_settings_postgres_location(client_db):
    tc, _ = client_db
    mock_engine = MagicMock()
    mock_engine.dialect.name = "postgresql"
    with patch("thumper.api.routes.get_engine", return_value=mock_engine), \
         patch("thumper.api.routes.DB_URL",
               "postgresql+psycopg://user:pass@dbhost:5432/thumper"):
        resp = tc.get("/api/settings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["database"]["backend"] == "postgresql"
    assert body["database"]["location"] == "dbhost:5432/thumper"


def test_settings_mysql_location_no_port(client_db):
    tc, _ = client_db
    mock_engine = MagicMock()
    mock_engine.dialect.name = "mysql"
    with patch("thumper.api.routes.get_engine", return_value=mock_engine), \
         patch("thumper.api.routes.DB_URL",
               "mysql+pymysql://user:pass@dbhost/thumper"):
        resp = tc.get("/api/settings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["database"]["backend"] == "mysql"
    assert body["database"]["location"] == "dbhost/thumper"
