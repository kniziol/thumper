"""Runtime configuration, all overridable via environment variables.

Defaults assume the repo layout (server/thumper/config.py → repo root is two
parents up) so `uvicorn thumper.main:app` works from a checkout with no setup.
"""
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Directory holding the installable plugins (each: plugin.py + manifest.yaml).
# This is the repo-root `plugins/` tree, NOT server/thumper/plugins/ (which is
# the plugin *framework* - base classes + loader).
PLUGINS_DIR = Path(os.environ.get("THUMPER_PLUGINS_DIR", str(REPO_ROOT / "plugins")))

# Database URL (SQLAlchemy format). A bare filesystem path is mapped to SQLite.
_db_raw = os.environ.get("THUMPER_DB", str(REPO_ROOT / "thumper.db"))
DB_URL = _db_raw if "://" in _db_raw else f"sqlite:///{_db_raw}"

# Public base URL endpoints use to reach this server's /api/trigger callback.
# Must be reachable from managed endpoints in production.
BASE_URL = os.environ.get("THUMPER_BASE_URL", "http://localhost:8000").rstrip("/")

# Shared enrollment token: an agent presents this to POST /api/enroll. The org
# embeds it in the install command it distributes (via MDM/SSH/etc). Dev default
# is obvious-and-insecure on purpose - override in production.
ENROLL_TOKEN = os.environ.get("THUMPER_ENROLL_TOKEN", "dev-enroll-token")

# Admin token gating the installer endpoint (GET /api/install.sh). The installer
# embeds the ENROLL_TOKEN, so it must not be fetchable anonymously; only the
# server-generated deploy command (which carries this token) can retrieve it.
# Dev default is obvious-and-insecure on purpose - override in production.
INSTALL_TOKEN = os.environ.get("THUMPER_INSTALL_TOKEN", "dev-install-token")

# Built static UI (ui/dist) - mounted at / when present (Docker / monolith mode).
UI_DIST = Path(os.environ.get("THUMPER_UI_DIST", str(REPO_ROOT / "ui" / "dist")))

# The endpoint agent script - served to endpoints by the self-bootstrapping
# install command so they don't need it pre-installed. It's a Bash script
# (curl + openssl only) so endpoints need no Python runtime.
AGENT_PATH = Path(os.environ.get("THUMPER_AGENT_PATH", str(REPO_ROOT / "agent" / "thumper_agent.sh")))

# Dashboard auto-refresh interval in seconds. 0 disables auto-refresh.
DASHBOARD_REFRESH = int(os.environ.get("THUMPER_DASHBOARD_REFRESH", "60"))
