"""The plugin contract. Community plugins import from here.

A plugin is a DIRECTORY under plugins/{deploy,alert}/<name>/ containing:
  - manifest.yaml : name, kind, display_name, version, author, description,
                    and config_schema (fields: string | secret | boolean) that
                    the UI renders into a config form automatically.
  - plugin.py     : defines a class named `Plugin` subclassing DeployPlugin or
                    AlertPlugin. It is constructed with the saved config dict.

The contract is intentionally minimal so it can grow without breaking plugins:
the `path` and HMAC `callback_url`/`hmac_secret` travel INSIDE the Token object,
not as separate arguments.
"""
from abc import ABC, abstractmethod

from pydantic import BaseModel


class AgentInstall(BaseModel):
    """What a deploy plugin distributes to endpoints. A deploy plugin's job is to
    get the agent RUNNING on the chosen machines - it runs `command`, which makes
    each machine self-enroll and pull its own unique token instance. Per-token
    content + HMAC secret are minted server-side at enroll time and never travel
    in the install (so the same command can fan out to a whole fleet safely)."""
    tripwire_id: str
    server_url: str
    enroll_token: str
    command: str         # the shell command to run on each endpoint


class DeployResult(BaseModel):
    state: str = "pending"        # deployed | pending | failed
    deployed_count: int = 0       # endpoints the install reached
    message: str = ""             # human-readable detail, surfaced to operators


class PluginError(Exception):
    """Raised for expected failures (missing config, unreachable target).
    The API turns these into a 400 with the message."""


class DeployPlugin(ABC):
    def __init__(self, config: dict):
        self.config = config or {}

    @abstractmethod
    def deploy(self, install: AgentInstall, targets: list[str]) -> DeployResult:
        """Run `install.command` on `targets` (or on machines derived from the
        plugin's own config - an MDM smart group, an SSH host list)."""

    def status(self, targets: list[str]) -> dict:
        """Optional: report current deployment status. Default: nothing known."""
        return {}


class AlertPlugin(ABC):
    def __init__(self, config: dict):
        self.config = config or {}

    @abstractmethod
    def alert(self, event: dict) -> None:
        """Deliver a fired-tripwire `event` to the destination. Raise on failure;
        the router logs it without failing the trigger."""

    def test(self) -> None:
        """Verify connectivity by delivering a clearly-labeled synthetic event
        through the real send path (so it exercises URL + auth + payload format,
        not just reachability). Raises (PluginError or a transport error) on
        failure. Plugins may override for a lighter check."""
        self.alert({
            "thumper_test": True,
            "event_type": "test",
            "tripwire_name": "thumper-connection-test",
            "endpoint_hostname": "thumper-server",
            "message": "Thumper test event - your integration is wired up correctly.",
        })
