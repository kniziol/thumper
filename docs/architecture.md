# Thumper architecture

One Docker image, three parts: a **UI**, a **FastAPI server** with two plugin
points, and an **endpoint agent + monitor** delivered by a deploy plugin.

## The model (definition → instance)

```
Tripwire (definition)   ──build install command──▶  [org's MDM / SSH / Ansible
  name, type, path,                                    pushes it to chosen devices]
  source                                                      │
                                                              ▼  each device:
Endpoint  ◀── self-enroll (shared enroll token) ──────────────┤  POST /api/enroll
   │                                                           │  GET  /api/agent/deployments
   └─ Deployment (UNIQUE content + UNIQUE hmac_secret) ◀───────┘  plant + watch (fs_usage)
                    │
                    └─ on read → HMAC-signed, enriched callback → Alert → SIEM/EDR/webhook
```

- **Tripwire** is a *definition* (a canary recipe). It lives on no machine.
- Deploying it mints one **Deployment** per endpoint - each with its **own**
  bait content and **own** HMAC secret. So a leak on one box can't forge another's
  triggers, and (later) a managed/BYO credential can be attributed to one box.
- The **org's MDM is the control plane** for *which* machines are in scope.
  Thumper provides the install command; it doesn't manage device groups.

## Components

### 1. UI (`ui/`)
React + Vite + TS. Talks only to the server via `src/api/http.ts`. Pages:
Dashboard, Tripwires (+ detail with the install command and per-endpoint
instances), Endpoints (+ detail), Create tripwire, Integrations (config forms
rendered from each plugin's manifest).

### 2. Server (`server/thumper/`)
FastAPI + stdlib `sqlite3` (no ORM).

| Module | Role |
| --- | --- |
| `api/routes.py` | All endpoints - JSON UI contract + plain-text agent protocol (enroll/pull/content + `/trigger`). |
| `db.py` / `store.py` | SQLite schema + repository functions (the **DB seam**, below). |
| `models.py` | Pydantic schemas - mirror `ui/src/api/types.ts`. |
| `tokens/` | Honeytoken generators + the recommended-path catalog. |
| `plugins/` | Framework: `base.py` (contract), `loader.py` (discovery). |
| `services/` | `deploy` (build/distribute install), `alerting` (fan-out), `signing` (HMAC), `content` (render bait per source), `integrations`. |

### 3. Endpoint agent + monitor (`agent/thumper_agent.sh`)
Delivered by a deploy plugin. Pure **Bash** (`curl` + `openssl`, POSIX `sh`) so
endpoints need no Python runtime. Enrolls, pulls its unique instances, plants
them, and watches. Read detection:
- **macOS**: `fs_usage` - real open/read events **with process + user**,
  pre-filtered with `grep` to just the bait paths (so the firehose is trimmed at
  the source, not in-process).
- **else**: `st_atime` poll fallback - best-effort only (many systems update
  atime lazily or not at all, so it can miss reads). `fs_usage` is the real sensor.

The agent never parses JSON: the agent-facing API speaks a plain-text protocol
(`key=value` for enroll/trigger, tab-separated records for the deployment list,
raw bytes for bait content), so enroll/pull/HMAC are all a few lines of shell.
HMAC is `openssl dgst -sha256 -hmac` over the exact callback body.

## The two things that must be right

### Trigger authentication (`POST /api/trigger`)
The callback is reachable by every endpoint, so it's effectively public.
- Each **deployment** has a unique `hmac_secret`, stored server-side, **never
  returned by the UI API** (only handed to that endpoint's agent via `/agent/deployments`).
- The agent signs the exact request body: `X-Thumper-Signature: sha256=<hmac>`.
- The server recomputes over the raw bytes and compares in constant time.
  Unknown deployment and bad signature both return `401`.
- Verified end-to-end, including that one endpoint's secret **cannot** forge
  another's trigger.

### macOS read-detection
`fs_usage` is the answer (Linux `auditd`/inotify `IN_ACCESS` is the follow-up).
It requires root - the agent runs as root under MDM. It also yields the process
and (via `ps`) the user, which enrich the alert. **Prototype on a real Mac before
locking the monitor.**

## Alert enrichment
`/trigger` accepts and stores: `accessed_path`, `process`, `pid`, `os_user`,
`event_type`, plus `timestamp` and a compact `triggered_by`. These flow to every
configured alert plugin (SIEM/EDR/webhook).

## Swapping the database
SQLite ships in the monolith with zero setup. Two seams, by how far you need to go:
- **Different file/location**: set `THUMPER_DB=/path/to/thumper.db`.
- **Different engine (Postgres/MySQL/…)**: all SQL is isolated in `db.py`
  (`connect`, schema) and `store.py` (every query). Reimplement those two modules
  against your engine - nothing else in the app writes SQL. The API/services deal
  only in plain rows returned by `store.py`.

## Plugins
See [plugins.md](plugins.md). Drop a directory under `plugins/{deploy,alert}/`,
get a config form and wiring for free.
