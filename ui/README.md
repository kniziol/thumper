# Thumper UI

Minimal React + Vite frontend for the Thumper honeytoken-tripwire monolith.

## Dev

```bash
npm install
npm run dev      # http://localhost:5173
```

## UI-first / mocked backend

During UI-first development the backend is **mocked in-browser** - there is no
server required. All data lives in [`src/api/mock.ts`](src/api/mock.ts), which
implements the same method signatures the real API will expose.

The single import point is [`src/api/index.ts`](src/api/index.ts):

```ts
export { mockApi as api, ... } from "./mock";
```

### Wiring the real backend

When `server/` (FastAPI) exists:

1. Write `src/api/http.ts` with a client whose method signatures match `mockApi`
   (`getStats`, `listTripwires`, `createTripwire`, `deployTripwire`,
   `listAlerts`, `listManifests`, `listIntegrations`, `saveIntegration`).
2. Change `src/api/index.ts` to export the http client instead of the mock.
3. The Vite dev proxy already forwards `/api` → `http://localhost:8000`
   (see [`vite.config.ts`](vite.config.ts)).

No page/component changes required - they only import from `src/api`.

## Pages

- **Dashboard** - stats, live alert banner, recent triggers, deployed tripwires.
- **Tripwires** - list + per-row deploy action.
- **Create tripwire** - 3-step: pick credential type → name & path → token preview.
- **Integrations** - deploy & alert plugins. Config forms are **rendered
  dynamically from each plugin's `config_schema`** (manifest), so new plugins
  get a UI with zero frontend changes.
