# llm-proxy admin UI

Minimal single-page admin UI for the llm-proxy admin API. Served from `/ui/` by the
Rust admin server; all fetches are same-origin relative URLs.

## Dev (component work)

```sh
npm install
npm run dev
```

`npm run dev` serves the UI on `:5173`. The admin API lives on the Rust server, so
either:

- set the **Admin URL** field in the header bar (e.g. `http://localhost:8080`), or
- set `VITE_ADMIN_URL` before starting:

```sh
VITE_ADMIN_URL=http://localhost:8080 npm run dev
```

The header-bar `Admin URL` value takes precedence when set; empty means same-origin.
The admin URL and chain prefix persist to `localStorage`. The token is kept in
`sessionStorage` only, so it is cleared when the tab closes and is never written
to `localStorage`.

## Build

```sh
npm install
npm run build
```

`vite build` outputs to `dist/` with `base: '/ui/'`.

## Notes

- Auth: `Authorization: Bearer <token>` is sent on all write endpoints and on
  `GET /tenants/{id}/spend` / `GET /keys/{id}/spend` / `GET /keys` (the key
  inventory). `GET /models` needs no token.
- Chain prefix: when set, write paths are prefixed as `/chains/{prefix}/…`,
  as is the Overview's `GET /keys` read. Unscoped by default.
- Request bodies send exactly the documented fields (the server rejects unknown
  fields). The minted key plaintext is shown once in a dialog with a copy button.
- Pages: **Get started** (a checklist built from `/ready`, `GET /keys`, `/clusters`,
  `/models`, `/pricing` and the token counters in `/stats/prometheus`), **Keys**
  (list, create with optional limits, edit limits, revoke), **Models & pricing**
  (routing from `/models`, the team's model allow-list, the rate card), and
  **Advanced** (tenants, clusters and config dump, raw status and stats).
- The Keys page creates keys in the `team` tenant: the admin API reserves
  `default`. The team model allow-list is written to both `team` and `default`
  (the tenant of the key `llm-proxy init` configures).
- Every page stays mounted, so switching pages keeps form input.

## Tests

```sh
npm test
```

Pure logic lives in `src/lib/onboarding.ts` and is unit-tested with vitest
(`src/lib/onboarding.test.ts`). The tests use response bodies captured from a
starter-config proxy.
