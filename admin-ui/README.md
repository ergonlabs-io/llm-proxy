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
Token, admin URL, and chain prefix persist to `localStorage`.

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
- The Overview tab lists every key (`GET /keys`, bearer-gated: id, tenant,
  revocation, budget) and every model pattern the config routes on
  (`GET /models`). Tenants still have no list endpoint: the Tenants tab is
  lookup-by-id plus create forms, and the Keys tab is mint/revoke/budget forms.
