---
title: Admin UI
description: "Serve the single-page admin console at /ui/, sign in with the admin token, and use its pages to check setup, create keys, and set prices."
summary: How to load the admin UI with LLMPROXY_ADMIN_UI_DIR, how to sign in
  with the admin token, and what each page does.
lastUpdated: 2026-10-25
related:
  - administration/admin-api
  - getting-started/quickstart
  - authentication/virtual-keys
  - limits-and-budgets/pricing-and-cost-tracking
  - help/limitations
---

The admin UI is a small web app that calls the
[Admin API](/docs/llm-proxy/administration/admin-api/). Use it to check your
setup, create and revoke keys, and set prices without curl commands. The admin
server serves the UI from memory at `/ui/`, on the same port as the API, so
no CORS setup is needed.

## At a glance

- **Default when unset:** the proxy loads the `admin-ui-dist` directory next
  to the binary, as the release archive unpacks it. With no such directory,
  `GET /ui` answers `404` with a hint.
- **How to turn on:** set the `admin` address in the config. Run the binary
  from the unpacked release archive, or set `LLMPROXY_ADMIN_UI_DIR`.
- **Failure mode:** a missing or broken UI directory logs a warning. The API
  keeps running.
- **Changes need a token:** the page loads without a token. Every change needs
  `LLMPROXY_ADMIN_TOKEN`.

## Serve the UI

The release archive holds the UI files in the `admin-ui-dist` directory. The
installer copies that directory to `~/.config/llm-proxy/admin-ui-dist`
(`/var/lib/llm-proxy/admin-ui-dist` when it runs as root). It also sets
`LLMPROXY_ADMIN_UI_DIR` in the service runner it writes.

If you run the binary from the directory where you unpacked the release
archive, the proxy finds `admin-ui-dist` next to it and you do not need
`LLMPROXY_ADMIN_UI_DIR`. Set the variable when the UI files are somewhere
else. It overrides the directory next to the binary.

To run the proxy with the installed copy, set both variables and start the proxy:

```sh
export LLMPROXY_ADMIN_TOKEN="$(cat admin-token)"
export LLMPROXY_ADMIN_UI_DIR="$HOME/.config/llm-proxy/admin-ui-dist"
llm-proxy --config llmproxy.yaml
```

The config needs the `admin` field. The starter config from `llm-proxy init`
sets `admin: 127.0.0.1:53422`.

Expected output: the proxy logs `admin UI: http://127.0.0.1:53422/ui/`. Open
that address in a browser. `GET /` on the admin address redirects to `/ui/`.

The proxy loads every file in the directory into memory at startup. The
directory must hold `index.html`. Restart the proxy after you change the files.

If you build from source, you need Node.js and npm:

```sh
make ui-install
make ui-build
export LLMPROXY_ADMIN_UI_DIR="$PWD/admin-ui/dist"
```

### If the UI does not load

| What you see | Cause | Fix |
|---|---|---|
| `GET /ui` answers `404` with `the admin UI is not loaded for this server instance ...` | `LLMPROXY_ADMIN_UI_DIR` is unset, empty, or the directory has no `index.html`. | Set the variable to the `admin-ui-dist` directory and restart. Check the startup log for `admin UI not loaded`. |
| The log line `LLMPROXY_ADMIN_TOKEN is not set: admin writes ... are refused with 403, in the admin UI too` | The proxy started without the token. | Restart with `LLMPROXY_ADMIN_TOKEN` set. |

## Sign in

The UI has no login page. Paste the admin token into the **Admin token**
field at the top of every page. `llm-proxy init` writes the token to the
`admin-token` file in the directory it creates. The installer prints the token
once for a new install, and keeps it in `service.env` as
`LLMPROXY_ADMIN_TOKEN`.

The token you paste must equal the value of `LLMPROXY_ADMIN_TOKEN` in the
proxy. The UI sends it as `Authorization: Bearer <token>` on gated calls. See
[Admin API](/docs/llm-proxy/administration/admin-api/#auth-model).

The UI applies the token about 0.6 seconds after you stop typing. The browser
keeps the token in `sessionStorage`. The token is gone when you
close the tab. The UI does not write it to `localStorage`.

**Caution.** The admin port uses plain HTTP. The admin token crosses the
network unencrypted if you bind the port to a non-loopback address. Keep the
port on loopback, or use a network you trust.

### Connection settings

The gear icon next to the token field shows two more fields. Leave both empty
when you use the UI from the admin port.

| Field | Use |
|---|---|
| Admin URL | The admin server to call. Empty means the server that served the page. Set it only when you run the UI with `npm run dev`. |
| Chain prefix | Not used with the `--config` dialect. Leave it empty. |

The browser keeps these two fields in `localStorage`.

## Pages

The UI has these pages, in this order: Get started, Keys, Models & pricing,
Billing, Traces, and Advanced. Billing and Traces show only when the
feature is configured (see below). The UI reads the admin API every 10
seconds.

### Get started

The page shows a checklist, a usage table, and the routing table.

| Step | Done when |
|---|---|
| Proxy is running | `GET /ready` answers `200` with `LIVE`. |
| Admin token accepted | `GET /keys` with your token answers `200`. |
| A provider and a route are configured | `GET /clusters` lists a provider, and `GET /models` lists a route. |
| A key for your app | The key list holds at least one key that is not revoked. |
| Prices are set, so requests have a cost | `GET /pricing` answers `200`. |
| First request went through | The Prometheus token counters show more than zero tokens. |

The title says how many steps are left. If the token step is blocked, its text
says why: the proxy has no `LLMPROXY_ADMIN_TOKEN` (`403`), or it rejected your
token (`401`).

The **Usage by tenant and provider** table sums input and output tokens from
`GET /stats/prometheus`. The counts start at zero when the proxy starts.

The **Routing** table shows which models go to which provider. It is read
only. You set providers and routes in the config file.

### Keys

- **Create a key.** Enter a name, then select **Create key**. The name becomes
  the `key_id`. The key goes in the `team` tenant. To use another tenant,
  select **Show advanced options**. The admin API reserves the `default`
  tenant, so the UI cannot create keys there.
- **Limits at creation.** You can set a spend limit in USD per day or per
  month, and a list of models for the key. The UI sends each limit after it
  creates the key. If a limit fails, the key still exists and the page shows
  the error.
- **The new key.** A dialog shows the key text once, with a copy button. The
  proxy cannot show it again. The dialog also builds a first request in
  curl, Python, or Node. You can change the proxy address and the model.
- **Key list.** The table shows each key with its models, its spend limit, and
  the spend in the current period. Spend comes from
  `GET /keys/{id}/spend`. Unpriced requests show as a count.
- **Limits.** Select **Limits** on a key to change its spend limit and its
  model list. An empty spend limit clears the budget. An empty model list sets
  the policy to all models that the tenant allows.
- **Revoke.** Select **Revoke** and confirm. Requests with that key fail at
  once. You cannot undo it.

The UI does not set rate limits, chargeback tags, or BYOK options for a key.
Use the [Admin API](/docs/llm-proxy/administration/admin-api/) for those.

### Models & pricing

- **Routing.** The same read-only table as on Get started.
- **Models your keys may use.** Sets the model allow-list of the `team`
  tenant and of the `default` tenant. The `default` tenant holds the key that
  `llm-proxy init` creates. Choose all models, or list models separated by
  commas. A trailing `*` matches a prefix. The UI creates the `team` tenant if
  it does not exist. The form does not show the current value, because the
  proxy has no read for tenant policies.
- **Prices.** A table of the active rate card, in USD per 1M tokens. If no
  rate card is active, the page warns that every request costs $0 and spend
  limits never refuse.
- **Edit prices.** A JSON editor for the rate card. It starts with the active
  card. **Insert template for configured providers** adds a skeleton. Replace
  every `PROVIDER_TYPE` and `MODEL_NAME` placeholder before you save. The
  converter turns a price in USD per 1M tokens into nanodollars per token.
  **Save prices** sends `PUT /pricing`.
- **Public price catalog.** Appears if the active card holds a catalog. You can
  search it. It is a reference and does not set cost.

Prices that you save in the UI live in the proxy store. With the `in_memory`
store they are lost on restart. To keep them, put the `price_list` under
`pricing` in the config file, or use a `persistent` or `shared` `auth.store`.
See [Pricing and cost tracking](/docs/llm-proxy/limits-and-budgets/pricing-and-cost-tracking/).

### Billing

The Billing page appears only when the config has a `ledger` block. The UI
checks with `GET /ledger/entries?limit=1`. A `404` that says no ledger is
configured hides the page. Without a valid admin token the UI cannot tell,
so the page stays hidden.

The page lists the newest ledger entries: the last 50, 200, or 1000. Each
row shows the finish time (UTC), the key and tenant, the requested model (and
the served model if it differs), the provider, the status, the input and
output tokens, the amount charged, and the duration. A filter box matches
key, tenant, model, provider, or status. The header shows the count and the
sum charged.

The page only reads. It never calls `POST /ledger/ack`, so it never removes
entries. Entries stay until your billing export acknowledges them. A request
that the proxy refuses before a provider is not in the ledger. See
[Billing ledger](/docs/llm-proxy/limits-and-budgets/billing-ledger/).

### Traces

The Traces page appears only when the config has `observability.traces`. The
UI checks with `GET /traces/capture`. It shows these items:

- **Counters.** The exporter state (up or down), and the counts for captured,
  written, dropped, bytes on disk, segments uploaded, segments lost, and
  upload failures. They come from `GET /stats/prometheus`.
- **Emergency switch.** The state, `running` or `stopped`, and a button to
  stop or resume export. The UI asks you to confirm. It sends the switch
  generation it read, so a stale page gets `409` and changes nothing. If the
  stop marker cannot be written, the page warns that a restart would resume
  export.
- **Tenants that export traces.** One row for each tenant that has an active
  key. **Opt in** and **Opt out** call `PUT /tenants/{id}/trace_export`. The
  UI asks you to confirm an opt-in, because a trace holds the full request and
  response bodies. With the `in_memory` store, opt-ins reset when the proxy
  restarts.

The page does not show trace bodies. Read them from the trace directory or the
bucket. See
[Request and response body export](/docs/llm-proxy/observability/trace-export/).

### Advanced

Advanced has three sections. Each section keeps its state while you switch.

| Section | What it does | API calls |
|---|---|---|
| Tenants | Creates a tenant, deletes a tenant, sets its model list, sets or clears its spend limit, and shows its spend. All actions use the tenant id field at the top of the section. | `POST /tenants`, `DELETE /tenants/{id}`, `PUT /tenants/{id}/policy`, `PUT /tenants/{id}/budget`, `GET /tenants/{id}/spend` |
| Clusters and config | Lists the providers with discovery, load-balancing policy, timeout, protocol, and endpoints. Loads the full config dump. | `GET /clusters`, `GET /config_dump` |
| Status and stats | Shows readiness and server info, a stats viewer (Prometheus or plain text), the key list, and the model patterns that the config routes on. | `GET /ready`, `GET /server_info`, `GET /stats/prometheus`, `GET /stats`, `GET /keys`, `GET /models` |

Deleting a tenant revokes every key of the tenant. The UI asks you to confirm.
The responses in Advanced show as raw JSON.

## Limitations

- The UI has the pages above. It has no page for access logs or request
  records. The Billing page is read only, and the Traces page does not show
  bodies.
- The UI does not manage tenant provider credentials, rate limits, chargeback
  tags, object ownership, or the lifecycle commands. Use the
  [Admin API](/docs/llm-proxy/administration/admin-api/).
- There is no login, session, or role model. One token has full admin rights.
- You cannot change providers or routes in the UI. Edit the config file and
  reload the proxy.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Develop the UI

```sh
make ui-dev
```

The dev server listens on `http://localhost:5173`. Set the Admin URL field to
your admin address, or set `VITE_ADMIN_URL` before you start it. The dev
server does not serve the admin API.
