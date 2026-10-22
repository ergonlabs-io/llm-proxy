// Pure helpers for the getting-started flow. Every input is an admin API
// response body; nothing here fetches, so each function is unit-tested.

/** One `GET /models` entry: a pattern routed on the model header. */
export interface ModelRow {
  model: string
  match: string
  route: string | null
  route_table: string
  target?: string | null
}

/** One `GET /models` path route: serves any model that reaches it. */
export interface PathRouteRow {
  path: string
  target: string | null
  route: string | null
  route_table: string
}

export interface Routing {
  models: ModelRow[]
  pathRoutes: PathRouteRow[]
}

export function parseRouting(bodyText: string): Routing | null {
  try {
    const v = JSON.parse(bodyText) as { models?: unknown; path_routes?: unknown }
    if (!Array.isArray(v.models)) return null
    return {
      models: v.models as ModelRow[],
      pathRoutes: Array.isArray(v.path_routes) ? (v.path_routes as PathRouteRow[]) : [],
    }
  } catch {
    return null
  }
}

/**
 * The model name to put in a sample request: the first exact pattern the
 * config routes on. A config that routes every model the same way names
 * none, so the caller shows a placeholder the user must replace.
 */
export function sampleModel(routing: Routing | null): string | null {
  const exact = routing?.models.find((m) => m.match === 'exact')
  return exact ? exact.model : null
}

interface ListenerDump {
  address?: string
  filter_chains?: { tls?: boolean }[]
}

/**
 * Base URLs a client can use, from `GET /config_dump` listeners. A wildcard
 * bind is reachable at the host the browser used to reach the admin port.
 */
export function proxyBaseUrls(configDumpText: string, browserHost: string): string[] {
  let listeners: ListenerDump[]
  try {
    const v = JSON.parse(configDumpText) as { listeners?: ListenerDump[] }
    listeners = Array.isArray(v.listeners) ? v.listeners : []
  } catch {
    return []
  }
  const urls: string[] = []
  for (const l of listeners) {
    if (!l.address) continue
    const idx = l.address.lastIndexOf(':')
    if (idx <= 0) continue
    let host = l.address.slice(0, idx)
    const port = l.address.slice(idx + 1)
    if (host === '0.0.0.0' || host === '[::]' || host === '::') host = browserHost
    const tls = (l.filter_chains ?? []).some((c) => c.tls === true)
    urls.push(`${tls ? 'https' : 'http'}://${host}:${port}`)
  }
  return urls
}

export type SnippetKind = 'curl' | 'python' | 'node'

/**
 * A first request with the key filled in. The key goes in the
 * Authorization header (or the SDK's api_key), never in the URL.
 */
export function firstRequestSnippet(
  kind: SnippetKind,
  baseUrl: string,
  key: string,
  model: string,
): string {
  const body = JSON.stringify({ model, messages: [{ role: 'user', content: 'Say hello' }] })
  switch (kind) {
    case 'curl':
      return [
        `curl --max-time 60 ${baseUrl}/v1/chat/completions \\`,
        `  -H "authorization: Bearer ${key}" \\`,
        `  -H "content-type: application/json" \\`,
        `  -d '${body}'`,
      ].join('\n')
    case 'python':
      return [
        'from openai import OpenAI',
        '',
        `client = OpenAI(base_url="${baseUrl}/v1", api_key="${key}")`,
        `reply = client.chat.completions.create(model="${model}", messages=[{"role": "user", "content": "Say hello"}])`,
        'print(reply.choices[0].message.content)',
      ].join('\n')
    case 'node':
      return [
        "import OpenAI from 'openai'",
        '',
        `const client = new OpenAI({ baseURL: '${baseUrl}/v1', apiKey: '${key}' })`,
        `const reply = await client.chat.completions.create({ model: '${model}', messages: [{ role: 'user', content: 'Say hello' }] })`,
        'console.log(reply.choices[0].message.content)',
      ].join('\n')
  }
}

/** Token totals from `envoy_llm_client_token_usage{provider,tenant,type}`. */
export interface UsageRow {
  tenant: string
  provider: string
  input: number
  output: number
  cached: number
}

const USAGE_LINE = /^envoy_llm_client_token_usage\{([^}]*)\}\s+([0-9.eE+-]+)\s*$/
const LABEL = /(\w+)="((?:[^"\\]|\\.)*)"/g

export function parseTokenUsage(prometheusText: string): UsageRow[] {
  const rows = new Map<string, UsageRow>()
  for (const line of prometheusText.split('\n')) {
    const m = USAGE_LINE.exec(line.trim())
    if (!m) continue
    const labels: Record<string, string> = {}
    for (const l of m[1].matchAll(LABEL)) labels[l[1]] = l[2]
    const value = Number(m[2])
    if (!Number.isFinite(value)) continue
    const tenant = labels.tenant ?? '-'
    const provider = labels.provider ?? '-'
    const k = `${tenant}\u0000${provider}`
    const row = rows.get(k) ?? { tenant, provider, input: 0, output: 0, cached: 0 }
    if (labels.type === 'input') row.input += value
    else if (labels.type === 'output') row.output += value
    else if (labels.type === 'cached') row.cached += value
    rows.set(k, row)
  }
  return [...rows.values()]
    .filter((r) => r.input + r.output + r.cached > 0)
    .sort((a, b) => b.input + b.output - (a.input + a.output))
}

export type StepState = 'done' | 'todo' | 'blocked' | 'unknown'

export interface Step {
  id: string
  title: string
  state: StepState
  detail: string
}

/** What the checklist knows; `null` means the read has not answered yet. */
export interface ChecklistInput {
  ready: { status: number; body: string } | null
  keys: { status: number; body: string } | null
  hasToken: boolean
  clusterCount: number | null
  routing: Routing | null
  pricingStatus: number | null
  tokensSeen: number | null
}

export function checklist(i: ChecklistInput): Step[] {
  const steps: Step[] = []

  const live = i.ready !== null && i.ready.status === 200 && i.ready.body.trim() === 'LIVE'
  steps.push({
    id: 'ready',
    title: 'Proxy is running',
    state: i.ready === null ? 'unknown' : live ? 'done' : 'blocked',
    detail: live
      ? 'The admin server answers and the proxy is ready for traffic.'
      : i.ready === null
        ? 'Checking...'
        : `The proxy is not ready yet (${i.ready.body.trim() || `HTTP ${i.ready.status}`}).`,
  })

  let tokenState: StepState
  let tokenDetail: string
  if (!i.hasToken) {
    tokenState = 'todo'
    tokenDetail =
      'Paste the admin token in the field at the top. `llm-proxy init` writes it to the admin-token file; the installer prints it.'
  } else if (i.keys === null) {
    tokenState = 'unknown'
    tokenDetail = 'Checking the token...'
  } else if (i.keys.status === 200) {
    tokenState = 'done'
    tokenDetail = 'The token is accepted. You can create tenants and keys.'
  } else if (i.keys.status === 403 && i.keys.body.includes('LLMPROXY_ADMIN_TOKEN is not set')) {
    tokenState = 'blocked'
    tokenDetail =
      'The proxy was started without LLMPROXY_ADMIN_TOKEN, so it refuses every change. Restart it with the variable set (for example LLMPROXY_ADMIN_TOKEN="$(cat admin-token)").'
  } else if (i.keys.status === 401) {
    tokenState = 'blocked'
    tokenDetail = 'The proxy rejected this token. Check that you pasted the whole value.'
  } else {
    tokenState = 'blocked'
    tokenDetail = `The key list answered HTTP ${i.keys.status}: ${i.keys.body.trim().slice(0, 200)}`
  }
  steps.push({ id: 'token', title: 'Admin token accepted', state: tokenState, detail: tokenDetail })

  const routed =
    i.routing !== null && (i.routing.models.length > 0 || i.routing.pathRoutes.length > 0)
  steps.push({
    id: 'provider',
    title: 'A provider and a route are configured',
    state:
      i.clusterCount === null || i.routing === null
        ? 'unknown'
        : i.clusterCount > 0 && routed
          ? 'done'
          : 'todo',
    detail:
      i.clusterCount !== null && i.clusterCount > 0 && routed
        ? 'See Routing below for which models go where. Providers are set in the config file, not here.'
        : 'Add a provider and a route in the config file (providers: and routes:), run `llm-proxy --config <file> --mode validate`, then restart or send SIGHUP.',
  })

  let keyCount: number | null = null
  if (i.keys?.status === 200) {
    try {
      const v = JSON.parse(i.keys.body) as { keys?: { revoked?: boolean }[] }
      keyCount = (v.keys ?? []).filter((k) => !k.revoked).length
    } catch {
      keyCount = null
    }
  }
  // Keys can only be listed with a working token; until then this step waits on the token step, not on a read.
  const keysUnreadable = tokenState !== 'done' && tokenState !== 'unknown'
  steps.push({
    id: 'key',
    title: 'A key for your app',
    state: keysUnreadable ? 'todo' : keyCount === null ? 'unknown' : keyCount > 0 ? 'done' : 'todo',
    detail: keysUnreadable
      ? 'Needs an accepted admin token first.'
      : keyCount !== null && keyCount > 0
        ? `${keyCount} active key${keyCount === 1 ? '' : 's'}. Create one key per app or person on the Keys page to see spend for each.`
        : 'Create a key on the Keys page. It is shown once, with a ready-to-run request.',
  })

  steps.push({
    id: 'pricing',
    title: 'Prices are set, so requests have a cost',
    state: i.pricingStatus === null ? 'unknown' : i.pricingStatus === 200 ? 'done' : 'todo',
    detail:
      i.pricingStatus === 200
        ? 'A rate card is active. Spend and budgets count real money.'
        : 'No rate card: every request costs $0 and spend limits never refuse. Add prices under Models & pricing.',
  })

  steps.push({
    id: 'first-request',
    title: 'First request went through',
    state: i.tokensSeen === null ? 'unknown' : i.tokensSeen > 0 ? 'done' : 'todo',
    detail:
      i.tokensSeen !== null && i.tokensSeen > 0
        ? `${i.tokensSeen} tokens metered so far. See Usage by tenant below.`
        : 'Run the request shown after you mint a key. This page updates when tokens are metered.',
  })

  return steps
}

/**
 * A rate-card skeleton for `PUT /pricing`, one entry per routed model and
 * one `providers` row per cluster. Provider types are left for the user:
 * they are not in any admin response, and guessing them from a cluster
 * name would price a request at another provider's rates.
 */
export function pricingTemplate(clusterNames: string[], models: string[], today: string): string {
  const providers: Record<string, string> = {}
  for (const c of clusterNames) providers[c] = 'PROVIDER_TYPE'
  const names = models.length > 0 ? models : ['MODEL_NAME']
  const entries = names.map((model) => ({
    provider_type: 'PROVIDER_TYPE',
    model,
    tier_mode: 'whole_request',
    tiers: [
      {
        input_nanodollars_per_token: 0,
        cached_input_nanodollars_per_token: 0,
        cache_write_nanodollars_per_token: 0,
        output_nanodollars_per_token: 0,
      },
    ],
  }))
  return JSON.stringify(
    { providers, price_list: { version: 'v1', effective_from: `${today}T00:00:00Z`, entries } },
    null,
    2,
  )
}

/** USD per 1M tokens to the integer nanodollars per token a rate card holds. */
export function usdPerMillionToNanodollars(usdPerMillion: number): number {
  return Math.round(usdPerMillion * 1000)
}

/**
 * Admin errors from the pricing parser name the internal carrier field
 * (`typed_config.inline_string`). Drop that prefix: the user wrote the JSON
 * in this page, not a typed config.
 */
export function friendlyPricingError(bodyText: string): string {
  return bodyText.replace(/^invalid value at `typed_config\.inline_string`:\s*/, '')
}
