import { describe, expect, it } from 'vitest'
import {
  checklist,
  firstRequestSnippet,
  friendlyPricingError,
  parseRouting,
  parseTokenUsage,
  pricingTemplate,
  proxyBaseUrls,
  sampleModel,
  usdPerMillionToNanodollars,
  type ChecklistInput,
} from './onboarding'

// Shapes copied from a starter-config proxy (`llm-proxy init`), not invented.
const STARTER_MODELS = JSON.stringify({
  header: 'x-llmproxy-model',
  models: [],
  path_routes: [{ path: 'prefix:/', target: 'provider:ollama', route: null, route_table: 'llmproxy_routes' }],
})

const STARTER_DUMP = JSON.stringify({
  listeners: [{ name: 'llmproxy_listener', address: '0.0.0.0:53421', filter_chains: [{ tls: false }] }],
})

const PROMETHEUS = [
  '# TYPE envoy_llm_client_token_usage counter',
  'envoy_llm_client_token_usage{provider="provider:ollama",tenant="-unauthenticated-",type="input"} 0',
  'envoy_llm_client_token_usage{provider="provider:ollama",tenant="acme",type="input"} 50',
  'envoy_llm_client_token_usage{provider="provider:ollama",tenant="acme",type="output"} 80',
  'envoy_llm_client_token_usage{provider="provider:ollama",tenant="acme",type="cached"} 0',
  'envoy_llm_client_token_usage{provider="provider:openai",tenant="default",type="output"} 3',
  'envoy_downstream_cx_total{listener="llmproxy_listener"} 11',
].join('\n')

function input(overrides: Partial<ChecklistInput>): ChecklistInput {
  return {
    ready: { status: 200, body: 'LIVE' },
    keys: { status: 200, body: JSON.stringify({ keys: [{ key_id: 'default-admin', revoked: false }] }) },
    hasToken: true,
    clusterCount: 1,
    routing: parseRouting(STARTER_MODELS),
    pricingStatus: 503,
    tokensSeen: 0,
    ...overrides,
  }
}

function state(steps: ReturnType<typeof checklist>, id: string) {
  return steps.find((s) => s.id === id)?.state
}

describe('routing', () => {
  it('counts a catch-all route as routing, so the starter config is not reported empty', () => {
    const routing = parseRouting(STARTER_MODELS)
    expect(routing?.pathRoutes[0].target).toBe('provider:ollama')
    expect(state(checklist(input({})), 'provider')).toBe('done')
  })

  it('reads a server without path_routes as having none', () => {
    const routing = parseRouting(JSON.stringify({ header: 'x', models: [] }))
    expect(routing).toEqual({ models: [], pathRoutes: [] })
    expect(state(checklist(input({ routing })), 'provider')).toBe('todo')
  })

  it('picks an exact model for samples and none for a catch-all', () => {
    expect(sampleModel(parseRouting(STARTER_MODELS))).toBeNull()
    const routing = parseRouting(
      JSON.stringify({
        models: [
          { model: 'claude-*', match: 'prefix', route: null, route_table: 't' },
          { model: 'gpt-4o-mini', match: 'exact', route: null, route_table: 't' },
        ],
      }),
    )
    expect(sampleModel(routing)).toBe('gpt-4o-mini')
  })
})

describe('proxyBaseUrls', () => {
  it('replaces a wildcard bind with the host the browser used', () => {
    expect(proxyBaseUrls(STARTER_DUMP, 'proxy.internal')).toEqual(['http://proxy.internal:53421'])
  })

  it('keeps a concrete address and uses https for a TLS listener', () => {
    const dump = JSON.stringify({
      listeners: [{ address: '10.0.0.5:8443', filter_chains: [{ tls: true }] }],
    })
    expect(proxyBaseUrls(dump, 'ignored')).toEqual(['https://10.0.0.5:8443'])
  })

  it('returns nothing for an unreadable dump', () => {
    expect(proxyBaseUrls('not json', 'h')).toEqual([])
  })
})

describe('firstRequestSnippet', () => {
  it('puts the key in a header, never in the URL', () => {
    const key = 'llmp_secretvalue'
    for (const kind of ['curl', 'python', 'node'] as const) {
      const text = firstRequestSnippet(kind, 'http://h:1', key, 'm')
      expect(text).toContain(key)
      const urls = text.match(/https?:\/\/\S+/g) ?? []
      expect(urls.length).toBeGreaterThan(0)
      for (const url of urls) expect(url).not.toContain(key)
    }
  })

  it('targets the OpenAI-compatible path', () => {
    expect(firstRequestSnippet('curl', 'http://h:1', 'k', 'gpt-4o-mini')).toContain(
      'http://h:1/v1/chat/completions',
    )
    expect(firstRequestSnippet('python', 'http://h:1', 'k', 'm')).toContain('base_url="http://h:1/v1"')
  })
})

describe('parseTokenUsage', () => {
  it('sums the token counters by tenant and provider and drops zero rows', () => {
    expect(parseTokenUsage(PROMETHEUS)).toEqual([
      { tenant: 'acme', provider: 'provider:ollama', input: 50, output: 80, cached: 0 },
      { tenant: 'default', provider: 'provider:openai', input: 0, output: 3, cached: 0 },
    ])
  })
})

describe('checklist', () => {
  it('tells a user without a token where to find it', () => {
    const steps = checklist(input({ hasToken: false, keys: null }))
    expect(state(steps, 'token')).toBe('todo')
    expect(steps.find((s) => s.id === 'token')?.detail).toContain('admin-token')
  })

  it('names the missing environment variable when the server has no token', () => {
    const steps = checklist(
      input({
        keys: {
          status: 403,
          body: 'admin write endpoints are disabled because LLMPROXY_ADMIN_TOKEN is not set',
        },
      }),
    )
    expect(state(steps, 'token')).toBe('blocked')
    expect(steps.find((s) => s.id === 'token')?.detail).toContain('Restart')
  })

  it('separates a wrong token from a missing one', () => {
    const steps = checklist(input({ keys: { status: 401, body: 'missing or invalid bearer token' } }))
    expect(steps.find((s) => s.id === 'token')?.detail).toContain('rejected')
  })

  it('marks pricing and the first request as open until they happen', () => {
    const before = checklist(input({}))
    expect(state(before, 'pricing')).toBe('todo')
    expect(state(before, 'first-request')).toBe('todo')
    const after = checklist(input({ pricingStatus: 200, tokensSeen: 26 }))
    expect(state(after, 'pricing')).toBe('done')
    expect(state(after, 'first-request')).toBe('done')
  })

  it('does not wait on the key list when the token is rejected', () => {
    const steps = checklist(input({ keys: { status: 401, body: 'missing or invalid bearer token' } }))
    expect(state(steps, 'key')).toBe('todo')
    expect(steps.find((s) => s.id === 'key')?.detail).toContain('admin token')
  })

  it('does not count revoked keys', () => {
    const keys = { status: 200, body: JSON.stringify({ keys: [{ key_id: 'k', revoked: true }] }) }
    expect(state(checklist(input({ keys })), 'key')).toBe('todo')
  })
})

describe('pricing helpers', () => {
  it('builds a template the server accepts in shape, with provider types left to fill in', () => {
    const card = JSON.parse(pricingTemplate(['provider:ollama'], ['gpt-4o-mini'], '2026-10-21'))
    expect(Object.keys(card).sort()).toEqual(['price_list', 'providers'])
    expect(card.providers).toEqual({ 'provider:ollama': 'PROVIDER_TYPE' })
    expect(card.price_list.effective_from).toBe('2026-10-21T00:00:00Z')
    expect(card.price_list.entries[0]).toMatchObject({ model: 'gpt-4o-mini', tier_mode: 'whole_request' })
  })

  it('converts USD per million tokens to nanodollars per token', () => {
    // gpt-4o-mini list price: $0.15 input, $0.60 output per 1M tokens.
    expect(usdPerMillionToNanodollars(0.15)).toBe(150)
    expect(usdPerMillionToNanodollars(0.6)).toBe(600)
  })

  it('drops the internal carrier path from parser errors', () => {
    expect(
      friendlyPricingError(
        'invalid value at `typed_config.inline_string`: pricing update is invalid JSON: missing field `providers`',
      ),
    ).toBe('pricing update is invalid JSON: missing field `providers`')
  })
})
