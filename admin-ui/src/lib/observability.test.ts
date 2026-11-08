import { describe, expect, it } from 'vitest'
import {
  featureState,
  microUsd,
  showFeature,
  newestWindowAfter,
  parseLedgerPage,
  parseTraceCounters,
  parseTraceGate,
  groupSpend,
  readLedgerSince,
  type FetchLedgerPage,
} from './observability'

// The 404 bodies the admin server sends when a block is absent from the config.
const NO_LEDGER =
  'no billing ledger is configured for this proxy; /ledger/* needs a `ledger` block (node.metadata["io.llmproxy.ledger"] in Envoy mode)'
const NO_TRACES =
  'no trace export is configured for this proxy; /traces/capture needs observability.traces (node.metadata["io.llmproxy.traces"] in Envoy mode)'

function entry(cursor: number, overrides: Record<string, unknown> = {}) {
  return {
    cursor,
    schema_version: 1,
    instance_id: 'node-a',
    epoch: 1,
    seq: cursor - 1,
    charged_micro_usd: 12,
    charged_scopes: [{ scope: 'key', id: 'support-bot', period: '2026-10-21' }],
    rate_card_version: 'v1+abc',
    policy_generation: 3,
    record: {
      finished_at: `2026-10-21T15:00:0${cursor}Z`,
      tenant_id: 'team',
      key_id: 'support-bot',
      requested_model: 'gpt-4o-mini',
      selected_cluster: 'provider:ollama',
      selected_provider: 'ollama',
      selected_model: 'gpt-4o-mini',
      status: 200,
      termination: 'complete',
      duration_ms: 7,
      response_flags: [],
      credential_source: 'platform',
      usage: { input_tokens: 10, output_tokens: 16, cache_read_tokens: 0, cache_write_tokens: 0 },
      ...overrides,
    },
  }
}

describe('featureState', () => {
  it('reads the not-configured 404 of either feature as absent, not as an error', () => {
    expect(featureState(404, NO_LEDGER)).toBe('not_configured')
    expect(featureState(404, NO_TRACES)).toBe('not_configured')
  })

  it('asks for a token when the gate refuses', () => {
    expect(featureState(401, 'missing or invalid bearer token')).toBe('needs_token')
    expect(featureState(403, 'admin write endpoints are disabled')).toBe('needs_token')
  })

  it('shows a page when enabled or failing, never when absent or locked', () => {
    expect(showFeature('enabled')).toBe(true)
    expect(showFeature('error')).toBe(true)
    expect(showFeature('not_configured')).toBe(false)
    expect(showFeature('needs_token')).toBe(false)
    expect(showFeature(null)).toBe(false)
  })

  it('keeps an unrelated 404 an error, so a wrong address is not hidden as "off"', () => {
    expect(featureState(404, "unknown admin endpoint '/ledger/entries'")).toBe('error')
    expect(featureState(200, '{}')).toBe('enabled')
  })
})

describe('ledger', () => {
  it('reads the newest window below committed_through', () => {
    expect(newestWindowAfter(250, 100)).toBe(150)
    expect(newestWindowAfter(3, 100)).toBe(0)
  })

  it('maps entries to rows, newest first', () => {
    const page = parseLedgerPage(
      JSON.stringify({ entries: [entry(1), entry(2)], next_after: 2, committed_through: 2, epochs: [] }),
    )
    expect(page?.committedThrough).toBe(2)
    expect(page?.rows.map((r) => r.cursor)).toEqual([2, 1])
    expect(page?.rows[0]).toMatchObject({
      tenant: 'team',
      key: 'support-bot',
      provider: 'ollama',
      status: 200,
      inputTokens: 10,
      outputTokens: 16,
      chargedMicroUsd: 12,
    })
  })

  it('keeps a request with no usage or status readable', () => {
    const page = parseLedgerPage(
      JSON.stringify({
        entries: [entry(1, { usage: null, status: null, termination: 'upstream_error', response_flags: ['UF'] })],
        committed_through: 1,
      }),
    )
    expect(page?.rows[0]).toMatchObject({ inputTokens: null, status: null, termination: 'upstream_error', flags: ['UF'] })
  })

  it('rejects a body that is not a ledger page', () => {
    expect(parseLedgerPage('{"entries":"x"}')).toBeNull()
    expect(parseLedgerPage('nope')).toBeNull()
  })

  it('formats micro-USD exactly', () => {
    expect(microUsd(12)).toBe('$0.000012')
    expect(microUsd(1_234_567)).toBe('$1.234567')
  })
})

describe('trace counters', () => {
  it('sums labelled series and reads the exporter gauge', () => {
    const text = [
      '# TYPE envoy_llmproxy_trace_dropped_total counter',
      'envoy_llmproxy_trace_captured_total 5',
      'envoy_llmproxy_trace_written_total{capture="complete"} 3',
      'envoy_llmproxy_trace_written_total{capture="partial"} 1',
      'envoy_llmproxy_trace_dropped_total{reason="queue_full"} 1',
      'envoy_llmproxy_trace_disk_bytes 2048',
      'envoy_llmproxy_trace_exporter_up 1',
      'envoy_llm_client_token_usage{provider="p",tenant="t",type="input"} 9',
    ].join('\n')
    expect(parseTraceCounters(text)).toMatchObject({
      captured: 5,
      written: 4,
      dropped: 1,
      diskBytes: 2048,
      exporterUp: true,
    })
  })

  it('reports no counters when export is not configured', () => {
    expect(parseTraceCounters('envoy_downstream_cx_total{listener="l"} 3')).toBeNull()
  })
})

describe('trace gate', () => {
  it('parses the gate status', () => {
    expect(parseTraceGate('{"disabled":false,"generation":0}')).toEqual({ disabled: false, generation: 0 })
    expect(parseTraceGate('{"disabled":"no"}')).toBeNull()
  })
})

describe('spend by model and key', () => {
  const page = (entries: ReturnType<typeof entry>[], through: number) =>
    parseLedgerPage(JSON.stringify({ entries, committed_through: through }))

  it('sums the ledger charge per tenant, key and requested model, largest first', () => {
    const rows = page(
      [
        entry(1, { key_id: 'a', requested_model: 'gpt-4o' }),
        entry(2, { key_id: 'a', requested_model: 'gpt-4o' }),
        entry(3, { key_id: 'b', requested_model: 'gpt-4o' }),
        { ...entry(4, { key_id: 'b', requested_model: 'mini', tenant_id: 'other' }), charged_micro_usd: 100 },
      ],
      4,
    )!.rows
    expect(groupSpend(rows)).toEqual([
      { tenant: 'other', key: 'b', model: 'mini', requests: 1, chargedMicroUsd: 100 },
      { tenant: 'team', key: 'a', model: 'gpt-4o', requests: 2, chargedMicroUsd: 24 },
      { tenant: 'team', key: 'b', model: 'gpt-4o', requests: 1, chargedMicroUsd: 12 },
    ])
  })

  it('does not merge groups whose fields only look alike when joined', () => {
    const rows = page(
      [entry(1, { key_id: 'a|b', requested_model: 'c' }), entry(2, { key_id: 'a', requested_model: 'b|c' })],
      2,
    )!.rows
    expect(groupSpend(rows)).toHaveLength(2)
  })

  // A ledger of 2500 entries, cursor n finished on day n of a fake clock.
  const day = 86_400_000
  const t0 = Date.parse('2026-01-01T00:00:00Z')
  const ledger = (total: number): FetchLedgerPage => async (after, limit) => {
    const entries = []
    for (let c = after + 1; c <= Math.min(total, after + limit); c++) {
      entries.push(entry(c, { finished_at: new Date(t0 + c * day / 100).toISOString() }))
    }
    return page(entries, total)
  }

  it('reads back to the window start and stops there', async () => {
    // Cursor c finished 0.01 day * c after t0, so a window from day 10 starts at cursor 1000.
    const inner = ledger(2500)
    const reads: number[] = []
    const got = await readLedgerSince(async (after, limit) => {
      reads.push(after)
      return inner(after, limit)
    }, t0 + 10 * day)
    // The head read, then the pages after 1500 and after 500; never the oldest page.
    expect(reads).toEqual([0, 1500, 500])
    // Entries older than day 10 (cursor < 1000) are dropped; the read stopped after the page holding them.
    expect(got?.truncated).toBe(false)
    expect(got?.rows.length).toBe(1501)
    expect(Math.min(...got!.rows.map((r) => r.cursor))).toBe(1000)
  })

  it('reports a partial read when the page cap cuts it off', async () => {
    const got = await readLedgerSince(ledger(2500), t0, 2)
    expect(got?.truncated).toBe(true)
    expect(got?.rows.length).toBe(2000)
  })

  it('fails the whole read when any page fails', async () => {
    const failing: FetchLedgerPage = async (_after, limit) => (limit === 1 ? page([], 2500) : null)
    expect(await readLedgerSince(failing, t0)).toBeNull()
  })
})
