import { describe, expect, it } from 'vitest'
import {
  featureState,
  microUsd,
  showFeature,
  newestWindowAfter,
  parseLedgerPage,
  parseTraceCounters,
  parseTraceGate,
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
