// Pure helpers for the Billing (ledger) and Traces (export gate) pages.

/** Whether an optional admin feature is there to show, from its probe's answer. */
export type FeatureState = 'enabled' | 'not_configured' | 'needs_token' | 'error'

/**
 * `/ledger/*` and `/traces/capture` answer 404 with a "no ... is configured"
 * body when the config has no `ledger` or `observability.traces` block. Both
 * sit behind the admin gate, so without a token the UI cannot tell.
 */
export function featureState(status: number | null, body: string): FeatureState {
  if (status === null) return 'error'
  if (status === 200) return 'enabled'
  if (status === 404 && body.includes('is configured for this proxy')) return 'not_configured'
  if (status === 401 || status === 403) return 'needs_token'
  return 'error'
}

/**
 * The `after` cursor that reads the newest `count` committed entries. The
 * ledger pages forward from a cursor and keeps entries until a billing
 * consumer acknowledges them, so the newest are just below
 * `committed_through`. A cursor below the oldest kept entry reads from the
 * oldest.
 */
/**
 * Whether to show a feature's page. An error keeps it: the feature answered
 * before, or answers something other than "not configured", and a page that
 * vanishes under the user on one failed poll reads as data loss.
 */
export function showFeature(state: FeatureState | null): boolean {
  return state === 'enabled' || state === 'error'
}

export function newestWindowAfter(committedThrough: number, count: number): number {
  return Math.max(0, committedThrough - count)
}

export interface LedgerRow {
  cursor: number
  finishedAt: string
  tenant: string
  key: string | null
  requestedModel: string | null
  provider: string | null
  servedModel: string | null
  status: number | null
  termination: string
  inputTokens: number | null
  outputTokens: number | null
  chargedMicroUsd: number
  durationMs: number
  flags: string[]
  credentialSource: string | null
}

interface RawEntry {
  cursor: number
  charged_micro_usd?: number
  record?: {
    finished_at?: string
    tenant_id?: string
    key_id?: string | null
    requested_model?: string | null
    selected_provider?: string | null
    selected_cluster?: string | null
    selected_model?: string | null
    status?: number | null
    termination?: string
    duration_ms?: number
    response_flags?: string[]
    credential_source?: string | null
    usage?: { input_tokens?: number; output_tokens?: number } | null
  }
}

export interface LedgerPage {
  rows: LedgerRow[]
  committedThrough: number
}

/** Rows newest first. Unreadable bodies give `null`. */
export function parseLedgerPage(bodyText: string): LedgerPage | null {
  let v: { entries?: RawEntry[]; committed_through?: number }
  try {
    v = JSON.parse(bodyText)
  } catch {
    return null
  }
  if (!Array.isArray(v.entries) || typeof v.committed_through !== 'number') return null
  const rows = v.entries.map((e): LedgerRow => {
    const r = e.record ?? {}
    return {
      cursor: e.cursor,
      finishedAt: r.finished_at ?? '',
      tenant: r.tenant_id ?? '-',
      key: r.key_id ?? null,
      requestedModel: r.requested_model ?? null,
      provider: r.selected_provider ?? r.selected_cluster ?? null,
      servedModel: r.selected_model ?? null,
      status: r.status ?? null,
      termination: r.termination ?? 'unknown',
      inputTokens: r.usage?.input_tokens ?? null,
      outputTokens: r.usage?.output_tokens ?? null,
      chargedMicroUsd: e.charged_micro_usd ?? 0,
      durationMs: r.duration_ms ?? 0,
      flags: r.response_flags ?? [],
      credentialSource: r.credential_source ?? null,
    }
  })
  rows.sort((a, b) => b.cursor - a.cursor)
  return { rows, committedThrough: v.committed_through }
}

/** Micro-USD as dollars, without float drift for the amounts a ledger holds. */
export function microUsd(amount: number): string {
  const whole = Math.floor(amount / 1_000_000)
  const frac = String(amount % 1_000_000).padStart(6, '0')
  return `$${whole}.${frac}`
}

/** Body-export counters from `/stats/prometheus` (`envoy_llmproxy_trace_*`), summed over labels. */
export interface TraceCounters {
  captured: number
  written: number
  dropped: number
  segmentsUploaded: number
  segmentsLost: number
  uploadFailures: number
  diskBytes: number
  exporterUp: boolean
}

const TRACE_SERIES: Record<string, keyof Omit<TraceCounters, 'exporterUp'> | 'exporterUp'> = {
  envoy_llmproxy_trace_captured_total: 'captured',
  envoy_llmproxy_trace_written_total: 'written',
  envoy_llmproxy_trace_dropped_total: 'dropped',
  envoy_llmproxy_trace_segments_uploaded_total: 'segmentsUploaded',
  envoy_llmproxy_trace_segments_lost_total: 'segmentsLost',
  envoy_llmproxy_trace_upload_failures_total: 'uploadFailures',
  envoy_llmproxy_trace_disk_bytes: 'diskBytes',
  envoy_llmproxy_trace_exporter_up: 'exporterUp',
}

/** `null` when no body-export series is present (export not configured). */
export function parseTraceCounters(prometheusText: string): TraceCounters | null {
  const c: TraceCounters = {
    captured: 0,
    written: 0,
    dropped: 0,
    segmentsUploaded: 0,
    segmentsLost: 0,
    uploadFailures: 0,
    diskBytes: 0,
    exporterUp: false,
  }
  let seen = false
  for (const raw of prometheusText.split('\n')) {
    const m = /^([a-z_]+)(?:\{[^}]*\})?\s+([0-9.eE+-]+)\s*$/.exec(raw.trim())
    if (!m) continue
    const field = TRACE_SERIES[m[1]]
    if (!field) continue
    seen = true
    const value = Number(m[2])
    if (!Number.isFinite(value)) continue
    if (field === 'exporterUp') c.exporterUp = value === 1
    else c[field] += value
  }
  return seen ? c : null
}

export interface TraceGate {
  disabled: boolean
  generation: number
}

export function parseTraceGate(bodyText: string): TraceGate | null {
  try {
    const v = JSON.parse(bodyText) as Partial<TraceGate>
    return typeof v.disabled === 'boolean' && typeof v.generation === 'number'
      ? { disabled: v.disabled, generation: v.generation }
      : null
  } catch {
    return null
  }
}
