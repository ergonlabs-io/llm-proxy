import { useEffect, useState } from 'react'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Table, THead, TRow, TH, TD } from './ui/table'
import { ResultPanel } from './forms'
import { apiFetch, type AdminConn, type ApiResult } from '../lib/api'
import type { AdminState } from '../lib/useAdminState'
import { parseTraceCounters, parseTraceGate, showFeature, type TraceGate } from '../lib/observability'

/** One tenant's opt-in, from `GET /tenants/{id}/trace_export`, or why it could not be read. */
type OptIn = { enabled: boolean } | { error: string }

/**
 * Per-tenant consent for the tenants the key list shows. A trace leaves the proxy only when export runs AND the
 * request's tenant opted in; an absent flag is not consent.
 */
function TenantOptIns({ conn, state }: { conn: AdminConn; state: AdminState }) {
  const tenants = [...new Set((state.keyRows ?? []).filter((k) => !k.revoked).map((k) => k.tenant))].sort()
  const [optIns, setOptIns] = useState<Record<string, OptIn>>({})
  const [result, setResult] = useState<ApiResult | null>(null)
  const [tick, setTick] = useState(0)
  const tenantList = tenants.join('\u0000')

  useEffect(() => {
    let active = true
    void Promise.all(
      tenants.map(async (t) => {
        const r = await apiFetch(conn, `/tenants/${encodeURIComponent(t)}/trace_export`, { auth: true })
        let value: OptIn = { error: r.bodyText.trim().slice(0, 120) || `HTTP ${r.status}` }
        if (r.ok) {
          try {
            value = { enabled: (JSON.parse(r.bodyText) as { enabled?: boolean }).enabled === true }
          } catch {
            value = { error: 'unreadable answer' }
          }
        }
        return [t, value] as const
      }),
    ).then((rows) => {
      if (active) setOptIns(Object.fromEntries(rows))
    })
    return () => {
      active = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [conn, tenantList, tick])

  async function set(tenant: string, enabled: boolean) {
    if (
      enabled &&
      !window.confirm(
        `Export traces for tenant "${tenant}"? Each trace carries the full request and response bodies to the collector.`,
      )
    )
      return
    const r = await apiFetch(conn, `/tenants/${encodeURIComponent(tenant)}/trace_export`, {
      method: 'PUT',
      auth: true,
      body: { schema_version: 1, enabled },
    })
    setResult(r.ok ? null : r)
    setTick((t) => t + 1)
  }

  if (tenants.length === 0) return <p className="text-xs text-zinc-500">No keys yet, so no tenant to opt in.</p>
  return (
    <div className="space-y-2">
      <Table>
        <THead>
          <TRow>
            <TH>Tenant</TH>
            <TH>Exports traces</TH>
            <TH> </TH>
          </TRow>
        </THead>
        <tbody>
          {tenants.map((t) => {
            const o = optIns[t]
            return (
              <TRow key={t}>
                <TD className="font-mono text-xs">{t}</TD>
                <TD className="text-xs">
                  {!o ? '...' : 'error' in o ? <span className="text-red-700">{o.error}</span> : o.enabled ? 'yes' : 'no'}
                </TD>
                <TD>
                  {o && !('error' in o) && (
                    <Button size="sm" variant="outline" onClick={() => void set(t, !o.enabled)}>
                      {o.enabled ? 'Opt out' : 'Opt in'}
                    </Button>
                  )}
                </TD>
              </TRow>
            )
          })}
        </tbody>
      </Table>
      {result && <ResultPanel result={result} />}
      <p className="text-xs text-zinc-500">
        With the in-memory store, opt-ins reset to off when the proxy restarts.
      </p>
    </div>
  )
}

/**
 * Body export ("traces"): its emergency switch (ADR-0008 decision 2), per-tenant consent and counters. The
 * bodies themselves go to segment files and S3; the admin API does not serve them, so neither does this page.
 */
export function Traces({ conn, state }: { conn: AdminConn; state: AdminState }) {
  const [gate, setGate] = useState<TraceGate | null>(null)
  const [result, setResult] = useState<ApiResult | null>(null)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    if (!showFeature(state.traces)) return
    let active = true
    void apiFetch(conn, '/traces/capture', { auth: true }).then((r) => {
      if (active) setGate(r.ok ? parseTraceGate(r.bodyText) : null)
    })
    return () => {
      active = false
    }
  }, [conn, state.traces, tick])

  async function toggle() {
    if (!gate) return
    const disable = !gate.disabled
    const question = disable
      ? 'Stop trace export now? No new trace leaves the proxy until you resume it. The stop survives a restart when the proxy can write its marker.'
      : 'Resume trace export? Traces, which can carry prompt and response bodies, are sent to the configured collector again.'
    if (!window.confirm(question)) return
    // Compare-and-set on the generation: if someone else changed the switch since this page read it, the server
    // answers 409 and nothing changes.
    const r = await apiFetch(conn, '/traces/capture', {
      method: 'POST',
      auth: true,
      body: { disabled: disable, expected_generation: gate.generation },
    })
    setResult(r)
    setTick((t) => t + 1)
  }

  return (
    <div className="space-y-4">
    <Card>
      <CardHeader>
        <CardTitle>Body export (traces)</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {(() => {
            const c = state.statsText ? parseTraceCounters(state.statsText) : null
            if (!c) return null
            return (
              <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-4">
                <dt className="text-zinc-500">Exporter</dt>
                <dd className={c.exporterUp ? 'text-green-700' : 'text-red-700'}>{c.exporterUp ? 'up' : 'down'}</dd>
                <dt className="text-zinc-500">Captured</dt>
                <dd>{c.captured}</dd>
                <dt className="text-zinc-500">Written</dt>
                <dd>{c.written}</dd>
                <dt className="text-zinc-500">Dropped</dt>
                <dd className={c.dropped > 0 ? 'text-amber-700' : ''}>{c.dropped}</dd>
                <dt className="text-zinc-500">On disk</dt>
                <dd>{(c.diskBytes / 1024).toFixed(1)} KiB</dd>
                <dt className="text-zinc-500">Segments uploaded</dt>
                <dd>{c.segmentsUploaded}</dd>
                <dt className="text-zinc-500">Segments lost</dt>
                <dd className={c.segmentsLost > 0 ? 'text-red-700' : ''}>{c.segmentsLost}</dd>
                <dt className="text-zinc-500">Upload failures</dt>
                <dd className={c.uploadFailures > 0 ? 'text-amber-700' : ''}>{c.uploadFailures}</dd>
              </dl>
            )
          })()}
          {gate ? (
            <div className="flex flex-wrap items-center gap-3">
              <Badge tone={gate.disabled ? 'red' : 'green'}>{gate.disabled ? 'stopped' : 'running'}</Badge>
              <Button size="sm" variant={gate.disabled ? 'default' : 'destructive'} onClick={() => void toggle()}>
                {gate.disabled ? 'Resume export' : 'Stop export'}
              </Button>
            </div>
          ) : (
            <p className="text-xs text-zinc-500">Reading the export status...</p>
          )}
          {result && !result.ok && <ResultPanel result={result} />}
          {result?.ok && (() => {
            try {
              const v = JSON.parse(result.bodyText) as { persisted?: boolean; disabled?: boolean }
              return v.disabled && v.persisted === false ? (
                <p className="text-xs text-amber-700">
                  Export is stopped, but the marker could not be written: a restart would resume it.
                </p>
              ) : null
            } catch {
              return null
            }
          })()}
          <p className="text-xs text-zinc-500">
            Each trace holds the raw request and response bodies of one request, written to compressed JSON-lines files
            in the <code className="font-mono">observability.traces</code> directory and uploaded to S3 when configured.
            Read them from there; the admin API does not serve them. A request is exported only when export runs and
            its tenant opted in below. Body export is for analytics, never billing: see Billing for charges.
          </p>
        </div>
      </CardContent>
    </Card>
    <Card>
      <CardHeader>
        <CardTitle>Tenants that export traces</CardTitle>
      </CardHeader>
      <CardContent>
        <TenantOptIns conn={conn} state={state} />
      </CardContent>
    </Card>
    </div>
  )
}
