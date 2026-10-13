import { Fragment, useCallback, useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { Input } from './ui/input'
import { Table, THead, TRow, TH, TD } from './ui/table'
import { apiFetch, type AdminConn, type ApiResult } from '../lib/api'

const PAGE = 50
const REFRESH_MS = 10_000

interface SpoolStats {
  node_id: string
  next_sequence: number
  durable_through_sequence: number
  acknowledged_through_sequence: number
  pending_records: number
  retained_records: number
  database_bytes: number
  disk_bytes: number
  max_disk_bytes: number
  quarantine_bytes: number
  poisoned: boolean
  durable_total: number
  rejected_total: number
  failures_total: number
}

/** Loosely typed: every field except `sequence` may be null or absent. */
type RequestRecord = Record<string, unknown>

interface SpoolRow {
  sequence: number
  record: RequestRecord
}

interface RecordsPage {
  records: SpoolRow[]
  next_after_sequence: number
  durable_through_sequence: number
}

export function formatBytes(n: number): string {
  if (!Number.isFinite(n)) return '-'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let v = n
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`
}

function errorMessage(r: ApiResult): string {
  try {
    const e = (JSON.parse(r.bodyText) as { error?: unknown }).error
    if (typeof e === 'string') return e
  } catch {
    // fall through to the raw body
  }
  return r.bodyText || `HTTP ${r.status}`
}

function str(v: unknown): string {
  return typeof v === 'string' && v ? v : '-'
}

function asObject(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null
}

/** Total tokens from a record's `usage` (input, output, and cache counts). */
function tokensOf(usage: unknown): string {
  const u = asObject(usage)
  if (!u) return '-'
  const parts = ['input_tokens', 'output_tokens', 'cache_read_tokens', 'cache_write_tokens']
    .map((k) => u[k])
    .filter((x): x is number => typeof x === 'number')
  return parts.length ? String(parts.reduce((a, b) => a + b, 0)) : '-'
}

/** A record's `cost` is `{amount, unit, currency}`; the proxy emits nanodollars. */
function costOf(cost: unknown): string {
  const c = asObject(cost)
  if (!c || typeof c.amount !== 'number') return '-'
  const currency = typeof c.currency === 'string' ? c.currency : ''
  if (c.unit === 'nanodollars') return `$${(c.amount / 1e9).toFixed(6)}`
  return `${c.amount} ${typeof c.unit === 'string' ? c.unit : ''} ${currency}`.trim()
}

function localTime(v: unknown): string {
  if (typeof v !== 'string' || !v) return '-'
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? v : d.toLocaleString()
}

function modelLabel(r: RequestRecord): string {
  const req = str(r.requested_model)
  const target = [r.selected_provider, r.selected_model]
    .filter((x): x is string => typeof x === 'string' && !!x)
    .join('/')
  return target ? `${req} → ${target}` : req
}

function statusTone(s: unknown): 'green' | 'amber' | 'red' | 'default' {
  if (typeof s !== 'number') return 'default'
  if (s >= 500) return 'red'
  if (s >= 400) return 'amber'
  return 'green'
}

function matches(row: SpoolRow, needle: string): boolean {
  const n = needle.trim().toLowerCase()
  if (!n) return true
  const r = row.record
  return [r.tenant_id, r.user_id, r.requested_model, r.selected_model, r.request_id].some(
    (v) => typeof v === 'string' && v.toLowerCase().includes(n),
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs text-zinc-500">{label}</p>
      <p className="font-mono text-sm font-medium">{value}</p>
    </div>
  )
}

export function Capture({ conn }: { conn: AdminConn }) {
  const [statsRes, setStatsRes] = useState<ApiResult | null>(null)
  const [stats, setStats] = useState<SpoolStats | null>(null)
  const [statsBusy, setStatsBusy] = useState(false)

  const [rows, setRows] = useState<SpoolRow[]>([])
  const [cursor, setCursor] = useState<number | null>(null)
  const [recErr, setRecErr] = useState<ApiResult | null>(null)
  const [recBusy, setRecBusy] = useState(false)
  const [expanded, setExpanded] = useState<number | null>(null)
  const [filter, setFilter] = useState('')

  const needsAdminUrl = import.meta.env.DEV && !conn.adminUrl.trim()

  const refreshStats = useCallback(async () => {
    setStatsBusy(true)
    try {
      const r = await apiFetch(conn, '/capture/spool/stats')
      setStatsRes(r)
      if (r.ok) {
        try {
          setStats(JSON.parse(r.bodyText) as SpoolStats)
        } catch {
          setStats(null)
        }
      } else {
        setStats(null)
      }
    } finally {
      setStatsBusy(false)
    }
  }, [conn])

  // Poll while the tab is visible; also refresh at once when it becomes visible.
  useEffect(() => {
    if (needsAdminUrl) return
    void refreshStats()
    const tick = () => {
      if (document.visibilityState === 'visible') void refreshStats()
    }
    const id = window.setInterval(tick, REFRESH_MS)
    document.addEventListener('visibilitychange', tick)
    return () => {
      window.clearInterval(id)
      document.removeEventListener('visibilitychange', tick)
    }
  }, [refreshStats, needsAdminUrl])

  async function fetchPage(after: number, append: boolean) {
    setRecBusy(true)
    try {
      const r = await apiFetch(
        conn,
        `/capture/spool/records?after=${after}&limit=${PAGE}`,
        { auth: true },
      )
      if (!r.ok) {
        setRecErr(r)
        return
      }
      setRecErr(null)
      const page = JSON.parse(r.bodyText) as RecordsPage
      setRows((prev) => (append ? [...prev, ...page.records] : page.records))
      setCursor(page.next_after_sequence)
    } catch (e) {
      setRecErr({ ok: false, status: 0, bodyText: `bad response: ${String(e)}` })
    } finally {
      setRecBusy(false)
    }
  }

  function recordsHint(r: ApiResult): string {
    switch (r.status) {
      case 401:
        return 'Bearer token needed (missing or invalid) — set it in the header bar.'
      case 403:
        return 'The agent grant needs "inspect": true to read records.'
      case 404:
        return 'Capture agent not configured.'
      case 503:
        return `Capture agent unreachable: ${errorMessage(r)}`
      default:
        return `HTTP ${r.status}: ${errorMessage(r)}`
    }
  }

  const visible = rows.filter((r) => matches(r, filter))
  const diskPct =
    stats && stats.max_disk_bytes > 0
      ? Math.min(100, (stats.disk_bytes / stats.max_disk_bytes) * 100)
      : null

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Capture spool (GET /capture/spool/stats)</CardTitle>
            <Button
              size="sm"
              variant="outline"
              onClick={() => void refreshStats()}
              disabled={statsBusy || needsAdminUrl}
            >
              <RefreshCw size={14} /> {statsBusy ? 'Loading...' : 'Refresh'}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {needsAdminUrl && (
            <p className="rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-800">
              Set an Admin URL in the header to query a running admin server while using Vite.
            </p>
          )}
          {statsRes?.status === 404 && (
            <p className="text-sm text-zinc-500">Capture agent not configured.</p>
          )}
          {statsRes && statsRes.status !== 404 && !statsRes.ok && (
            <p className="rounded-md bg-red-50 px-3 py-2 text-xs text-red-800">
              {statsRes.status === 503
                ? `Capture agent unreachable: ${errorMessage(statsRes)}`
                : `HTTP ${statsRes.status}: ${errorMessage(statsRes)}`}
            </p>
          )}
          {stats && (
            <div className="space-y-4">
              {stats.poisoned && (
                <p className="rounded-md bg-red-600 px-3 py-2 text-sm font-bold text-white">
                  SPOOL POISONED
                </p>
              )}
              <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                <Stat label="retained records" value={String(stats.retained_records)} />
                <Stat label="pending records" value={String(stats.pending_records)} />
                <Stat label="quarantine" value={formatBytes(stats.quarantine_bytes)} />
                <Stat label="node id" value={stats.node_id} />
                <Stat label="durable through" value={String(stats.durable_through_sequence)} />
                <Stat label="acknowledged through" value={String(stats.acknowledged_through_sequence)} />
                <Stat label="next sequence" value={String(stats.next_sequence)} />
                <Stat label="database" value={formatBytes(stats.database_bytes)} />
              </div>
              <div>
                <p className="mb-1 text-xs text-zinc-500">
                  Disk: {formatBytes(stats.disk_bytes)} of {formatBytes(stats.max_disk_bytes)}
                  {diskPct !== null && ` (${diskPct.toFixed(1)}%)`}
                </p>
                <div className="h-2 overflow-hidden rounded-full bg-zinc-100">
                  <div
                    className={`h-full ${diskPct !== null && diskPct >= 90 ? 'bg-red-500' : 'bg-zinc-700'}`}
                    style={{ width: `${diskPct ?? 0}%` }}
                  />
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <Badge tone="green">durable {stats.durable_total}</Badge>
                <Badge tone={stats.rejected_total > 0 ? 'amber' : 'default'}>
                  rejected {stats.rejected_total}
                </Badge>
                <Badge tone={stats.failures_total > 0 ? 'red' : 'default'}>
                  failures {stats.failures_total}
                </Badge>
                <Badge tone={stats.poisoned ? 'red' : 'green'}>
                  {stats.poisoned ? 'poisoned' : 'healthy'}
                </Badge>
              </div>
              {stats.acknowledged_through_sequence === 0 && stats.retained_records > 0 && (
                <p className="text-xs text-zinc-500">
                  No reader acknowledges records yet; the spool only grows until a delivery path exists.
                </p>
              )}
              <p className="text-[11px] text-zinc-400">Auto-refreshes every 10 s while this tab is visible.</p>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Records (GET /capture/spool/records)</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <Button size="sm" onClick={() => void fetchPage(0, false)} disabled={recBusy || needsAdminUrl}>
              {recBusy ? 'Loading...' : 'Load records'}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                void fetchPage(Math.max(0, (stats?.durable_through_sequence ?? 0) - PAGE), false)
              }
              disabled={recBusy || needsAdminUrl || !stats}
              title="Start at durable_through_sequence - 50"
            >
              Jump to latest
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => cursor !== null && void fetchPage(cursor, true)}
              disabled={recBusy || needsAdminUrl || cursor === null}
            >
              Load more
            </Button>
            <Input
              className="max-w-xs"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="filter loaded: tenant, user, model, request id"
            />
            <span className="text-xs text-zinc-500">
              {visible.length} of {rows.length} loaded
            </span>
          </div>
          {!conn.token && (
            <p className="mb-3 rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-800">
              Reading records needs a bearer token — set it in the header bar.
            </p>
          )}
          {recErr && (
            <p className="mb-3 rounded-md bg-red-50 px-3 py-2 text-xs text-red-800">
              {recordsHint(recErr)}
            </p>
          )}
          {rows.length > 0 && (
            <Table>
              <THead>
                <TRow>
                  <TH>Seq</TH>
                  <TH>Finished</TH>
                  <TH>Tenant</TH>
                  <TH>User</TH>
                  <TH>Model</TH>
                  <TH>Status</TH>
                  <TH>ms</TH>
                  <TH>Tokens</TH>
                  <TH>Cost</TH>
                </TRow>
              </THead>
              <tbody>
                {visible.map((row) => {
                  const r = row.record
                  const open = expanded === row.sequence
                  return (
                    <Fragment key={row.sequence}>
                      <tr
                        className="cursor-pointer border-t border-zinc-100 hover:bg-zinc-50"
                        onClick={() => setExpanded(open ? null : row.sequence)}
                      >
                        <TD className="font-mono">{row.sequence}</TD>
                        <TD>{localTime(r.finished_at)}</TD>
                        <TD>{str(r.tenant_id)}</TD>
                        <TD>{str(r.user_id)}</TD>
                        <TD>{modelLabel(r)}</TD>
                        <TD>
                          <Badge tone={statusTone(r.status)}>
                            {typeof r.status === 'number' ? r.status : '-'}
                          </Badge>
                        </TD>
                        <TD>{typeof r.duration_ms === 'number' ? r.duration_ms : '-'}</TD>
                        <TD>{tokensOf(r.usage)}</TD>
                        <TD>{costOf(r.cost)}</TD>
                      </tr>
                      {open && (
                        <tr className="border-t border-zinc-100 bg-zinc-50">
                          <td colSpan={9} className="px-3 py-2">
                            <pre className="max-h-96 overflow-auto text-xs">
                              {JSON.stringify(r, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
