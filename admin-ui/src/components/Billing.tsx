import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Input } from './ui/input'
import { Table, THead, TRow, TH, TD } from './ui/table'
import { ResultPanel } from './forms'
import { apiFetch, type AdminConn, type ApiResult } from '../lib/api'
import type { AdminState } from '../lib/useAdminState'
import { microUsd, newestWindowAfter, parseLedgerPage, showFeature, type LedgerRow } from '../lib/observability'

const WINDOWS = [50, 200, 1000]

function statusTone(row: LedgerRow): 'green' | 'red' | 'amber' | 'default' {
  if (row.status === null) return 'amber'
  if (row.status < 400) return 'green'
  return row.status === 429 ? 'amber' : 'red'
}

/**
 * Recent requests from the billing ledger: one entry for every request
 * dialled to a provider. Read-only: this page never calls `/ledger/ack`,
 * which deletes entries and belongs to the billing consumer.
 */
export function Billing({ conn, state }: { conn: AdminConn; state: AdminState }) {
  const [count, setCount] = useState(WINDOWS[0])
  const [rows, setRows] = useState<LedgerRow[] | null>(null)
  const [error, setError] = useState<ApiResult | null>(null)
  const [filter, setFilter] = useState('')
  const [busy, setBusy] = useState(false)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    if (!showFeature(state.ledger)) return
    let active = true
    setBusy(true)
    void (async () => {
      // One read learns where the ledger ends; the second reads the newest window.
      const head = await apiFetch(conn, '/ledger/entries?limit=1', { auth: true })
      const headPage = head.ok ? parseLedgerPage(head.bodyText) : null
      if (!headPage) {
        if (active) {
          setError(head)
          setBusy(false)
        }
        return
      }
      const after = newestWindowAfter(headPage.committedThrough, count)
      const page = await apiFetch(conn, `/ledger/entries?after=${after}&limit=${count}`, { auth: true })
      if (!active) return
      const parsed = page.ok ? parseLedgerPage(page.bodyText) : null
      setRows(parsed ? parsed.rows : null)
      setError(parsed ? null : page)
      setBusy(false)
    })()
    return () => {
      active = false
    }
  }, [conn, state.ledger, state.tokensSeen, count, tick])

  const needle = filter.trim().toLowerCase()
  const shown = (rows ?? []).filter(
    (r) =>
      !needle ||
      [r.tenant, r.key, r.requestedModel, r.provider, r.servedModel, String(r.status)].some((v) =>
        (v ?? '').toLowerCase().includes(needle),
      ),
  )
  const total = shown.reduce((n, r) => n + r.chargedMicroUsd, 0)

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-2">
            <CardTitle>Recent requests (billing ledger)</CardTitle>
            <Button size="sm" variant="outline" onClick={() => setTick((t) => t + 1)} disabled={busy}>
              <RefreshCw size={14} /> Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <Input
              className="max-w-xs"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by key, tenant, model, provider or status"
              aria-label="Filter requests"
            />
            <select
              value={count}
              onChange={(e) => setCount(Number(e.target.value))}
              className="h-9 rounded-md border border-zinc-300 bg-white px-2 text-sm"
              aria-label="How many requests"
            >
              {WINDOWS.map((w) => (
                <option key={w} value={w}>
                  last {w}
                </option>
              ))}
            </select>
            <span className="text-xs text-zinc-600">
              {shown.length} request{shown.length === 1 ? '' : 's'}, {microUsd(total)} charged
            </span>
          </div>
          {error && <ResultPanel result={error} />}
          {rows && rows.length === 0 && (
            <p className="text-xs text-zinc-500">No entries yet. Each request sent to a provider adds one.</p>
          )}
          {shown.length > 0 && (
            <Table>
              <THead>
                <TRow>
                  <TH>Finished (UTC)</TH>
                  <TH>Key</TH>
                  <TH>Model</TH>
                  <TH>Provider</TH>
                  <TH>Status</TH>
                  <TH>Tokens in / out</TH>
                  <TH>Charged</TH>
                  <TH>ms</TH>
                </TRow>
              </THead>
              <tbody>
                {shown.map((r) => (
                  <TRow key={r.cursor}>
                    <TD className="whitespace-nowrap font-mono text-xs">{r.finishedAt.replace('T', ' ').slice(0, 19)}</TD>
                    <TD className="text-xs">
                      {r.key ?? '-'}
                      {r.tenant !== 'team' && <span className="block text-zinc-500">{r.tenant}</span>}
                    </TD>
                    <TD className="font-mono text-xs">
                      {r.requestedModel ?? '-'}
                      {r.servedModel && r.servedModel !== r.requestedModel && (
                        <span className="block text-zinc-500">served {r.servedModel}</span>
                      )}
                    </TD>
                    <TD className="text-xs">{r.provider ?? '-'}</TD>
                    <TD>
                      <Badge tone={statusTone(r)}>{r.status ?? r.termination}</Badge>
                      {r.flags.length > 0 && <span className="ml-1 font-mono text-[11px] text-zinc-500">{r.flags.join(',')}</span>}
                    </TD>
                    <TD className="text-xs">
                      {r.inputTokens ?? '-'} / {r.outputTokens ?? '-'}
                    </TD>
                    <TD className="text-xs">
                      {microUsd(r.chargedMicroUsd)}
                      {r.credentialSource === 'tenant' && <span className="block text-zinc-500">own key</span>}
                    </TD>
                    <TD className="text-xs">{r.durationMs}</TD>
                  </TRow>
                ))}
              </tbody>
            </Table>
          )}
          <p className="mt-3 text-xs text-zinc-500">
            The ledger holds one entry for every request sent to a provider, including ones charged $0. Requests the
            proxy refused before a provider (wrong key, model not allowed, spend limit) are not in it. Entries stay
            until your billing export acknowledges them; this page only reads.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
