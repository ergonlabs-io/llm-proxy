import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Table, THead, TRow, TH, TD } from './ui/table'
import { ResultPanel } from './forms'
import { apiFetch, type AdminConn, type ApiResult } from '../lib/api'
import {
  SPEND_DAYS,
  groupSpend,
  microUsd,
  parseLedgerPage,
  readLedgerSince,
  type LedgerWindow,
} from '../lib/observability'

/**
 * Billing-ledger spend for the last 30 days, grouped by tenant, key and
 * requested model. Grouped here from `/ledger/entries`, the same read the
 * request list uses, so it shows only what this token can already see. Read
 * only: it never calls `/ledger/ack`.
 */
export function SpendByModel({ conn, refreshKey }: { conn: AdminConn; refreshKey: unknown }) {
  const [window, setWindow] = useState<LedgerWindow | null>(null)
  const [error, setError] = useState<ApiResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    let active = true
    setBusy(true)
    void (async () => {
      let failure: ApiResult | null = null
      const since = Date.now() - SPEND_DAYS * 86_400_000
      const result = await readLedgerSince(async (after, limit) => {
        const r = await apiFetch(conn, `/ledger/entries?after=${after}&limit=${limit}`, { auth: true })
        const parsed = r.ok ? parseLedgerPage(r.bodyText) : null
        if (!parsed) failure = r
        return parsed
      }, since)
      if (!active) return
      setWindow(result)
      setError(result ? null : failure)
      setBusy(false)
    })()
    return () => {
      active = false
    }
  }, [conn, refreshKey, tick])

  const groups = groupSpend(window?.rows ?? [])
  const total = groups.reduce((n, g) => n + g.chargedMicroUsd, 0)

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-2">
          <CardTitle>Spend by model and key, last {SPEND_DAYS} days</CardTitle>
          <Button size="sm" variant="outline" onClick={() => setTick((t) => t + 1)} disabled={busy}>
            <RefreshCw size={14} /> Refresh
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {error && <ResultPanel result={error} />}
        {window && (
          <p className="mb-3 text-xs text-zinc-600">
            {window.rows.length} request{window.rows.length === 1 ? '' : 's'}, {microUsd(total)} charged
          </p>
        )}
        {window?.truncated && (
          <p className="mb-3 text-xs text-amber-700">
            The ledger holds more entries in this window than one load reads, so older requests are missing from
            these figures. Use the DuckDB recipe in the docs for the full window.
          </p>
        )}
        {window && groups.length === 0 && (
          <p className="text-xs text-zinc-500">No ledger entries in the last {SPEND_DAYS} days.</p>
        )}
        {groups.length > 0 && (
          <Table>
            <THead>
              <TRow>
                <TH>Tenant</TH>
                <TH>Key</TH>
                <TH>Model</TH>
                <TH>Requests</TH>
                <TH>Charged</TH>
              </TRow>
            </THead>
            <tbody>
              {groups.map((g) => (
                <TRow key={`${g.tenant}\u0000${g.key}\u0000${g.model}`}>
                  <TD className="text-xs">{g.tenant}</TD>
                  <TD className="text-xs">{g.key}</TD>
                  <TD className="font-mono text-xs">{g.model}</TD>
                  <TD className="text-xs">{g.requests}</TD>
                  <TD className="text-xs">{microUsd(g.chargedMicroUsd)}</TD>
                </TRow>
              ))}
            </tbody>
          </Table>
        )}
        <p className="mt-3 text-xs text-zinc-500">
          Grouped from the ledger entries this token can read. Entries the billing export has acknowledged are gone
          from the ledger and not counted here.
        </p>
      </CardContent>
    </Card>
  )
}
