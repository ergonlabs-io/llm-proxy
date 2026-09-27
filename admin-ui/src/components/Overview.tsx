import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { Table, THead, TRow, TH, TD } from './ui/table'
import { ResultPanel } from './forms'
import {
  apiFetch,
  scopedWritePath,
  type AdminConn,
  type ApiResult,
} from '../lib/api'

/** One row of `GET /keys`: identity, revocation, and the budget ceiling. */
interface KeyRow {
  key_id: string
  tenant: string
  revoked: boolean
  /** `null` is "no ceiling configured"; a zero ceiling is a real number. */
  budget: { max_micro_usd: number; max_usd: string; period: string } | null
}

/** One row of `GET /models`: a pattern the config routes on. */
interface ModelRow {
  model: string
  match: string
  route: string | null
  route_table: string
}

function budgetLabel(budget: KeyRow['budget']): string {
  if (!budget) return 'unlimited'
  return `$${budget.max_usd} / ${budget.period}`
}

function parseRows<T>(r: ApiResult, field: string): T[] | null {
  if (!r.ok) return null
  try {
    const parsed = JSON.parse(r.bodyText) as Record<string, unknown>
    const rows = parsed[field]
    return Array.isArray(rows) ? (rows as T[]) : null
  } catch {
    return null
  }
}

export function Overview({ conn }: { conn: AdminConn }) {
  const [ready, setReady] = useState<ApiResult | null>(null)
  const [info, setInfo] = useState<ApiResult | null>(null)
  const [stats, setStats] = useState<ApiResult | null>(null)
  const [statsKind, setStatsKind] = useState<'text' | 'prometheus'>('prometheus')
  const [busy, setBusy] = useState(false)

  const [keysRes, setKeysRes] = useState<ApiResult | null>(null)
  const [keyRows, setKeyRows] = useState<KeyRow[] | null>(null)
  const [keysBusy, setKeysBusy] = useState(false)

  const [modelsRes, setModelsRes] = useState<ApiResult | null>(null)
  const [modelRows, setModelRows] = useState<ModelRow[] | null>(null)
  const [modelHeader, setModelHeader] = useState('x-llmproxy-model')
  const [modelsBusy, setModelsBusy] = useState(false)

  const authed = !!conn.token
  const keysPath = scopedWritePath('/keys', conn.chainPrefix)

  async function refresh() {
    setBusy(true)
    try {
      const [r, i] = await Promise.all([
        apiFetch(conn, '/ready'),
        apiFetch(conn, '/server_info'),
      ])
      setReady(r)
      setInfo(i)
    } finally {
      setBusy(false)
    }
  }

  async function loadStats() {
    setStats(
      await apiFetch(conn, statsKind === 'prometheus' ? '/stats/prometheus' : '/stats'),
    )
  }

  async function loadKeys() {
    setKeysBusy(true)
    try {
      const r = await apiFetch(conn, keysPath, { auth: true })
      setKeysRes(r)
      setKeyRows(parseRows<KeyRow>(r, 'keys'))
    } finally {
      setKeysBusy(false)
    }
  }

  async function loadModels() {
    setModelsBusy(true)
    try {
      const r = await apiFetch(conn, '/models')
      setModelsRes(r)
      setModelRows(parseRows<ModelRow>(r, 'models'))
      if (r.ok) {
        try {
          const parsed = JSON.parse(r.bodyText) as { header?: string }
          if (parsed.header) setModelHeader(parsed.header)
        } catch {
          // keep the previous header
        }
      }
    } finally {
      setModelsBusy(false)
    }
  }

  // Models are ungated, so they load with the page. Keys are bearer-gated:
  // load as soon as a token exists, and drop the list when it is removed so a
  // stale inventory is never shown as if it were current.
  useEffect(() => {
    void loadModels()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  useEffect(() => {
    if (conn.token) {
      void loadKeys()
    } else {
      setKeysRes(null)
      setKeyRows(null)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [conn.token])

  const live = ready?.ok && ready.bodyText.trim() === 'LIVE'

  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Status</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="mb-3 flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={refresh} disabled={busy}>
              <RefreshCw size={14} /> {busy ? 'Loading...' : 'Refresh'}
            </Button>
            {ready && (
              <Badge tone={live ? 'green' : 'amber'}>
                {ready.bodyText.trim() || `(HTTP ${ready.status})`}
              </Badge>
            )}
          </div>
          <div className="space-y-3">
            <div>
              <p className="mb-1 text-xs font-medium text-zinc-500">GET /ready</p>
              <ResultPanel result={ready} />
            </div>
            <div>
              <p className="mb-1 text-xs font-medium text-zinc-500">GET /server_info</p>
              <ResultPanel result={info} />
            </div>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Stats viewer</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="mb-3 flex items-center gap-2">
            <select
              value={statsKind}
              onChange={(e) => setStatsKind(e.target.value as 'text' | 'prometheus')}
              className="h-8 rounded-md border border-zinc-300 bg-white px-2 text-sm"
            >
              <option value="prometheus">GET /stats/prometheus</option>
              <option value="text">GET /stats (404 when unwired)</option>
            </select>
            <Button size="sm" variant="outline" onClick={loadStats}>
              Load
            </Button>
          </div>
          <ResultPanel result={stats} />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Keys (GET /keys)</CardTitle>
            <Button size="sm" variant="outline" onClick={loadKeys} disabled={!authed || keysBusy}>
              <RefreshCw size={14} /> {keysBusy ? 'Loading...' : 'Refresh'}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {!authed ? (
            <p className="rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-800">
              The key inventory is bearer-gated — set the token in the header bar to load it.
            </p>
          ) : (
            <>
              {conn.chainPrefix.trim() && (
                <p className="mb-2 font-mono text-[11px] text-zinc-500">
                  reading {keysPath}
                </p>
              )}
              {keyRows ? (
                keyRows.length === 0 ? (
                  <p className="mb-3 text-xs text-zinc-500">No keys minted yet.</p>
                ) : (
                  <Table>
                    <THead>
                      <TRow>
                        <TH>Key id</TH>
                        <TH>Tenant</TH>
                        <TH>Status</TH>
                        <TH>Budget</TH>
                      </TRow>
                    </THead>
                    <tbody>
                      {keyRows.map((k) => (
                        <TRow key={`${k.tenant}/${k.key_id}`}>
                          <TD className="font-medium">{k.key_id}</TD>
                          <TD>{k.tenant}</TD>
                          <TD>
                            <Badge tone={k.revoked ? 'red' : 'green'}>
                              {k.revoked ? 'revoked' : 'active'}
                            </Badge>
                          </TD>
                          <TD>{budgetLabel(k.budget)}</TD>
                        </TRow>
                      ))}
                    </tbody>
                  </Table>
                )
              ) : (
                <p className="mb-3 text-xs text-zinc-500">No parsed key list yet.</p>
              )}
            </>
          )}
          <div className="mt-3">
            <ResultPanel result={keysRes} />
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Models (GET /models)</CardTitle>
            <Button size="sm" variant="outline" onClick={loadModels} disabled={modelsBusy}>
              <RefreshCw size={14} /> {modelsBusy ? 'Loading...' : 'Refresh'}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <p className="mb-2 text-xs text-zinc-500">
            Model patterns the loaded config routes on, matched on{' '}
            <code className="font-mono">{modelHeader}</code>.
          </p>
          {modelRows ? (
            modelRows.length === 0 ? (
              <p className="mb-3 text-xs text-zinc-500">
                No route matches on a model header.
              </p>
            ) : (
              <Table>
                <THead>
                  <TRow>
                    <TH>Model</TH>
                    <TH>Match</TH>
                    <TH>Route</TH>
                    <TH>Route table</TH>
                  </TRow>
                </THead>
                <tbody>
                  {modelRows.map((m) => (
                    <TRow key={`${m.route_table}/${m.route ?? ''}/${m.model}`}>
                      <TD className="font-medium">{m.model}</TD>
                      <TD>
                        <Badge tone={m.match === 'exact' ? 'green' : 'default'}>
                          {m.match}
                        </Badge>
                      </TD>
                      <TD>{m.route ?? '-'}</TD>
                      <TD>{m.route_table}</TD>
                    </TRow>
                  ))}
                </tbody>
              </Table>
            )
          ) : (
            <p className="mb-3 text-xs text-zinc-500">No parsed model list yet.</p>
          )}
          <div className="mt-3">
            <ResultPanel result={modelsRes} />
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
