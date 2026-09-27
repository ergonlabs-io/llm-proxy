import { useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { ResultPanel } from './forms'
import { apiFetch, type AdminConn, type ApiResult } from '../lib/api'

export function Overview({ conn }: { conn: AdminConn }) {
  const [ready, setReady] = useState<ApiResult | null>(null)
  const [info, setInfo] = useState<ApiResult | null>(null)
  const [stats, setStats] = useState<ApiResult | null>(null)
  const [statsKind, setStatsKind] = useState<'text' | 'prometheus'>('prometheus')
  const [busy, setBusy] = useState(false)

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
    </div>
  )
}
