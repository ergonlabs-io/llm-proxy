import { useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Table, THead, TRow, TH, TD } from './ui/table'
import { ResultPanel } from './forms'
import { apiFetch, type AdminConn, type ApiResult } from '../lib/api'

interface Endpoint {
  host: string
  port: number
  weight?: number
  priority?: number
  hostname?: string
  health_flags?: unknown
  metadata?: unknown
}

interface Cluster {
  name: string
  discovery?: string
  lb_policy?: string
  connect_timeout_ms?: number
  upstream_protocol?: string
  tls?: unknown
  endpoints?: Endpoint[]
  initialized?: boolean
  circuit_breakers?: unknown
}

export function Clusters({ conn }: { conn: AdminConn }) {
  const [result, setResult] = useState<ApiResult | null>(null)
  const [clusters, setClusters] = useState<Cluster[] | null>(null)
  const [dump, setDump] = useState<ApiResult | null>(null)
  const [busy, setBusy] = useState(false)

  async function load() {
    setBusy(true)
    try {
      const r = await apiFetch(conn, '/clusters')
      setResult(r)
      if (r.ok) {
        try {
          setClusters(JSON.parse(r.bodyText) as Cluster[])
        } catch {
          setClusters(null)
        }
      } else {
        setClusters(null)
      }
    } finally {
      setBusy(false)
    }
  }

  async function loadDump() {
    setDump(await apiFetch(conn, '/config_dump'))
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Clusters (GET /clusters)</CardTitle>
            <Button size="sm" variant="outline" onClick={load} disabled={busy}>
              <RefreshCw size={14} /> {busy ? 'Loading...' : 'Load'}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {clusters ? (
            <Table>
              <THead>
                <TRow>
                  <TH>Name</TH>
                  <TH>Discovery</TH>
                  <TH>LB policy</TH>
                  <TH>Timeout ms</TH>
                  <TH>Protocol</TH>
                  <TH>Endpoints</TH>
                </TRow>
              </THead>
              <tbody>
                {clusters.map((c) => (
                  <TRow key={c.name}>
                    <TD className="font-medium">{c.name}</TD>
                    <TD>{c.discovery ?? '-'}</TD>
                    <TD>{c.lb_policy ?? '-'}</TD>
                    <TD>{c.connect_timeout_ms ?? '-'}</TD>
                    <TD>{c.upstream_protocol ?? '-'}</TD>
                    <TD>
                      {(c.endpoints ?? [])
                        .map((e) => `${e.host}:${e.port}`)
                        .join(', ') || '-'}
                    </TD>
                  </TRow>
                ))}
              </tbody>
            </Table>
          ) : (
            <p className="mb-3 text-xs text-zinc-500">No parsed cluster list yet. Load to fetch.</p>
          )}
          <div className="mt-3">
            <ResultPanel result={result} />
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Config dump (GET /config_dump)</CardTitle>
            <Button size="sm" variant="outline" onClick={loadDump}>
              Load
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <ResultPanel result={dump} />
        </CardContent>
      </Card>
    </div>
  )
}
