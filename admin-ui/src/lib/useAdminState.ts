import { useCallback, useEffect, useState } from 'react'
import { apiFetch, scopedWritePath, type AdminConn, type ApiResult } from './api'
import { parseRouting, parseTokenUsage, type Routing, type UsageRow } from './onboarding'

/** One row of `GET /keys`. */
export interface KeyRow {
  key_id: string
  tenant: string
  revoked: boolean
  /** `null` is "no ceiling configured"; a zero ceiling is a real number. */
  budget: { max_micro_usd: number; max_usd: string; period: string } | null
  policy: { access: 'all' | { only: string[] }; deny?: string[] } | null
}

export interface ClusterRow {
  name: string
  endpoints?: { host: string; port: number }[]
}

/** Every read the getting-started, keys and models pages share, loaded together. */
export interface AdminState {
  ready: ApiResult | null
  keys: ApiResult | null
  keyRows: KeyRow[] | null
  clusters: ClusterRow[] | null
  routing: Routing | null
  pricing: ApiResult | null
  configDump: ApiResult | null
  usage: UsageRow[] | null
  tokensSeen: number | null
  loading: boolean
  refresh: () => void
}

function parseJson<T>(r: ApiResult | null): T | null {
  if (!r?.ok) return null
  try {
    return JSON.parse(r.bodyText) as T
  } catch {
    return null
  }
}

export function useAdminState(conn: AdminConn, pollMs = 10_000): AdminState {
  const [ready, setReady] = useState<ApiResult | null>(null)
  const [keys, setKeys] = useState<ApiResult | null>(null)
  const [clusters, setClusters] = useState<ApiResult | null>(null)
  const [models, setModels] = useState<ApiResult | null>(null)
  const [pricing, setPricing] = useState<ApiResult | null>(null)
  const [configDump, setConfigDump] = useState<ApiResult | null>(null)
  const [stats, setStats] = useState<ApiResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [tick, setTick] = useState(0)

  const refresh = useCallback(() => setTick((t) => t + 1), [])

  useEffect(() => {
    let active = true
    // Vite's dev server does not serve the admin API; wait for an explicit URL.
    if (import.meta.env.DEV && !conn.adminUrl.trim()) return
    setLoading(true)
    void Promise.all([
      apiFetch(conn, '/ready'),
      conn.token
        ? apiFetch(conn, scopedWritePath('/keys', conn.chainPrefix), { auth: true })
        : Promise.resolve(null),
      apiFetch(conn, '/clusters'),
      apiFetch(conn, '/models'),
      apiFetch(conn, '/pricing', { scopedWrite: true }),
      apiFetch(conn, '/config_dump'),
      apiFetch(conn, '/stats/prometheus'),
    ]).then(([r, k, c, m, p, d, s]) => {
      if (!active) return
      setReady(r)
      setKeys(k)
      setClusters(c)
      setModels(m)
      setPricing(p)
      setConfigDump(d)
      setStats(s)
      setLoading(false)
    })
    return () => {
      active = false
    }
  }, [conn, tick])

  useEffect(() => {
    if (pollMs <= 0) return
    const id = window.setInterval(refresh, pollMs)
    return () => window.clearInterval(id)
  }, [pollMs, refresh])

  const keyRows = parseJson<{ keys?: KeyRow[] }>(keys)?.keys ?? null
  const usage = stats?.ok ? parseTokenUsage(stats.bodyText) : null
  return {
    ready,
    keys,
    keyRows,
    clusters: parseJson<ClusterRow[]>(clusters),
    routing: models?.ok ? parseRouting(models.bodyText) : null,
    pricing,
    configDump,
    usage,
    tokensSeen: usage ? usage.reduce((n, u) => n + u.input + u.output + u.cached, 0) : null,
    loading,
    refresh,
  }
}
