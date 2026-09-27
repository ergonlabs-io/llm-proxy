// Shared admin connection state + fetch helper.
// Same-origin by default; VITE_ADMIN_URL override is for `npm run dev`.

export interface AdminConn {
  token: string
  adminUrl: string
  chainPrefix: string
}

const LS_KEY = 'llm-proxy-admin-conn-v1'

export function loadConn(): AdminConn {
  const envDefault = (import.meta.env.VITE_ADMIN_URL as string | undefined) ?? ''
  try {
    const raw = localStorage.getItem(LS_KEY)
    if (raw) {
      const p = JSON.parse(raw) as Partial<AdminConn>
      return {
        token: p.token ?? '',
        adminUrl: p.adminUrl ?? envDefault,
        chainPrefix: p.chainPrefix ?? '',
      }
    }
  } catch {
    // ignore corrupt storage
  }
  return { token: '', adminUrl: envDefault, chainPrefix: '' }
}

export function saveConn(c: AdminConn): void {
  localStorage.setItem(LS_KEY, JSON.stringify(c))
}

export interface ApiResult {
  ok: boolean
  status: number
  bodyText: string
}

function joinBase(base: string, path: string): string {
  if (!base) return path
  const b = base.replace(/\/+$/, '')
  return `${b}${path}`
}

/** Prepend /chains/{prefix} to write paths when a chain prefix is set. */
export function scopedWritePath(path: string, chainPrefix: string): string {
  const p = chainPrefix.trim().replace(/^\/+|\/+$/g, '')
  if (!p) return path
  return `/chains/${p}${path}`
}

export async function apiFetch(
  conn: AdminConn,
  path: string,
  opts: { method?: string; body?: unknown; auth?: boolean; scopedWrite?: boolean } = {},
): Promise<ApiResult> {
  const finalPath =
    opts.scopedWrite === true ? scopedWritePath(path, conn.chainPrefix) : path
  const url = joinBase(conn.adminUrl.trim(), finalPath)
  const headers: Record<string, string> = {}
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'
  if (opts.auth && conn.token) headers['Authorization'] = `Bearer ${conn.token}`
  let res: Response
  try {
    res = await fetch(url, {
      method: opts.method ?? 'GET',
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    })
  } catch (e) {
    return { ok: false, status: 0, bodyText: `network error: ${String(e)}` }
  }
  const text = await res.text()
  return { ok: res.ok, status: res.status, bodyText: text }
}

/** Pretty-print JSON bodies, fall back to raw text. */
export function pretty(bodyText: string): string {
  if (!bodyText) return '(empty body)'
  try {
    return JSON.stringify(JSON.parse(bodyText), null, 2)
  } catch {
    return bodyText
  }
}
