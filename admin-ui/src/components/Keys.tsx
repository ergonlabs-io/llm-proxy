import { useEffect, useState } from 'react'
import { Check, Copy, RefreshCw } from 'lucide-react'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Input } from './ui/input'
import { Dialog } from './ui/tabs'
import { Table, THead, TRow, TH, TD } from './ui/table'
import { Field, ResultPanel } from './forms'
import { apiFetch, type AdminConn, type ApiResult } from '../lib/api'
import type { AdminState, KeyRow } from '../lib/useAdminState'
import { firstRequestSnippet, proxyBaseUrls, sampleModel, type SnippetKind } from '../lib/onboarding'

/**
 * Tenant new keys go to unless the user opens the advanced options. Not `default`: the admin API reserves that
 * name (missing tenants normalize to it), so it cannot mint keys there.
 */
export const TEAM_TENANT = 'team'

interface Minted {
  key: string
  keyId: string
  /** The key's own model list, if the user set one; the sample request uses its first exact name. */
  models: string[]
}

interface Spend {
  spend_usd: string
  unpriced_requests: number
}

function splitList(text: string): string[] {
  return text
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

function policyLabel(policy: KeyRow['policy']): string {
  if (!policy || policy.access === 'all') return 'all the tenant allows'
  return policy.access.only.join(', ')
}

function budgetLabel(budget: KeyRow['budget']): string {
  if (!budget) return 'no limit'
  return `$${budget.max_usd} / ${budget.period === 'daily' ? 'day' : 'month'}`
}

function browserHost(conn: AdminConn): string {
  try {
    return new URL(conn.adminUrl.trim() || window.location.href).hostname
  } catch {
    return window.location.hostname
  }
}

/** Budget and model limits for one key; sends only what the user set. */
async function applyLimits(
  conn: AdminConn,
  keyId: string,
  limits: { budgetUsd: string; period: 'daily' | 'monthly'; models: string },
): Promise<ApiResult[]> {
  const id = encodeURIComponent(keyId)
  const results: ApiResult[] = []
  const budget = limits.budgetUsd.trim()
  results.push(
    await apiFetch(conn, `/keys/${id}/budget`, {
      method: 'PUT',
      auth: true,
      scopedWrite: true,
      body: { budget: budget ? { max_usd: budget, period: limits.period } : null },
    }),
  )
  const only = splitList(limits.models)
  results.push(
    await apiFetch(conn, `/keys/${id}/policy`, {
      method: 'PUT',
      auth: true,
      scopedWrite: true,
      body: only.length > 0 ? { access: { only } } : { access: 'all' },
    }),
  )
  return results
}

function LimitFields({
  budgetUsd,
  period,
  models,
  onChange,
}: {
  budgetUsd: string
  period: 'daily' | 'monthly'
  models: string
  onChange: (v: { budgetUsd: string; period: 'daily' | 'monthly'; models: string }) => void
}) {
  return (
    <div className="grid gap-2 sm:grid-cols-3">
      <Field label="Spend limit, USD (empty = none)">
        <Input
          value={budgetUsd}
          onChange={(e) => onChange({ budgetUsd: e.target.value, period, models })}
          placeholder="25.00"
          inputMode="decimal"
        />
      </Field>
      <Field label="per">
        <select
          value={period}
          onChange={(e) => onChange({ budgetUsd, period: e.target.value as 'daily' | 'monthly', models })}
          className="h-9 w-full rounded-md border border-zinc-300 bg-white px-2 text-sm"
        >
          <option value="daily">day</option>
          <option value="monthly">month</option>
        </select>
      </Field>
      <Field label="Models (comma-separated, empty = all)">
        <Input
          value={models}
          onChange={(e) => onChange({ budgetUsd, period, models: e.target.value })}
          placeholder="gpt-4o-mini, claude-*"
        />
      </Field>
    </div>
  )
}

export function Keys({ conn, state }: { conn: AdminConn; state: AdminState }) {
  const authed = !!conn.token
  const keys = state.keyRows ?? []
  const showTenant = new Set(keys.map((k) => k.tenant)).size > 1

  // ---- mint ----
  const [name, setName] = useState('')
  const [tenant, setTenant] = useState(TEAM_TENANT)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [limits, setLimits] = useState({ budgetUsd: '', period: 'monthly' as 'daily' | 'monthly', models: '' })
  const [mintError, setMintError] = useState<ApiResult | null>(null)
  const [minted, setMinted] = useState<Minted | null>(null)
  const [busy, setBusy] = useState(false)

  const mintBlocked = !authed
    ? 'Paste the admin token at the top first.'
    : !name.trim()
      ? 'Give the key a name, for example the app or person it is for.'
      : null

  async function mint() {
    if (mintBlocked) return
    setBusy(true)
    setMintError(null)
    try {
      const keyId = name.trim()
      const r = await apiFetch(conn, '/keys', {
        method: 'POST',
        auth: true,
        scopedWrite: true,
        body: { tenant: tenant.trim() || TEAM_TENANT, key_id: keyId },
      })
      if (!r.ok) {
        setMintError(r)
        return
      }
      let key: string | undefined
      try {
        key = (JSON.parse(r.bodyText) as { key?: string }).key
      } catch {
        key = undefined
      }
      if (!key) {
        setMintError({ ...r, bodyText: 'The proxy answered without a key.' })
        return
      }
      if (limits.budgetUsd.trim() || limits.models.trim()) {
        const failed = (await applyLimits(conn, keyId, limits)).find((x) => !x.ok)
        if (failed) setMintError({ ...failed, bodyText: `Key created, but a limit was not set: ${failed.bodyText}` })
      }
      setMinted({ key, keyId, models: splitList(limits.models) })
      setName('')
      setLimits({ budgetUsd: '', period: 'monthly', models: '' })
      state.refresh()
    } finally {
      setBusy(false)
    }
  }

  // ---- per-key spend ----
  const [spend, setSpend] = useState<Record<string, Spend | null>>({})
  const keyIds = keys.map((k) => k.key_id).join('\u0000')
  useEffect(() => {
    if (!authed || keys.length === 0) return
    let active = true
    void Promise.all(
      keys.map(async (k) => {
        const r = await apiFetch(conn, `/keys/${encodeURIComponent(k.key_id)}/spend`, {
          auth: true,
          scopedWrite: true,
        })
        try {
          return [k.key_id, r.ok ? (JSON.parse(r.bodyText) as Spend) : null] as const
        } catch {
          return [k.key_id, null] as const
        }
      }),
    ).then((rows) => {
      if (active) setSpend(Object.fromEntries(rows))
    })
    return () => {
      active = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [conn, keyIds, state.tokensSeen])

  // ---- edit / revoke ----
  const [editing, setEditing] = useState<string | null>(null)
  const [editLimits, setEditLimits] = useState({ budgetUsd: '', period: 'monthly' as 'daily' | 'monthly', models: '' })
  const [rowResult, setRowResult] = useState<ApiResult | null>(null)

  function startEdit(k: KeyRow) {
    setRowResult(null)
    setEditing(k.key_id)
    setEditLimits({
      budgetUsd: k.budget?.max_usd ?? '',
      period: k.budget?.period === 'daily' ? 'daily' : 'monthly',
      models: k.policy && k.policy.access !== 'all' ? k.policy.access.only.join(', ') : '',
    })
  }

  async function saveEdit() {
    if (!editing) return
    const results = await applyLimits(conn, editing, editLimits)
    const failed = results.find((r) => !r.ok)
    setRowResult(failed ?? results[results.length - 1])
    if (!failed) setEditing(null)
    state.refresh()
  }

  async function revoke(keyId: string) {
    if (!window.confirm(`Revoke key "${keyId}"? Requests with it fail at once. This cannot be undone.`)) return
    setRowResult(
      await apiFetch(conn, `/keys/${encodeURIComponent(keyId)}`, {
        method: 'DELETE',
        auth: true,
        scopedWrite: true,
      }),
    )
    state.refresh()
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Create a key</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <Field label="Name">
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="for example: support-bot or alice"
                onKeyDown={(e) => e.key === 'Enter' && void mint()}
              />
            </Field>
            <LimitFields {...limits} onChange={setLimits} />
            <button
              type="button"
              className="text-xs text-zinc-500 underline"
              onClick={() => setShowAdvanced((v) => !v)}
            >
              {showAdvanced ? 'Hide' : 'Show'} advanced options
            </button>
            {showAdvanced && (
              <Field label="Tenant (keys in one tenant share its model access and budget)">
                <Input value={tenant} onChange={(e) => setTenant(e.target.value)} />
              </Field>
            )}
            <div className="flex items-center gap-3">
              <Button size="sm" onClick={mint} disabled={!!mintBlocked || busy}>
                {busy ? 'Creating...' : 'Create key'}
              </Button>
              {mintBlocked && <span className="text-xs text-zinc-500">{mintBlocked}</span>}
            </div>
            {mintError && <ResultPanel result={mintError} />}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Keys</CardTitle>
            <Button size="sm" variant="outline" onClick={state.refresh} disabled={!authed || state.loading}>
              <RefreshCw size={14} /> Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {!authed ? (
            <p className="text-xs text-zinc-500">Paste the admin token at the top to list keys.</p>
          ) : state.keys && !state.keys.ok ? (
            <ResultPanel result={state.keys} />
          ) : keys.length === 0 ? (
            <p className="text-xs text-zinc-500">No keys yet. Create one above.</p>
          ) : (
            <Table>
              <THead>
                <TRow>
                  <TH>Name</TH>
                  {showTenant && <TH>Tenant</TH>}
                  <TH>Models</TH>
                  <TH>Spend limit</TH>
                  <TH>Spent this period</TH>
                  <TH> </TH>
                </TRow>
              </THead>
              <tbody>
                {keys.map((k) => {
                  const s = spend[k.key_id]
                  return (
                    <TRow key={`${k.tenant}/${k.key_id}`}>
                      <TD className="font-medium">
                        {k.key_id} {k.revoked && <Badge tone="red">revoked</Badge>}
                      </TD>
                      {showTenant && <TD>{k.tenant}</TD>}
                      <TD className="text-xs">{policyLabel(k.policy)}</TD>
                      <TD className="text-xs">{budgetLabel(k.budget)}</TD>
                      <TD className="text-xs">
                        {s ? `$${s.spend_usd}` : '-'}
                        {s && s.unpriced_requests > 0 && (
                          <span className="block text-amber-700">{s.unpriced_requests} unpriced</span>
                        )}
                      </TD>
                      <TD>
                        {!k.revoked && (
                          <div className="flex gap-1">
                            <Button size="sm" variant="outline" onClick={() => startEdit(k)}>
                              Limits
                            </Button>
                            <Button size="sm" variant="destructive" onClick={() => void revoke(k.key_id)}>
                              Revoke
                            </Button>
                          </div>
                        )}
                      </TD>
                    </TRow>
                  )
                })}
              </tbody>
            </Table>
          )}
          {editing && (
            <div className="mt-3 space-y-2 rounded-md border border-zinc-200 p-3">
              <p className="text-sm font-medium">Limits for {editing}</p>
              <LimitFields {...editLimits} onChange={setEditLimits} />
              <div className="flex gap-2">
                <Button size="sm" onClick={() => void saveEdit()}>
                  Save
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setEditing(null)}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
          {rowResult && !rowResult.ok && (
            <div className="mt-3">
              <ResultPanel result={rowResult} />
            </div>
          )}
          <p className="mt-3 text-xs text-zinc-500">
            A key's model list only narrows what its tenant may use. Spend counts priced requests; set prices under
            Models &amp; pricing.
          </p>
        </CardContent>
      </Card>

      {minted && (
        <MintedKeyDialog conn={conn} state={state} minted={minted} onClose={() => setMinted(null)} />
      )}
    </div>
  )
}

function MintedKeyDialog({
  conn,
  state,
  minted,
  onClose,
}: {
  conn: AdminConn
  state: AdminState
  minted: Minted
  onClose: () => void
}) {
  const baseUrls = state.configDump?.ok ? proxyBaseUrls(state.configDump.bodyText, browserHost(conn)) : []
  const [baseUrl, setBaseUrl] = useState(baseUrls[0] ?? 'http://127.0.0.1:53421')
  const [model, setModel] = useState(
    minted.models.find((m) => !m.includes('*')) ?? sampleModel(state.routing) ?? '',
  )
  const [kind, setKind] = useState<SnippetKind>('curl')
  const [copied, setCopied] = useState<'key' | 'snippet' | null>(null)
  const snippet = firstRequestSnippet(kind, baseUrl, minted.key, model.trim() || 'MODEL_NAME')

  async function copy(text: string, what: 'key' | 'snippet') {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(what)
    } catch {
      setCopied(null)
    }
  }

  return (
    <Dialog open onClose={onClose} title={`Key "${minted.keyId}" created: copy it now`}>
      <p className="mb-2 text-xs text-zinc-500">The key is shown once. The proxy cannot show it again.</p>
      <div className="flex items-center gap-2 rounded-md bg-zinc-950 p-3">
        <code className="flex-1 break-all font-mono text-sm text-zinc-100">{minted.key}</code>
        <Button size="sm" variant="secondary" onClick={() => void copy(minted.key, 'key')}>
          {copied === 'key' ? <Check size={14} /> : <Copy size={14} />}
          {copied === 'key' ? 'Copied' : 'Copy'}
        </Button>
      </div>

      <p className="mb-2 mt-4 text-sm font-medium">Send a first request</p>
      <div className="grid gap-2 sm:grid-cols-2">
        <Field label="Proxy address">
          {baseUrls.length > 1 ? (
            <select
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              className="h-9 w-full rounded-md border border-zinc-300 bg-white px-2 text-sm"
            >
              {baseUrls.map((u) => (
                <option key={u}>{u}</option>
              ))}
            </select>
          ) : (
            <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
          )}
        </Field>
        <Field label="Model">
          <Input value={model} onChange={(e) => setModel(e.target.value)} placeholder="a model your provider serves" />
        </Field>
      </div>
      <div className="mt-2 flex gap-1">
        {(['curl', 'python', 'node'] as const).map((k) => (
          <Button key={k} size="sm" variant={kind === k ? 'default' : 'outline'} onClick={() => setKind(k)}>
            {k === 'curl' ? 'curl' : k === 'python' ? 'Python' : 'Node'}
          </Button>
        ))}
        <Button size="sm" variant="secondary" className="ml-auto" onClick={() => void copy(snippet, 'snippet')}>
          {copied === 'snippet' ? <Check size={14} /> : <Copy size={14} />} Copy
        </Button>
      </div>
      <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-md bg-zinc-950 p-3 font-mono text-xs text-zinc-100">
        {snippet}
      </pre>
      <p className="mt-2 text-xs text-zinc-500">
        The Get started page marks the first request done once its tokens are metered.
      </p>
      <div className="mt-3 text-right">
        <Button size="sm" onClick={onClose}>
          Done
        </Button>
      </div>
    </Dialog>
  )
}
