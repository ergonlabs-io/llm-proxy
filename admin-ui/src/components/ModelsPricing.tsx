import { useState } from 'react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Input } from './ui/input'
import { Field, ResultPanel } from './forms'
import { RoutingTable } from './Routing'
import { Pricing } from './Pricing'
import { apiFetch, type AdminConn, type ApiResult } from '../lib/api'
import type { AdminState } from '../lib/useAdminState'
import { TEAM_TENANT } from './Keys'

/**
 * For a single team, "the models our keys may use" is the allow-list of two
 * tenants: the one the Keys page creates keys in, and `default`, which holds
 * the key `llm-proxy init` configures. A key's own list can only narrow it.
 */
const TEAM_TENANTS = [TEAM_TENANT, 'default']

function TeamModels({ conn }: { conn: AdminConn }) {
  const [mode, setMode] = useState<'all' | 'only'>('all')
  const [only, setOnly] = useState('')
  const [result, setResult] = useState<ApiResult | null>(null)

  async function save() {
    const list = only
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
    const body = mode === 'all' ? { access: 'all' } : { access: { only: list } }
    for (const tenant of TEAM_TENANTS) {
      const path = `/tenants/${tenant}/policy`
      let r = await apiFetch(conn, path, { method: 'PUT', auth: true, scopedWrite: true, body })
      // The team tenant exists only once a key was created in it.
      if (r.status === 404 && tenant === TEAM_TENANT) {
        const created = await apiFetch(conn, '/tenants', {
          method: 'POST',
          auth: true,
          scopedWrite: true,
          body: { tenant },
        })
        r = created.ok ? await apiFetch(conn, path, { method: 'PUT', auth: true, scopedWrite: true, body }) : created
      }
      if (!r.ok) {
        setResult({ ...r, bodyText: `tenant ${tenant}: ${r.bodyText}` })
        return
      }
      setResult(r)
    }
  }

  const blocked = !conn.token
    ? 'Paste the admin token at the top first.'
    : mode === 'only' && !only.trim()
      ? 'List at least one model, or choose all models.'
      : null

  return (
    <Card>
      <CardHeader>
        <CardTitle>Models your keys may use</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          <p className="text-xs text-zinc-600">
            Applies to every key created on the Keys page (tenant <code className="font-mono">{TEAM_TENANT}</code>) and to
            the key <code className="font-mono">llm-proxy init</code> made (tenant <code className="font-mono">default</code>).
            A key's own model list can narrow this further.
          </p>
          <div className="flex gap-4 text-sm">
            <label className="flex items-center gap-1.5">
              <input type="radio" checked={mode === 'all'} onChange={() => setMode('all')} /> All routed models
            </label>
            <label className="flex items-center gap-1.5">
              <input type="radio" checked={mode === 'only'} onChange={() => setMode('only')} /> Only these
            </label>
          </div>
          {mode === 'only' && (
            <Field label="Models (comma-separated; a trailing * matches a prefix)">
              <Input value={only} onChange={(e) => setOnly(e.target.value)} placeholder="gpt-4o-mini, claude-*" />
            </Field>
          )}
          <div className="flex items-center gap-3">
            <Button size="sm" onClick={() => void save()} disabled={!!blocked}>
              Save
            </Button>
            {blocked && <span className="text-xs text-zinc-500">{blocked}</span>}
          </div>
          {result && (result.ok ? <p className="text-xs text-green-700">Saved. It applies to the next request.</p> : <ResultPanel result={result} />)}
          <p className="text-xs text-zinc-500">
            The proxy has no read for this setting yet, so this form does not show the current value. Until it is set,
            what an unset tenant may use is decided by <code className="font-mono">auth.enforce.tenants_without_policy</code>{' '}
            in the config (the starter config allows every model).
          </p>
        </div>
      </CardContent>
    </Card>
  )
}

export function ModelsPricing({ conn, state }: { conn: AdminConn; state: AdminState }) {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Routing</CardTitle>
        </CardHeader>
        <CardContent>
          <RoutingTable routing={state.routing} />
        </CardContent>
      </Card>
      <TeamModels conn={conn} />
      <Pricing conn={conn} state={state} />
    </div>
  )
}
