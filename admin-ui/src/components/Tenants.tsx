import { useState } from 'react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Input } from './ui/input'
import { Field, ResultPanel } from './forms'
import { apiFetch, type AdminConn, type ApiResult } from '../lib/api'

type BudgetPeriod = 'daily' | 'monthly'

function budgetBody(maxUsd: string, period: BudgetPeriod, clear: boolean): unknown {
  if (clear) return { budget: null }
  return { budget: { max_usd: maxUsd, period } }
}

export function Tenants({ conn }: { conn: AdminConn }) {
  const [createRes, setCreateRes] = useState<ApiResult | null>(null)
  const [lookupId, setLookupId] = useState('')
  const [deleteRes, setDeleteRes] = useState<ApiResult | null>(null)
  const [policyMode, setPolicyMode] = useState<'all' | 'only'>('all')
  const [policyOnly, setPolicyOnly] = useState('')
  const [policyDeny, setPolicyDeny] = useState('')
  const [policyRes, setPolicyRes] = useState<ApiResult | null>(null)
  const [budgetMax, setBudgetMax] = useState('500.00')
  const [budgetPeriod, setBudgetPeriod] = useState<BudgetPeriod>('daily')
  const [budgetClear, setBudgetClear] = useState(false)
  const [budgetRes, setBudgetRes] = useState<ApiResult | null>(null)
  const [spendRes, setSpendRes] = useState<ApiResult | null>(null)

  const authed = !!conn.token

  async function create() {
    if (!lookupId.trim()) return
    setCreateRes(
      await apiFetch(conn, '/tenants', {
        method: 'POST',
        auth: true,
        scopedWrite: true,
        body: { tenant: lookupId.trim() },
      }),
    )
  }

  async function remove() {
    if (!lookupId.trim()) return
    if (
      !window.confirm(
        `Delete tenant "${lookupId.trim()}"? Every key of the tenant is revoked at once. This cannot be undone.`,
      )
    )
      return
    setDeleteRes(
      await apiFetch(conn, `/tenants/${encodeURIComponent(lookupId.trim())}`, {
        method: 'DELETE',
        auth: true,
        scopedWrite: true,
      }),
    )
  }

  async function setPolicy() {
    if (!lookupId.trim()) return
    const only = policyOnly.split(',').map((s) => s.trim()).filter(Boolean)
    const deny = policyDeny.split(',').map((s) => s.trim()).filter(Boolean)
    // Rust note: deny_unknown_fields rejects extras, so build exactly {access, deny?}.
    const body: Record<string, unknown> =
      policyMode === 'all' ? { access: 'all' } : { access: { only } }
    if (deny.length > 0) body['deny'] = deny
    setPolicyRes(
      await apiFetch(conn, `/tenants/${encodeURIComponent(lookupId.trim())}/policy`, {
        method: 'PUT',
        auth: true,
        scopedWrite: true,
        body,
      }),
    )
  }

  async function setBudget() {
    if (!lookupId.trim()) return
    setBudgetRes(
      await apiFetch(conn, `/tenants/${encodeURIComponent(lookupId.trim())}/budget`, {
        method: 'PUT',
        auth: true,
        scopedWrite: true,
        body: budgetBody(budgetMax.trim(), budgetPeriod, budgetClear),
      }),
    )
  }

  async function viewSpend() {
    if (!lookupId.trim()) return
    setSpendRes(
      await apiFetch(conn, `/tenants/${encodeURIComponent(lookupId.trim())}/spend`, {
        auth: true,
        scopedWrite: true,
      }),
    )
  }

  const target = lookupId.trim()
  const blocked = !authed
    ? 'Paste the admin token at the top first.'
    : !target
      ? 'Enter a tenant id above.'
      : null

  return (
    <div className="space-y-4">
      <p className="text-xs text-zinc-600">
        Tenants group keys that share model access and a budget. A single team can skip this page: the Keys page
        puts every key in the <code className="font-mono">team</code> tenant.
      </p>
      {!authed && (
        <p className="rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-800">
          Writes and spend reads need the admin token: paste it at the top.
        </p>
      )}
      <Card>
        <CardContent>
          <Field label="Tenant id (used by every action on this page)">
            <Input value={lookupId} onChange={(e) => setLookupId(e.target.value)} placeholder="for example: team-a" />
          </Field>
          {blocked && <p className="mt-1 text-xs text-zinc-500">{blocked}</p>}
        </CardContent>
      </Card>
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Create tenant</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Button size="sm" onClick={create} disabled={!!blocked}>
                Create {target || 'tenant'}
              </Button>
              <ResultPanel result={createRes} />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Spend and delete</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline" onClick={viewSpend} disabled={!!blocked}>View spend</Button>
                <Button size="sm" variant="destructive" onClick={remove} disabled={!!blocked}>Delete tenant</Button>
              </div>
              <ResultPanel result={deleteRes} />
              <ResultPanel result={spendRes} />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Models this tenant may use</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Field label="access">
                <select
                  value={policyMode}
                  onChange={(e) => setPolicyMode(e.target.value as 'all' | 'only')}
                  className="h-9 w-full rounded-md border border-zinc-300 bg-white px-2 text-sm"
                >
                  <option value="all">all models</option>
                  <option value="only">only these models</option>
                </select>
              </Field>
              {policyMode === 'only' && (
                <Field label="only (comma-separated models)">
                  <Input value={policyOnly} onChange={(e) => setPolicyOnly(e.target.value)} placeholder="gpt-4o, claude-3" />
                </Field>
              )}
              <Field label="deny (comma-separated, optional)">
                <Input value={policyDeny} onChange={(e) => setPolicyDeny(e.target.value)} placeholder="" />
              </Field>
              <Button size="sm" onClick={setPolicy} disabled={!!blocked}>Save models</Button>
              <ResultPanel result={policyRes} />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Tenant spend limit</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Field label="max_usd">
                <Input value={budgetMax} onChange={(e) => setBudgetMax(e.target.value)} placeholder="500.00" disabled={budgetClear} />
              </Field>
              <Field label="period">
                <select
                  value={budgetPeriod}
                  onChange={(e) => setBudgetPeriod(e.target.value as BudgetPeriod)}
                  className="h-9 w-full rounded-md border border-zinc-300 bg-white px-2 text-sm"
                  disabled={budgetClear}
                >
                  <option value="daily">daily</option>
                  <option value="monthly">monthly</option>
                </select>
              </Field>
              <label className="flex items-center gap-2 text-xs">
                <input type="checkbox" checked={budgetClear} onChange={(e) => setBudgetClear(e.target.checked)} />
                Clear budget (send null)
              </label>
              <Button size="sm" onClick={setBudget} disabled={!!blocked}>Save limit</Button>
              <ResultPanel result={budgetRes} />
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
