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
  const [createId, setCreateId] = useState('')
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
    if (!createId.trim()) return
    setCreateRes(
      await apiFetch(conn, '/tenants', {
        method: 'POST',
        auth: true,
        scopedWrite: true,
        body: { tenant: createId.trim() },
      }),
    )
  }

  async function remove() {
    if (!lookupId.trim()) return
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
      }),
    )
  }

  return (
    <div className="space-y-4">
      {!authed && (
        <p className="rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-800">
          Writes and spend reads need a bearer token — set it in the header bar.
        </p>
      )}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Create tenant (POST /tenants)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Field label="tenant">
                <Input value={createId} onChange={(e) => setCreateId(e.target.value)} placeholder="acme" />
              </Field>
              <Button size="sm" onClick={create}>Create</Button>
              <ResultPanel result={createRes} />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Lookup tenant (no list endpoint — use id)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Field label="tenant id">
                <Input value={lookupId} onChange={(e) => setLookupId(e.target.value)} placeholder="acme" />
              </Field>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="destructive" onClick={remove}>Delete</Button>
                <Button size="sm" variant="outline" onClick={viewSpend}>View spend</Button>
              </div>
              <ResultPanel result={deleteRes} />
              <ResultPanel result={spendRes} />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Set policy (PUT /tenants/id/policy)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Field label="access">
                <select
                  value={policyMode}
                  onChange={(e) => setPolicyMode(e.target.value as 'all' | 'only')}
                  className="h-9 w-full rounded-md border border-zinc-300 bg-white px-2 text-sm"
                >
                  <option value="all">all</option>
                  <option value="only">{'{only: [...]}'}</option>
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
              <Button size="sm" onClick={setPolicy}>Save policy</Button>
              <ResultPanel result={policyRes} />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Set budget (PUT /tenants/id/budget)</CardTitle>
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
              <Button size="sm" onClick={setBudget}>Save budget</Button>
              <ResultPanel result={budgetRes} />
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
