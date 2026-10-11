import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Input } from './ui/input'
import { Dialog } from './ui/tabs'
import { Field, ResultPanel } from './forms'
import { apiFetch, type AdminConn, type ApiResult } from '../lib/api'

export function Keys({ conn }: { conn: AdminConn }) {
  const [tenant, setTenant] = useState('')
  const [keyId, setKeyId] = useState('')
  const [mintRes, setMintRes] = useState<ApiResult | null>(null)
  const [mintedKey, setMintedKey] = useState<string | null>(null)
  const [showKey, setShowKey] = useState(false)
  const [copied, setCopied] = useState(false)
  const [revokeId, setRevokeId] = useState('')
  const [revokeRes, setRevokeRes] = useState<ApiResult | null>(null)
  const [budgetMax, setBudgetMax] = useState('500.00')
  const [budgetPeriod, setBudgetPeriod] = useState<'daily' | 'monthly'>('daily')
  const [budgetClear, setBudgetClear] = useState(false)
  const [budgetRes, setBudgetRes] = useState<ApiResult | null>(null)
  const [spendId, setSpendId] = useState('')
  const [spendRes, setSpendRes] = useState<ApiResult | null>(null)

  function dismissKey() {
    setShowKey(false)
    setMintedKey(null)
    setCopied(false)
  }

  async function mint() {
    if (!tenant.trim() || !keyId.trim()) return
    dismissKey()
    const r = await apiFetch(conn, '/keys', {
      method: 'POST',
      auth: true,
      scopedWrite: true,
      body: { tenant: tenant.trim(), key_id: keyId.trim() },
    })
    if (!r.ok) {
      setMintRes(r)
      return
    }
    try {
      const parsed = JSON.parse(r.bodyText) as { key?: string; [field: string]: unknown }
      const { key, ...identity } = parsed
      // Keep the secret only in the dialog, never in the persistent result panel.
      setMintRes({ ...r, bodyText: JSON.stringify(identity) })
      if (typeof key === 'string' && key) {
        setMintedKey(key)
        setShowKey(true)
      }
    } catch {
      setMintRes({ ...r, bodyText: 'Invalid key mint response' })
    }
  }

  async function revoke() {
    if (!revokeId.trim()) return
    setRevokeRes(
      await apiFetch(conn, `/keys/${encodeURIComponent(revokeId.trim())}`, {
        method: 'DELETE',
        auth: true,
        scopedWrite: true,
      }),
    )
  }

  async function setBudget() {
    const id = revokeId.trim() || keyId.trim()
    if (!id) return
    const body = budgetClear
      ? { budget: null }
      : { budget: { max_usd: budgetMax.trim(), period: budgetPeriod } }
    setBudgetRes(
      await apiFetch(conn, `/keys/${encodeURIComponent(id)}/budget`, {
        method: 'PUT',
        auth: true,
        scopedWrite: true,
        body,
      }),
    )
  }

  async function viewSpend() {
    if (!spendId.trim()) return
    setSpendRes(
      await apiFetch(conn, `/keys/${encodeURIComponent(spendId.trim())}/spend`, {
        auth: true,
        scopedWrite: true,
      }),
    )
  }

  async function copyKey() {
    if (!mintedKey) return
    try {
      await navigator.clipboard.writeText(mintedKey)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Mint key (POST /keys)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Field label="tenant">
                <Input value={tenant} onChange={(e) => setTenant(e.target.value)} placeholder="acme" />
              </Field>
              <Field label="key_id">
                <Input value={keyId} onChange={(e) => setKeyId(e.target.value)} placeholder="service-a" />
              </Field>
              <Button size="sm" onClick={mint}>Mint (201)</Button>
              <ResultPanel result={mintRes} />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Revoke / budget / spend</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Field label="key id (revoke + budget target)">
                <Input value={revokeId} onChange={(e) => setRevokeId(e.target.value)} placeholder="service-a" />
              </Field>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="destructive" onClick={revoke}>Revoke (DELETE)</Button>
              </div>
              <ResultPanel result={revokeRes} />
              <div className="grid grid-cols-2 gap-2">
                <Field label="max_usd">
                  <Input value={budgetMax} onChange={(e) => setBudgetMax(e.target.value)} disabled={budgetClear} />
                </Field>
                <Field label="period">
                  <select
                    value={budgetPeriod}
                    onChange={(e) => setBudgetPeriod(e.target.value as 'daily' | 'monthly')}
                    className="h-9 w-full rounded-md border border-zinc-300 bg-white px-2 text-sm"
                    disabled={budgetClear}
                  >
                    <option value="daily">daily</option>
                    <option value="monthly">monthly</option>
                  </select>
                </Field>
              </div>
              <label className="flex items-center gap-2 text-xs">
                <input type="checkbox" checked={budgetClear} onChange={(e) => setBudgetClear(e.target.checked)} />
                Clear budget (send null)
              </label>
              <Button size="sm" variant="outline" onClick={setBudget}>Save budget (PUT)</Button>
              <ResultPanel result={budgetRes} />
              <Field label="key id (spend lookup)">
                <Input value={spendId} onChange={(e) => setSpendId(e.target.value)} placeholder="service-a" />
              </Field>
              <Button size="sm" variant="outline" onClick={viewSpend}>View spend (bearer-gated)</Button>
              <ResultPanel result={spendRes} />
            </div>
          </CardContent>
        </Card>
      </div>
      <Dialog open={showKey} onClose={dismissKey} title="Key minted — copy it now">
        <p className="mb-2 text-xs text-zinc-500">
          The plaintext key is shown once. It cannot be retrieved again.
        </p>
        <div className="flex items-center gap-2 rounded-md bg-zinc-950 p-3">
          <code className="flex-1 break-all font-mono text-sm text-zinc-100">{mintedKey}</code>
          <Button size="sm" variant="secondary" onClick={copyKey}>
            {copied ? <Check size={14} /> : <Copy size={14} />}
            {copied ? 'Copied' : 'Copy'}
          </Button>
        </div>
        <div className="mt-3 text-right">
          <Button size="sm" onClick={dismissKey}>Done</Button>
        </div>
      </Dialog>
    </div>
  )
}
