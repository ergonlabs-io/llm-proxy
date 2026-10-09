import { useEffect, useState } from 'react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Input, Textarea } from './ui/input'
import { Field, ResultPanel } from './forms'
import { apiFetch, type AdminConn, type ApiResult } from '../lib/api'

type Catalog = { fetched_at: string; models: { id: string; pricing: Record<string, unknown>; billing_status: string }[] }
type PricingInventory = { catalog?: Catalog; rate_card_version: string; price_list: { entries: unknown[] }; providers: Record<string, string> }

export function Pricing({ conn }: { conn: AdminConn }) {
  const [catalog, setCatalog] = useState<Catalog | null>(null)
  const [revision, setRevision] = useState(0)
  const [search, setSearch] = useState('')
  const [inventory, setInventory] = useState<PricingInventory | null>(null)
  const [raw, setRaw] = useState('')
  const [result, setResult] = useState<ApiResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    let active = true
    setInventory(null)
    setCatalog(null)
    apiFetch(conn, '/pricing', { scopedWrite: true }).then((response) => {
      if (!active) return
      if (!response.ok) { setError(`Pricing unavailable: ${response.bodyText}`); return }
      try {
        const value = JSON.parse(response.bodyText) as PricingInventory
        setInventory(value)
        setCatalog(value.catalog && Array.isArray(value.catalog.models) && value.catalog.models.every((model) => typeof model?.id === 'string' && model.pricing && typeof model.pricing === 'object') ? value.catalog : null)
        setRaw(JSON.stringify({ price_list: value.price_list, providers: value.providers, catalog: value.catalog }, null, 2))
        setError(null)
      } catch { setError('Invalid pricing response from proxy') }
    }).catch((failure: unknown) => { if (active) setError(String(failure)) })
    return () => { active = false }
  }, [conn.adminUrl, conn.chainPrefix, revision])

  async function submit() {
    setError(null)
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch (e) {
      setError(`Invalid JSON: ${String(e)}`)
      return
    }
    // Opaque rate-card: pass the parsed value straight through.
    const response = await apiFetch(conn, '/pricing', {
      method: 'PUT',
      auth: true,
      scopedWrite: true,
      body: parsed,
    })
    setResult(response)
    if (response.ok) setRevision((value) => value + 1)
  }

  return (
    <div className="space-y-4">
    <Button size="sm" onClick={() => setRevision((value) => value + 1)}>Refresh pricing</Button>
    {error && <p className="text-xs text-red-600">{error}</p>}
    {catalog && <Card>
      <CardHeader><CardTitle>Pricing from proxy</CardTitle></CardHeader>
      <CardContent>
        <p className="mb-3 text-sm">{catalog.models.length} models · Fetched {catalog.fetched_at}. Token rates are USD per token. Negative rates remain unpriced. {inventory?.price_list.entries.length} token rate cards active. Version {inventory?.rate_card_version}. Non-token charges are listed but excluded from token cost calculation.</p>
        <Input aria-label="Search pricing models" placeholder="Search models" value={search} onChange={(e) => setSearch(e.target.value)} />
        <div className="mt-3 max-h-96 overflow-auto">
          {catalog.models.filter((model) => model.id.toLowerCase().includes(search.toLowerCase())).map((model) => <details key={model.id} className="border-b py-2 text-sm">
            <summary className="cursor-pointer font-mono">{model.id} · input {String(model.pricing.prompt)} · output {String(model.pricing.completion)}</summary>
            <p className="mt-2">{model.billing_status}</p>
            <pre className="mt-2 whitespace-pre-wrap text-xs">{JSON.stringify(model.pricing, null, 2)}</pre>
          </details>)}
        </div>

      </CardContent>
    </Card>}
    <Card>
      <CardHeader>
        <CardTitle>Rate card (PUT /pricing)</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          <Field label="rate-card JSON (opaque, sent as-is)">
            <Textarea rows={12} value={raw} onChange={(e) => setRaw(e.target.value)} />
          </Field>
          <Button size="sm" onClick={submit}>Upload rate card</Button>
          <ResultPanel result={result} />
        </div>
      </CardContent>
    </Card>
    </div>
  )
}
