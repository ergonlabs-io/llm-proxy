import { useEffect, useState } from 'react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Input, Textarea } from './ui/input'
import { Table, THead, TRow, TH, TD } from './ui/table'
import { Field, ResultPanel } from './forms'
import { apiFetch, type AdminConn, type ApiResult } from '../lib/api'
import type { AdminState } from '../lib/useAdminState'
import { friendlyPricingError, pricingTemplate, usdPerMillionToNanodollars } from '../lib/onboarding'

type Catalog = { fetched_at: string; models: { id: string; pricing: Record<string, unknown>; billing_status: string }[] }
interface Tier {
  input_nanodollars_per_token?: number
  output_nanodollars_per_token?: number
  cached_input_nanodollars_per_token?: number
}
interface Entry {
  provider_type: string
  model: string
  basis?: string
  tiers?: Tier[]
}
type PricingInventory = {
  catalog?: Catalog
  rate_card_version: string
  price_list: { entries: Entry[] }
  providers: Record<string, string>
}

/** Nanodollars per token as USD per 1M tokens, the unit provider price pages use. */
function perMillion(n: number | undefined): string {
  return n === undefined ? '-' : `$${(n / 1000).toFixed(n % 1000 === 0 ? 2 : 4)}`
}

function validCatalog(value: PricingInventory): Catalog | null {
  const c = value.catalog
  return c &&
    Array.isArray(c.models) &&
    c.models.every((model) => typeof model?.id === 'string' && model.pricing && typeof model.pricing === 'object')
    ? c
    : null
}

export function Pricing({ conn, state }: { conn: AdminConn; state: AdminState }) {
  const [search, setSearch] = useState('')
  const [raw, setRaw] = useState('')
  const [result, setResult] = useState<ApiResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [usd, setUsd] = useState('')

  const inventory: PricingInventory | null = (() => {
    if (!state.pricing?.ok) return null
    try {
      return JSON.parse(state.pricing.bodyText) as PricingInventory
    } catch {
      return null
    }
  })()
  const catalog = inventory ? validCatalog(inventory) : null
  const noCard = state.pricing !== null && state.pricing.status === 503

  // Seed the editor once with the active card, so an edit starts from what is live.
  useEffect(() => {
    if (raw || !inventory) return
    setRaw(
      JSON.stringify({ price_list: inventory.price_list, providers: inventory.providers, catalog: inventory.catalog }, null, 2),
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.pricing])

  function insertTemplate() {
    const clusters = (state.clusters ?? []).map((c) => c.name)
    const models = (state.routing?.models ?? []).filter((m) => m.match === 'exact').map((m) => m.model)
    setRaw(pricingTemplate(clusters, models, new Date().toISOString().slice(0, 10)))
  }

  async function submit() {
    setError(null)
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch (e) {
      setError(`Not valid JSON: ${String(e)}`)
      return
    }
    if (raw.includes('PROVIDER_TYPE') || raw.includes('MODEL_NAME')) {
      setError('Replace every PROVIDER_TYPE and MODEL_NAME placeholder first.')
      return
    }
    const response = await apiFetch(conn, '/pricing', {
      method: 'PUT',
      auth: true,
      scopedWrite: true,
      body: parsed,
    })
    setResult(response.ok ? response : { ...response, bodyText: friendlyPricingError(response.bodyText) })
    if (response.ok) state.refresh()
  }

  const nano = Number(usd)
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Prices</CardTitle>
        </CardHeader>
        <CardContent>
          {noCard && (
            <p className="mb-3 rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-800">
              No prices are set, so every request costs $0 and spend limits never refuse. Add prices below.
            </p>
          )}
          {inventory && (
            <>
              <p className="mb-2 text-xs text-zinc-500">Version {inventory.rate_card_version}. Prices are USD per 1M tokens.</p>
              <Table>
                <THead>
                  <TRow>
                    <TH>Model</TH>
                    <TH>Provider type</TH>
                    <TH>Input</TH>
                    <TH>Cached input</TH>
                    <TH>Output</TH>
                  </TRow>
                </THead>
                <tbody>
                  {inventory.price_list.entries.slice(0, 200).map((e) => {
                    const t = e.tiers?.[0]
                    return (
                      <TRow key={`${e.provider_type}/${e.model}`}>
                        <TD className="font-mono text-xs">{e.model}</TD>
                        <TD className="text-xs">{e.provider_type}</TD>
                        <TD className="text-xs">{e.basis && e.basis !== 'tokens' ? e.basis : perMillion(t?.input_nanodollars_per_token)}</TD>
                        <TD className="text-xs">{perMillion(t?.cached_input_nanodollars_per_token)}</TD>
                        <TD className="text-xs">{perMillion(t?.output_nanodollars_per_token)}</TD>
                      </TRow>
                    )
                  })}
                </tbody>
              </Table>
              {inventory.price_list.entries.length > 200 && (
                <p className="mt-2 text-xs text-zinc-500">Showing 200 of {inventory.price_list.entries.length} entries.</p>
              )}
            </>
          )}
          {state.pricing && !state.pricing.ok && !noCard && <ResultPanel result={state.pricing} />}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Edit prices</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <p className="text-xs text-zinc-600">
              The rate card lists a price per model and provider type, in nanodollars per token, and maps each provider
              (cluster) to its provider type. Start from a template, fill in the placeholders, then save.
            </p>
            <div className="flex flex-wrap items-end gap-2">
              <Button size="sm" variant="outline" onClick={insertTemplate}>
                Insert template for configured providers
              </Button>
              <label className="flex items-center gap-1 text-xs text-zinc-600">
                $ per 1M tokens
                <Input className="h-8 w-24" value={usd} onChange={(e) => setUsd(e.target.value)} placeholder="0.15" />
                <span>
                  ={' '}
                  <code className="font-mono">
                    {usd.trim() && Number.isFinite(nano) ? usdPerMillionToNanodollars(nano) : '?'}
                  </code>{' '}
                  nanodollars per token
                </span>
              </label>
            </div>
            <Field label="Rate card (JSON)">
              <Textarea rows={14} value={raw} onChange={(e) => setRaw(e.target.value)} spellCheck={false} />
            </Field>
            {error && <p className="text-xs text-red-600">{error}</p>}
            <Button size="sm" onClick={() => void submit()} disabled={!conn.token}>
              Save prices
            </Button>
            {!conn.token && <span className="ml-2 text-xs text-zinc-500">Paste the admin token at the top first.</span>}
            <ResultPanel result={result} />
            <p className="text-xs text-zinc-500">
              Prices saved here live in the proxy's store: with the in-memory store they are lost on restart. To keep
              them, put its <code className="font-mono">price_list</code> under{' '}
              <code className="font-mono">pricing:</code> in the config file (the config maps providers to their types
              itself), or use a persistent or shared <code className="font-mono">auth.store</code>.
            </p>
          </div>
        </CardContent>
      </Card>

      {catalog && (
        <Card>
          <CardHeader>
            <CardTitle>Public price catalog</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="mb-3 text-sm">
              {catalog.models.length} models, fetched {catalog.fetched_at}. Token rates are USD per token. Reference only;
              not used for cost.
            </p>
            <Input aria-label="Search pricing models" placeholder="Search models" value={search} onChange={(e) => setSearch(e.target.value)} />
            <div className="mt-3 max-h-96 overflow-auto">
              {catalog.models
                .filter((model) => model.id.toLowerCase().includes(search.toLowerCase()))
                .map((model) => (
                  <details key={model.id} className="border-b py-2 text-sm">
                    <summary className="cursor-pointer font-mono">
                      {model.id} · input {String(model.pricing.prompt)} · output {String(model.pricing.completion)}
                    </summary>
                    <p className="mt-2">{model.billing_status}</p>
                    <pre className="mt-2 whitespace-pre-wrap text-xs">{JSON.stringify(model.pricing, null, 2)}</pre>
                  </details>
                ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
