import { useState } from 'react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Textarea } from './ui/input'
import { Field, ResultPanel } from './forms'
import { apiFetch, type AdminConn, type ApiResult } from '../lib/api'

const SAMPLE = `{
  "version": 1,
  "models": {}
}`

export function Pricing({ conn }: { conn: AdminConn }) {
  const [raw, setRaw] = useState(SAMPLE)
  const [result, setResult] = useState<ApiResult | null>(null)
  const [error, setError] = useState<string | null>(null)

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
    setResult(
      await apiFetch(conn, '/pricing', {
        method: 'PUT',
        auth: true,
        scopedWrite: true,
        body: parsed,
      }),
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Rate card (PUT /pricing)</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          <Field label="rate-card JSON (opaque, sent as-is)">
            <Textarea rows={12} value={raw} onChange={(e) => setRaw(e.target.value)} />
          </Field>
          {error && <p className="text-xs text-red-600">{error}</p>}
          <Button size="sm" onClick={submit}>Upload rate card</Button>
          <ResultPanel result={result} />
        </div>
      </CardContent>
    </Card>
  )
}
