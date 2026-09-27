import type { ReactNode } from 'react'
import { Badge } from './ui/badge'
import type { ApiResult } from '../lib/api'
import { pretty } from '../lib/api'

export function ResultPanel({ result }: { result: ApiResult | null }) {
  if (!result) return <p className="text-xs text-zinc-400">No request yet.</p>
  return (
    <div className="space-y-2">
      <Badge tone={result.ok ? 'green' : result.status === 0 ? 'amber' : 'red'}>
        {result.status === 0 ? 'network error' : `HTTP ${result.status}`}
      </Badge>
      <pre className="result-panel max-h-96 overflow-auto rounded-md bg-zinc-950 p-3 text-zinc-100">
        {pretty(result.bodyText)}
      </pre>
    </div>
  )
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-zinc-600">{label}</span>
      {children}
    </label>
  )
}
