import { CheckCircle2, Circle, CircleAlert, Loader2, RefreshCw } from 'lucide-react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Table, THead, TRow, TH, TD } from './ui/table'
import type { AdminConn } from '../lib/api'
import type { AdminState } from '../lib/useAdminState'
import { checklist, type StepState } from '../lib/onboarding'
import { RoutingTable } from './Routing'

const NEXT_TAB: Record<string, { tab: string; label: string } | undefined> = {
  key: { tab: 'keys', label: 'Open Keys' },
  pricing: { tab: 'models', label: 'Open Models & pricing' },
  'first-request': { tab: 'keys', label: 'Create a key' },
}

function StepIcon({ state }: { state: StepState }) {
  switch (state) {
    case 'done':
      return <CheckCircle2 size={18} className="shrink-0 text-green-600" />
    case 'blocked':
      return <CircleAlert size={18} className="shrink-0 text-red-600" />
    case 'unknown':
      return <Loader2 size={18} className="shrink-0 animate-spin text-zinc-400" />
    default:
      return <Circle size={18} className="shrink-0 text-zinc-400" />
  }
}

export function GetStarted({
  conn,
  state,
  onNavigate,
}: {
  conn: AdminConn
  state: AdminState
  onNavigate: (tab: string) => void
}) {
  const steps = checklist({
    ready: state.ready && { status: state.ready.status, body: state.ready.bodyText },
    keys: state.keys && { status: state.keys.status, body: state.keys.bodyText },
    hasToken: !!conn.token,
    clusterCount: state.clusters?.length ?? null,
    routing: state.routing,
    pricingStatus: state.pricing?.status ?? null,
    tokensSeen: state.tokensSeen,
  })
  const remaining = steps.filter((s) => s.state !== 'done').length

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-2">
            <CardTitle>
              {remaining === 0 ? 'You are set up' : `Get started: ${remaining} step${remaining === 1 ? '' : 's'} left`}
            </CardTitle>
            <Button size="sm" variant="outline" onClick={state.refresh} disabled={state.loading}>
              <RefreshCw size={14} /> Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <ol className="space-y-3">
            {steps.map((s) => {
              const next = NEXT_TAB[s.id]
              return (
                <li key={s.id} className="flex items-start gap-3">
                  <StepIcon state={s.state} />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium">{s.title}</p>
                    <p className="text-xs text-zinc-600">{s.detail}</p>
                  </div>
                  {next && s.state === 'todo' && (
                    <Button size="sm" variant="outline" onClick={() => onNavigate(next.tab)}>
                      {next.label}
                    </Button>
                  )}
                </li>
              )
            })}
          </ol>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Usage by tenant and provider</CardTitle>
        </CardHeader>
        <CardContent>
          {state.usage && state.usage.length > 0 ? (
            <Table>
              <THead>
                <TRow>
                  <TH>Tenant</TH>
                  <TH>Provider</TH>
                  <TH>Input tokens</TH>
                  <TH>Output tokens</TH>
                </TRow>
              </THead>
              <tbody>
                {state.usage.map((u) => (
                  <TRow key={`${u.tenant}/${u.provider}`}>
                    <TD>{u.tenant}</TD>
                    <TD>{u.provider}</TD>
                    <TD>{u.input}</TD>
                    <TD>{u.output}</TD>
                  </TRow>
                ))}
              </tbody>
            </Table>
          ) : (
            <p className="text-xs text-zinc-500">
              No tokens metered yet. Counts start at zero each time the proxy starts. Spend per key is on the Keys
              page.
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Routing</CardTitle>
        </CardHeader>
        <CardContent>
          <RoutingTable routing={state.routing} />
        </CardContent>
      </Card>
    </div>
  )
}
