import { Badge } from './ui/badge'
import { Table, THead, TRow, TH, TD } from './ui/table'
import type { Routing } from '../lib/onboarding'

/** Which models go to which provider, from `GET /models`. Read-only: routes live in the config file. */
export function RoutingTable({ routing }: { routing: Routing | null }) {
  if (!routing) return <p className="text-xs text-zinc-500">Loading routes...</p>
  if (routing.models.length === 0 && routing.pathRoutes.length === 0) {
    return (
      <p className="text-xs text-zinc-500">
        No routes. Add a provider and a route in the config file, then reload the proxy.
      </p>
    )
  }
  return (
    <div className="space-y-2">
      <Table>
        <THead>
          <TRow>
            <TH>Model</TH>
            <TH>Match</TH>
            <TH>Goes to</TH>
          </TRow>
        </THead>
        <tbody>
          {routing.models.map((m) => (
            <TRow key={`${m.route_table}/${m.route ?? ''}/${m.model}`}>
              <TD className="font-mono text-xs">{m.model}</TD>
              <TD>
                <Badge tone={m.match === 'exact' ? 'green' : 'default'}>{m.match}</Badge>
              </TD>
              <TD className="font-mono text-xs">{m.target ?? '-'}</TD>
            </TRow>
          ))}
          {routing.pathRoutes.map((r) => (
            <TRow key={`${r.route_table}/${r.route ?? ''}/${r.path}`}>
              <TD className="text-xs">any model</TD>
              <TD>
                <Badge>{r.path}</Badge>
              </TD>
              <TD className="font-mono text-xs">{r.target ?? '-'}</TD>
            </TRow>
          ))}
        </tbody>
      </Table>
      <p className="text-xs text-zinc-500">
        Routes and providers are set in the config file. "any model" rows match on the request path only, so they
        serve every model that reaches them.
      </p>
    </div>
  )
}
