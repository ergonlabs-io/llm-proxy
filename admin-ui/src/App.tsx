import { useEffect, useState } from 'react'
import { KeyRound, Link2, Route } from 'lucide-react'
import { Tabs } from './components/ui/tabs'
import { Input } from './components/ui/input'
import { Overview } from './components/Overview'
import { Clusters } from './components/Clusters'
import { Tenants } from './components/Tenants'
import { Keys } from './components/Keys'
import { Pricing } from './components/Pricing'
import { Capture } from './components/Capture'
import { loadConn, saveConn, scopedWritePath, type AdminConn } from './lib/api'

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'clusters', label: 'Clusters' },
  { id: 'tenants', label: 'Tenants' },
  { id: 'keys', label: 'Keys' },
  { id: 'pricing', label: 'Pricing' },
  { id: 'capture', label: 'Capture' },
]

export default function App() {
  const [conn, setConn] = useState<AdminConn>(() => loadConn())
  const [tab, setTab] = useState('overview')

  useEffect(() => {
    saveConn(conn)
  }, [conn])

  const scopedExample = scopedWritePath('/keys', conn.chainPrefix)

  return (
    <div className="mx-auto min-h-screen max-w-6xl px-4 pb-16">
      <header className="sticky top-0 z-10 -mx-4 border-b border-zinc-200 bg-zinc-50/95 px-4 py-3 backdrop-blur">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="mr-2 text-base font-bold">llm-proxy admin</h1>
          <label className="flex min-w-52 flex-1 items-center gap-1.5">
            <KeyRound size={14} className="shrink-0 text-zinc-400" />
            <Input
              type="password"
              value={conn.token}
              onChange={(e) => setConn({ ...conn, token: e.target.value })}
              placeholder="Bearer token (writes + spend reads)"
            />
          </label>
          <label className="flex w-56 items-center gap-1.5">
            <Link2 size={14} className="shrink-0 text-zinc-400" />
            <Input
              value={conn.adminUrl}
              onChange={(e) => setConn({ ...conn, adminUrl: e.target.value })}
              placeholder="Admin URL (empty = same origin)"
              title="Override for npm run dev, e.g. http://localhost:8080"
            />
          </label>
          <label className="flex w-44 items-center gap-1.5">
            <Route size={14} className="shrink-0 text-zinc-400" />
            <Input
              value={conn.chainPrefix}
              onChange={(e) => setConn({ ...conn, chainPrefix: e.target.value })}
              placeholder="chain prefix (optional)"
              title="Prepended to write paths as /chains/{prefix}"
            />
          </label>
        </div>
        {conn.chainPrefix.trim() && (
          <p className="mt-1 font-mono text-[11px] text-zinc-500">
            writes go to {scopedExample}… (unscoped by default)
          </p>
        )}
      </header>

      <div className="mt-4">
        <Tabs tabs={TABS} active={tab} onChange={setTab} />
      </div>

      <main className="mt-4">
        {tab === 'overview' && <Overview conn={conn} />}
        {tab === 'clusters' && <Clusters conn={conn} />}
        {tab === 'tenants' && <Tenants conn={conn} />}
        {tab === 'keys' && <Keys conn={conn} />}
        {tab === 'pricing' && <Pricing conn={conn} />}
        {tab === 'capture' && <Capture conn={conn} />}
      </main>
    </div>
  )
}
