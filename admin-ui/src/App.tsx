import { useEffect, useState } from 'react'
import { KeyRound, Link2, Route, Settings2 } from 'lucide-react'
import { Tabs } from './components/ui/tabs'
import { Input } from './components/ui/input'
import { GetStarted } from './components/GetStarted'
import { Keys } from './components/Keys'
import { ModelsPricing } from './components/ModelsPricing'
import { Advanced } from './components/Advanced'
import { loadConn, saveConn, scopedWritePath, type AdminConn } from './lib/api'
import { useAdminState } from './lib/useAdminState'

const TABS = [
  { id: 'start', label: 'Get started' },
  { id: 'keys', label: 'Keys' },
  { id: 'models', label: 'Models & pricing' },
  { id: 'advanced', label: 'Advanced' },
]

export default function App() {
  const [conn, setConn] = useState<AdminConn>(() => loadConn())
  const [tab, setTab] = useState('start')
  // The admin URL is for `npm run dev`, the chain prefix for configs with more than one auth chain. Neither is
  // needed on the embedded UI with one chain, so they stay out of sight unless already set.
  const [showConnection, setShowConnection] = useState(
    () => import.meta.env.DEV || !!conn.adminUrl.trim() || !!conn.chainPrefix.trim(),
  )
  const state = useAdminState(conn)

  useEffect(() => {
    saveConn(conn)
  }, [conn])

  const scopedExample = scopedWritePath('/keys', conn.chainPrefix)

  return (
    <div className="mx-auto min-h-screen max-w-6xl px-4 pb-16">
      <header className="sticky top-0 z-10 -mx-4 border-b border-zinc-200 bg-zinc-50/95 px-4 py-3 backdrop-blur">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="mr-2 text-base font-bold">llm-proxy</h1>
          <label className="flex min-w-52 flex-1 items-center gap-1.5">
            <KeyRound size={14} className="shrink-0 text-zinc-400" />
            <Input
              type="password"
              value={conn.token}
              onChange={(e) => setConn({ ...conn, token: e.target.value })}
              placeholder="Admin token (from the admin-token file or the installer)"
              aria-label="Admin token"
            />
          </label>
          <button
            type="button"
            onClick={() => setShowConnection((v) => !v)}
            className="rounded-md p-2 text-zinc-500 hover:bg-zinc-100"
            title="Connection settings"
            aria-label="Connection settings"
          >
            <Settings2 size={16} />
          </button>
        </div>
        {showConnection && (
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <label className="flex w-64 items-center gap-1.5">
              <Link2 size={14} className="shrink-0 text-zinc-400" />
              <Input
                value={conn.adminUrl}
                onChange={(e) => setConn({ ...conn, adminUrl: e.target.value })}
                placeholder="Admin URL (empty = this server)"
                title="Only for npm run dev, e.g. http://localhost:53422"
              />
            </label>
            <label className="flex w-56 items-center gap-1.5">
              <Route size={14} className="shrink-0 text-zinc-400" />
              <Input
                value={conn.chainPrefix}
                onChange={(e) => setConn({ ...conn, chainPrefix: e.target.value })}
                placeholder="Chain prefix (optional)"
                title="Only for configs with more than one auth chain: prepended to write paths as /chains/{prefix}"
              />
            </label>
            {conn.chainPrefix.trim() && (
              <p className="font-mono text-[11px] text-zinc-500">writes go to {scopedExample}…</p>
            )}
          </div>
        )}
      </header>

      <div className="mt-4">
        <Tabs tabs={TABS} active={tab} onChange={setTab} />
      </div>

      {/* Every page stays mounted, so switching tabs keeps what the user typed. */}
      <main className="mt-4">
        <div hidden={tab !== 'start'}>
          <GetStarted conn={conn} state={state} onNavigate={setTab} />
        </div>
        <div hidden={tab !== 'keys'}>
          <Keys conn={conn} state={state} />
        </div>
        <div hidden={tab !== 'models'}>
          <ModelsPricing conn={conn} state={state} />
        </div>
        <div hidden={tab !== 'advanced'}>
          <Advanced conn={conn} />
        </div>
      </main>
    </div>
  )
}
