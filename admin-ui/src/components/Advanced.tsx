import { useState } from 'react'
import { Tabs } from './ui/tabs'
import { Overview } from './Overview'
import { Clusters } from './Clusters'
import { Tenants } from './Tenants'
import type { AdminConn } from '../lib/api'

const SECTIONS = [
  { id: 'tenants', label: 'Tenants' },
  { id: 'clusters', label: 'Clusters and config' },
  { id: 'status', label: 'Status and stats' },
]

/** Operator views a single team does not need to get started; each keeps its state while hidden. */
export function Advanced({ conn }: { conn: AdminConn }) {
  const [section, setSection] = useState('tenants')
  return (
    <div className="space-y-4">
      <Tabs tabs={SECTIONS} active={section} onChange={setSection} />
      <div hidden={section !== 'tenants'}>
        <Tenants conn={conn} />
      </div>
      <div hidden={section !== 'clusters'}>
        <Clusters conn={conn} />
      </div>
      <div hidden={section !== 'status'}>
        <Overview conn={conn} />
      </div>
    </div>
  )
}
