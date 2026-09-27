import type { ReactNode } from 'react'

type Tone = 'default' | 'green' | 'red' | 'amber'

const tones: Record<Tone, string> = {
  default: 'bg-zinc-100 text-zinc-700',
  green: 'bg-green-100 text-green-800',
  red: 'bg-red-100 text-red-800',
  amber: 'bg-amber-100 text-amber-800',
}

export function Badge({ tone = 'default', children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${tones[tone]}`}>
      {children}
    </span>
  )
}
