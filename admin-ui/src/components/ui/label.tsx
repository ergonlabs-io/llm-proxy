import type { LabelHTMLAttributes } from 'react'

export function Label(props: LabelHTMLAttributes<HTMLLabelElement>) {
  return (
    <label
      {...props}
      className={`mb-1 block text-xs font-medium text-zinc-600 ${props.className ?? ''}`}
    />
  )
}
