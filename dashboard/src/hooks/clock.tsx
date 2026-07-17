/* oxlint-disable react/only-export-components */
import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react'

const ClockContext = createContext<number | null>(null)

export function ClockProvider({
  children,
  now: controlledNow,
}: {
  children: ReactNode
  now?: number
}) {
  const [internalNow, setInternalNow] = useState(() => Date.now())

  useEffect(() => {
    if (controlledNow !== undefined) return undefined
    const interval = window.setInterval(
      () => setInternalNow(Date.now()),
      1_000,
    )
    return () => window.clearInterval(interval)
  }, [controlledNow])

  return (
    <ClockContext value={controlledNow ?? internalNow}>
      {children}
    </ClockContext>
  )
}

export function useServerNow(serverOffsetMs = 0): number {
  const now = useContext(ClockContext)
  if (now === null) {
    throw new Error('useServerNow must be used within ClockProvider')
  }
  return now + serverOffsetMs
}
