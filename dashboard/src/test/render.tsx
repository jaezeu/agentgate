import {
  QueryClient,
  QueryClientProvider,
} from '@tanstack/react-query'
import { act, render, type RenderOptions } from '@testing-library/react'
import {
  useState,
  type ReactElement,
  type ReactNode,
} from 'react'
import { AgentGateClient } from '../api/client'
import { ApiProvider } from '../api/context'
import { ClockProvider } from '../hooks/clock'

export function createTestClient(): AgentGateClient {
  return new AgentGateClient('http://localhost/')
}

export function renderView(
  ui: ReactElement,
  {
    client = createTestClient(),
    clockNow,
    ...renderOptions
  }: RenderOptions & {
    client?: AgentGateClient
    clockNow?: number
  } = {},
) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  })

  let updateClock: ((now: number) => void) | undefined

  function Wrapper({ children }: { children: ReactNode }) {
    const [now, setNow] = useState(clockNow)
    updateClock = setNow
    return (
      <QueryClientProvider client={queryClient}>
        <ApiProvider client={client}>
          <ClockProvider now={now}>{children}</ClockProvider>
        </ApiProvider>
      </QueryClientProvider>
    )
  }

  return {
    client,
    queryClient,
    setClock(now: number) {
      if (!updateClock) throw new Error('Test clock is not mounted')
      act(() => updateClock?.(now))
    },
    ...render(ui, { wrapper: Wrapper, ...renderOptions }),
  }
}
