/* oxlint-disable react/only-export-components */
import { createContext, useContext, type ReactNode } from 'react'
import type { AgentGateClient } from './client'

const ApiContext = createContext<AgentGateClient | null>(null)

export function ApiProvider({
  client,
  children,
}: {
  client: AgentGateClient
  children: ReactNode
}) {
  return <ApiContext value={client}>{children}</ApiContext>
}

export function useApi(): AgentGateClient {
  const client = useContext(ApiContext)
  if (!client) {
    throw new Error('useApi must be used within ApiProvider')
  }
  return client
}
