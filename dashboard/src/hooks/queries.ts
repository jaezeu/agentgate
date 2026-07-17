import { useQuery } from '@tanstack/react-query'
import type { RequestFilters } from '../api/client'
import { useApi } from '../api/context'
import { CompatibilityError } from '../api/schema'

function retryRequest(failureCount: number, error: unknown): boolean {
  if (error instanceof CompatibilityError) return false
  if (
    typeof error === 'object' &&
    error !== null &&
    'status' in error &&
    typeof error.status === 'number' &&
    error.status < 500
  ) {
    return false
  }
  return failureCount < 1
}

export function useRequestList(filters: RequestFilters) {
  const api = useApi()
  return useQuery({
    queryKey: ['requests', filters],
    queryFn: ({ signal }) => api.listRequests(filters, signal),
    retry: retryRequest,
    retryDelay: 100,
    staleTime: 20_000,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
  })
}

export function useRequestDetail(requestId: string, enabled = true) {
  const api = useApi()
  return useQuery({
    queryKey: ['request', requestId],
    queryFn: ({ signal }) => api.getRequest(requestId, signal),
    enabled,
    retry: retryRequest,
    retryDelay: 100,
    staleTime: 20_000,
  })
}
