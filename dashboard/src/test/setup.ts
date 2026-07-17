import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterAll, afterEach, beforeAll, vi } from 'vitest'
import { server } from './server'
import '../index.css'

interface MutableMediaQueryList extends MediaQueryList {
  update(): void
}

let viewportWidth = 1280
const mediaQueries = new Set<MutableMediaQueryList>()

function matches(query: string): boolean {
  const maxWidth = query.match(/max-width:\s*(\d+)px/)
  const minWidth = query.match(/min-width:\s*(\d+)px/)
  if (maxWidth && viewportWidth > Number(maxWidth[1])) return false
  if (minWidth && viewportWidth < Number(minWidth[1])) return false
  return true
}

Object.defineProperty(window, 'matchMedia', {
  configurable: true,
  value: (query: string): MediaQueryList => {
    const listeners = new Set<(event: MediaQueryListEvent) => void>()
    let currentMatch = matches(query)
    const mediaQuery: MutableMediaQueryList = {
      media: query,
      get matches() {
        return currentMatch
      },
      onchange: null,
      addEventListener: (
        _type: string,
        listener: EventListenerOrEventListenerObject,
      ) => {
        listeners.add(listener as (event: MediaQueryListEvent) => void)
      },
      removeEventListener: (
        _type: string,
        listener: EventListenerOrEventListenerObject,
      ) => {
        listeners.delete(listener as (event: MediaQueryListEvent) => void)
      },
      addListener: (listener) => {
        if (listener) listeners.add(listener)
      },
      removeListener: (listener) => {
        if (listener) listeners.delete(listener)
      },
      dispatchEvent: () => true,
      update() {
        const nextMatch = matches(query)
        if (nextMatch === currentMatch) return
        currentMatch = nextMatch
        const event = {
          matches: currentMatch,
          media: query,
        } as MediaQueryListEvent
        listeners.forEach((listener) => listener(event))
        mediaQuery.onchange?.(event)
      },
    }
    mediaQueries.add(mediaQuery)
    return mediaQuery
  },
})

Object.defineProperty(navigator, 'clipboard', {
  configurable: true,
  value: {
    writeText: vi.fn().mockResolvedValue(undefined),
  },
})

export function setViewport(width: number): void {
  viewportWidth = width
  mediaQueries.forEach((mediaQuery) => mediaQuery.update())
}

export function setOnline(online: boolean): void {
  Object.defineProperty(navigator, 'onLine', {
    configurable: true,
    value: online,
  })
  window.dispatchEvent(new Event(online ? 'online' : 'offline'))
}

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))

afterEach(() => {
  cleanup()
  server.resetHandlers()
  setViewport(1280)
  setOnline(true)
  window.history.replaceState(null, '', '/active')
  vi.useRealTimers()
})

afterAll(() => server.close())
