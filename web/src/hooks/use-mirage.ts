import { useCallback, useEffect, useRef, useState } from "react"

import { fetchState, type MirageState, type Severity } from "@/lib/api"

export interface IncidentEvent {
  id: string
  severity: Severity
  stage: string
  new: boolean
}

export interface AlertEvent {
  title: string
  detail: string
}

interface Options {
  onIncident?: (event: IncidentEvent) => void
  onAlert?: (event: AlertEvent) => void
}

/**
 * Live control-plane state: one fetch on mount, a push stream (server-sent events) for
 * instant updates, and a 3-second poll as a safety net if the stream drops.
 */
export function useMirage(options: Options = {}) {
  const [state, setState] = useState<MirageState | null>(null)
  const [error, setError] = useState<string | null>(null)
  // Server clock minus browser clock, so "Xs ago" uses the server's notion of now.
  const [offset, setOffset] = useState(0)
  const handlers = useRef(options)
  const inflight = useRef(false)
  const again = useRef(false)

  useEffect(() => {
    handlers.current = options
  })

  // Coalesces bursts: while a fetch is running, further calls just ask for one more pass.
  const refresh = useCallback(async () => {
    if (inflight.current) {
      again.current = true
      return
    }
    inflight.current = true
    try {
      do {
        again.current = false
        try {
          const next = await fetchState()
          setState(next)
          setOffset(next.health.now - Date.now() / 1000)
          setError(null)
        } catch (err) {
          setError(err instanceof Error ? err.message : "The control plane is unreachable.")
        }
      } while (again.current)
    } finally {
      inflight.current = false
    }
  }, [])

  useEffect(() => {
    void refresh()
    const id = window.setInterval(refresh, 3000)
    return () => window.clearInterval(id)
  }, [refresh])

  useEffect(() => {
    const events = new EventSource("/events")
    events.addEventListener("incident", (e) => {
      handlers.current.onIncident?.(JSON.parse((e as MessageEvent).data) as IncidentEvent)
      void refresh()
    })
    events.addEventListener("alert", (e) => {
      handlers.current.onAlert?.(JSON.parse((e as MessageEvent).data) as AlertEvent)
      void refresh()
    })
    events.addEventListener("changed", () => void refresh())
    return () => events.close()
  }, [refresh])

  return { state, error, refresh, offset }
}

/** Seconds since the epoch on the server's clock, re-rendering every `intervalMs`. */
export function useServerNow(offset: number, intervalMs = 1000) {
  const [clientNow, setClientNow] = useState(() => Date.now() / 1000)
  useEffect(() => {
    const id = window.setInterval(() => setClientNow(Date.now() / 1000), intervalMs)
    return () => window.clearInterval(id)
  }, [intervalMs])
  return clientNow + offset
}
