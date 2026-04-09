import { useEffect, useRef, useCallback } from 'react'
import { useAppStore } from '../store/useAppStore'

export function useNetworkMonitor(enabled = true) {
  const { addConnection, setConnections, sidecarStatus } = useAppStore()
  const esRef = useRef<EventSource | null>(null)

  const start = useCallback(() => {
    if (esRef.current || sidecarStatus !== 'ready') return
    const es = new EventSource('http://127.0.0.1:8765/api/network/stream')
    esRef.current = es
    es.onmessage = (ev) => {
      try {
        const d = JSON.parse(ev.data)
        if (d.type === 'new_high_risk_connection' && d.data) addConnection(d.data)
      } catch { /* ignore */ }
    }
    es.onerror = () => {
      es.close(); esRef.current = null
      setTimeout(start, 5000)
    }
  }, [addConnection, sidecarStatus])

  const stop = useCallback(() => {
    esRef.current?.close(); esRef.current = null
  }, [])

  useEffect(() => {
    if (!enabled || sidecarStatus !== 'ready') return
    let cancelled = false
    const poll = async () => {
      try {
        const r = await fetch('http://127.0.0.1:8765/api/network/live')
        if (!cancelled && r.ok) setConnections(await r.json())
      } catch { /* sidecar not ready */ }
    }
    poll()
    const iv = setInterval(poll, 10000)
    start()
    return () => { cancelled = true; clearInterval(iv); stop() }
  }, [enabled, sidecarStatus, setConnections, start, stop])

  return { start, stop }
}
