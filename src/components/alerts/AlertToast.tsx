import React, { useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X, AlertTriangle, ShieldAlert, Info } from 'lucide-react'
import { useAppStore } from '../../store/useAppStore'
import { getRiskColor } from '../../lib/utils'

interface ToastItem {
  id: string
  app_name: string
  title: string
  risk_level: string
  timestamp: string
}

function AlertToast({ toast, onDismiss }: { toast: ToastItem; onDismiss: () => void }) {
  useEffect(() => {
    const t = setTimeout(onDismiss, 8000)
    return () => clearTimeout(t)
  }, [onDismiss])

  const Icon = toast.risk_level === 'SEVERE' ? ShieldAlert
    : toast.risk_level === 'HIGH' ? AlertTriangle
    : Info

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 40, scale: 0.95 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 40, scale: 0.95 }}
      transition={{ type: 'spring', stiffness: 400, damping: 30 }}
      className="flex items-start gap-3 p-3 rounded-card border shadow-xl w-80"
      style={{
        background: 'var(--bg-elevated)',
        borderColor: 'var(--border-default)',
        borderLeftWidth: 3,
        borderLeftColor: getRiskColor(toast.risk_level),
      }}
    >
      <Icon size={16} className="flex-shrink-0 mt-0.5" style={{ color: getRiskColor(toast.risk_level) }} />
      <div className="flex-1 min-w-0">
        <div className="text-sm font-semibold text-text-primary truncate">{toast.app_name}</div>
        <div className="text-xs text-text-secondary mt-0.5 line-clamp-2">{toast.title}</div>
      </div>
      <button onClick={onDismiss} className="flex-shrink-0 text-text-tertiary hover:text-text-primary transition-colors">
        <X size={14} />
      </button>
    </motion.div>
  )
}

export function AlertToastContainer() {
  const { alerts, unreadAlertCount } = useAppStore()
  const [dismissed, setDismissed] = React.useState<Set<string>>(new Set())
  const [shown, setShown] = React.useState<Set<string>>(new Set())

  // Show only the most recent alerts that haven't been shown before
  const toasts = alerts
    .slice(0, 3)
    .filter(a => !dismissed.has(a.id))
    .filter(a => shown.has(a.id))

  // Track newly added alerts
  useEffect(() => {
    if (alerts.length > 0) {
      const newIds = alerts.slice(0, 3).map(a => a.id)
      setShown(prev => {
        const next = new Set(prev)
        newIds.forEach(id => next.add(id))
        return next
      })
    }
  }, [unreadAlertCount])

  const dismiss = (id: string) => {
    setDismissed(prev => new Set([...prev, id]))
  }

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
      <AnimatePresence>
        {toasts.map(toast => (
          <div key={toast.id} className="pointer-events-auto">
            <AlertToast
              toast={toast}
              onDismiss={() => dismiss(toast.id)}
            />
          </div>
        ))}
      </AnimatePresence>
    </div>
  )
}
