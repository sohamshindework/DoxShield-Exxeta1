import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { RefreshCw, Download, AlertTriangle, Info, Loader2 } from 'lucide-react'
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { useAppStore } from '../../store/useAppStore'
import { RiskGauge } from './RiskGauge'
import { AppRiskCard } from './AppRiskCard'
import { NetworkFeed } from './NetworkFeed'
import { getRiskColor, formatRelativeTime } from '../../lib/utils'
import { SIDECAR_BASE } from '../../hooks/useSidecar'
import { exportReport } from '../../lib/report'

function MiniBar({ value }: { value: number }) {
  const pct = Math.min(value, 100)
  const color = value <= 25 ? 'var(--risk-low)' : value <= 50 ? 'var(--risk-medium)' : 'var(--risk-high)'
  return (
    <div className="w-20 h-1 rounded-full bg-bg-tertiary overflow-hidden">
      <motion.div className="h-full rounded-full" style={{ background: color }}
        initial={{ width: 0 }} animate={{ width: `${pct}%` }} transition={{ duration: 0.8, ease: 'easeOut' }}
      />
    </div>
  )
}

export function ConsumerDashboard() {
  const { overallRisk, apps, cookies, lastScanAt, isScanning, setIsScanning, setScanProgress, setOverallRisk, setApps, setCookies, setLastScanAt, alerts } = useAppStore()
  const topApps = [...apps].sort((a, b) => b.risk_score - a.risk_score).slice(0, 5)
  const [exporting, setExporting] = useState(false)
  const [exportStatus, setExportStatus] = useState<{ ok: boolean; msg: string } | null>(null)

  const pieData = [
    { name: 'App Risk',     value: overallRisk?.app_risk_score     || 0 },
    { name: 'Network Risk', value: overallRisk?.network_risk_score || 0 },
    { name: 'Cookie Risk',  value: overallRisk?.cookie_risk_score  || 0 },
  ]
  const PIE_COLORS = ['var(--risk-high)', 'var(--risk-medium)', 'var(--risk-severe)']

  const handleRescan = async () => {
    setIsScanning(true)
    const es = new EventSource(`${SIDECAR_BASE}/api/scan/full-stream`)
    es.onmessage = (ev) => {
      try {
        const d = JSON.parse(ev.data)
        if (d.step === 'complete') {
          es.close(); setIsScanning(false); setScanProgress(null)
          if (d.data?.overall) setOverallRisk(d.data.overall)
          if (d.data?.apps) setApps(d.data.apps)
          if (d.data?.cookies) setCookies(d.data.cookies)
          if (d.data?.scanned_at) setLastScanAt(d.data.scanned_at)
        } else if (d.step === 'error') {
          es.close(); setIsScanning(false)
        } else {
          setScanProgress({ step: d.step, detail: d.detail })
        }
      } catch { /* ignore */ }
    }
    es.onerror = () => { es.close(); setIsScanning(false) }
  }

  const handleExport = async () => {
    setExporting(true)
    setExportStatus(null)
    try {
      await exportReport(useAppStore.getState())
      setExportStatus({ ok: true, msg: 'Report saved!' })
    } catch {
      setExportStatus({ ok: false, msg: 'Export failed' })
    } finally {
      setExporting(false)
      setTimeout(() => setExportStatus(null), 4000)
    }
  }

  const actions = topApps
    .flatMap(app => app.recommended_actions.map(a => ({ ...a, appName: app.app_name })))
    .sort((a, b) => (a.priority === 'HIGH' ? -1 : 1)).slice(0, 5)

  const recentAlerts = alerts.slice(0, 3)

  return (
    <div className="p-6 space-y-5">
      <div className="grid grid-cols-[65fr_35fr] gap-5">
        {/* LEFT */}
        <div className="space-y-5">

          {/* Risk score card */}
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}
            className="rounded-card p-4 border" style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-subtle)' }}>
            <div className="grid grid-cols-3 gap-4">
              <div className="flex items-center justify-center">
                <RiskGauge score={overallRisk?.sovereignty_score ?? 0} size={160} />
              </div>
              <div className="flex flex-col justify-center gap-3">
                <div className="text-md text-text-secondary font-medium">Overall Sovereignty Score</div>
                <div className="h-px bg-border-subtle" />
                {[
                  { label: 'App Risk',     score: overallRisk?.app_risk_score     ?? 0 },
                  { label: 'Network Risk', score: overallRisk?.network_risk_score ?? 0 },
                  { label: 'Cookie Risk',  score: overallRisk?.cookie_risk_score  ?? 0 },
                ].map(({ label, score }) => (
                  <div key={label} className="flex items-center gap-2">
                    <span className="text-xs text-text-secondary w-24">{label}</span>
                    <MiniBar value={score} />
                    <span className="text-xs text-text-primary font-medium w-6 text-right">{score}</span>
                  </div>
                ))}
              </div>
              <div className="flex flex-col justify-center gap-2">
                <div className="text-xs text-text-tertiary">
                  {lastScanAt ? `Last scanned ${formatRelativeTime(lastScanAt)}` : 'Never scanned'}
                </div>
                <button onClick={handleRescan} disabled={isScanning}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-button text-xs font-medium transition-colors"
                  style={{ background: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-default)' }}>
                  <RefreshCw size={12} className={isScanning ? 'animate-spin' : ''} />
                  {isScanning ? 'Scanning…' : 'Rescan Now'}
                </button>
                <div className="flex flex-col items-start gap-1">
                  {exportStatus && (
                    <span className="text-[10px]" style={{ color: exportStatus.ok ? 'var(--risk-low)' : 'var(--risk-high)' }}>
                      {exportStatus.msg}
                    </span>
                  )}
                  <button
                    onClick={handleExport}
                    disabled={exporting}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-button text-xs font-medium hover:bg-bg-tertiary transition-colors disabled:opacity-50"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    {exporting ? <Loader2 size={12} className="animate-spin" /> : <Download size={12} />}
                    {exporting ? 'Generating…' : 'Export Report'}
                  </button>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Top apps */}
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05, duration: 0.2 }}
            className="rounded-card border" style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-subtle)' }}>
            <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderBottomColor: 'var(--border-subtle)' }}>
              <h2 className="text-lg font-semibold text-text-primary">Applications</h2>
              <button className="text-xs text-accent-blue hover:underline" onClick={() => useAppStore.getState().setCurrentPage('apps')}>View All →</button>
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
              {topApps.length === 0
                ? <div className="px-4 py-8 text-center text-text-tertiary text-base">Run a scan to see app risks.</div>
                : topApps.map((app, i) => <AppRiskCard key={app.app_id} app={app} index={i} />)
              }
            </div>
          </motion.div>

          {/* Live network */}
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1, duration: 0.2 }}
            className="rounded-card border" style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-subtle)' }}>
            <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderBottomColor: 'var(--border-subtle)' }}>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-semibold text-text-primary">Live Network Connections</h2>
                <div className="relative w-2 h-2 live-dot"><div className="w-full h-full rounded-full bg-risk-low" /></div>
              </div>
              <span className="text-xs text-text-tertiary">Updates every 10s</span>
            </div>
            <div className="p-2"><NetworkFeed /></div>
          </motion.div>
        </div>

        {/* RIGHT */}
        <div className="space-y-5">

          {/* Quick actions */}
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.06, duration: 0.2 }}
            className="rounded-card border" style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-subtle)' }}>
            <div className="px-4 py-3 border-b" style={{ borderBottomColor: 'var(--border-subtle)' }}>
              <h2 className="text-lg font-semibold text-text-primary">Recommended Actions</h2>
            </div>
            <div className="p-3 space-y-2">
              {actions.length === 0
                ? <div className="text-center py-4 text-text-tertiary text-base">Run a scan to see recommendations</div>
                : actions.map((a, i) => (
                  <div key={i} className="flex items-start gap-2.5 p-2.5 rounded-lg hover:bg-bg-tertiary transition-colors cursor-pointer">
                    {a.priority === 'HIGH'
                      ? <AlertTriangle size={14} className="text-risk-high mt-0.5 flex-shrink-0" />
                      : <Info size={14} className="text-risk-medium mt-0.5 flex-shrink-0" />
                    }
                    <div className="min-w-0">
                      <div className="text-base font-medium text-text-primary">{a.title}</div>
                      <div className="text-xs text-text-secondary mt-0.5">{(a as any).appName}</div>
                    </div>
                  </div>
                ))
              }
            </div>
          </motion.div>

          {/* Donut chart */}
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1, duration: 0.2 }}
            className="rounded-card border p-4" style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-subtle)' }}>
            <h2 className="text-lg font-semibold text-text-primary mb-3">Risk Breakdown</h2>
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={3} dataKey="value">
                  {pieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 8, color: 'var(--text-primary)', fontSize: 12 }} />
                <Legend formatter={(v) => <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{v}</span>} />
              </PieChart>
            </ResponsiveContainer>
          </motion.div>

          {/* Recent alerts */}
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.14, duration: 0.2 }}
            className="rounded-card border" style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-subtle)' }}>
            <div className="px-4 py-3 border-b" style={{ borderBottomColor: 'var(--border-subtle)' }}>
              <h2 className="text-lg font-semibold text-text-primary">Recent Alerts</h2>
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
              {recentAlerts.length === 0
                ? <div className="px-4 py-4 text-center text-text-tertiary text-base">No alerts yet</div>
                : recentAlerts.map(alert => (
                  <div key={alert.id} className="flex items-center gap-3 px-4 py-3">
                    <div className="w-1.5 h-6 rounded-full flex-shrink-0" style={{ background: getRiskColor(alert.risk_level) }} />
                    <div className="flex-1 min-w-0">
                      <div className="text-base font-medium text-text-primary truncate">{alert.app_name}</div>
                      <div className="text-xs text-text-secondary truncate">{alert.title}</div>
                    </div>
                    <span className="text-xs text-text-tertiary flex-shrink-0">{formatRelativeTime(alert.timestamp)}</span>
                  </div>
                ))
              }
            </div>
            <div className="px-4 py-2">
              <button className="text-xs text-accent-blue hover:underline" onClick={() => useAppStore.getState().setCurrentPage('alerts')}>
                View All Alerts →
              </button>
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  )
}
