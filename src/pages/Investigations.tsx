import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { Search, Play, Check, X, Ban, FileText, AlertTriangle, Loader2, ShieldCheck } from 'lucide-react'
import { cn } from '../lib/utils'
import { ACTION_LABELS, STAGES, api, describeStatus, type DemoUser } from '../lib/investigations'

/* eslint-disable @typescript-eslint/no-explicit-any */
type Any = any

const card = 'rounded-card border p-4'
const cardStyle = { background: 'var(--bg-secondary)', borderColor: 'var(--border-subtle)' }
const phaseColor = { working: '#3B82F6', waiting: '#F59E0B', finished: '#10B981', stopped: '#6B7280' }

export default function Investigations() {
  const [config, setConfig] = useState<Any>(null)
  const [demoUser, setDemoUser] = useState<DemoUser | null>(null)
  const [incidents, setIncidents] = useState<Any[]>([])
  const [list, setList] = useState<Any[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [inv, setInv] = useState<Any>(null)
  const [error, setError] = useState<string | null>(null)
  const [focusEvidence, setFocusEvidence] = useState<string | null>(null)

  useEffect(() => {
    api('/api/investigations/config', null).then((c: Any) => {
      setConfig(c)
      if (c.demo_identities) setDemoUser('analyst')
    }).catch(e => setError(e.message))
  }, [])

  const refreshLists = useCallback(async () => {
    try {
      setIncidents(await api('/api/incidents', demoUser))
      setList(await api('/api/investigations', demoUser))
      setError(null)
    } catch (e: Any) { setError(e.message) }
  }, [demoUser])

  useEffect(() => { if (config) refreshLists() }, [config, refreshLists])

  const status = inv?.status as string | undefined
  // Keep the "Recent investigations" list in step with the open investigation.
  useEffect(() => { if (config && status) refreshLists() }, [status, config, refreshLists])

  useEffect(() => {
    if (!selected) return
    let stop = false
    const load = async () => {
      try {
        const data = await api(`/api/investigations/${selected}`, demoUser)
        if (!stop) setInv(data)
      } catch (e: Any) { if (!stop) setError(e.message) }
    }
    load()
    const working = !status || describeStatus(status).phase === 'working'
    const iv = working ? setInterval(load, 1000) : undefined
    return () => { stop = true; if (iv) clearInterval(iv) }
  }, [selected, demoUser, status])

  const start = async (target_type: 'incident' | 'app', target_ref: string) => {
    try {
      const r: Any = await api('/api/investigations', demoUser, { method: 'POST', body: JSON.stringify({ target_type, target_ref }) })
      setInv(null); setSelected(r.id); refreshLists()
    } catch (e: Any) { setError(e.message) }
  }

  const detect = async () => {
    try { await api('/api/incidents/detect', demoUser, { method: 'POST' }); refreshLists() }
    catch (e: Any) { setError(e.message) }
  }

  const cancel = async () => {
    if (!selected) return
    try { await api(`/api/investigations/${selected}/cancel`, demoUser, { method: 'POST' }); setInv({ ...inv, status: 'running' }) }
    catch (e: Any) { setError(e.message) }
  }

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Investigations</h1>
          <p className="text-sm text-text-secondary mt-1 max-w-2xl">
            Evidence-based privacy investigations. Proposed actions never run without approval from a
            second person. Decision support only — not a legal assessment.
          </p>
        </div>
        {config?.demo_identities && (
          <label className="text-xs text-text-secondary flex items-center gap-2">
            Acting as (demo)
            <select value={demoUser ?? 'viewer'} onChange={e => setDemoUser(e.target.value as DemoUser)}
              className="rounded-input px-2 py-1 text-xs text-text-primary"
              style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)' }}>
              <option value="analyst">Analyst</option>
              <option value="approver">Approver</option>
              <option value="viewer">Viewer</option>
            </select>
          </label>
        )}
      </div>

      {config && (
        <div className="text-xs text-text-tertiary flex flex-wrap gap-x-4 gap-y-1">
          <span>Model: {config.llm?.available ? `${config.llm.mode} (local)` : 'none — rules-only assessment'}</span>
          <span>Tool budget: {config.budget?.max_tool_calls} calls</span>
          <span>Policy fetching: {config.policy_fetch_enabled ? 'on' : 'off'}</span>
          {!config.durable_checkpoints && <span>Paused runs do not survive a restart</span>}
        </div>
      )}

      {error && (
        <div className="rounded-card px-3 py-2 text-sm flex items-center gap-2" style={{ background: 'rgba(239,68,68,0.1)', color: '#FCA5A5' }}>
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      <div className="grid gap-5" style={{ gridTemplateColumns: 'minmax(260px, 340px) 1fr' }}>
        <div className="space-y-4">
          <div className={card} style={cardStyle}>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-md font-semibold text-text-primary">Incidents</h2>
              <button onClick={detect} className="text-xs text-text-secondary hover:text-text-primary flex items-center gap-1">
                <Search size={12} /> Detect
              </button>
            </div>
            {incidents.length === 0 && <p className="text-sm text-text-tertiary">No incidents yet. Run detection.</p>}
            <div className="space-y-2">
              {incidents.map(i => (
                <div key={i.id} className="flex items-start gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-text-primary truncate" title={i.title}>{i.title}</div>
                    <div className="text-xs text-text-tertiary">{i.type.replace(/_/g, ' ')} · {i.severity}</div>
                  </div>
                  <button onClick={() => start('incident', i.id)} title="Investigate"
                    className="p-1.5 rounded-button text-accent-blue hover:bg-bg-tertiary"><Play size={13} /></button>
                </div>
              ))}
            </div>
          </div>

          <div className={card} style={cardStyle}>
            <h2 className="text-md font-semibold text-text-primary mb-3">Recent investigations</h2>
            {list.length === 0 && <p className="text-sm text-text-tertiary">None yet.</p>}
            <div className="space-y-1">
              {list.map(r => {
                const d = describeStatus(r.status)
                return (
                  <button key={r.id} onClick={() => { setInv(null); setSelected(r.id) }}
                    className={cn('w-full text-left px-2 py-1.5 rounded-button hover:bg-bg-tertiary', selected === r.id && 'bg-bg-tertiary')}>
                    <div className="text-sm text-text-primary truncate">{r.label || r.target_ref}</div>
                    <div className="text-xs" style={{ color: phaseColor[d.phase] }}>{d.label}</div>
                  </button>
                )
              })}
            </div>
          </div>
        </div>

        <div className="space-y-4 min-w-0">
          {!selected && <div className={card} style={cardStyle}><p className="text-sm text-text-tertiary">Select an incident to investigate, or open a recent investigation.</p></div>}
          {selected && !inv && <div className={card} style={cardStyle}><Loader2 size={16} className="animate-spin text-text-tertiary" /></div>}
          {inv && <Detail inv={inv} demoUser={demoUser} onChanged={setInv} onCancel={cancel}
            focusEvidence={focusEvidence} setFocusEvidence={setFocusEvidence} setError={setError} />}
        </div>
      </div>
    </div>
  )
}

function Detail({ inv, demoUser, onChanged, onCancel, focusEvidence, setFocusEvidence, setError }: {
  inv: Any; demoUser: DemoUser | null; onChanged: (v: Any) => void; onCancel: () => void
  focusEvidence: string | null; setFocusEvidence: (id: string | null) => void; setError: (e: string | null) => void
}) {
  const snap = inv.snapshot || {}
  const d = describeStatus(inv.status)
  const reached = useMemo(() => new Set((snap.timeline || []).map((t: Any) => t.stage)), [snap.timeline])
  // While paused, the graph sits at the approval interrupt (its last finished node is "propose").
  const current = inv.status === 'awaiting_approval' ? 'await_approval' : snap.stage
  const a = snap.assessment

  return (
    <>
      <div className={card} style={cardStyle}>
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="text-lg font-semibold text-text-primary">{inv.label || inv.target_ref}</div>
            <div className="text-sm mt-0.5 flex items-center gap-1.5" style={{ color: phaseColor[d.phase] }}>
              {d.phase === 'working' && <Loader2 size={13} className="animate-spin" />}
              {d.label}
            </div>
            <div className="text-xs text-text-secondary mt-1">{d.detail}</div>
          </div>
          {(d.phase === 'working' || d.phase === 'waiting') && (
            <button onClick={onCancel} className="text-xs flex items-center gap-1 px-2 py-1 rounded-button text-text-secondary hover:text-text-primary"
              style={{ border: '1px solid var(--border-default)' }}><Ban size={12} /> Cancel</button>
          )}
        </div>
        <div className="flex items-center gap-1 mt-4 flex-wrap">
          {STAGES.map((s, i) => (
            <React.Fragment key={s.id}>
              <span className={cn('text-xs px-2 py-0.5 rounded-badge', current === s.id ? 'text-white' : reached.has(s.id) ? 'text-text-primary' : 'text-text-tertiary')}
                style={{ background: current === s.id ? phaseColor[d.phase] : reached.has(s.id) ? 'var(--bg-tertiary)' : 'transparent' }}>{s.label}</span>
              {i < STAGES.length - 1 && <span className="text-text-tertiary text-xs">›</span>}
            </React.Fragment>
          ))}
        </div>
        {snap.budget?.max_tool_calls !== undefined && (
          <div className="text-xs text-text-tertiary mt-3">
            Tool calls {snap.budget.used}/{snap.budget.max_tool_calls} · Evidence items {snap.evidence?.length ?? 0}
            {snap.flags?.length > 0 && <> · Flags: {snap.flags.join(', ')}</>}
          </div>
        )}
      </div>

      {a && (
        <div className={card} style={cardStyle}>
          <div className="flex items-center justify-between">
            <h2 className="text-md font-semibold text-text-primary">Assessment</h2>
            <span className="text-xs text-text-secondary">Review priority: <b>{a.review_priority}</b> · basis: {a.basis}</span>
          </div>
          <p className="text-sm text-text-secondary mt-2">{a.summary}</p>
          <div className="space-y-3 mt-3">
            {a.concerns.map((c: Any) => (
              <div key={c.id} className="rounded-button p-3" style={{ background: 'var(--bg-tertiary)' }}>
                <div className="text-sm font-medium text-text-primary">{c.title}</div>
                <Row label="Observed">{c.observed} <Cites ids={c.evidence_ids} onPick={setFocusEvidence} /></Row>
                <Row label="Why it may matter">{c.why_it_matters}</Row>
                <Row label="Unknown">{c.unknowns}</Row>
                <Row label="To verify">{c.verify}</Row>
              </div>
            ))}
          </div>
          {a.uncertainties?.length > 0 && (
            <ul className="mt-3 space-y-1">
              {a.uncertainties.map((u: Any, i: number) => (
                <li key={i} className="text-xs text-text-secondary">• {u.text} <Cites ids={u.evidence_ids} onPick={setFocusEvidence} /></li>
              ))}
            </ul>
          )}
          {a.ai_explanation && (
            <div className="mt-3 text-xs text-text-secondary">
              <div className="text-text-tertiary">{a.ai_explanation.label}</div>
              <p className="mt-1">{a.ai_explanation.summary}</p>
            </div>
          )}
          <p className="text-xs text-text-tertiary mt-3 italic">{a.disclaimer}</p>
        </div>
      )}

      {snap.proposals?.length > 0 && (
        <div className={card} style={cardStyle}>
          <h2 className="text-md font-semibold text-text-primary mb-1">Proposed actions</h2>
          <p className="text-xs text-text-tertiary mb-3">Each approval covers this exact payload once. Nobody can approve an action they proposed.</p>
          <div className="space-y-3">
            {snap.proposals.map((p: Any) => (
              <Proposal key={p.id} p={p} inv={inv} demoUser={demoUser} onChanged={onChanged} setError={setError}
                execution={(snap.executions || []).find((e: Any) => e.action_id === p.id)} onPick={setFocusEvidence} />
            ))}
          </div>
        </div>
      )}

      {snap.evidence?.length > 0 && (
        <div className={card} style={cardStyle}>
          <h2 className="text-md font-semibold text-text-primary mb-3">Evidence</h2>
          <div className="space-y-1.5">
            {snap.evidence.map((e: Any) => (
              <div key={e.id} id={`ev-${e.id}`} className="text-xs rounded-button px-2 py-1.5"
                style={{ background: focusEvidence === e.id ? 'rgba(59,130,246,0.15)' : 'transparent' }}>
                <span className="font-mono text-text-tertiary mr-2">{e.id}</span>
                <span className="text-text-tertiary mr-2">{e.source_tool} · {e.trust}</span>
                <span className="text-text-primary">{e.summary}</span>
                {e.limitations && <div className="text-text-tertiary mt-0.5">Limitation: {e.limitations}</div>}
              </div>
            ))}
          </div>
        </div>
      )}

      {inv.report && (
        <div className={card} style={cardStyle}>
          <h2 className="text-md font-semibold text-text-primary mb-2 flex items-center gap-2"><FileText size={14} /> Report</h2>
          <pre className="text-xs text-text-secondary whitespace-pre-wrap font-mono">{inv.report.markdown}</pre>
        </div>
      )}
    </>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return <div className="text-xs mt-1.5"><span className="text-text-tertiary">{label}: </span><span className="text-text-secondary">{children}</span></div>
}

function Cites({ ids, onPick }: { ids: string[]; onPick: (id: string) => void }) {
  if (!ids?.length) return null
  return (
    <>{ids.map(id => (
      <button key={id} onClick={() => { onPick(id); document.getElementById(`ev-${id}`)?.scrollIntoView({ block: 'center' }) }}
        className="font-mono text-[10px] text-accent-blue hover:underline mr-1">[{id.slice(-2)}]</button>
    ))}</>
  )
}

function Proposal({ p, inv, demoUser, onChanged, setError, execution, onPick }: {
  p: Any; inv: Any; demoUser: DemoUser | null; onChanged: (v: Any) => void; setError: (e: string | null) => void
  execution?: Any; onPick: (id: string) => void
}) {
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const canDecide = inv.status === 'awaiting_approval' && p.status === 'proposed'

  const decide = async (decision: 'approve' | 'reject') => {
    setBusy(true)
    try {
      await api(`/api/investigations/${inv.id}/actions/${p.id}/decision`, demoUser, {
        method: 'POST', body: JSON.stringify({ decision, reason, payload_hash: p.payload_hash }),
      })
      onChanged(await api(`/api/investigations/${inv.id}`, demoUser))
      setError(null)
    } catch (e: Any) { setError(e.message) } finally { setBusy(false) }
  }

  return (
    <div className="rounded-button p-3" style={{ background: 'var(--bg-tertiary)' }}>
      <div className="flex items-center justify-between gap-2">
        <div className="text-sm font-medium text-text-primary">{ACTION_LABELS[p.kind] ?? p.kind}{p.version > 1 && ` (v${p.version})`}</div>
        <span className="text-xs text-text-secondary">{p.status}</span>
      </div>
      <Row label="Reason">{p.reason} <Cites ids={p.evidence_ids} onPick={onPick} /></Row>
      <Row label="Expected effect">{p.expected_effect}</Row>
      <Row label="Limitations">{p.limitations}</Row>
      <details className="mt-2">
        <summary className="text-xs text-text-tertiary cursor-pointer">Payload preview</summary>
        <pre className="text-xs text-text-secondary whitespace-pre-wrap font-mono mt-1">{Object.entries(p.args || {}).map(([k, v]) => `${k}: ${v}`).join('\n')}</pre>
        <div className="text-[10px] text-text-tertiary font-mono mt-1">payload {String(p.payload_hash).slice(0, 16)}…</div>
      </details>
      {canDecide && (
        <div className="flex items-center gap-2 mt-3">
          <input value={reason} onChange={e => setReason(e.target.value)} placeholder="Reason (required)"
            className="flex-1 rounded-input px-2 py-1 text-xs text-text-primary"
            style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-default)' }} />
          <button disabled={busy || !reason.trim()} onClick={() => decide('approve')}
            className="text-xs flex items-center gap-1 px-2 py-1 rounded-button text-white disabled:opacity-40" style={{ background: '#10B981' }}><Check size={12} /> Approve</button>
          <button disabled={busy || !reason.trim()} onClick={() => decide('reject')}
            className="text-xs flex items-center gap-1 px-2 py-1 rounded-button text-white disabled:opacity-40" style={{ background: '#EF4444' }}><X size={12} /> Reject</button>
        </div>
      )}
      {execution && (
        <div className="text-xs mt-2 flex items-center gap-1" style={{ color: execution.ok ? '#10B981' : '#FCA5A5' }}>
          {execution.ok ? <ShieldCheck size={12} /> : <AlertTriangle size={12} />}
          {execution.ok ? 'Done (draft / dry-run only)' : `Failed: ${execution.error_code}`}
        </div>
      )}
    </div>
  )
}
