// Client helpers for the M4 investigation API (sidecar/agent/api.py).
import { SIDECAR_BASE } from '../hooks/useSidecar'

export type DemoUser = 'analyst' | 'approver' | 'viewer'

export const STAGES = [
  { id: 'triage', label: 'Triage' },
  { id: 'investigate', label: 'Investigate' },
  { id: 'assess', label: 'Assess' },
  { id: 'propose_actions', label: 'Propose' },
  { id: 'await_approval', label: 'Approval' },
  { id: 'execute', label: 'Execute' },
  { id: 'report', label: 'Report' },
] as const

export type Phase = 'working' | 'waiting' | 'finished' | 'stopped'

/** What the user should understand about an investigation's status. */
export function describeStatus(status: string): { phase: Phase; label: string; detail: string } {
  switch (status) {
    case 'queued':
    case 'running':
    case 'resuming':
      return { phase: 'working', label: 'Investigating', detail: 'Collecting and checking evidence with read-only tools.' }
    case 'awaiting_approval':
      return { phase: 'waiting', label: 'Waiting for approval', detail: 'Nothing has been executed. An approver must review each proposed action.' }
    case 'completed':
      return { phase: 'finished', label: 'Finished', detail: 'The report is ready.' }
    case 'cancelled':
      return { phase: 'stopped', label: 'Cancelled', detail: 'Stopped by a user. Pending actions were cancelled.' }
    case 'rejected_target':
      return { phase: 'stopped', label: 'Not investigated', detail: 'The target was not found or is out of scope.' }
    case 'closed_by_rules':
      return { phase: 'finished', label: 'Closed', detail: 'The incident was already resolved or dismissed.' }
    case 'interrupted':
      return { phase: 'stopped', label: 'Interrupted', detail: 'DoxShield restarted while this was paused. Pending actions were cancelled; start a new investigation.' }
    case 'failed':
      return { phase: 'stopped', label: 'Unable to continue', detail: 'The investigation stopped safely. No action was executed.' }
    default:
      return { phase: 'stopped', label: status, detail: '' }
  }
}

export const ACTION_LABELS: Record<string, string> = {
  create_ticket: 'Ticket draft',
  draft_dpo_notification: 'DPO notification draft',
  send_alert_email: 'Alert email draft',
  propose_block_rule: 'Block-rule proposal (dry-run)',
}

async function authHeaders(demoUser: DemoUser | null): Promise<Record<string, string>> {
  if (demoUser) return { 'X-DoxShield-Demo-User': demoUser }
  const loader = (window.sovereign as unknown as { loadToken?: () => Promise<string | null> } | undefined)?.loadToken
  const token = loader ? await loader() : null
  return token ? { Authorization: `Bearer ${token}` } : {}
}

export async function api<T = unknown>(path: string, demoUser: DemoUser | null, init?: RequestInit): Promise<T> {
  const headers = { 'Content-Type': 'application/json', ...(await authHeaders(demoUser)), ...(init?.headers || {}) }
  const r = await fetch(`${SIDECAR_BASE}${path}`, { ...init, headers })
  const body = await r.json().catch(() => ({}))
  if (!r.ok) {
    const detail = (body as { detail?: unknown }).detail
    const msg = typeof detail === 'string' ? detail
      : (detail as { message?: string } | undefined)?.message ?? `HTTP ${r.status}`
    throw new Error(msg)
  }
  return body as T
}
