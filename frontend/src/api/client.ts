const BASE = '/api'

export interface Incident {
  id: number
  alert_id: number
  summary: string
  mitre_tactics: string[]
  risk_level: string
  confidence: number
  status: string
  event_count?: number
  created_at: string | null
  hostname: string | null
}

export interface AgentStep {
  id: number
  step_number: number
  phase: string
  agent: string
  thought: string | null
  tool_used: string | null
  tool_input: Record<string, unknown> | null
  tool_output: Record<string, unknown> | null
  conclusion: string | null
  created_at: string | null
}

export interface ActionItem {
  id: number
  action_type: string
  approved: boolean
  executed_at: string | null
}

export interface WazuhAlert {
  id: number
  hostname: string | null
  username: string | null
  severity: number | null
  rule_name: string | null
  mitre_id: string | null
  timestamp: string | null
  raw_json: Record<string, any> | null
}

export interface SimilarIncident { id: string; text: string }

export interface IncidentDetail extends Incident {
  severity: number | null
  process: string | null
  steps: AgentStep[]
  actions: ActionItem[]
  alert: WazuhAlert | null
  similar: SimilarIncident[]
}

export interface ThreatSummary {
  total_incidents: number
  critical: number
  high: number
  open_incidents: number
  resolved: number
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, init)
  if (!res.ok) {
    let message = `Request failed with status ${res.status}`
    try {
      const body = await res.json()
      if (typeof body.detail === 'string') message = body.detail
    } catch {
      // Keep the status-based message when the response is not JSON.
    }
    throw new Error(message)
  }
  return res.json()
}

export function fetchThreatSummary(): Promise<ThreatSummary> {
  return request('/threat-summary')
}

export function fetchIncidents(limit = 100): Promise<Incident[]> {
  return request(`/incidents?limit=${limit}`)
}

export function fetchIncident(id: number): Promise<IncidentDetail> {
  return request(`/incident/${id}`)
}

export function analyzeAlert(alert: Record<string, unknown>): Promise<{ incident_id: number }> {
  return request('/alert/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(alert),
  })
}

export function approveAction(actionId: number): Promise<{ message: string }> {
  return request(`/response/approve/${actionId}`, { method: 'POST' })
}

export function dismissAction(actionId: number): Promise<{ message: string }> {
  return request(`/response/dismiss/${actionId}`, { method: 'POST' })
}

export function updateIncidentStatus(id: number, status: string): Promise<{ id: number; status: string }> {
  return request(`/incident/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  })
}

// ── Forensics & Mitigation ────────────────────────────────────────────

export interface ForensicEvent {
  image?: string
  target_file?: string
  source_process?: string
  command_line?: string
  process_id?: string
  user?: string
  parent_image?: string
  hashes?: string
  destination_ip?: string
  destination_port?: string
  protocol?: string
  dll_loaded?: string
  event_type?: string
  target_object?: string
  details?: string
  query_name?: string
  query_results?: string
  rule?: string
  event_id?: string
  timestamp?: string
}

export interface ForensicsData {
  incident_id: number
  process_name: string
  total_events: number
  message?: string
  categories?: Record<string, ForensicEvent[]>
  summary?: Record<string, number>
  rules_fired?: Record<string, number>
  mitre_techniques?: string[]
  risk_indicators?: string[]
}

export interface MitigateAction {
  action: string
  detail: string
  pid?: number
  path?: string
  sha256?: string
  files_count?: number
  original_path?: string
  quarantine_path?: string
}

export interface MitigateResult {
  incident_id: number
  process_name: string
  actions_taken: MitigateAction[]
  errors: string[]
  status: string
  total_files_cleaned?: number
  total_dirs_cleaned?: number
  dropped_files_found?: number
}

export function fetchForensics(incidentId: number): Promise<ForensicsData> {
  return request(`/forensics/${incidentId}`)
}

export function mitigateThreat(incidentId: number): Promise<MitigateResult> {
  return request(`/mitigate/${incidentId}`, { method: 'POST' })
}

