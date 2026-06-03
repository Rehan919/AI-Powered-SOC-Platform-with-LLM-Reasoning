import { Link, useNavigate } from 'react-router-dom'
import { IncidentDetail, updateIncidentStatus } from '../api/client'

const STATUSES = ['open', 'in_progress', 'resolved', 'false_positive']

export default function IncidentHeader({ inc, tab, onChanged }: {
  inc: IncidentDetail; tab: 'ai' | 'alert' | 'forensics'; onChanged?: () => void
}) {
  const nav = useNavigate()
  const change = async (s: string) => { await updateIncidentStatus(inc.id, s); onChanged?.() }

  return (
    <div style={{ marginBottom: 32 }}>
      <Link to="/" className="back">← Back to Dashboard</Link>

      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16, margin: '12px 0 24px' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 700, letterSpacing: '-0.03em' }}>
            Incident <span style={{ color: 'var(--accent)' }}>#{inc.id}</span>
          </h1>
          <div style={{ color: 'var(--muted)', fontSize: '0.875rem', marginTop: 4 }}>
            {inc.hostname || 'Unknown host'} · {new Date(inc.created_at || '').toLocaleString()}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          {inc.event_count && inc.event_count > 1
            ? <span className="badge medium">×{inc.event_count} events</span>
            : null}
          <span className={`badge ${inc.risk_level}`}>{inc.risk_level || 'n/a'}</span>
          <select className="input" value={inc.status} onChange={(e) => change(e.target.value)}>
            {STATUSES.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
          </select>
        </div>
      </div>

      <div className="tabs">
        <div className={`tab${tab === 'ai' ? ' active' : ''}`} onClick={() => nav(`/incident/${inc.id}`)}>AI Review</div>
        <div className={`tab${tab === 'alert' ? ' active' : ''}`} onClick={() => nav(`/incident/${inc.id}/alert`)}>Wazuh Alert</div>
        <div className={`tab${tab === 'forensics' ? ' active' : ''}`} onClick={() => nav(`/incident/${inc.id}/forensics`)}>☠️ Forensics</div>
      </div>
    </div>
  )
}

