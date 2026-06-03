import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { fetchIncident, IncidentDetail } from '../api/client'
import IncidentHeader from '../components/IncidentHeader'

export default function AlertDetail() {
  const { id } = useParams()
  const [inc, setInc] = useState<IncidentDetail | null>(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)

  const load = () => { if (id) fetchIncident(Number(id)).then(setInc).catch((e) => setError(e.message)) }
  useEffect(load, [id])

  if (error) return <div className="page" style={{ color: 'var(--crit)' }}>{error}</div>
  if (!inc) return <div className="page" style={{ color: 'var(--muted)' }}>Loading…</div>

  const a = inc.alert
  const raw = a?.raw_json || {}
  const ed: Record<string, string> = raw.win_eventdata || {}
  const copy = () => { navigator.clipboard.writeText(JSON.stringify(raw, null, 2)); setCopied(true); setTimeout(() => setCopied(false), 1500) }

  const fields: [string, any][] = [
    ['Host', a?.hostname], ['User', a?.username],
    ['MITRE', a?.mitre_id || raw.mitre], ['Event ID', raw.event_id],
    ['Source IP', raw.source_ip], ['Destination IP', raw.destination_ip],
    ['Process', raw.process], ['Timestamp', a?.timestamp ? new Date(a.timestamp).toLocaleString() : null],
  ]

  return (
    <div className="page">
      <IncidentHeader inc={inc} tab="alert" onChanged={load} />

      {/* overview — light card */}
      <div className="card">
        <h3>Alert Overview</h3>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12, marginBottom: 20 }}>
          <div style={{ fontSize: '1.1rem', fontWeight: 700 }}>{a?.rule_name || raw.rule || 'Unknown rule'}</div>
          <span className="badge high">level {a?.severity ?? raw.severity ?? '—'}</span>
        </div>
        <div className="grid2">
          {fields.map(([k, v]) => v != null && (
            <div key={k}>
              <div style={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--muted)', marginBottom: 3 }}>{k}</div>
              <div style={{ fontSize: '0.9rem', fontWeight: 500 }}>{String(v)}</div>
            </div>
          ))}
        </div>
      </div>

      {/* event message — dark card */}
      {raw.event_message && (
        <div className="card-dark">
          <h3>Event Message</h3>
          <pre className="raw" style={{ whiteSpace: 'pre-wrap' }}>{raw.event_message}</pre>
        </div>
      )}

      {/* windows event data — dark card */}
      {Object.keys(ed).length > 0 && (
        <div className="card-dark">
          <h3>Windows Event Data</h3>
          <table className="tbl">
            <tbody>
              {Object.entries(ed).map(([k, v]) => (
                <tr key={k}>
                  <td style={{ color: 'var(--dim)', width: 220 }}>{k}</td>
                  <td>{String(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* raw JSON — dark card */}
      <div className="card-dark">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0 }}>Raw Alert (JSON)</h3>
          <button className="btn btn-sm" onClick={copy}>{copied ? 'Copied!' : 'Copy'}</button>
        </div>
        <pre className="raw">{JSON.stringify(raw, null, 2)}</pre>
      </div>
    </div>
  )
}
