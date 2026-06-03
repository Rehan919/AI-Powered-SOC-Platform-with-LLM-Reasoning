import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { fetchThreatSummary, fetchIncidents, ThreatSummary, Incident } from '../api/client'

const RISK_CLR: Record<string, string> = { critical: '#fb7185', high: '#fb923c', medium: '#fbbf24', low: '#34d399' }

export default function Dashboard() {
  const [summary, setSummary] = useState<ThreatSummary | null>(null)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [riskFilter, setRiskFilter] = useState('')
  const [auto, setAuto] = useState(true)
  const [updated, setUpdated] = useState<Date | null>(null)

  const load = useCallback(() => {
    Promise.all([fetchThreatSummary(), fetchIncidents()])
      .then(([s, inc]) => { setSummary(s); setIncidents(inc); setUpdated(new Date()); setError('') })
      .catch((e) => setError(e instanceof Error ? e.message : 'Unable to load'))
  }, [])

  useEffect(() => {
    load()
    if (!auto) return
    const t = setInterval(load, 8000)
    return () => clearInterval(t)
  }, [auto, load])

  const mitre = useMemo(() => {
    const m: Record<string, number> = {}
    incidents.forEach((i) => (i.mitre_tactics || []).forEach((t) => { if (t) m[t] = (m[t] || 0) + 1 }))
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 8)
  }, [incidents])

  const riskDist = useMemo(() => {
    const d: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    incidents.forEach((i) => { if (d[i.risk_level] !== undefined) d[i.risk_level]++ })
    return d
  }, [incidents])

  const activity = useMemo(() => {
    const now = new Date()
    return Array.from({ length: 7 }, (_, k) => {
      const day = new Date(now); day.setDate(now.getDate() - (6 - k))
      const key = day.toDateString()
      return {
        label: day.toLocaleDateString(undefined, { weekday: 'short' }),
        count: incidents.filter((i) => i.created_at && new Date(i.created_at).toDateString() === key).length
      }
    })
  }, [incidents])

  const filtered = useMemo(() => {
    const q = query.toLowerCase()
    return incidents.filter((i) => {
      if (riskFilter && i.risk_level !== riskFilter) return false
      if (!q) return true
      return [i.hostname, i.summary, (i.mitre_tactics || []).join(',')].some((f) => (f || '').toLowerCase().includes(q))
    })
  }, [incidents, query, riskFilter])

  return (
    <div className="page">
      {/* header row */}
      <div className="row between wrap" style={{ marginBottom: 32, gap: 16 }}>
        <div>
          <div className="page-title">Threat Dashboard</div>
          <div className="page-sub">Real-time security incident monitoring · Wazuh + AI analysis</div>
        </div>
        <div className="row gap" style={{ flexWrap: 'wrap' }}>
          {updated && <span style={{ fontSize: '0.8rem', color: 'var(--muted)' }}>Updated {updated.toLocaleTimeString()}</span>}
          <label className="row" style={{ gap: 8, cursor: 'pointer', fontSize: '0.85rem', color: 'var(--muted)' }}>
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
            <span className={`live ${auto ? 'on' : 'off'}`} />
            Live
          </label>
          <button className="btn btn-primary btn-sm" onClick={load}>Refresh</button>
        </div>
      </div>

      {error && <div style={{ color: 'var(--crit)', marginBottom: 16, fontSize: '0.875rem' }}>{error}</div>}

      {/* stat cards — dark */}
      {summary && (
        <div className="stats" style={{ marginBottom: 24 }}>
          {[
            { v: summary.total_incidents, l: 'Total Incidents', c: '#8771ff' },
            { v: summary.critical,        l: 'Critical',        c: '#fb7185', r: 'critical' },
            { v: summary.high,            l: 'High',            c: '#fb923c', r: 'high' },
            { v: summary.open_incidents,  l: 'Open',            c: '#fbbf24' },
            { v: summary.resolved,        l: 'Resolved',        c: '#34d399' },
          ].map(({ v, l, c, r }) => (
            <div key={l} className={`stat ${r ? 'clk' : ''}`}
              style={riskFilter === r ? { outline: `2px solid ${c}`, outlineOffset: 2 } : {}}
              onClick={() => r && setRiskFilter(riskFilter === r ? '' : r)}>
              <div className="v" style={{ color: c }}>{v}</div>
              <div className="l">{l}</div>
            </div>
          ))}
        </div>
      )}

      {/* two-col charts */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
        <div className="card" style={{ marginBottom: 0 }}>
          <h3>Risk Distribution</h3>
          {(['critical','high','medium','low'] as const).map((r) => {
            const max = Math.max(1, ...Object.values(riskDist))
            return (
              <div key={r} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                <span style={{ width: 64, fontSize: '0.7rem', fontWeight: 600, color: RISK_CLR[r], textTransform: 'uppercase' }}>{r}</span>
                <div style={{ flex: 1, height: 8, background: 'var(--bg)', borderRadius: 99, overflow: 'hidden' }}>
                  <div style={{ width: `${(riskDist[r] / max) * 100}%`, height: '100%', background: RISK_CLR[r], borderRadius: 99 }} />
                </div>
                <span style={{ width: 20, textAlign: 'right', fontSize: '0.8rem', color: 'var(--muted)' }}>{riskDist[r]}</span>
              </div>
            )
          })}
        </div>
        <div className="card" style={{ marginBottom: 0 }}>
          <h3>Activity · 7 days</h3>
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 8, height: 88 }}>
            {activity.map((a, i) => {
              const max = Math.max(1, ...activity.map((x) => x.count))
              return (
                <div key={i} style={{ flex: 1, textAlign: 'center' }}>
                  <div style={{ height: `${(a.count / max) * 68}px`, minHeight: 3, background: 'var(--accent)', borderRadius: 4, transition: 'height .3s' }} />
                  <div style={{ fontSize: '0.65rem', color: 'var(--muted)', marginTop: 5 }}>{a.label}</div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* MITRE chips */}
      {mitre.length > 0 && (
        <div className="card">
          <h3>MITRE ATT&amp;CK Techniques</h3>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {mitre.map(([t, n]) => (
              <span key={t} className="chip" onClick={() => setQuery(t)}>{t} <b>×{n}</b></span>
            ))}
          </div>
        </div>
      )}

      {/* incidents table — dark card */}
      <div className="row between wrap" style={{ marginBottom: 14, gap: 12 }}>
        <h2 style={{ color: 'var(--text)' }}>
          Incidents {riskFilter && <span className={`badge ${riskFilter}`} style={{ marginLeft: 8 }}>{riskFilter}</span>}
          <span style={{ fontWeight: 400, fontSize: '0.85rem', color: 'var(--muted)', marginLeft: 8 }}>({filtered.length})</span>
        </h2>
        <input className="input" style={{ minWidth: 260 }} value={query}
          onChange={(e) => setQuery(e.target.value)} placeholder="Search host, summary, MITRE…" />
      </div>

      <div className="card-dark" style={{ padding: '8px 24px 20px' }}>
        <table className="tbl">
          <thead>
            <tr><th>#</th><th>Host</th><th>Summary</th><th>Risk</th><th>MITRE</th><th>Status</th><th>Time</th></tr>
          </thead>
          <tbody>
            {filtered.map((i) => (
              <tr key={i.id}>
                <td>
                  <Link to={`/incident/${i.id}`} style={{ color: 'var(--accent-2)', fontWeight: 600 }}>#{i.id}</Link>
                  {i.event_count && i.event_count > 1
                    ? <span className="badge medium" style={{ marginLeft: 8 }}>×{i.event_count}</span>
                    : null}
                </td>
                <td style={{ color: 'var(--text-inv)' }}>{i.hostname || '—'}</td>
                <td className="ellipsis" style={{ color: 'var(--dim)', maxWidth: 340 }}>
                  {(i.summary || '—').replace(/[#*`>]/g, '').replace(/\s+/g, ' ').trim().slice(0, 120)}
                </td>
                <td>{i.risk_level ? <span className={`badge ${i.risk_level}`}>{i.risk_level}</span> : '—'}</td>
                <td style={{ color: 'var(--dim)', fontSize: '0.8rem' }}>{(i.mitre_tactics || []).join(', ') || '—'}</td>
                <td style={{ color: 'var(--dim)' }}>{i.status?.replace('_', ' ') || '—'}</td>
                <td style={{ color: 'var(--dim)', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                  {i.created_at ? new Date(i.created_at).toLocaleString() : '—'}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={7} style={{ textAlign: 'center', padding: '2rem', color: 'var(--dim)' }}>No matching incidents.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
