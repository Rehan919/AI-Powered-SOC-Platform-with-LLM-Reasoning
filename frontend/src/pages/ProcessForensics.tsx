import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { fetchIncident, fetchForensics, mitigateThreat, IncidentDetail, ForensicsData, MitigateResult } from '../api/client'
import IncidentHeader from '../components/IncidentHeader'

const CATEGORY_META: Record<string, { icon: string; label: string; color: string }> = {
  files_created:          { icon: '🗂️', label: 'Files Dropped',           color: '#fb923c' },
  processes_spawned:      { icon: '⚙️', label: 'Processes Spawned',       color: '#8771ff' },
  network_connections:    { icon: '🌐', label: 'Network Connections',     color: '#fb7185' },
  dlls_loaded:            { icon: '📦', label: 'DLLs Loaded',             color: '#38bdf8' },
  registry_modifications: { icon: '🔑', label: 'Registry Modifications',  color: '#fbbf24' },
  dns_queries:            { icon: '🌍', label: 'DNS Queries',             color: '#34d399' },
  other_events:           { icon: '📋', label: 'Other Events',            color: '#a78bfa' },
}

const ACTION_ICONS: Record<string, string> = {
  kill_process: '💀',
  clean_directory: '🧹',
  clean_file: '🗑️',
  quarantine: '🔒',
  hash_blocked: '🛡️',
  incident_resolved: '✅',
}

function shortenPath(p: string) {
  return p.replace(/\\\\\\\\/g, '\\').replace(/\\\\/g, '\\')
}

export default function ProcessForensics() {
  const { id } = useParams()
  const [inc, setInc] = useState<IncidentDetail | null>(null)
  const [forensics, setForensics] = useState<ForensicsData | null>(null)
  const [mitigateResult, setMitigateResult] = useState<MitigateResult | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [mitigating, setMitigating] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})

  const load = useCallback(() => {
    if (!id) return
    setLoading(true)
    Promise.all([fetchIncident(Number(id)), fetchForensics(Number(id))])
      .then(([i, f]) => { setInc(i); setForensics(f); setError('') })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [id])

  useEffect(load, [load])

  const toggle = (key: string) => setExpanded((prev) => ({ ...prev, [key]: !prev[key] }))

  const handleMitigate = async () => {
    if (!id) return
    setMitigating(true)
    setShowConfirm(false)
    try {
      const result = await mitigateThreat(Number(id))
      setMitigateResult(result)
      load() // refresh incident status
    } catch (e: any) {
      setError(e.message || 'Mitigation failed')
    } finally {
      setMitigating(false)
    }
  }

  if (error && !inc) return <div className="page" style={{ color: 'var(--crit)' }}>{error}</div>
  if (loading) return <div className="page" style={{ color: 'var(--muted)' }}>Loading forensic data…</div>
  if (!inc) return <div className="page" style={{ color: 'var(--muted)' }}>Incident not found</div>

  const cats = forensics?.categories || {}
  const summary = forensics?.summary || {}

  return (
    <div className="page">
      <IncidentHeader inc={inc} tab="forensics" onChanged={load} />

      {error && <div style={{ color: 'var(--crit)', marginBottom: 16, fontSize: '0.875rem' }}>{error}</div>}

      {/* ── Process Overview ─────────────────────────────── */}
      <div className="card" style={{ position: 'relative', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', top: 0, right: 0, width: 200, height: 200, background: 'radial-gradient(circle, rgba(82,53,239,0.08) 0%, transparent 70%)', pointerEvents: 'none' }} />
        <h3>Process Forensics</h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap', marginBottom: 20 }}>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, fontFamily: 'monospace', wordBreak: 'break-all' }}>
            {forensics?.process_name ? shortenPath(forensics.process_name) : 'Unknown'}
          </div>
          <span className="badge high" style={{ fontSize: '0.75rem' }}>
            {forensics?.total_events ?? 0} Sysmon events
          </span>
        </div>

        {/* Summary counters */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 10 }}>
          {Object.entries(summary).filter(([, v]) => v > 0).map(([key, count]) => {
            const meta = CATEGORY_META[key]
            if (!meta) return null
            return (
              <div key={key} className="forensic-stat" style={{ '--fc': meta.color } as any}>
                <div className="forensic-stat-icon">{meta.icon}</div>
                <div className="forensic-stat-value">{count}</div>
                <div className="forensic-stat-label">{meta.label}</div>
              </div>
            )
          })}
        </div>
      </div>

      {/* ── Risk Indicators ──────────────────────────────── */}
      {forensics?.risk_indicators && forensics.risk_indicators.length > 0 && (
        <div className="card-dark">
          <h3>⚠️ Risk Indicators</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {forensics.risk_indicators.map((r, i) => (
              <div key={i} className="risk-indicator">
                <span className="risk-dot" />
                {r}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── MITRE + Rules ────────────────────────────────── */}
      {((forensics?.mitre_techniques?.length ?? 0) > 0 || Object.keys(forensics?.rules_fired || {}).length > 0) && (
        <div className="card">
          <h3>Detection Coverage</h3>
          {(forensics?.mitre_techniques?.length ?? 0) > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>MITRE ATT&CK</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {forensics!.mitre_techniques!.map((t) => <span key={t} className="chip">{t}</span>)}
              </div>
            </div>
          )}
          {Object.keys(forensics?.rules_fired || {}).length > 0 && (
            <div>
              <div style={{ fontSize: '0.7rem', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Rules Triggered</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {Object.entries(forensics!.rules_fired!).sort((a, b) => b[1] - a[1]).map(([rule, count]) => (
                  <div key={rule} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem' }}>
                    <span className="badge high" style={{ minWidth: 32, textAlign: 'center' }}>×{count}</span>
                    <span>{rule}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Event Categories (expandable) ────────────────── */}
      {Object.entries(cats).map(([key, events]) => {
        const meta = CATEGORY_META[key] || { icon: '📋', label: key, color: '#a78bfa' }
        const isOpen = expanded[key] ?? false
        return (
          <div key={key} className="card-dark forensic-category" onClick={() => toggle(key)}>
            <div className="forensic-category-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: '1.2rem' }}>{meta.icon}</span>
                <span style={{ fontSize: '0.85rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: meta.color }}>{meta.label}</span>
                <span className="badge medium" style={{ fontSize: '0.7rem' }}>{events.length}</span>
              </div>
              <span style={{ color: 'var(--dim)', fontSize: '1.2rem', transition: 'transform 0.2s', transform: isOpen ? 'rotate(180deg)' : 'rotate(0)' }}>▼</span>
            </div>
            {isOpen && (
              <div onClick={(e) => e.stopPropagation()} style={{ marginTop: 16 }}>
                <table className="tbl">
                  <thead>
                    <tr>
                      {key === 'files_created' && <><th>Source Process</th><th>File Dropped</th><th>Time</th></>}
                      {key === 'processes_spawned' && <><th>Image</th><th>Command Line</th><th>PID</th><th>User</th></>}
                      {key === 'network_connections' && <><th>Process</th><th>Destination</th><th>Port</th><th>Protocol</th></>}
                      {key === 'dlls_loaded' && <><th>Process</th><th>DLL Loaded</th><th>Time</th></>}
                      {key === 'registry_modifications' && <><th>Type</th><th>Process</th><th>Registry Key</th><th>Value</th></>}
                      {key === 'dns_queries' && <><th>Process</th><th>Domain</th><th>Result</th></>}
                      {key === 'other_events' && <><th>Event ID</th><th>Rule</th><th>Time</th></>}
                    </tr>
                  </thead>
                  <tbody>
                    {events.slice(0, 50).map((e, i) => (
                      <tr key={i}>
                        {key === 'files_created' && <>
                          <td className="ellipsis" style={{ maxWidth: 200 }}>{shortenPath(e.source_process || '')}</td>
                          <td className="ellipsis" style={{ maxWidth: 400, color: meta.color }}>{shortenPath(e.target_file || '')}</td>
                          <td style={{ whiteSpace: 'nowrap', fontSize: '0.78rem' }}>{e.timestamp?.split('T')[1]?.split('.')[0] || ''}</td>
                        </>}
                        {key === 'processes_spawned' && <>
                          <td className="ellipsis" style={{ maxWidth: 200 }}>{shortenPath(e.image || '')}</td>
                          <td className="ellipsis" style={{ maxWidth: 340, fontFamily: 'monospace', fontSize: '0.78rem' }}>{shortenPath(e.command_line || '')}</td>
                          <td>{e.process_id}</td>
                          <td>{e.user?.split('\\').pop()}</td>
                        </>}
                        {key === 'network_connections' && <>
                          <td className="ellipsis" style={{ maxWidth: 200 }}>{shortenPath(e.image || '')}</td>
                          <td style={{ color: '#fb7185', fontFamily: 'monospace' }}>{e.destination_ip}</td>
                          <td>{e.destination_port}</td>
                          <td>{e.protocol}</td>
                        </>}
                        {key === 'dlls_loaded' && <>
                          <td className="ellipsis" style={{ maxWidth: 200 }}>{shortenPath(e.image || '')}</td>
                          <td className="ellipsis" style={{ maxWidth: 400 }}>{shortenPath(e.dll_loaded || '')}</td>
                          <td style={{ whiteSpace: 'nowrap', fontSize: '0.78rem' }}>{e.timestamp?.split('T')[1]?.split('.')[0] || ''}</td>
                        </>}
                        {key === 'registry_modifications' && <>
                          <td><span className="badge high">{e.event_type}</span></td>
                          <td className="ellipsis" style={{ maxWidth: 200 }}>{shortenPath(e.image || '')}</td>
                          <td className="ellipsis" style={{ maxWidth: 300, fontFamily: 'monospace', fontSize: '0.78rem' }}>{e.target_object}</td>
                          <td className="ellipsis" style={{ maxWidth: 160 }}>{e.details}</td>
                        </>}
                        {key === 'dns_queries' && <>
                          <td className="ellipsis" style={{ maxWidth: 200 }}>{shortenPath(e.image || '')}</td>
                          <td style={{ color: '#34d399', fontFamily: 'monospace' }}>{e.query_name}</td>
                          <td className="ellipsis" style={{ maxWidth: 200 }}>{e.query_results}</td>
                        </>}
                        {key === 'other_events' && <>
                          <td>{e.event_id}</td>
                          <td className="ellipsis" style={{ maxWidth: 400 }}>{e.rule}</td>
                          <td style={{ whiteSpace: 'nowrap', fontSize: '0.78rem' }}>{e.timestamp?.split('T')[1]?.split('.')[0] || ''}</td>
                        </>}
                      </tr>
                    ))}
                  </tbody>
                </table>
                {events.length > 50 && (
                  <div style={{ textAlign: 'center', padding: '12px 0', color: 'var(--dim)', fontSize: '0.8rem' }}>
                    Showing 50 of {events.length} events
                  </div>
                )}
              </div>
            )}
          </div>
        )
      })}

      {/* ── Mitigation Result ────────────────────────────── */}
      {mitigateResult && (
        <div className="card-dark" style={{ border: mitigateResult.status === 'completed' ? '1px solid rgba(52,211,153,0.3)' : '1px solid rgba(251,113,133,0.3)' }}>
          <h3>{mitigateResult.status === 'completed' ? '✅ Threat Mitigated' : '⚠️ Mitigation Completed with Errors'}</h3>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 20 }}>
            <div className="forensic-stat" style={{ '--fc': '#34d399' } as any}>
              <div className="forensic-stat-value">{mitigateResult.total_dirs_cleaned ?? 0}</div>
              <div className="forensic-stat-label">Dirs Cleaned</div>
            </div>
            <div className="forensic-stat" style={{ '--fc': '#fb923c' } as any}>
              <div className="forensic-stat-value">{mitigateResult.dropped_files_found ?? 0}</div>
              <div className="forensic-stat-label">Files Found</div>
            </div>
            <div className="forensic-stat" style={{ '--fc': '#34d399' } as any}>
              <div className="forensic-stat-value">{mitigateResult.actions_taken.length}</div>
              <div className="forensic-stat-label">Actions Taken</div>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {mitigateResult.actions_taken.map((a, i) => (
              <div key={i} className="mitigate-action">
                <span style={{ fontSize: '1.1rem' }}>{ACTION_ICONS[a.action] || '✔️'}</span>
                <span>{a.detail}</span>
              </div>
            ))}
          </div>

          {mitigateResult.errors.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--crit)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Errors</div>
              {mitigateResult.errors.map((e, i) => (
                <div key={i} style={{ fontSize: '0.8rem', color: 'var(--crit)', padding: '4px 0' }}>• {e}</div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── MITIGATE BUTTON ──────────────────────────────── */}
      {!mitigateResult && (
        <div className="card" style={{ textAlign: 'center', position: 'relative' }}>
          <h3>Threat Response</h3>

          {!showConfirm ? (
            <div>
              <p style={{ color: 'var(--muted)', fontSize: '0.875rem', marginBottom: 20 }}>
                Kill all running instances, clean dropped files, quarantine the executable, and resolve the incident.
              </p>
              <button
                className="btn mitigate-btn"
                onClick={() => setShowConfirm(true)}
                disabled={mitigating || !forensics?.total_events}
              >
                {mitigating ? 'Mitigating…' : '☠️ Mitigate Threat'}
              </button>
            </div>
          ) : (
            <div className="confirm-dialog">
              <div style={{ fontSize: '2rem', marginBottom: 12 }}>⚠️</div>
              <div style={{ fontSize: '1rem', fontWeight: 700, marginBottom: 8 }}>Confirm Full Threat Mitigation</div>
              <div style={{ fontSize: '0.85rem', color: 'var(--muted)', marginBottom: 20, maxWidth: 480, margin: '0 auto 20px' }}>
                This will <b>kill all running processes</b> of <code>{forensics?.process_name ? shortenPath(forensics.process_name).split('\\').pop() : 'the threat'}</code>,{' '}
                <b>delete {summary.files_created ?? 0} dropped files</b>, <b>quarantine the original executable</b>,
                and mark the incident as resolved. This action cannot be undone.
              </div>
              <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
                <button className="btn btn-no" onClick={() => setShowConfirm(false)}>Cancel</button>
                <button
                  className="btn mitigate-btn"
                  onClick={handleMitigate}
                  disabled={mitigating}
                >
                  {mitigating ? '⏳ Mitigating…' : '☠️ Confirm — Kill & Clean Everything'}
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
