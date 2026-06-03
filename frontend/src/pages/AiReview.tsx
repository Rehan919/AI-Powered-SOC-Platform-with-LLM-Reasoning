import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { fetchIncident, approveAction, dismissAction, IncidentDetail } from '../api/client'
import IncidentHeader from '../components/IncidentHeader'
import Markdown from '../components/Markdown'

const PHASE: Record<string, string> = { observe: 'Observe', plan: 'Plan', act: 'Act', reflect: 'Reflect', report: 'Report' }

export default function AiReview() {
  const { id } = useParams()
  const [inc, setInc] = useState<IncidentDetail | null>(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')

  const load = () => { if (id) fetchIncident(Number(id)).then(setInc).catch((e) => setError(e.message)) }
  useEffect(load, [id])

  if (error) return <div className="page" style={{ color: 'var(--crit)' }}>{error}</div>
  if (!inc) return <div className="page" style={{ color: 'var(--muted)' }}>Loading…</div>

  const act = async (fn: (n: number) => Promise<{ message: string }>, aid: number) => {
    const r = await fn(aid); setMsg(r.message); load()
  }

  return (
    <div className="page">
      <IncidentHeader inc={inc} tab="ai" onChanged={load} />

      {/* verdict — light card */}
      <div className="card">
        <h3>Verdict</h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <span className={`badge ${inc.risk_level}`}>{inc.risk_level}</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--muted)' }}>Confidence</span>
            <div style={{ width: 160, height: 6, background: 'var(--bg)', borderRadius: 99, overflow: 'hidden' }}>
              <div style={{ width: `${inc.confidence}%`, height: '100%', background: 'var(--accent)', borderRadius: 99 }} />
            </div>
            <span style={{ fontWeight: 700, fontSize: '0.875rem' }}>{inc.confidence}%</span>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {inc.mitre_tactics.map((t) => <span key={t} className="chip">{t}</span>)}
          </div>
        </div>
      </div>

      {/* AI report — dark card */}
      <div className="card-dark">
        <h3>AI Incident Report</h3>
        <div style={{ color: 'var(--text-inv)' }}>
          <Markdown text={inc.summary} />
        </div>
      </div>

      {/* OPAR timeline — dark card */}
      <div className="card-dark">
        <h3>OPAR Reasoning Timeline</h3>
        <div className="timeline">
          {inc.steps.map((s) => (
            <div className="step" key={s.id}>
              <div className="ph">
                <b style={{ color: 'var(--accent-2)' }}>{PHASE[s.phase] || s.phase}</b>
                <span style={{ color: 'var(--dim)' }}> · {s.agent}</span>
                {s.tool_used && <span style={{ color: 'var(--accent)' }}> → {s.tool_used}</span>}
              </div>
              {s.conclusion && <div className="cc">{s.conclusion}</div>}
              {s.thought && <div style={{ fontSize: '0.78rem', color: 'var(--dim)', fontStyle: 'italic', marginTop: 2 }}>{s.thought}</div>}
              {s.tool_output && (
                <pre className="raw" style={{ marginTop: 8, maxHeight: 160 }}>{JSON.stringify(s.tool_output, null, 2)}</pre>
              )}
            </div>
          ))}
          {inc.steps.length === 0 && <div style={{ color: 'var(--dim)' }}>No reasoning steps recorded.</div>}
        </div>
      </div>

      {/* similar incidents — light card */}
      {inc.similar && inc.similar.length > 0 && (
        <div className="card">
          <h3>Similar Past Incidents</h3>
          {inc.similar.map((s) => {
            const m = s.id.match(/inc_(\d+)/)
            return (
              <div key={s.id} style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                {m ? <a href={`/incident/${m[1]}`} style={{ fontWeight: 600 }}>#{m[1]}</a> : <span>{s.id}</span>}
                <span style={{ color: 'var(--muted)', fontSize: '0.85rem', marginLeft: 8 }}>{s.text.slice(0, 140)}</span>
              </div>
            )
          })}
        </div>
      )}

      {/* response actions — light card */}
      <div className="card">
        <h3>Response Actions</h3>
        {msg && <div style={{ color: 'var(--low)', marginBottom: 12, fontSize: '0.85rem' }}>{msg}</div>}
        {inc.actions.length === 0
          ? <p style={{ color: 'var(--muted)', fontSize: '0.875rem' }}>No actions suggested.</p>
          : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {inc.actions.map((a) => (
                <div key={a.id} style={{
                  display: 'flex', alignItems: 'center', gap: 12,
                  background: 'var(--bg)', border: '1px solid var(--border)',
                  borderRadius: 16, padding: '12px 18px'
                }}>
                  <span style={{ flex: 1, fontWeight: 600, fontSize: '0.875rem' }}>
                    {a.action_type.replace(/_/g, ' ').toUpperCase()}
                  </span>
                  {a.approved
                    ? <span className="badge low">executed</span>
                    : <>
                        <button className="btn btn-ok btn-sm" onClick={() => act(approveAction, a.id)}>Approve</button>
                        <button className="btn btn-no btn-sm" onClick={() => act(dismissAction, a.id)}>Dismiss</button>
                      </>}
                </div>
              ))}
            </div>
          )}
      </div>
    </div>
  )
}
