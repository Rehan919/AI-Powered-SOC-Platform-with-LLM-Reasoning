import { ReactNode } from 'react'

function inline(s: string): ReactNode[] {
  return s.split(/(\*\*[^*]+\*\*)/g).map((p, i) =>
    p.startsWith('**') && p.endsWith('**') ? <strong key={i}>{p.slice(2, -2)}</strong> : <span key={i}>{p}</span>)
}

function headColor(h: string): string {
  const s = h.toLowerCase()
  if (s.includes('impact')) return 'var(--high)'
  if (s.includes('recommend') || s.includes('action')) return 'var(--low)'
  if (s.includes('what happened') || s.includes('detail')) return 'var(--med)'
  return 'var(--accent)'
}

function Heading({ text }: { text: string }) {
  const c = headColor(text)
  return (
    <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', fontSize: '0.92rem', fontWeight: 700,
      textTransform: 'uppercase', letterSpacing: '0.6px', color: c, margin: '1.4rem 0 0.6rem',
      paddingBottom: '0.4rem', borderBottom: '1px solid var(--border)' }}>
      <span style={{ width: 4, height: 15, background: c, borderRadius: 2, display: 'inline-block' }} />
      {text}
    </h4>
  )
}

export default function Markdown({ text }: { text: string }) {
  const out: ReactNode[] = []
  let list: string[] = []
  const flush = (k: string) => {
    if (list.length) { out.push(<ul key={k} style={{ margin: '0.25rem 0 0.5rem 1.2rem', lineHeight: 1.65 }}>{list.map((l, j) => <li key={j} style={{ marginBottom: '0.3rem' }}>{inline(l)}</li>)}</ul>); list = [] }
  }
  ;(text || '').split('\n').forEach((ln, i) => {
    const t = ln.trim()
    if (t.startsWith('## ')) { flush('u' + i); out.push(<Heading key={i} text={t.slice(3)} />) }
    else if (t.startsWith('# ')) { flush('u' + i); out.push(<Heading key={i} text={t.slice(2)} />) }
    else if (t.startsWith('### ')) { flush('u' + i); out.push(<Heading key={i} text={t.slice(4)} />) }
    else if (t.startsWith('- ') || t.startsWith('* ')) { list.push(t.slice(2)) }
    else if (t === '') { flush('u' + i) }
    else { flush('u' + i); out.push(<p key={i} style={{ lineHeight: 1.65, margin: '0.25rem 0' }}>{inline(t)}</p>) }
  })
  flush('end')
  return <>{out}</>
}
