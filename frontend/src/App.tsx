import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import AiReview from './pages/AiReview'
import AlertDetail from './pages/AlertDetail'
import ProcessForensics from './pages/ProcessForensics'
import './styles/global.css'

export default function App() {
  return (
    <BrowserRouter>
      <header className="topnav">
        <div className="topnav-inner">
          <div className="brand">
            <div className="brand-icon">S</div>
            <span>SentinelForge</span>
          </div>
          <nav className="nav-links">
            <NavLink to="/" end className={({ isActive }) => 'nav-link' + (isActive ? ' active' : '')}>Dashboard</NavLink>
          </nav>
          <span style={{ fontSize: '0.75rem', color: 'var(--muted)' }}>AI-Powered SOC</span>
        </div>
      </header>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/incident/:id" element={<AiReview />} />
        <Route path="/incident/:id/alert" element={<AlertDetail />} />
        <Route path="/incident/:id/forensics" element={<ProcessForensics />} />
      </Routes>
    </BrowserRouter>
  )
}
