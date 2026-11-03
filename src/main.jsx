import React, { useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  Activity, ArrowDownRight, ArrowUpRight, Bell, Check, ChevronDown,
  ChevronRight, CircleHelp, Clock3, Command, CreditCard, Globe2,
  LayoutDashboard, LifeBuoy, ListFilter, LockKeyhole, Menu, MoreHorizontal,
  Plus, Search, Settings2, ShieldCheck, SlidersHorizontal, Sparkles,
  X, Zap
} from 'lucide-react'
import './styles.css'

const initialDomains = [
  { name: 'northstar.studio', registrar: 'Cloudflare Registrar', expires: 'Dec 18, 2026', days: 45, status: 'Healthy', ssl: 'Valid', uptime: '99.99%', initials: 'N', color: 'violet' },
  { name: 'getorbit.app', registrar: 'Porkbun', expires: 'Nov 14, 2026', days: 11, status: 'Renew soon', ssl: 'Valid', uptime: '99.98%', initials: 'G', color: 'mint' },
  { name: 'atelierandco.com', registrar: 'Namecheap', expires: 'Jan 09, 2027', days: 67, status: 'Healthy', ssl: 'Valid', uptime: '100%', initials: 'A', color: 'amber' },
  { name: 'fieldnotes.design', registrar: 'Cloudflare Registrar', expires: 'Nov 08, 2026', days: 5, status: 'Renew soon', ssl: 'Valid', uptime: '99.91%', initials: 'F', color: 'blue' },
  { name: 'usemonogram.io', registrar: 'Porkbun', expires: 'Feb 22, 2027', days: 111, status: 'Healthy', ssl: 'Expiring', uptime: '99.97%', initials: 'M', color: 'rose' },
]

const navGroups = [
  { label: 'WORKSPACE', items: [
    { id: 'Overview', icon: LayoutDashboard },
    { id: 'Domains', icon: Globe2, count: '05' },
    { id: 'Monitoring', icon: Activity },
    { id: 'Expiry calendar', icon: Clock3 },
  ]},
  { label: 'MANAGE', items: [
    { id: 'DNS records', icon: SlidersHorizontal },
    { id: 'SSL certificates', icon: LockKeyhole },
    { id: 'Activity log', icon: ListFilter },
  ]},
]

function App() {
  const [domains, setDomains] = useState(() => {
    try { return JSON.parse(localStorage.getItem('dp-domains')) || initialDomains } catch { return initialDomains }
  })
  const [active, setActive] = useState('Overview')
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('All domains')
  const [modal, setModal] = useState(false)
  const [mobileMenu, setMobileMenu] = useState(false)
  const [toast, setToast] = useState('')
  const [form, setForm] = useState({ name: '', registrar: 'Cloudflare Registrar', expires: '' })

  const saveDomains = (next) => {
    setDomains(next)
    localStorage.setItem('dp-domains', JSON.stringify(next))
  }
  const visible = useMemo(() => domains.filter(d => {
    const matches = d.name.toLowerCase().includes(query.toLowerCase())
    const status = filter === 'All domains' || (filter === 'Renew soon' ? d.days <= 14 : d.status === filter)
    return matches && status
  }), [domains, query, filter])

  const notify = (message) => {
    setToast(message)
    window.setTimeout(() => setToast(''), 2600)
  }

  const addDomain = (e) => {
    e.preventDefault()
    const clean = form.name.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '')
    if (!clean || !clean.includes('.') || domains.some(d => d.name === clean)) {
      notify('Enter a valid, unique domain name')
      return
    }
    const expires = form.expires ? new Date(form.expires + 'T00:00:00') : new Date(Date.now() + 365 * 86400000)
    const next = [{ name: clean, registrar: form.registrar, expires: expires.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' }), days: Math.ceil((expires - new Date()) / 86400000), status: 'Healthy', ssl: 'Not checked', uptime: '—', initials: clean[0].toUpperCase(), color: 'blue' }, ...domains]
    saveDomains(next)
    setForm({ name: '', registrar: 'Cloudflare Registrar', expires: '' })
    setModal(false)
    notify('Domain added to your workspace')
  }

  const selectNav = (id) => { setActive(id); setMobileMenu(false) }
  const pageTitle = active === 'Overview' ? 'Overview' : active

  return <div className="app-shell">
    <aside className={`sidebar ${mobileMenu ? 'sidebar-open' : ''}`}>
      <div className="brand"><div className="brand-mark"><span /></div><span>domainpilot</span><span className="brand-beta">BETA</span></div>
      <button className="workspace-switch"><div className="workspace-avatar">J</div><span><b>Josh's workspace</b><small>Personal workspace</small></span><ChevronDown size={15} /></button>
      <div className="side-scroll">
        {navGroups.map(group => <div className="nav-group" key={group.label}>
          <div className="nav-label">{group.label}</div>
          {group.items.map(item => <button key={item.id} onClick={() => selectNav(item.id)} className={`nav-item ${active === item.id ? 'active' : ''}`}>
            <item.icon size={17} strokeWidth={1.8} /><span>{item.id}</span>{item.count && <em>{item.count}</em>}
          </button>)}
        </div>)}
      </div>
      <div className="sidebar-bottom">
        <div className="plan-card"><div className="plan-icon"><Sparkles size={15}/></div><div><b>Free plan</b><small>{domains.length} of 25 domains used</small></div><button aria-label="Plan details"><ChevronRight size={15}/></button><div className="plan-progress"><i style={{width: `${Math.min(domains.length / 25 * 100, 100)}%`}} /></div></div>
        <button className="nav-item" onClick={() => selectNav('Settings')}><Settings2 size={17}/><span>Settings</span></button>
        <button className="nav-item" onClick={() => notify('Help center is coming soon')}><LifeBuoy size={17}/><span>Help & support</span></button>
        <div className="profile"><div className="profile-avatar">JD</div><div><b>Josh Drn</b><small>Administrator</small></div><MoreHorizontal size={18}/></div>
      </div>
    </aside>
    {mobileMenu && <button className="mobile-scrim" onClick={() => setMobileMenu(false)} aria-label="Close menu" />}
    <main className="main-area">
      <header className="topbar">
        <button className="icon-button mobile-menu-button" onClick={() => setMobileMenu(true)} aria-label="Open menu"><Menu size={20}/></button>
        <div className="breadcrumbs"><span>Workspace</span><ChevronRight size={14}/><b>{pageTitle}</b></div>
        <div className="top-actions"><div className="system-status"><i/> All systems operational</div><button className="icon-button search-shortcut" onClick={() => document.getElementById('domain-search')?.focus()}><Search size={17}/><kbd>⌘ K</kbd></button><button className="icon-button notification-button" onClick={() => notify('You’re all caught up')} aria-label="Notifications"><Bell size={17}/><i/></button><div className="top-avatar">JD</div></div>
      </header>
      <div className="page-content">
        <div className="page-heading">
          <div><div className="eyebrow"><span className="eyebrow-line"/> YOUR CONTROL ROOM</div><h1>{pageTitle}<span className="heading-period">.</span></h1><p>A clear view of everything you own on the internet.</p></div>
          <button className="primary-button" onClick={() => setModal(true)}><Plus size={17}/> Add domain</button>
        </div>
        {active === 'Overview' || active === 'Domains' ? <>
          <section className="metrics">
            <div className="metric metric-main"><div className="metric-top"><span>DOMAIN PORTFOLIO</span><Globe2 size={16}/></div><div className="metric-number">{String(domains.length).padStart(2,'0')}<span> domains</span></div><div className="metric-foot"><span className="metric-dot green"/> Across your workspace <span className="metric-foot-right">Updated just now</span></div></div>
            <div className="metric"><div className="metric-top"><span>HEALTHY</span><ShieldCheck size={16}/></div><div className="metric-number">{domains.filter(d => d.status === 'Healthy').length}<span> / {domains.length}</span></div><div className="metric-foot"><span className="metric-dot green"/> No known issues</div></div>
            <div className="metric"><div className="metric-top"><span>RENEWAL WINDOW</span><Clock3 size={16}/></div><div className="metric-number">{domains.filter(d => d.days <= 14).length}<span> due soon</span></div><div className="metric-foot"><span className="metric-dot amber"/> Within 14 days</div></div>
            <div className="metric"><div className="metric-top"><span>SSL CERTIFICATES</span><LockKeyhole size={16}/></div><div className="metric-number">{domains.filter(d => d.ssl === 'Valid').length}<span> valid</span></div><div className="metric-foot"><span className="metric-dot green"/> {domains.filter(d => d.ssl === 'Expiring').length} need attention</div></div>
          </section>
          <section className="insight-strip"><div className="insight-symbol"><Zap size={17}/></div><div><b>Your portfolio is looking good.</b><span> Keep an eye on upcoming renewals to avoid unexpected downtime.</span></div><button onClick={() => selectNav('Expiry calendar')}>View calendar <ArrowUpRight size={14}/></button></section>
          <section className="domains-section">
            <div className="section-heading"><div><div className="eyebrow">PORTFOLIO</div><h2>Your domains <span>{domains.length}</span></h2></div><button className="text-button" onClick={() => selectNav('Domains')}>View all domains <ArrowUpRight size={15}/></button></div>
            <div className="table-toolbar"><div className="search-field"><Search size={16}/><input id="domain-search" value={query} onChange={e => setQuery(e.target.value)} placeholder="Search domains..." /><kbd>⌘ F</kbd></div><div className="filter-wrap"><ListFilter size={15}/><select value={filter} onChange={e => setFilter(e.target.value)}><option>All domains</option><option>Healthy</option><option>Renew soon</option></select><ChevronDown size={14}/></div><button className="filter-icon" onClick={() => setFilter('All domains')} aria-label="Clear filters"><SlidersHorizontal size={16}/></button></div>
            <div className="domain-table">
              <div className="table-head"><span>DOMAIN</span><span>REGISTRAR</span><span>EXPIRATION</span><span>SSL STATUS</span><span>UPTIME</span><span/></div>
              {visible.length ? visible.map((d, i) => <div className="domain-row" key={d.name}><div className="domain-identity"><div className={`domain-favicon ${d.color}`}>{d.initials}</div><div><b>{d.name}</b><small>{d.status === 'Renew soon' ? 'Renewal approaching' : 'Connected domain'}</small></div></div><div className="registrar-cell">{d.registrar}</div><div className="expiry-cell"><b>{d.expires}</b><small className={d.days <= 14 ? 'warning-text' : ''}>{d.days < 0 ? 'Expired' : `${d.days} days left`}</small></div><div><span className={`status-pill ${d.ssl === 'Valid' ? 'status-good' : d.ssl === 'Expiring' ? 'status-warn' : 'status-muted'}`}><i/>{d.ssl}</span></div><div className="uptime-cell">{d.uptime}</div><button className="row-more" onClick={() => notify(`Selected ${d.name}`)} aria-label={`Options for ${d.name}`}><MoreHorizontal size={18}/></button></div>) : <div className="empty-state"><Globe2 size={24}/><b>No domains found</b><span>Try another search or change your filter.</span></div>}
            </div>
            <div className="table-footer"><span>Showing <b>{visible.length}</b> of <b>{domains.length}</b> domains</span><span className="demo-note"><i/> Workspace preview · Data stored in this browser</span></div>
          </section>
          <footer className="page-footer"><span>© 2026 DomainPilot</span><span><span className="footer-live"/> Monitoring preview <span className="footer-divider">·</span> Built for the details.</span></footer>
        </> : <section className="coming-panel"><div className="coming-icon"><Command size={22}/></div><div className="eyebrow">WORKSPACE MODULE</div><h2>{active}</h2><p>This space is being prepared. Your domain portfolio stays right here while we bring the rest of DomainPilot online.</p><button className="secondary-button" onClick={() => selectNav('Overview')}>Back to overview <ChevronRight size={15}/></button></section>}
      </div>
    </main>
    {modal && <div className="modal-backdrop" onMouseDown={e => e.target === e.currentTarget && setModal(false)}><form className="modal" onSubmit={addDomain}><div className="modal-head"><div><div className="eyebrow">PORTFOLIO</div><h2>Add a domain</h2></div><button type="button" className="icon-button" onClick={() => setModal(false)}><X size={18}/></button></div><p className="modal-copy">Bring a domain into your workspace. Monitoring integrations will be connected in a later step.</p><label>Domain name<input autoFocus placeholder="example.com" value={form.name} onChange={e => setForm({...form, name:e.target.value})}/></label><label>Registrar<select value={form.registrar} onChange={e => setForm({...form, registrar:e.target.value})}><option>Cloudflare Registrar</option><option>Namecheap</option><option>Porkbun</option><option>GoDaddy</option><option>Other</option></select></label><label>Expiration date <span className="optional">OPTIONAL</span><input type="date" value={form.expires} onChange={e => setForm({...form, expires:e.target.value})}/></label><div className="modal-actions"><button type="button" className="secondary-button" onClick={() => setModal(false)}>Cancel</button><button className="primary-button" type="submit"><Plus size={16}/> Add domain</button></div></form></div>}
    {toast && <div className="toast"><Check size={16}/>{toast}</div>}
  </div>
}

createRoot(document.getElementById('root')).render(<App />)
