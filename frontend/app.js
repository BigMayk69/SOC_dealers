const API_ROOT = `${(window.SOC_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '')}/api`;
const ROLE_EMAILS = {
  SOC_LEAD_ADMIN: 'admin@dealers.corp',
  SENIOR_ANALYST: 'senior.analyst@dealers.corp',
  TIER1_ANALYST: 'tier1.analyst@dealers.corp',
  AUDITOR: 'auditor@dealers.corp',
};
const ROLE_LABELS = {
  SOC_LEAD_ADMIN: 'SOC lead admin',
  SENIOR_ANALYST: 'Senior analyst',
  TIER1_ANALYST: 'Tier 1 analyst',
  AUDITOR: 'Auditor',
};
const state = {
  user: null, role: 'SOC_LEAD_ADMIN', view: 'dashboard', summary: null,
  incidents: [], alerts: [], selectedIncident: null, graph: null,
  selectedAlertId: null,
  incidentFilters: { search: '', status: '', priority: '', min_risk: '' },
  alertFilters: { search: '', source: '', severity: '' },
  stream: null, streamAt: null, streamData: null, busy: false,
  copilotMessages: [],
};

const $ = (selector, root = document) => root.querySelector(selector);
const view = $('#view');
const escapeHtml = (value = '') => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
const number = (value, digits = 0) => Number(value || 0).toLocaleString(undefined, { maximumFractionDigits: digits });
const dateTime = value => value ? new Date(value).toLocaleString() : '—';
const shortTime = value => value ? new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—';
const permission = name => Boolean(state.user?.permissions?.includes(name));
const priorityClass = value => /P1|Critical/i.test(value || '') ? 'critical' : /P2|High/i.test(value || '') ? 'high' : /P3|Medium/i.test(value || '') ? 'medium' : 'low';
const statusClass = value => String(value || '').toLowerCase().replace(/[^a-z]+/g, '-');

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Accept', 'application/json');
  headers.set('X-User-Email', ROLE_EMAILS[state.role] || ROLE_EMAILS.SOC_LEAD_ADMIN);
  headers.set('X-User-Role', state.role);
  if (options.body !== undefined) headers.set('Content-Type', 'application/json');
  let response;
  try {
    response = await fetch(`${API_ROOT}${path}`, { ...options, headers });
  } catch (error) {
    throw new Error(`Could not reach backend at ${API_ROOT}. Start it with python run.py. ${error.message}`);
  }
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    let message = body;
    try { message = JSON.parse(body).detail || JSON.parse(body).message || body; } catch { /* use response text */ }
    throw new Error(`${response.status} ${response.statusText}${message ? ` — ${typeof message === 'string' ? message : JSON.stringify(message)}` : ''}`);
  }
  if (response.status === 204) return null;
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

const api = {
  summary: () => request('/cockpit/summary'),
  incidents: filters => {
    const query = new URLSearchParams({ skip: '0', limit: '50' });
    Object.entries(filters).forEach(([key, value]) => { if (value !== '' && value != null) query.set(key, value); });
    return request(`/incidents?${query}`);
  },
  incident: id => request(`/incidents/${encodeURIComponent(id)}`),
  graph: id => request(`/cockpit/graph/${encodeURIComponent(id)}`),
  alerts: filters => {
    const query = new URLSearchParams({ skip: '0', limit: '50' });
    Object.entries(filters).forEach(([key, value]) => { if (value !== '' && value != null) query.set(key, value); });
    return request(`/alerts?${query}`);
  },
  currentUser: () => request('/auth/me'),
  roles: () => request('/auth/roles'),
  updateIncident: (id, data) => request(`/incidents/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(data) }),
  triage: id => request(`/incidents/${encodeURIComponent(id)}/triage-ai`, { method: 'POST', body: JSON.stringify({}) }),
  contain: (id, actionType, target) => request(`/incidents/${encodeURIComponent(id)}/contain`, { method: 'POST', body: JSON.stringify({ incident_id: id, action_type: actionType, target, status: 'Pending', executed_by: state.user?.email || ROLE_EMAILS[state.role] }) }),
  copilot: (incidentId, messages) => request('/copilot/chat', { method: 'POST', body: JSON.stringify({ incident_id: incidentId || null, messages }) }),
};

function toast(message, kind = 'success') {
  const node = document.createElement('div');
  node.className = `toast ${kind}`;
  node.textContent = message;
  $('#toasts').append(node);
  setTimeout(() => node.remove(), 5000);
}
function setNotice(message, kind = 'error') {
  const node = $('#notice');
  node.className = `notice ${kind}`;
  node.textContent = message;
}
function clearNotice() { $('#notice').className = 'notice hidden'; }
function setApiState(online, text) {
  $('#api-dot').className = `status-dot ${online ? 'online' : 'offline'}`;
  $('#api-state').textContent = online ? 'Backend online' : 'Backend unavailable';
  $('#api-address').textContent = text || API_ROOT.replace(/^https?:\/\//, '');
}
function setStreamStatus(type, text) {
  $('#stream-status').className = `live-indicator ${type}`;
  $('#stream-status').innerHTML = `<span></span>${escapeHtml(text)}`;
}
function requirePermission(name, actionName) {
  if (permission(name)) return true;
  toast(`${actionName} is unavailable for the ${ROLE_LABELS[state.role]} demo role.`, 'error');
  return false;
}
function confirmAction(title, copy, confirmLabel = 'Confirm action') {
  return new Promise(resolve => {
    const dialog = $('#confirm-dialog');
    $('#confirm-title').textContent = title;
    $('#confirm-copy').textContent = copy;
    $('#confirm-ok').textContent = confirmLabel;
    dialog.addEventListener('close', () => resolve(dialog.returnValue === 'confirm'), { once: true });
    dialog.showModal();
  });
}

function renderMetric(label, value, detail, icon, tone = '', liveKey = '') {
  return `<article class="metric-card"><div class="metric-top"><span>${escapeHtml(label)}</span><i class="metric-icon ${tone}">${icon}</i></div><strong ${liveKey ? `data-live="${liveKey}"` : ''}>${escapeHtml(value)}</strong><small>${escapeHtml(detail)}</small></article>`;
}
function incidentRows(items, compact = false) {
  if (!items?.length) return `<div class="empty-state"><span>⌁</span><b>No incidents match</b><small>Adjust the filters or check the API connection.</small></div>`;
  return `<div class="incident-list">${items.map(i => `<button class="incident-row ${compact ? 'compact' : ''}" data-incident="${escapeHtml(i.id)}">
    <span class="priority-mark ${priorityClass(i.priority)}"></span>
    <span class="incident-main"><b>${escapeHtml(i.title)}</b><small class="mono">${escapeHtml(i.id)} <span>·</span> ${number(i.alert_count)} alerts</small></span>
    <span class="incident-risk"><b>${number(i.risk_score)}</b><small>RISK</small></span>
    <span class="badge ${priorityClass(i.priority)}">${escapeHtml(i.priority || '—')}</span>
    <span class="status-pill ${statusClass(i.status)}">${escapeHtml(i.status || '—')}</span>
  </button>`).join('')}</div>`;
}
function barChart(object, kind = 'source') {
  const entries = Object.entries(object || {}).sort((a, b) => b[1] - a[1]).slice(0, 7);
  if (!entries.length) return '<div class="subtle-empty">No telemetry distribution returned.</div>';
  const max = Math.max(...entries.map(([, count]) => count), 1);
  return `<div class="bar-list">${entries.map(([label, count], i) => `<div class="bar-item"><div class="bar-label"><span>${escapeHtml(label)}</span><b>${number(count)}</b></div><div class="bar-track"><i class="${kind}" style="width:${Math.max(3, count / max * 100)}%;animation-delay:${i * 45}ms"></i></div></div>`).join('')}</div>`;
}

function renderDashboard() {
  state.view = 'dashboard';
  $('#crumb-current').textContent = 'OVERVIEW';
  const data = state.summary;
  if (!data) { view.innerHTML = errorPanel('Dashboard unavailable', 'No cockpit summary has been received yet. Check that the FastAPI backend is running and that SOC_API_BASE_URL points to it.', 'refresh-dashboard'); return; }
  const k = data.kpis || {};
  const health = data.connection_health || {};
  const liveMetrics = state.streamData?.metrics;
  const displayedAlerts = liveMetrics?.total_alerts ?? k.total_raw_alerts;
  const displayedIncidents = liveMetrics?.total_incidents ?? k.consolidated_incidents;
  const healthItems = [
    ['API', health.backend_status || 'Unknown', health.backend_status === 'online'],
    ['DATABASE', health.database_connected ? 'Connected' : 'Unknown', Boolean(health.database_connected)],
    ['AI ENGINE', health.ai_engine || 'Unknown', true],
    ['VERSION', health.api_version || '—', true],
  ];
  view.innerHTML = `<div class="page-heading"><div><div class="eyebrow">SECURITY OPERATIONS · LIVE</div><h1>Command center</h1><p>Prioritized incidents, response metrics, and backend health.</p></div><button class="button button-primary" data-action="open-incidents">View incident queue <span>↗</span></button></div>
    <div id="stream-stale" class="stale-banner ${state.streamAt ? 'hidden' : ''}"><span>◷</span>Live feed is reconnecting. Summary values are from the last successful API response.</div>
    <div class="metrics-grid">
      ${renderMetric('Raw alerts', number(displayedAlerts), 'Current telemetry volume', '⌑', '', 'alerts')}
      ${renderMetric('Consolidated incidents', number(displayedIncidents), `${number(k.critical_p1_count)} critical P1 require attention`, '⌁', 'orange', 'incidents')}
      ${renderMetric('Volume reduction', `${number(liveMetrics?.reduction_pct ?? k.volume_reduction_pct, 1)}%`, 'Alerts grouped into incidents', '↘', 'green', 'reduction')}
      ${renderMetric('Average triage time', `${number(k.average_mttt_seconds)}s`, `Target ${number(k.mttt_target_seconds)}s · ${k.target_sla_met ? 'SLA met' : 'SLA missed'}`, '◷', k.target_sla_met ? 'green' : 'orange')}
    </div>
    <div class="dashboard-grid">
      <section class="panel queue-panel"><div class="panel-heading"><div><div class="eyebrow">RISK ORDERED</div><h2>Priority queue</h2></div><button class="text-button" data-action="open-incidents">All incidents <span>→</span></button></div>
       ${incidentRows((data.incidents_queue || []).slice(0, 8), true)}</section>
      <div class="right-stack">
        <section class="panel"><div class="panel-heading"><div><div class="eyebrow">TELEMETRY</div><h2>Sources</h2></div><span class="panel-caption">BY EVENT COUNT</span></div>${barChart(data.telemetry_breakdown?.by_source, 'source')}</section>
        <section class="panel"><div class="panel-heading"><div><div class="eyebrow">SEVERITY</div><h2>Alert distribution</h2></div></div>${barChart(data.telemetry_breakdown?.by_severity, 'severity')}</section>
      </div>
    </div>
    <div class="bottom-grid"><section class="panel"><div class="panel-heading"><div><div class="eyebrow">SYSTEM</div><h2>Connection health</h2></div><span class="health-chip"><i></i>API HEALTHY</span></div><div class="health-grid">${healthItems.map(([label, value, online]) => `<div class="health-item"><span class="health-check ${online ? '' : 'bad'}">${online ? '✓' : '!'}</span><div><small>${escapeHtml(label)}</small><b>${escapeHtml(value)}</b></div></div>`).join('')}</div><div class="server-time">Server time · ${escapeHtml(dateTime(health.server_time))}</div></section>
    <section class="panel"><div class="panel-heading"><div><div class="eyebrow">RECENT RESPONSE</div><h2>Containment activity</h2></div><span class="panel-caption">LATEST 10</span></div>${renderActions(data.recent_containment_actions || [])}</section></div>`;
  setApiState(true);
}
function renderActions(actions) {
  if (!actions.length) return '<div class="subtle-empty">No containment actions recorded.</div>';
  return `<div class="action-list">${actions.slice(0, 5).map(a => `<div class="action-row"><span class="action-icon">⌁</span><div><b>${escapeHtml(a.action_type)}</b><small>${escapeHtml(a.target)} · ${escapeHtml(a.incident_id)}</small></div><span class="status-pill ${statusClass(a.status)}">${escapeHtml(a.status)}</span></div>`).join('')}</div>`;
}

function renderIncidentView() {
  state.view = 'incidents';
  $('#crumb-current').textContent = 'INCIDENTS';
  view.innerHTML = `<div class="page-heading"><div><div class="eyebrow">INVESTIGATION QUEUE</div><h1>Incidents</h1><p>Filter and inspect incidents returned by the backend.</p></div><button class="button button-quiet" data-action="reload-incidents">↻ Refresh queue</button></div>
    <form class="filter-bar" id="incident-filter"><label class="search-field"><span>⌕</span><input name="search" placeholder="Search title or incident ID" value="${escapeHtml(state.incidentFilters.search)}" /></label>
      <select name="status"><option value="">All statuses</option>${['New','Triaging','Contained','Closed'].map(v => `<option ${state.incidentFilters.status === v ? 'selected' : ''}>${v}</option>`).join('')}</select>
      <select name="priority"><option value="">All priorities</option>${['P1 - Critical','P2 - High','P3 - Medium','P4 - Low'].map(v => `<option ${state.incidentFilters.priority === v ? 'selected' : ''}>${v}</option>`).join('')}</select>
      <label class="risk-filter">Min risk <input type="number" name="min_risk" min="0" max="100" placeholder="0" value="${escapeHtml(state.incidentFilters.min_risk)}" /></label>
      <button class="button button-primary" type="submit">Apply filters</button></form>
    <div class="panel table-panel"><div class="table-meta"><span>${state.incidents.length ? `${number(state.incidents.length)} results · max 50 per request` : 'No results'}</span><span class="table-sort">ORDERED BY RISK ↓</span></div>${incidentRows(state.incidents)}</div>`;
}
function renderAlertView() {
  state.view = 'alerts';
  $('#crumb-current').textContent = 'ALERT STREAM';
  const rows = state.alerts.map(a => `<tr><td class="mono">${escapeHtml(shortTime(a.timestamp))}</td><td><span class="source-pill">${escapeHtml(a.source)}</span></td><td><span class="severity-dot ${priorityClass(a.severity)}"></span>${escapeHtml(a.severity)}</td><td><b>${escapeHtml(a.rule_name)}</b><small class="cell-secondary">${escapeHtml(a.event_type)}</small></td><td>${escapeHtml(a.src_host || a.src_ip || '—')}</td><td>${escapeHtml(a.username || '—')}</td><td>${a.incident_id ? `<button class="inline-link" data-incident="${escapeHtml(a.incident_id)}">${escapeHtml(a.incident_id)}</button>` : '—'}</td></tr>`).join('');
  view.innerHTML = `<div class="page-heading"><div><div class="eyebrow">RAW TELEMETRY</div><h1>Alert stream</h1><p>Latest backend alerts. The API returns an array, paged with skip and limit.</p></div><button class="button button-quiet" data-action="reload-alerts">↻ Refresh alerts</button></div>
    <form class="filter-bar" id="alert-filter"><label class="search-field"><span>⌕</span><input name="search" placeholder="Search rule, host, or user" value="${escapeHtml(state.alertFilters.search)}" /></label><input name="source" placeholder="Source" value="${escapeHtml(state.alertFilters.source)}" /><select name="severity"><option value="">All severity</option>${['Critical','High','Medium','Low','Informational'].map(v => `<option ${state.alertFilters.severity === v ? 'selected' : ''}>${v}</option>`).join('')}</select><button class="button button-primary" type="submit">Apply filters</button></form>
    <div class="panel table-panel"><div class="table-meta"><span>${state.alerts.length ? `${number(state.alerts.length)} alerts · latest first` : 'No alerts returned'}</span><span class="table-sort">50 PER REQUEST</span></div><div class="table-scroll"><table><thead><tr><th>TIME</th><th>SOURCE</th><th>SEVERITY</th><th>DETECTION</th><th>HOST</th><th>IDENTITY</th><th>INCIDENT</th></tr></thead><tbody>${rows || `<tr><td colspan="7"><div class="empty-state"><span>⌑</span><b>No alerts match</b><small>Adjust the filters or check the API response.</small></div></td></tr>`}</tbody></table></div></div>`;
}

function renderGraph(graphResponse) {
  const graph = graphResponse?.graph || { nodes: [], edges: [] };
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const nodeLabel = node => node.label || node.entity_value || node.name || node.id || node.type || 'Entity';
  const edgeLabel = edge => edge.label || edge.relationship || edge.type || edge.relation || 'linked to';
  return `<div class="graph-summary"><div class="graph-count"><b>${number(graphResponse?.stats?.total_nodes ?? nodes.length)}</b><small>NODES</small></div><div class="graph-count"><b>${number(graphResponse?.stats?.total_edges ?? edges.length)}</b><small>EDGES</small></div><span class="graph-note">Topology provided by correlation engine</span></div>
    ${nodes.length ? `<div class="node-list">${nodes.slice(0, 18).map(n => `<span class="graph-node"><i>${escapeHtml(String(n.type || n.entity_type || 'E').slice(0,1).toUpperCase())}</i>${escapeHtml(nodeLabel(n))}</span>`).join('')}</div>` : '<div class="subtle-empty">No topology nodes returned for this incident.</div>'}
    ${edges.length ? `<div class="edge-list">${edges.slice(0, 12).map(e => `<div><span>${escapeHtml(e.source || e.from || '—')}</span><i>→ ${escapeHtml(edgeLabel(e))} →</i><span>${escapeHtml(e.target || e.to || '—')}</span></div>`).join('')}</div>` : ''}`;
}
function alertPivots(alert) {
  return {
    host: [...new Set([alert.src_host, alert.dest_host].filter(Boolean).map(value => String(value).toLowerCase()))],
    user: [...new Set([alert.username].filter(Boolean).map(value => String(value).toLowerCase()))],
    ip: [...new Set([alert.src_ip, alert.dest_ip, alert.dst_ip].filter(Boolean).map(value => String(value).toLowerCase()))],
  };
}
function sharedAlertPivots(left, right) {
  const a = alertPivots(left), b = alertPivots(right), shared = [];
  for (const kind of ['host', 'user', 'ip']) {
    for (const value of a[kind]) if (b[kind].includes(value)) shared.push({ kind, value });
  }
  return shared;
}
function alertTime(alert) {
  const value = Date.parse(alert.timestamp || '');
  return Number.isFinite(value) ? value : 0;
}
function renderEventTrail(incident) {
  const events = [...(incident.alerts || [])].sort((a, b) => alertTime(a) - alertTime(b));
  if (!events.length) return '<section class="panel"><div class="panel-heading"><div><div class="eyebrow">ALERT CORRELATION</div><h2>Event trail</h2></div></div><div class="subtle-empty">No linked alerts were returned for this incident.</div></section>';
  if (!events.some(item => item.id === state.selectedAlertId)) state.selectedAlertId = events[events.length - 1].id;
  const target = events.find(item => item.id === state.selectedAlertId) || events[events.length - 1];
  const before = events.filter(item => item.id !== target.id && alertTime(item) < alertTime(target));
  const reverseTrail = [{ alert: target, link: [] }];
  let current = target;
  while (reverseTrail.length < 9) {
    const prior = before.filter(item => alertTime(item) < alertTime(current) && !reverseTrail.some(entry => entry.alert.id === item.id))
      .map(item => ({ alert: item, link: sharedAlertPivots(item, current) }))
      .filter(entry => entry.link.length)
      .sort((a, b) => alertTime(b.alert) - alertTime(a.alert))[0];
    if (!prior) break;
    reverseTrail.push(prior);
    current = prior.alert;
  }
  const trail = reverseTrail.reverse();
  const targetIndex = trail.findIndex(entry => entry.alert.id === target.id);
  const trailRows = trail.map((entry, index) => {
    const alert = entry.alert;
    const next = trail[index + 1];
    const pivotNames = next ? sharedAlertPivots(alert, next.alert).map(p => `${p.kind}: ${p.value}`).join(' · ') : '';
    return `<div class="trail-event ${alert.id === target.id ? 'is-target' : ''}">
      <span class="trail-rail"><i></i></span>
      <div class="trail-card"><div class="trail-card-top"><span class="trail-time">${escapeHtml(dateTime(alert.timestamp))}</span><span class="severity-tag ${priorityClass(alert.severity)}">${escapeHtml(alert.severity || '—')}</span>${alert.id === target.id ? '<span class="target-tag">TARGET ALERT</span>' : ''}</div>
      <b>${escapeHtml(alert.rule_name || alert.event_type || 'Security event')}</b><small>${escapeHtml(alert.source || 'Unknown source')} · ${escapeHtml(alert.event_type || 'Event')} · ${escapeHtml(alert.id)}</small>
      <div class="trail-context">${[alert.src_host && `Host ${alert.src_host}`, alert.username && `User ${alert.username}`, (alert.dest_ip || alert.dst_ip || alert.src_ip) && `IP ${alert.dest_ip || alert.dst_ip || alert.src_ip}`].filter(Boolean).map(escapeHtml).join('<span>·</span>')}</div>
      ${next ? `<div class="trail-link">↓ Correlated via ${escapeHtml(pivotNames || 'shared entity')}</div>` : ''}</div></div>`;
  }).join('');
  return `<section class="panel event-trail-panel"><div class="panel-heading"><div><div class="eyebrow">CORRELATION PATH · ${number(trail.length)} EVENTS</div><h2>Trail to a specific alert</h2></div><label class="trail-target-select"><span>TARGET</span><select id="trail-target-select">${events.map(item => `<option value="${escapeHtml(item.id)}" ${item.id === target.id ? 'selected' : ''}>${escapeHtml(shortTime(item.timestamp))} · ${escapeHtml(item.severity)} · ${escapeHtml(item.rule_name || item.id)}</option>`).join('')}</select></label></div>
    <p class="trail-disclaimer">Shows up to ${trail.length - 1} earlier alerts connected to the target through shared host, user, or IP pivots. Correlation indicates a relationship; it does not prove causation.</p>
    <div class="trail-list">${trailRows}</div>
    <div class="trail-footer">${targetIndex === 0 ? 'No earlier linked alert was found in this incident.' : `Showing ${targetIndex} earlier correlated event${targetIndex === 1 ? '' : 's'} leading to ${escapeHtml(target.id)}.`}</div>
  </section>`;
}
function renderDetail(incident) {
  state.selectedIncident = incident;
  state.view = 'detail';
  $('#crumb-current').textContent = 'INCIDENT DETAIL';
  const a = incident.alerts || [];
  const actions = incident.containment_actions || [];
  const statusOptions = ['New','Triaging','Contained','Closed'];
  const tactics = incident.mitre_tactics || [];
  const tech = incident.mitre_techniques || [];
  const recs = incident.containment_recommendations || [];
  view.innerHTML = `<button class="back-link" data-action="back-incidents">← Incident queue</button><div class="page-heading detail-heading"><div><div class="eyebrow">INCIDENT DOSSIER · ${escapeHtml(incident.id)}</div><h1>${escapeHtml(incident.title)}</h1><p>Created ${escapeHtml(dateTime(incident.created_at))} · Updated ${escapeHtml(dateTime(incident.updated_at))}</p></div><span class="badge ${priorityClass(incident.priority)} large">${escapeHtml(incident.priority)}</span></div>
    <div class="detail-kpis"><div><small>RISK SCORE</small><b>${number(incident.risk_score)}</b><i class="risk-meter"><span style="width:${Math.max(0, Math.min(100, Number(incident.risk_score || 0)))}%"></span></i></div><div><small>STATUS</small><b><span class="status-pill ${statusClass(incident.status)}">${escapeHtml(incident.status)}</span></b></div><div><small>RELATED ALERTS</small><b>${number(incident.alert_count)}</b></div><div><small>TRIAGE TIME</small><b>${number(incident.triage_time_seconds)}s</b></div></div>
    <div class="detail-grid"><div class="detail-main">
      <section class="panel"><div class="panel-heading"><div><div class="eyebrow">AI BRIEFING</div><h2>Assessment</h2></div>${incident.ai_confidence_score != null ? `<span class="confidence">${Math.round(Number(incident.ai_confidence_score) * 100)}% CONFIDENCE</span>` : ''}</div><div class="briefing"><h3>Executive summary</h3><p>${escapeHtml(incident.summary_ai || 'No AI summary is recorded yet. Generate a fresh triage to request an assessment from the backend.')}</p>${incident.root_cause_ai ? `<h3>Root cause</h3><p>${escapeHtml(incident.root_cause_ai)}</p>` : ''}${incident.attack_narrative_ai ? `<h3>Attack narrative</h3><p>${escapeHtml(incident.attack_narrative_ai)}</p>` : ''}</div><div class="panel-actions">${permission('agent:investigate') ? '<button class="button button-quiet" data-action="triage">✧ Generate AI triage</button>' : ''}<span class="action-feedback" id="triage-feedback"></span></div></section>
      ${renderEventTrail(incident)}
      <section class="panel"><div class="panel-heading"><div><div class="eyebrow">CORRELATION ENGINE</div><h2>Incident graph</h2></div></div>${state.graph ? renderGraph(state.graph) : '<div class="subtle-empty">Loading incident topology…</div>'}</section>
      <section class="panel"><div class="panel-heading"><div><div class="eyebrow">MITRE ATT&CK</div><h2>Observed techniques</h2></div></div>${tactics.length ? `<div class="tag-row">${tactics.map(t => `<span class="tactic-tag">${escapeHtml(t)}</span>`).join('')}</div>` : '<div class="subtle-empty">No tactics mapped.</div>'}${tech.length ? `<div class="tech-list">${tech.map(t => `<div><span class="mono">${escapeHtml(t.technique_id || t.id || 'MITRE')}</span><b>${escapeHtml(t.technique_name || t.name || 'Technique')}</b><small>${escapeHtml(t.tactic || '')}</small></div>`).join('')}</div>` : ''}</section>
      <section class="panel"><div class="panel-heading"><div><div class="eyebrow">LINKED TELEMETRY</div><h2>Alerts <span class="count-badge">${number(a.length)}</span></h2></div></div>${a.length ? `<div class="related-alerts">${a.slice(0, 12).map(alert => `<button class="related-alert ${alert.id === state.selectedAlertId ? 'selected' : ''}" data-alert="${escapeHtml(alert.id)}"><span class="severity-dot ${priorityClass(alert.severity)}"></span><div><b>${escapeHtml(alert.rule_name)}</b><small>${escapeHtml(alert.source)} · ${escapeHtml(alert.event_type)} · ${escapeHtml(dateTime(alert.timestamp))}</small></div><span class="mono">${escapeHtml(alert.mitre_technique_id || '')}</span></button>`).join('')}</div>` : '<div class="subtle-empty">No linked alerts returned in the dossier.</div>'}</section>
      <section class="panel"><div class="panel-heading"><div><div class="eyebrow">ANALYST COPILOT</div><h2>Ask about this incident</h2></div><span class="panel-caption">AI SERVICE RESPONSE</span></div><div class="chat-log" id="chat-log">${state.copilotMessages.length ? state.copilotMessages.map(m => `<div class="chat-message ${m.role}"><small>${m.role === 'user' ? 'YOU' : 'COPILOT'}</small><p>${escapeHtml(m.content)}</p></div>`).join('') : '<div class="subtle-empty">Ask a question using incident context.</div>'}</div><form class="chat-form" id="copilot-form"><input name="message" placeholder="What should I investigate next?" required /><button class="button button-primary" type="submit" ${permission('copilot:chat') ? '' : 'disabled'}>Send ↗</button></form></section>
    </div><aside class="detail-side">
      <section class="panel"><div class="panel-heading"><div><div class="eyebrow">WORKFLOW</div><h2>Incident state</h2></div></div>${['SOC_LEAD_ADMIN','SENIOR_ANALYST'].includes(state.user?.role) ? `<form id="incident-update" class="stack-form"><label>Status<select name="status">${statusOptions.map(s => `<option ${incident.status === s ? 'selected' : ''}>${s}</option>`).join('')}</select></label><label>Priority<select name="priority">${['P1 - Critical','P2 - High','P3 - Medium','P4 - Low'].map(s => `<option ${incident.priority === s ? 'selected' : ''}>${s}</option>`).join('')}</select></label><label>Assigned analyst<input name="assigned_analyst" value="${escapeHtml(incident.assigned_analyst || '')}" /></label><button class="button button-primary full-width" type="submit">Save changes</button><small class="form-hint">Backend persists status, priority, and assignee. Notes are not persisted by its current route. This UI role gate does not secure the unguarded backend route.</small></form>` : `<div class="subtle-empty">${escapeHtml(incident.status)} · ${escapeHtml(incident.priority)}<br />Read-only for this demo role.</div>`}</section>
      <section class="panel"><div class="panel-heading"><div><div class="eyebrow">RECOMMENDED</div><h2>Containment actions</h2></div></div>${recs.length ? `<div class="recommend-list">${recs.map(r => `<div><b>${escapeHtml(r.action_type || r.label || 'Action')}</b><small>${escapeHtml(r.description || r.rationale || '')}</small><button class="button button-danger-outline" data-action="contain" data-type="${escapeHtml(r.action_type || 'isolate_host')}" data-target="${escapeHtml(r.target || (incident.impacted_hosts || [])[0] || '')}" ${permission('containment:execute') ? '' : 'disabled'}>Execute on ${escapeHtml(r.target || (incident.impacted_hosts || [])[0] || 'target')}</button></div>`).join('')}</div>` : '<div class="subtle-empty">No recommendations returned.</div>'}<div class="permission-footnote">Containment simulates a state change in this backend. Confirmation required. UI role gating is only a convenience; backend authorization must be enforced server-side.</div></section>
      <section class="panel"><div class="panel-heading"><div><div class="eyebrow">AUDIT TRAIL</div><h2>Containment history</h2></div></div>${renderActions(actions)}</section>
      <section class="panel"><div class="panel-heading"><div><div class="eyebrow">IMPACTED ENTITIES</div><h2>Scope</h2></div></div>${renderEntities('Hosts', incident.impacted_hosts)}${renderEntities('Users', incident.impacted_users)}${renderEntities('IP addresses', incident.impacted_ips)}</section>
    </aside></div>`;
  const log = $('#chat-log'); if (log) log.scrollTop = log.scrollHeight;
}
function renderEntities(label, entities = []) {
  if (!entities?.length) return '';
  return `<div class="entity-group"><small>${escapeHtml(label)}</small><div>${entities.map(e => `<span class="entity-chip">${escapeHtml(e)}</span>`).join('')}</div></div>`;
}

async function loadSummary({ render = true } = {}) {
  try {
    state.summary = await api.summary();
    setApiState(true);
    if (render && state.view === 'dashboard') renderDashboard();
    return state.summary;
  } catch (error) {
    setApiState(false);
    if (state.summary) setNotice(`Refresh failed; showing the last successful dashboard response. ${error.message}`, 'warning');
    else setNotice(error.message);
    return null;
  }
}
async function loadIncidents({ render = true } = {}) {
  try {
    state.incidents = await api.incidents(state.incidentFilters);
    setApiState(true);
    if (render && state.view === 'incidents') renderIncidentView();
  } catch (error) {
    setNotice(`Incident request failed${state.incidents.length ? '; showing the last successful result' : ''}. ${error.message}`, state.incidents.length ? 'warning' : 'error');
    if (!state.incidents.length) view.innerHTML = errorPanel('Could not load incidents', error.message, 'reload-incidents');
  }
}
async function loadAlerts({ render = true } = {}) {
  try {
    state.alerts = await api.alerts(state.alertFilters);
    setApiState(true);
    if (render && state.view === 'alerts') renderAlertView();
  } catch (error) {
    setNotice(`Alert request failed${state.alerts.length ? '; showing the last successful result' : ''}. ${error.message}`, state.alerts.length ? 'warning' : 'error');
    if (!state.alerts.length) view.innerHTML = errorPanel('Could not load alerts', error.message, 'reload-alerts');
  }
}
function errorPanel(title, message, action) {
  return `<div class="panel error-panel"><span class="error-symbol">!</span><h2>${escapeHtml(title)}</h2><p>${escapeHtml(message)}</p><button class="button button-primary" data-action="${action}">Retry</button></div>`;
}
async function openIncident(id) {
  clearNotice();
  state.selectedIncident = null; state.graph = null; state.copilotMessages = []; state.selectedAlertId = null;
  view.innerHTML = '<div class="loading-state"><span class="spinner"></span>Loading incident dossier…</div>';
  state.view = 'detail';
  $('#crumb-current').textContent = 'INCIDENT DETAIL';
  try {
    const [incident, graph] = await Promise.all([api.incident(id), api.graph(id).catch(error => ({ error: error.message }))]);
    state.graph = graph?.error ? null : graph;
    renderDetail(incident);
    if (graph?.error) toast(`Graph unavailable: ${graph.error}`, 'error');
  } catch (error) {
    view.innerHTML = errorPanel('Could not load incident', error.message, 'back-incidents');
  }
}
async function loadUser() {
  try {
    state.user = await api.currentUser();
  } catch (error) {
    state.user = { email: ROLE_EMAILS[state.role], full_name: 'Demo analyst', role: state.role, permissions: [] };
    setNotice(`Could not resolve current demo identity. ${error.message}`, 'warning');
  }
  const shortName = (state.user.full_name || state.user.email || 'A').split(/[ (]/)[0];
  $('#user-avatar').textContent = shortName.slice(0, 1).toUpperCase();
  $('#user-avatar').title = `${state.user.full_name || state.user.email} · ${state.user.role}`;
  $('#role-select').value = state.role;
}
async function loadRoles() {
  const select = $('#role-select');
  try {
    const roles = await api.roles();
    select.innerHTML = roles.map(r => `<option value="${escapeHtml(r.role)}">${escapeHtml(ROLE_LABELS[r.role] || r.role)}</option>`).join('');
  } catch {
    select.innerHTML = Object.entries(ROLE_LABELS).map(([value, label]) => `<option value="${value}">${label}</option>`).join('');
  }
  select.value = state.role;
}
function connectStream() {
  if (state.stream) state.stream.close();
  const url = `${API_ROOT}/cockpit/stream`;
  setStreamStatus('connecting', 'Connecting live feed');
  const source = new EventSource(url);
  state.stream = source;
  source.onopen = () => {
    setStreamStatus('live', 'Connected · awaiting update');
  };
  source.onmessage = event => {
    try {
      state.streamData = JSON.parse(event.data);
      state.streamAt = Date.now();
      setStreamStatus('live', 'Live · updated just now');
      updateLiveDashboard();
    } catch { setStreamStatus('degraded', 'Live feed sent invalid data'); }
  };
  source.onerror = () => {
    state.streamAt = null;
    setStreamStatus('degraded', 'Live feed disconnected · reconnecting');
    updateLiveDashboard();
  };
}
function updateLiveDashboard() {
  if (state.view !== 'dashboard') return;
  const metrics = state.streamData?.metrics;
  if (metrics) {
    const alerts = $('[data-live="alerts"]');
    const incidents = $('[data-live="incidents"]');
    const reduction = $('[data-live="reduction"]');
    if (alerts) alerts.textContent = number(metrics.total_alerts);
    if (incidents) incidents.textContent = number(metrics.total_incidents);
    if (reduction) reduction.textContent = `${number(metrics.reduction_pct, 1)}%`;
  }
  let stale = $('#stream-stale');
  if (!stale && !state.streamAt) {
    stale = document.createElement('div');
    stale.id = 'stream-stale';
    stale.className = 'stale-banner';
    stale.innerHTML = '<span>◷</span>Live feed is reconnecting. Summary values are from the last successful API response.';
    $('.page-heading', view)?.after(stale);
  }
  stale?.classList.toggle('hidden', Boolean(state.streamAt));
}
async function showView(name) {
  clearNotice();
  document.querySelectorAll('.nav-item').forEach(node => node.classList.toggle('active', node.dataset.view === name));
  if (name === 'dashboard') { state.view = name; if (!state.summary) await loadSummary({ render: false }); renderDashboard(); }
  if (name === 'incidents') { state.view = name; view.innerHTML = '<div class="loading-state"><span class="spinner"></span>Loading incident queue…</div>'; await loadIncidents({ render: false }); renderIncidentView(); }
  if (name === 'alerts') { state.view = name; view.innerHTML = '<div class="loading-state"><span class="spinner"></span>Loading alerts…</div>'; await loadAlerts({ render: false }); renderAlertView(); }
}

document.addEventListener('click', async event => {
  const alertButton = event.target.closest('[data-alert]');
  if (alertButton) {
    state.selectedAlertId = alertButton.dataset.alert;
    const trailPanel = $('.event-trail-panel');
    if (trailPanel && state.selectedIncident) trailPanel.outerHTML = renderEventTrail(state.selectedIncident);
    document.querySelectorAll('.related-alert').forEach(node => node.classList.toggle('selected', node.dataset.alert === state.selectedAlertId));
    return;
  }
  const incidentButton = event.target.closest('[data-incident]');
  if (incidentButton) { await openIncident(incidentButton.dataset.incident); return; }
  const nav = event.target.closest('[data-view]');
  if (nav) { await showView(nav.dataset.view); return; }
  const action = event.target.closest('[data-action]');
  if (!action) return;
  switch (action.dataset.action) {
    case 'open-incidents': await showView('incidents'); break;
    case 'reload-incidents': await loadIncidents(); clearNotice(); break;
    case 'reload-alerts': await loadAlerts(); clearNotice(); break;
    case 'refresh-dashboard': await loadSummary(); break;
    case 'back-incidents': await showView('incidents'); break;
    case 'triage': {
      if (!requirePermission('agent:investigate', 'AI triage')) return;
      action.disabled = true; action.textContent = 'Generating…';
      try {
        const result = await api.triage(state.selectedIncident.id);
        toast(`AI triage returned by ${result.model_used || 'backend'}.`);
        await openIncident(state.selectedIncident.id);
      } catch (error) { toast(`AI triage failed: ${error.message}`, 'error'); action.disabled = false; action.textContent = '✧ Generate AI triage'; }
      break;
    }
    case 'contain': {
      if (!requirePermission('containment:execute', 'Containment')) return;
      const target = action.dataset.target;
      const type = action.dataset.type;
      if (!target) { toast('No target was provided by the recommendation.', 'error'); return; }
      const ok = await confirmAction('Execute containment?', `The backend simulates “${type}” against ${target} and records the action. Incident/entity state may change.`, 'Execute containment');
      if (!ok) return;
      try { const result = await api.contain(state.selectedIncident.id, type, target); toast(`Backend recorded action ${result.id ?? ''}: ${result.status || 'completed'}.`); await openIncident(state.selectedIncident.id); await loadSummary({ render: false }); }
      catch (error) { toast(`Containment failed: ${error.message}`, 'error'); }
      break;
    }
  }
});

document.addEventListener('change', event => {
  if (event.target.id !== 'trail-target-select') return;
  state.selectedAlertId = event.target.value;
  const trailPanel = $('.event-trail-panel');
  if (trailPanel && state.selectedIncident) trailPanel.outerHTML = renderEventTrail(state.selectedIncident);
  document.querySelectorAll('.related-alert').forEach(node => node.classList.toggle('selected', node.dataset.alert === state.selectedAlertId));
});

document.addEventListener('submit', async event => {
  if (event.target.id === 'incident-filter') {
    event.preventDefault(); const form = new FormData(event.target);
    state.incidentFilters = Object.fromEntries(['search','status','priority','min_risk'].map(key => [key, String(form.get(key) || '').trim()]));
    view.innerHTML = '<div class="loading-state"><span class="spinner"></span>Applying filters…</div>'; await loadIncidents({ render: false }); renderIncidentView();
  }
  if (event.target.id === 'alert-filter') {
    event.preventDefault(); const form = new FormData(event.target);
    state.alertFilters = Object.fromEntries(['search','source','severity'].map(key => [key, String(form.get(key) || '').trim()]));
    view.innerHTML = '<div class="loading-state"><span class="spinner"></span>Filtering alerts…</div>'; await loadAlerts({ render: false }); renderAlertView();
  }
  if (event.target.id === 'incident-update') {
    event.preventDefault();
    if (!['SOC_LEAD_ADMIN','SENIOR_ANALYST'].includes(state.user?.role)) { toast('Incident changes are disabled for this demo role.', 'error'); return; }
    const payload = Object.fromEntries(new FormData(event.target));
    try { const updated = await api.updateIncident(state.selectedIncident.id, payload); toast('Incident updated by backend.'); state.selectedIncident = updated; await openIncident(updated.id); await loadSummary({ render: false }); }
    catch (error) { toast(`Incident update failed: ${error.message}`, 'error'); }
  }
  if (event.target.id === 'copilot-form') {
    event.preventDefault(); if (!requirePermission('copilot:chat', 'Copilot')) return;
    const input = event.target.elements.message; const message = input.value.trim(); if (!message) return;
    state.copilotMessages.push({ role: 'user', content: message });
    const contextId = state.selectedIncident?.id || null;
    state.view === 'detail' ? renderDetail(state.selectedIncident) : null;
    try {
      const result = await api.copilot(contextId, state.copilotMessages);
      state.copilotMessages.push({ role: 'assistant', content: result.reply || 'The API returned no reply.' });
      if (state.view === 'detail') renderDetail(state.selectedIncident);
    } catch (error) {
      state.copilotMessages.push({ role: 'assistant', content: `The backend request failed: ${error.message}` });
      if (state.view === 'detail') renderDetail(state.selectedIncident);
    }
  }
});

$('#refresh-btn').addEventListener('click', async () => {
  clearNotice();
  if (state.view === 'dashboard') { await loadSummary(); }
  else if (state.view === 'incidents') await loadIncidents();
  else if (state.view === 'alerts') await loadAlerts();
  else if (state.view === 'detail' && state.selectedIncident) await openIncident(state.selectedIncident.id);
});
$('#role-select').addEventListener('change', async event => {
  state.role = event.target.value;
  await loadUser();
  if (state.view === 'detail' && state.selectedIncident) await openIncident(state.selectedIncident.id);
  else await showView(state.view === 'detail' ? 'incidents' : state.view);
});

async function init() {
  $('#api-address').textContent = API_ROOT.replace(/^https?:\/\//, '');
  await loadRoles();
  await loadUser();
  connectStream();
  await loadSummary({ render: false });
  renderDashboard();
  if (!state.summary) setApiState(false);
  setInterval(() => {
    if (state.streamAt && Date.now() - state.streamAt > 12000) {
      setStreamStatus('degraded', 'Live feed stale · reconnecting');
      state.streamAt = null;
      updateLiveDashboard();
    }
  }, 4000);
}
init();
