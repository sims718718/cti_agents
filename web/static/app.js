/* CTI Agents — SPA */
'use strict';

// ── Router ────────────────────────────────────────────────────────────────────
const views = {
  dashboard: document.getElementById('view-dashboard'),
  new:       document.getElementById('view-new'),
  feeds:     document.getElementById('view-feeds'),
  report:    document.getElementById('view-report'),
};

let _pollTimer = null;

function showView(name, params = {}) {
  clearPoll();
  Object.values(views).forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  const v = views[name];
  if (!v) return;
  v.classList.add('active');

  const navBtn = document.querySelector(`.nav-btn[data-view="${name}"]`);
  if (navBtn) navBtn.classList.add('active');

  if (name === 'dashboard') loadDashboard();
  if (name === 'report')    loadReport(params.runId);
  if (name === 'feeds')     loadFeedsView();
  if (name === 'new')       loadFeedChecklists();
}

// Nav buttons
document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => showView(btn.dataset.view));
});

document.getElementById('refresh-btn').addEventListener('click', loadDashboard);
document.getElementById('back-btn').addEventListener('click', () => showView('dashboard'));

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function loadDashboard() {
  const tbody = document.getElementById('runs-tbody');
  tbody.innerHTML = '<tr><td colspan="8" class="empty">Loading…</td></tr>';
  try {
    const runs = await apiFetch('/api/runs');
    if (!runs.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty">No runs yet. Click "+ New Analysis" to get started.</td></tr>';
      return;
    }
    tbody.innerHTML = runs.map(r => `
      <tr>
        <td><a href="#" class="run-link" data-id="${r.run_id}">${esc(r.name)}</a></td>
        <td><span class="badge badge-${r.status}">${r.status}</span></td>
        <td>${r.final_score !== null ? r.final_score + '/10' : '—'}</td>
        <td>${(r.feed_types || []).join(', ')}</td>
        <td>${r.has_documents ? '✓ ' + (r.document_names || []).length : '—'}</td>
        <td>${r.total_iterations !== null ? r.total_iterations : '—'}</td>
        <td>${fmtDate(r.created_at)}</td>
        <td>
          <button class="btn btn-ghost btn-sm run-view-btn" data-id="${r.run_id}">View</button>
          <button class="btn btn-danger btn-sm run-del-btn" data-id="${r.run_id}" style="margin-left:4px">Del</button>
        </td>
      </tr>
    `).join('');

    tbody.querySelectorAll('.run-link, .run-view-btn').forEach(el => {
      el.addEventListener('click', e => { e.preventDefault(); showView('report', { runId: el.dataset.id }); });
    });
    tbody.querySelectorAll('.run-del-btn').forEach(btn => {
      btn.addEventListener('click', () => deleteRun(btn.dataset.id));
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty" style="color:var(--danger)">${esc(err.message)}</td></tr>`;
  }
}

async function deleteRun(runId) {
  if (!confirm('Delete this run?')) return;
  try {
    await apiFetch(`/api/runs/${runId}`, { method: 'DELETE' });
    loadDashboard();
  } catch (err) {
    alert('Delete failed: ' + err.message);
  }
}

// ── New Analysis Form ─────────────────────────────────────────────────────────
const stixCb    = document.getElementById('feed-stix-cb');
const stixGroup = document.getElementById('stix-url-group');
stixCb.addEventListener('change', () => {
  stixGroup.style.display = stixCb.checked ? 'block' : 'none';
});

const timeRangeEl      = document.getElementById('time-range');
const customRangeGroup = document.getElementById('custom-range-group');
timeRangeEl.addEventListener('change', () => {
  customRangeGroup.style.display = timeRangeEl.value === 'custom' ? 'flex' : 'none';
});

// Select-all / deselect-all buttons for the per-feed checklists
document.getElementById('rss-select-all').addEventListener('click', () => {
  document.querySelectorAll('#rss-checklist input[type=checkbox]').forEach(cb => cb.checked = true);
});
document.getElementById('rss-deselect-all').addEventListener('click', () => {
  document.querySelectorAll('#rss-checklist input[type=checkbox]').forEach(cb => cb.checked = false);
});
document.getElementById('api-select-all').addEventListener('click', () => {
  document.querySelectorAll('#api-checklist input[type=checkbox]').forEach(cb => cb.checked = true);
});
document.getElementById('api-deselect-all').addEventListener('click', () => {
  document.querySelectorAll('#api-checklist input[type=checkbox]').forEach(cb => cb.checked = false);
});

async function loadFeedChecklists() {
  const rssEl = document.getElementById('rss-checklist');
  const apiEl = document.getElementById('api-checklist');
  try {
    const { rss, api } = await apiFetch('/api/feeds');

    rssEl.innerHTML = rss.map(f => `
      <label class="feed-check-item">
        <input type="checkbox" class="rss-feed-cb" data-id="${esc(f.id)}" checked>
        <span>${esc(f.name)}</span>
        ${f.builtin ? '' : '<span class="feed-custom-badge">custom</span>'}
      </label>
    `).join('');

    apiEl.innerHTML = api.map(f => `
      <label class="feed-check-item">
        <input type="checkbox" class="api-feed-cb" data-id="${esc(f.id)}" checked>
        <span>${esc(f.name)}</span>
        ${f.builtin ? '' : '<span class="feed-custom-badge">custom</span>'}
      </label>
    `).join('');
  } catch (err) {
    rssEl.innerHTML = `<span style="color:var(--danger)">${esc(err.message)}</span>`;
    apiEl.innerHTML = '';
  }
}

// File upload
const fileInput = document.getElementById('file-input');
const fileDrop  = document.getElementById('file-drop');
const fileList  = document.getElementById('file-list');
let selectedFiles = [];

fileInput.addEventListener('change', () => addFiles(Array.from(fileInput.files)));
fileDrop.addEventListener('dragover', e => { e.preventDefault(); fileDrop.classList.add('drag'); });
fileDrop.addEventListener('dragleave', () => fileDrop.classList.remove('drag'));
fileDrop.addEventListener('drop', e => {
  e.preventDefault();
  fileDrop.classList.remove('drag');
  addFiles(Array.from(e.dataTransfer.files));
});

function addFiles(files) {
  for (const f of files) {
    if (!selectedFiles.find(x => x.name === f.name && x.size === f.size)) {
      selectedFiles.push(f);
    }
  }
  renderFileList();
}

function renderFileList() {
  fileList.innerHTML = selectedFiles.map((f, i) => `
    <div class="file-pill">
      📄 ${esc(f.name)} <small style="color:var(--muted)">(${fmtBytes(f.size)})</small>
      <span data-idx="${i}" class="remove-file-btn" title="Remove">✕</span>
    </div>
  `).join('');
  fileList.querySelectorAll('.remove-file-btn').forEach(btn => {
    btn.addEventListener('click', () => { selectedFiles.splice(+btn.dataset.idx, 1); renderFileList(); });
  });
}

document.getElementById('new-run-form').addEventListener('submit', async e => {
  e.preventDefault();
  const errEl  = document.getElementById('form-error');
  const spinner = document.getElementById('submit-spinner');
  const btn    = document.getElementById('submit-btn');
  errEl.style.display = 'none';
  spinner.style.display = 'inline-block';
  btn.disabled = true;

  try {
    const fd = new FormData();
    fd.append('name', document.getElementById('run-name').value.trim());

    // Collect selected RSS feed IDs
    const selectedRss = Array.from(document.querySelectorAll('#rss-checklist .rss-feed-cb:checked'))
      .map(cb => cb.dataset.id);
    // Collect selected API feed IDs
    const selectedApi = Array.from(document.querySelectorAll('#api-checklist .api-feed-cb:checked'))
      .map(cb => cb.dataset.id);

    const feeds = [];
    if (selectedRss.length > 0) feeds.push('rss');
    if (selectedApi.length > 0) feeds.push('api');
    if (document.querySelector('[name=feed_stix]').checked) feeds.push('stix');
    fd.append('feed_types', feeds.join(',') || 'rss,api');

    if (selectedRss.length > 0) fd.append('selected_rss', selectedRss.join(','));
    if (selectedApi.length > 0) fd.append('selected_api', selectedApi.join(','));

    fd.append('max_iterations',       document.getElementById('max-iter').value);
    fd.append('quality_threshold',    document.getElementById('threshold').value);
    fd.append('hunt_refinement_iters', document.getElementById('hunt-refine-iters').value);

    const timeRange = document.getElementById('time-range').value;
    fd.append('time_range', timeRange);
    if (timeRange === 'custom') {
      const df = document.getElementById('date-from').value;
      const dt = document.getElementById('date-to').value;
      if (df) fd.append('date_from', df);
      if (dt) fd.append('date_to', dt);
    }

    const stixUrl = document.getElementById('stix-url').value.trim();
    if (stixUrl) fd.append('stix_url', stixUrl);

    for (const f of selectedFiles) fd.append('files', f, f.name);

    const res = await apiFetch('/api/runs', { method: 'POST', body: fd });
    selectedFiles = [];
    renderFileList();
    e.target.reset();
    stixGroup.style.display = 'none';
    customRangeGroup.style.display = 'none';
    showView('report', { runId: res.run_id });
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  } finally {
    spinner.style.display = 'none';
    btn.disabled = false;
  }
});

// ── Report Detail ─────────────────────────────────────────────────────────────
let _currentRunId = null;

async function loadReport(runId) {
  _currentRunId = runId;

  // Reset panels
  document.getElementById('running-panel').style.display  = 'none';
  document.getElementById('error-panel').style.display    = 'none';
  document.getElementById('report-content').style.display = 'none';
  document.getElementById('report-name').textContent = 'Loading…';
  document.getElementById('report-meta').textContent = '';
  document.getElementById('log-panel').innerHTML = '';

  let status;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      status = await apiFetch(`/api/runs/${runId}/status`);
      break;
    } catch (err) {
      if (attempt === 2) { showError(err.message); return; }
      await new Promise(r => setTimeout(r, 600));
    }
  }
  pollReport(runId, status);
}

function pollReport(runId, initial) {
  handleStatus(runId, initial);
  if (initial.status === 'pending' || initial.status === 'running') {
    _pollTimer = setInterval(async () => {
      if (_currentRunId !== runId) { clearPoll(); return; }
      try {
        const s = await apiFetch(`/api/runs/${runId}/status`);
        handleStatus(runId, s);
        if (s.status !== 'pending' && s.status !== 'running') clearPoll();
      } catch { /* retry */ }
    }, 4000);
  }
}

function clearPoll() {
  if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
}

async function handleStatus(runId, status) {
  document.getElementById('report-name').textContent = status.name || runId;
  document.getElementById('report-meta').textContent =
    `${(status.feed_types || []).join(', ')} · Created ${fmtDate(status.created_at)}`;

  renderLog(status.log || []);

  if (status.status === 'pending' || status.status === 'running') {
    document.getElementById('running-panel').style.display = 'block';
    document.getElementById('run-status-label').textContent =
      status.status === 'pending' ? 'Queued, waiting to start…' : 'Running pipeline…';
    return;
  }

  document.getElementById('running-panel').style.display = 'none';

  if (status.status === 'failed') {
    showError(status.error || 'Pipeline failed with an unknown error.');
    return;
  }

  if (status.status === 'completed' && status.report) {
    renderReport(status.report);
  }
}

function showError(msg) {
  const el = document.getElementById('error-panel');
  el.textContent = '✗ ' + msg;
  el.style.display = 'block';
}

function renderLog(tokens) {
  const panel = document.getElementById('log-panel');
  panel.innerHTML = tokens.map(t => {
    let cls = '';
    if (t.startsWith('phase:'))    cls = 'phase';
    else if (t.startsWith('agent:')) cls = 'agent';
    else if (t === 'approved')      cls = 'approved';
    else if (t === 'max_iterations_reached') cls = 'failed';
    return `<span class="log-line ${cls}">${fmtToken(t)}</span>`;
  }).join('');
  panel.scrollTop = panel.scrollHeight;
}

function fmtToken(t) {
  const map = {
    'phase:collection': '● Phase 1: Intelligence Collection',
    'phase:analysis':   '● Phase 2: Multi-Agent Analysis Loop',
    'phase:complete':   '● Pipeline Complete',
    'approved':         '✓ Analysis approved',
    'iterating':        '↻ Quality threshold not met — iterating…',
    'max_iterations_reached': '⚠ Max iterations reached',
    'hunt_approved':          '✓ Hunt plan approved',
    'hunt_iterating':         '↻ Hunt plan refining…',
    'hunt_max_iterations_reached': '⚠ Hunt refinement max passes reached',
  };
  if (map[t]) return map[t];
  if (t.startsWith('collected:'))         return `  Collected ${t.split(':')[1]} total items`;
  if (t.startsWith('iteration:'))         return `  ── Iteration ${t.split(':')[1]}`;
  if (t.startsWith('agent:'))             return `  ▸ Running ${t.split(':')[1]}…`;
  if (t.startsWith('summarizer_done:'))   return `  ✓ Summarizer: ${t.split(':')[1].replace('_', ' ')}`;
  if (t.startsWith('hunter_done:'))       return `  ✓ Hunter: ${t.split(':')[1].replace('_', ' ')}`;
  if (t.startsWith('review_done:'))       return `  ✓ Review: ${t.split(':')[1]}`;
  if (t.startsWith('hunt_refinement:'))   return `  ── Hunt Refinement Pass ${t.split(':')[1]}`;
  if (t.startsWith('hunt_review_done:'))  return `  ✓ Hunt Review: ${t.split(':')[1]}`;
  return '  ' + t;
}

// ── Report rendering ──────────────────────────────────────────────────────────
function renderReport(r) {
  document.getElementById('report-content').style.display = 'block';

  // Tab switching
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    });
  });

  renderSummaryTab(r.intel_summary || {});
  renderHuntTab(r.hunt_plan || {});
  renderReviewTab(r.lead_analyst_review || {}, r.iteration_history || []);
  renderIOCsTab(r.intel_summary || {});
}

// ── Summary tab ───────────────────────────────────────────────────────────────
function renderSummaryTab(s) {
  const landscape = s.threat_landscape || {};

  // Executive summary
  const execEl = document.getElementById('executive-summary');
  execEl.innerHTML = `
    <div class="card-title">Executive Summary</div>
    <p style="line-height:1.8;color:var(--muted)">${esc(landscape.executive_summary || landscape.summary || s.executive_summary || 'No summary available.')}</p>
    ${landscape.overall_threat_level ? `<div style="margin-top:0.75rem"><span class="badge badge-${sev(landscape.overall_threat_level)}">${landscape.overall_threat_level}</span> overall threat level</div>` : ''}
  `;

  // Primary threats table
  const threats = landscape.primary_threats || [];
  document.getElementById('threats-tbody').innerHTML = threats.length ? threats.map(t => `
    <tr>
      <td class="threat-name">${esc(t.name || t.threat_name || '')}</td>
      <td><span class="badge">${esc(t.type || t.threat_type || '')}</span></td>
      <td><span class="badge badge-${sev(t.severity)}">${esc(t.severity || '')}</span></td>
      <td class="threat-mitre">${esc((t.mitre_techniques || t.mitre || []).join(', '))}</td>
      <td>${esc((t.target_sectors || t.sectors || []).join(', '))}</td>
    </tr>
  `).join('') : '<tr><td colspan="5" class="empty">No threat data.</td></tr>';

  // Active campaigns
  const campaigns = landscape.active_campaigns || [];
  const campEl = document.getElementById('campaigns-list');
  if (campaigns.length) {
    campEl.innerHTML = `<ul class="bullet-list">${campaigns.map(c =>
      `<li>${esc(typeof c === 'string' ? c : c.name || JSON.stringify(c))}</li>`
    ).join('')}</ul>`;
    document.getElementById('campaigns-section').style.display = 'block';
  } else {
    document.getElementById('campaigns-section').style.display = 'none';
  }

  // Exploited vulns
  const vulns = s.exploited_vulnerabilities || landscape.exploited_vulnerabilities || [];
  document.getElementById('vulns-tbody').innerHTML = vulns.length ? vulns.map(v => `
    <tr>
      <td style="font-family:var(--font-mono)">${esc(v.cve_id || v.cve || '')}</td>
      <td>${esc(v.description || v.title || '')}</td>
      <td>${esc(String(v.cvss_score || v.cvss || '—'))}</td>
      <td>${v.actively_exploited !== undefined ? (v.actively_exploited ? '⚠ Yes' : 'No') : '—'}</td>
    </tr>
  `).join('') : '<tr><td colspan="4" class="empty">No vulnerability data.</td></tr>';

  // Priorities
  const prios = s.recommended_priorities || [];
  const prioEl = document.getElementById('priorities-list');
  if (prios.length) {
    prioEl.innerHTML = prios.map(p => `<li>${esc(typeof p === 'string' ? p : p.action || JSON.stringify(p))}</li>`).join('');
    document.getElementById('priorities-section').style.display = 'block';
  } else {
    document.getElementById('priorities-section').style.display = 'none';
  }
}

// ── Hunt tab ──────────────────────────────────────────────────────────────────
function renderHuntTab(hp) {
  const meta = hp.hunt_plan || {};
  const metaEl = document.getElementById('hunt-meta');
  metaEl.innerHTML = `
    <div class="card-title">Hunt Overview</div>
    <p style="color:var(--muted);line-height:1.7">${esc(meta.overview || meta.objective || hp.overview || hp.summary || '')}</p>
    ${meta.priority_level ? `<div style="margin-top:0.5rem"><span class="badge badge-${sev(meta.priority_level)}">${meta.priority_level}</span> priority</div>` : ''}
  `;

  // Hypotheses
  const hyps = hp.hypotheses || [];
  document.getElementById('hypotheses-list').innerHTML = hyps.length ? hyps.map((h, idx) => {
    const queries = h.hunt_queries || h.detection_queries || h.queries || [];
    const queryBlocks = Array.isArray(queries)
      ? queries.map(q => {
          const platform = typeof q === 'string' ? 'Query' : (q.platform || 'Query');
          const text     = typeof q === 'string' ? q       : (q.query || JSON.stringify(q));
          const desc     = typeof q === 'object' ? (q.description || '') : '';
          return `<div class="query-block">
            <div class="query-platform-label">${esc(platform)}</div>
            ${desc ? `<div class="query-desc">${esc(desc)}</div>` : ''}
            <pre class="query">${esc(text)}</pre>
          </div>`;
        }).join('')
      : `<pre class="query">${esc(String(queries))}</pre>`;

    return `
      <div class="hyp-card">
        <div class="hyp-header">
          <div class="hyp-title">${idx + 1}. ${esc(h.hypothesis || h.name || h.title || 'Hypothesis')}</div>
          ${h.priority ? `<span class="badge badge-${sev(h.priority)}">${h.priority}</span>` : ''}
        </div>
        <p style="color:var(--muted);margin-bottom:0.75rem;line-height:1.6">${esc(h.description || '')}</p>
        <div class="hyp-meta">
          ${(h.mitre_techniques || h.mitre || []).map(t => `<span class="tag">${esc(t)}</span>`).join('')}
          ${(h.data_sources || []).map(d => `<span class="tag" style="color:var(--info)">${esc(d)}</span>`).join('')}
        </div>
        ${queryBlocks}
        ${h.false_positives ? `<div style="margin-top:0.5rem;font-size:12px;color:var(--warning)">⚠ FP: ${esc(h.false_positives)}</div>` : ''}
      </div>
    `;
  }).join('') : '<div class="empty">No hypotheses generated.</div>';

  // IOC hunt list
  const iocHunt = hp.ioc_hunt_list || [];
  document.getElementById('ioc-hunt-tbody').innerHTML = iocHunt.length ? iocHunt.map(i => `
    <tr>
      <td style="font-family:var(--font-mono)">${esc(i.indicator || i.ioc || i.value || '')}</td>
      <td><span class="badge">${esc(i.type || i.ioc_type || '')}</span></td>
      <td style="color:var(--muted)">${esc(i.context || i.description || '')}</td>
    </tr>
  `).join('') : '<tr><td colspan="3" class="empty">No IOC hunt list.</td></tr>';
}

// ── Review tab ────────────────────────────────────────────────────────────────
function renderReviewTab(rev, history) {
  const score = rev.overall_score;
  document.getElementById('review-score').textContent = score !== undefined ? score : '—';
  document.getElementById('review-bar').style.width = score ? (score * 10) + '%' : '0%';
  document.getElementById('review-status-text').textContent =
    rev.approved ? '✓ Approved' : (score ? `Score ${score}/10 — not approved` : '');

  // Sub-scores
  const sub = rev.scores || {};
  const subLabels = {
    intel_completeness:     'Intel Completeness',
    intel_accuracy:         'Intel Accuracy',
    intel_actionability:    'Intel Actionability',
    hunt_hypothesis_quality:'Hypothesis Quality',
    hunt_query_quality:     'Query Quality',
    hunt_coverage:          'Hunt Coverage',
  };
  document.getElementById('sub-scores').innerHTML = Object.entries(subLabels).map(([k, label]) => {
    const v = sub[k];
    return `
      <div class="sub-score-row">
        <div class="sub-score-label">${label}<span>${v !== undefined ? v + '/10' : '—'}</span></div>
        <div class="score-bar-outer"><div class="score-bar-inner" style="width:${v ? v*10 : 0}%"></div></div>
      </div>
    `;
  }).join('');

  // Strengths / gaps
  document.getElementById('strengths-list').innerHTML = (rev.strengths || []).map(s => `<li>${esc(s)}</li>`).join('') || '<li style="color:var(--muted)">None listed.</li>';
  document.getElementById('gaps-list').innerHTML = (rev.critical_gaps || []).map(g => `<li>${esc(g)}</li>`).join('') || '<li style="color:var(--muted)">None listed.</li>';

  document.getElementById('reviewer-notes').textContent = rev.reviewer_notes || '';

  // Iteration history
  document.getElementById('iter-tbody').innerHTML = history.map(h => `
    <tr>
      <td>#${h.iteration}</td>
      <td>${h.score !== undefined ? h.score + '/10' : '—'}</td>
      <td>${h.approved ? '<span class="badge badge-completed">Yes</span>' : '<span class="badge badge-failed">No</span>'}</td>
    </tr>
  `).join('') || '<tr><td colspan="3" class="empty">No history.</td></tr>';
}

// ── IOCs tab ──────────────────────────────────────────────────────────────────
function renderIOCsTab(s) {
  const iocs = s.key_iocs || {};
  const grid = [
    { title: 'IP Addresses', key: 'ip_addresses', altKey: 'ips' },
    { title: 'Domains',      key: 'domains' },
    { title: 'URLs',         key: 'urls' },
    { title: 'File Hashes',  key: 'file_hashes', altKey: 'hashes' },
  ];

  document.getElementById('ioc-grid').innerHTML = grid.map(g => {
    const items = iocs[g.key] || (g.altKey ? iocs[g.altKey] : null) || [];
    return `
      <div class="ioc-cell">
        <div class="ioc-cell-title">${g.title} (${items.length})</div>
        <ul class="ioc-list">
          ${items.length ? items.map(i => `<li>${esc(typeof i === 'string' ? i : i.value || i.indicator || JSON.stringify(i))}</li>`).join('') : '<li style="color:var(--muted)">None.</li>'}
        </ul>
      </div>
    `;
  }).join('');
}

// ── Utilities ─────────────────────────────────────────────────────────────────
async function apiFetch(url, opts = {}) {
  const res = await fetch(url, opts);
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { const j = await res.json(); msg = j.detail || msg; } catch {}
    throw new Error(msg);
  }
  return res.json();
}

function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtDate(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(1) + ' MB';
}

function sev(s) {
  if (!s) return '';
  const l = s.toLowerCase();
  if (l === 'critical') return 'critical';
  if (l === 'high')     return 'high';
  if (l === 'medium')   return 'medium';
  if (l === 'low')      return 'low';
  if (l === 'completed' || l === 'approved') return 'completed';
  if (l === 'failed')   return 'failed';
  if (l === 'running')  return 'running';
  if (l === 'pending')  return 'pending';
  return '';
}

// ── Feeds Management View ─────────────────────────────────────────────────────
async function loadFeedsView() {
  try {
    const { rss, api } = await apiFetch('/api/feeds');
    renderFeedsTable('rss-feeds-tbody', rss, 3);
    renderFeedsTable('api-feeds-tbody', api, 4, true);
  } catch (err) {
    const msg = `<tr><td colspan="4" class="empty" style="color:var(--danger)">${esc(err.message)}</td></tr>`;
    document.getElementById('rss-feeds-tbody').innerHTML = msg;
    document.getElementById('api-feeds-tbody').innerHTML =
      `<tr><td colspan="5" class="empty" style="color:var(--danger)">${esc(err.message)}</td></tr>`;
  }
}

function renderFeedsTable(tbodyId, feeds, colspan, showMethod = false) {
  const tbody = document.getElementById(tbodyId);
  if (!feeds.length) {
    tbody.innerHTML = `<tr><td colspan="${colspan + 1}" class="empty">No feeds.</td></tr>`;
    return;
  }
  tbody.innerHTML = feeds.map(f => `
    <tr>
      <td>${esc(f.name)}</td>
      <td style="font-family:var(--font-mono);font-size:12px;color:var(--muted);word-break:break-all">${esc(f.url || '')}</td>
      ${showMethod ? `<td><span class="badge">${esc(f.method || 'GET')}</span></td>` : ''}
      <td>${f.builtin
        ? '<span class="badge badge-pending">built-in</span>'
        : '<span class="feed-custom-badge">custom</span>'}</td>
      <td>${f.builtin ? '' : `<button class="btn btn-danger btn-sm feed-del-btn" data-id="${esc(f.id)}">Delete</button>`}</td>
    </tr>
  `).join('');

  tbody.querySelectorAll('.feed-del-btn').forEach(btn => {
    btn.addEventListener('click', () => deleteFeed(btn.dataset.id));
  });
}

async function deleteFeed(feedId) {
  if (!confirm('Delete this custom feed?')) return;
  try {
    await apiFetch(`/api/feeds/${feedId}`, { method: 'DELETE' });
    loadFeedsView();
    // Refresh checklists if New Analysis was previously loaded
    loadFeedChecklists();
  } catch (err) {
    alert('Delete failed: ' + err.message);
  }
}

// ── Add RSS feed inline form ───────────────────────────────────────────────────
document.getElementById('show-add-rss-btn').addEventListener('click', () => {
  document.getElementById('add-rss-form').style.display = 'flex';
  document.getElementById('show-add-rss-btn').style.display = 'none';
});
document.getElementById('cancel-rss-btn').addEventListener('click', () => {
  document.getElementById('add-rss-form').style.display = 'none';
  document.getElementById('show-add-rss-btn').style.display = '';
});
document.getElementById('save-rss-btn').addEventListener('click', async () => {
  const name = document.getElementById('new-rss-name').value.trim();
  const url  = document.getElementById('new-rss-url').value.trim();
  if (!name || !url) { alert('Name and URL are required.'); return; }
  try {
    const fd = new FormData();
    fd.append('name', name);
    fd.append('url', url);
    await apiFetch('/api/feeds/rss', { method: 'POST', body: fd });
    document.getElementById('new-rss-name').value = '';
    document.getElementById('new-rss-url').value  = '';
    document.getElementById('add-rss-form').style.display  = 'none';
    document.getElementById('show-add-rss-btn').style.display = '';
    loadFeedsView();
    loadFeedChecklists();
  } catch (err) {
    alert('Failed to add feed: ' + err.message);
  }
});

// ── Add API feed inline form ───────────────────────────────────────────────────
document.getElementById('show-add-api-btn').addEventListener('click', () => {
  document.getElementById('add-api-form').style.display = 'flex';
  document.getElementById('show-add-api-btn').style.display = 'none';
});
document.getElementById('cancel-api-btn').addEventListener('click', () => {
  document.getElementById('add-api-form').style.display = 'none';
  document.getElementById('show-add-api-btn').style.display = '';
});
document.getElementById('save-api-btn').addEventListener('click', async () => {
  const name   = document.getElementById('new-api-name').value.trim();
  const url    = document.getElementById('new-api-url').value.trim();
  const method = document.getElementById('new-api-method').value;
  if (!name || !url) { alert('Name and URL are required.'); return; }
  try {
    const fd = new FormData();
    fd.append('name', name);
    fd.append('url', url);
    fd.append('method', method);
    await apiFetch('/api/feeds/api', { method: 'POST', body: fd });
    document.getElementById('new-api-name').value = '';
    document.getElementById('new-api-url').value  = '';
    document.getElementById('add-api-form').style.display  = 'none';
    document.getElementById('show-add-api-btn').style.display = '';
    loadFeedsView();
    loadFeedChecklists();
  } catch (err) {
    alert('Failed to add feed: ' + err.message);
  }
});

// ── Init ──────────────────────────────────────────────────────────────────────
showView('dashboard');
loadFeedChecklists();
