/**
 * MCP Tools Admin — Activité
 *
 * Trois niveaux complémentaires : audit métier, HTTP et déroulé corrélé d'un
 * appel. Le serveur exclut les données sensibles avant qu'elles arrivent ici.
 */

let _currentLogsTab = 'activity';

async function loadLogs() {
    const el = document.getElementById('view-logs');
    try {
        const [auditR, logsR, activityR] = await Promise.all([apiAudit(), apiLogs(), apiActivity()]);
        app.audit = auditR.status === 'ok' ? (auditR.entries || []) : [];
        app.logs = logsR.status === 'ok' ? (logsR.logs || []) : [];
        app.activity = activityR.status === 'ok' ? (activityR.events || []) : [];
        el.innerHTML = renderLogsView();
    } catch (e) {
        if (e.message !== 'Unauthorized') el.innerHTML = '<div class="empty-state">⚠️ Erreur de chargement</div>';
    }
}

function renderLogsView() {
    return `<div class="view-header">
        <div class="view-title">📋 Activité</div>
        <div style="display:flex;gap:0.4rem;align-items:center">
            <label style="font-size:0.72rem;color:#666;display:flex;align-items:center;gap:0.3rem">🔄
                <select id="logRefreshInterval" onchange="updateLogRefresh()" style="padding:0.2rem 0.4rem;border-radius:4px;border:none;background:rgba(255,255,255,0.1);color:#ccc;font-size:0.72rem">
                    <option value="0">Manuel</option><option value="5" selected>5s</option><option value="10">10s</option><option value="30">30s</option>
                </select>
            </label>
            <button class="btn btn-secondary btn-sm" onclick="loadLogs()">🔄</button>
        </div>
    </div>
    <div class="tabs">
        <button class="tab ${_currentLogsTab === 'activity' ? 'active' : ''}" data-log-tab="activity" onclick="switchLogsTab('activity')">⚡ Déroulé des appels <span class="count">${app.activity.length}</span></button>
        <button class="tab ${_currentLogsTab === 'audit' ? 'active' : ''}" data-log-tab="audit" onclick="switchLogsTab('audit')">🔍 Journal métier <span class="count">${app.audit.length}</span></button>
        <button class="tab ${_currentLogsTab === 'http' ? 'active' : ''}" data-log-tab="http" onclick="switchLogsTab('http')">🌐 Journal HTTP <span class="count">${app.logs.length}</span></button>
    </div>
    <div id="logsTabContent">${renderCurrentLogsTab()}</div>`;
}

function renderCurrentLogsTab() {
    if (_currentLogsTab === 'activity') return renderActivityTab();
    return _currentLogsTab === 'audit' ? renderAuditTab() : renderHttpLogsTab();
}

function switchLogsTab(tab) {
    _currentLogsTab = tab;
    const content = document.getElementById('logsTabContent');
    if (content) content.innerHTML = renderCurrentLogsTab();
    document.querySelectorAll('[data-log-tab]').forEach(button => button.classList.toggle('active', button.dataset.logTab === tab));
}

// ═══════════════ DÉROULÉ CORRÉLÉ ═══════════════

function renderActivityTab() {
    if (!app.activity.length) {
        return `<div class="empty-state"><div class="empty-state-icon">⚡</div>Aucune trace d'appel enregistrée.<br><span style="font-size:0.75rem;color:#555">Les étapes HTTP, MCP, outil et sandbox apparaîtront ici.</span></div>`;
    }
    const types = [...new Set(app.activity.map(event => event.event).filter(Boolean))].sort();
    return `<div class="activity-filters">
        <div class="search-bar"><span class="search-icon">🔍</span><input class="search-input" id="activityFilterSearch" placeholder="Agent, outil, modèle, trace, étape…" oninput="filterActivity()"></div>
        <select id="activityFilterType" onchange="filterActivity()"><option value="">Toutes les étapes</option>${types.map(type => `<option value="${esc(type)}">${esc(type)}</option>`).join('')}</select>
        <select id="activityFilterLevel" onchange="filterActivity()"><option value="">Tous les niveaux</option><option value="info">Info</option><option value="warning">Avertissement</option><option value="error">Erreur</option></select>
    </div><div id="activityEntries">${app.activity.map(renderActivityEntry).join('')}</div>`;
}

function filterActivity() {
    const type = document.getElementById('activityFilterType')?.value || '';
    const level = document.getElementById('activityFilterLevel')?.value || '';
    const search = (document.getElementById('activityFilterSearch')?.value || '').toLowerCase();
    const entries = app.activity.filter(event => (!type || event.event === type) && (!level || event.level === level) && (!search || JSON.stringify(event).toLowerCase().includes(search)));
    const el = document.getElementById('activityEntries');
    if (el) el.innerHTML = entries.length ? entries.map(renderActivityEntry).join('') : '<div class="empty-state" style="padding:1.5rem">Aucun résultat pour ces filtres</div>';
}

function renderActivityEntry(event) {
    const level = ['info', 'warning', 'error'].includes(event.level) ? event.level : 'info';
    const tags = [event.tool && `🔧 ${event.tool}`, event.actor && `👤 ${event.actor}`, event.model && `🤖 ${event.model}`, event.agent_id && `🤝 ${event.agent_id}`, event.call_id && `☎ ${event.call_id}`, event.trace_id && `⌁ ${event.trace_id}`].filter(Boolean);
    const details = JSON.stringify(event, null, 2);
    return `<div class="activity-entry activity-${level}">
        <div class="activity-time">${fmtTime(event.timestamp)}<span>${fmtDateShort(event.timestamp)}</span></div>
        <div class="activity-level">${level === 'error' ? '✖' : level === 'warning' ? '⚠' : '●'}</div>
        <div class="activity-body"><div class="activity-summary"><code>${esc(event.event || 'unknown')}</code><span>${esc(event.message || '')}</span></div>
        ${tags.length ? `<div class="activity-tags">${tags.map(tag => `<span>${esc(tag)}</span>`).join('')}</div>` : ''}
        <details><summary>Détails sûrs</summary><pre>${esc(details)}</pre></details></div>
    </div>`;
}

// ═══════════════ JOURNAL MÉTIER ═══════════════

function renderAuditTab() {
    if (!app.audit.length) return '<div class="empty-state"><div class="empty-state-icon">🔍</div>Aucune action métier enregistrée.</div>';
    const actors = [...new Set(app.audit.map(entry => entry.actor).filter(Boolean))].sort();
    return `<div class="audit-filters" id="auditFilters">
        <div class="audit-filter-group"><label>Acteur</label><select id="auditFilterActor" onchange="filterAudit()"><option value="">Tous</option>${actors.map(actor => `<option value="${esc(actor)}">${esc(actor)}</option>`).join('')}</select></div>
        <div class="audit-filter-group"><label>Action</label><select id="auditFilterAction" onchange="filterAudit()"><option value="">Toutes</option><option value="token_create">🔑 Création token</option><option value="token_update">✏️ Modification token</option><option value="token_revoke">🗑️ Révocation token</option><option value="token_purge">🧹 Purge tokens</option><option value="tool_run">▶️ Exécution outil</option><option value="login_failed">❌ Échec connexion</option></select></div>
        <div class="audit-filter-group"><label>Recherche</label><input type="text" id="auditFilterSearch" placeholder="Rechercher…" oninput="filterAudit()"></div>
    </div><div id="auditEntries">${app.audit.map(renderAuditEntry).join('')}</div>`;
}

function filterAudit() {
    const actor = document.getElementById('auditFilterActor')?.value || '';
    const action = document.getElementById('auditFilterAction')?.value || '';
    const search = (document.getElementById('auditFilterSearch')?.value || '').toLowerCase();
    const entries = app.audit.filter(entry => (!actor || entry.actor === actor) && (!action || entry.action === action) && (!search || `${entry.actor} ${entry.action} ${entry.target} ${entry.details}`.toLowerCase().includes(search)));
    const el = document.getElementById('auditEntries');
    if (el) el.innerHTML = entries.length ? entries.map(renderAuditEntry).join('') : '<div class="empty-state" style="padding:1.5rem">Aucun résultat pour ces filtres</div>';
}

function renderAuditEntry(entry) {
    const info = getActionInfo(entry.action);
    return `<div class="audit-entry ${entry.status === 'error' ? 'audit-error' : 'audit-success'}"><div class="audit-entry-time"><span class="audit-time">${fmtTime(entry.timestamp)}</span><span class="audit-date">${fmtDateShort(entry.timestamp)}</span></div><div class="audit-entry-icon">${info.icon}</div><div class="audit-entry-body"><div class="audit-entry-summary"><span class="audit-actor">${esc(entry.actor)}</span><span class="audit-action-label">${info.label}</span>${entry.target ? `<span class="audit-target">${esc(entry.target)}</span>` : ''}</div>${entry.details ? `<div class="audit-entry-details">${esc(entry.details)}</div>` : ''}</div>${entry.status === 'error' ? '<div class="audit-entry-status"><span class="badge badge-red">Erreur</span></div>' : ''}</div>`;
}

function getActionInfo(action) {
    const map = { token_create: { icon: '🔑', label: 'a créé le token' }, token_update: { icon: '✏️', label: 'a modifié le token' }, token_revoke: { icon: '🗑️', label: 'a révoqué le token' }, token_purge: { icon: '🧹', label: 'a purgé les tokens expirés' }, tool_run: { icon: '▶️', label: 'a exécuté l’outil' }, login_failed: { icon: '❌', label: 'échec de connexion' } };
    return map[action] || { icon: '📌', label: action };
}

// ═══════════════ JOURNAL HTTP ═══════════════

function renderHttpLogsTab() {
    if (!app.logs.length) return '<div class="empty-state"><div class="empty-state-icon">🌐</div>Aucune requête HTTP enregistrée</div>';
    return `<div id="logEntries">${app.logs.map(renderLogEntry).join('')}</div>`;
}

function renderLogEntry(log) {
    const method = log.method || '?';
    const status = log.status || 0;
    const statusClass = status >= 500 ? 's5xx' : status >= 400 ? 's4xx' : 's2xx';
    return `<div class="log-entry"><span class="log-time">${fmtTime(log.timestamp)}</span><span class="log-method ${method}">${method}</span><span class="log-path">${esc(log.path || '')}</span><span class="log-status ${statusClass}">${status}</span><span class="log-duration">${fmtDuration(log.duration_ms || 0)}</span><span class="log-client">${esc(log.client || '')}</span></div>`;
}

// ═══════════════ RAFRAÎCHISSEMENT ═══════════════

let _logRefreshTimer = null;

function updateLogRefresh() {
    const interval = parseInt(document.getElementById('logRefreshInterval')?.value || '0', 10);
    if (_logRefreshTimer) clearInterval(_logRefreshTimer);
    _logRefreshTimer = null;
    if (!interval) return;
    _logRefreshTimer = setInterval(async () => {
        if (!document.getElementById('view-logs')?.classList.contains('active')) return;
        try {
            const [auditR, logsR, activityR] = await Promise.all([apiAudit(), apiLogs(), apiActivity()]);
            if (auditR.status === 'ok') app.audit = auditR.entries || [];
            if (logsR.status === 'ok') app.logs = logsR.logs || [];
            if (activityR.status === 'ok') app.activity = activityR.events || [];
            const content = document.getElementById('logsTabContent');
            if (content) content.innerHTML = renderCurrentLogsTab();
            document.querySelectorAll('[data-log-tab] .count').forEach(count => {
                const tab = count.closest('[data-log-tab]').dataset.logTab;
                count.textContent = tab === 'activity' ? app.activity.length : tab === 'audit' ? app.audit.length : app.logs.length;
            });
        } catch {}
    }, interval * 1000);
}
