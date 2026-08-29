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
        app.activityCalls = activityR.status === 'ok' ? (activityR.calls || []) : [];
        app.activityStats = activityR.status === 'ok' ? (activityR.stats || null) : null;
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
        <button class="tab ${_currentLogsTab === 'activity' ? 'active' : ''}" data-log-tab="activity" onclick="switchLogsTab('activity')">⚡ Déroulé des appels <span class="count">${app.activityCalls.filter(call => call.kind === 'tool_call').length}</span></button>
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
    const calls = app.activityCalls || [];
    const toolCalls = calls.filter(call => call.kind === 'tool_call');
    if (!calls.length) {
        return `<div class="empty-state"><div class="empty-state-icon">⚡</div>Aucune trace d'appel enregistrée.<br><span style="font-size:0.75rem;color:#555">Chaque appel affichera sa demande, son exécution, sa réponse MCP et son verdict terminal.</span></div>`;
    }
    const states = [...new Set(calls.map(call => call.terminal_state).filter(Boolean))].sort();
    const tools = [...new Set(calls.map(call => call.tool).filter(Boolean))].sort();
    const stats = app.activityStats || {};
    const retention = stats.max_events ? `<div class="activity-retention">Affichés ${esc(String(app.activity.length))}/${esc(String(stats.stored_events || 0))} événements conservés · buffer ${esc(String(stats.max_events))} · ${esc(String(stats.max_age_seconds || 0))} s · génération ${esc(stats.server_generation || '—')}${stats.evicted_capacity || stats.evicted_age ? ` · ⚠ évictions ${esc(String((stats.evicted_capacity || 0) + (stats.evicted_age || 0)))}` : ''}</div>` : '';
    return `<div class="activity-filters">
        <div class="search-bar"><span class="search-icon">🔍</span><input class="search-input" id="activityFilterSearch" placeholder="Agent, outil, call, trace, étape…" oninput="filterActivity()"></div>
        <select id="activityFilterKind" onchange="filterActivity()"><option value="tool_call" selected>Appels tools</option><option value="">Toutes les requêtes</option><option value="mcp_protocol">Protocole MCP</option><option value="admin">API admin</option></select>
        <select id="activityFilterState" onchange="filterActivity()"><option value="">Tous les verdicts</option>${states.map(state => `<option value="${esc(state)}">${esc(activityStateInfo(state).label)}</option>`).join('')}</select>
        <select id="activityFilterTool" onchange="filterActivity()"><option value="">Tous les tools</option>${tools.map(tool => `<option value="${esc(tool)}">${esc(tool)}</option>`).join('')}</select>
    </div>${retention}<div id="activityEntries">${toolCalls.length ? toolCalls.map(renderActivityCall).join('') : '<div class="empty-state" style="padding:1.5rem">Aucun appel d’outil dans cette fenêtre. Choisissez « Toutes les requêtes » pour voir le protocole.</div>'}</div>`;
}

function filterActivity() {
    const kind = document.getElementById('activityFilterKind')?.value || '';
    const state = document.getElementById('activityFilterState')?.value || '';
    const tool = document.getElementById('activityFilterTool')?.value || '';
    const search = (document.getElementById('activityFilterSearch')?.value || '').toLowerCase();
    const entries = (app.activityCalls || []).filter(call => (
        (!kind || call.kind === kind)
        && (!state || call.terminal_state === state)
        && (!tool || call.tool === tool)
        && (!search || JSON.stringify(call).toLowerCase().includes(search))
    ));
    const el = document.getElementById('activityEntries');
    if (el) el.innerHTML = entries.length ? entries.map(renderActivityCall).join('') : '<div class="empty-state" style="padding:1.5rem">Aucun résultat pour ces filtres</div>';
}

function activityStateInfo(state) {
    const states = {
        succeeded: { icon: '✅', label: 'Terminé — réponse MCP émise', level: 'success' },
        tool_failed: { icon: '❌', label: 'Échec outil', level: 'error' },
        remote_result_uncertain: { icon: '⚠️', label: 'Résultat distant incertain', level: 'warning' },
        response_missing: { icon: '❌', label: 'Réponse MCP absente', level: 'error' },
        response_delivery_failed: { icon: '❌', label: 'Émission ASGI échouée', level: 'error' },
        response_terminal_unobserved: { icon: '⚠️', label: 'Réponse terminale non observée', level: 'warning' },
        response_incomplete: { icon: '⚠️', label: 'Réponse incomplète', level: 'warning' },
        client_cancelled: { icon: '⚠️', label: 'Client annulé', level: 'warning' },
        cancelled: { icon: '⚠️', label: 'Annulé', level: 'warning' },
        transport_failed: { icon: '❌', label: 'Transport en échec', level: 'error' },
        transport_completed: { icon: '✅', label: 'Transport terminé', level: 'success' },
        incomplete: { icon: '⚠️', label: 'Incomplet', level: 'warning' },
    };
    return states[state] || { icon: '•', label: state || 'Inconnu', level: 'warning' };
}

function renderActivityCall(call) {
    const state = activityStateInfo(call.terminal_state);
    const verdictLabel = call.terminal_state === 'succeeded' && !call.mcp_terminal_required
        ? 'Terminé — réponse HTTP émise'
        : state.label;
    const tags = [
        call.tool && `🔧 ${call.tool}`,
        call.actor && `👤 ${call.actor}`,
        call.agent_id && `🤝 ${call.agent_id}`,
        call.model && `🤖 ${call.model}`,
        call.call_id && `☎ ${call.call_id}`,
        call.rpc_request_id !== undefined && `JSON-RPC ${call.rpc_request_id}`,
        call.mcp_session_ref && `session ${call.mcp_session_ref}`,
        call.trace_id && `⌁ ${call.trace_id}`,
        call.timeline_complete === false && '⚠ chronologie partielle',
    ].filter(Boolean);
    const duration = typeof call.duration_ms === 'number' ? fmtDuration(call.duration_ms) : '—';
    const transport = call.transport_state || '—';
    const open = state.level !== 'success' || call.timeline_complete === false ? ' open' : '';
    return `<details class="activity-call activity-${state.level}"${open}>
        <summary><div class="activity-call-summary">
            <span class="activity-call-time">${fmtTime(call.started_at)}<small>${fmtDateShort(call.started_at)}</small></span>
            <span class="activity-call-verdict">${state.icon} ${esc(verdictLabel)}</span>
            <code>${esc(call.tool || call.rpc_method || call.path || 'appel')}</code>
            <span class="activity-call-duration">${esc(duration)}</span>
            <span class="activity-call-transport">${esc(transport)}</span>
            <span class="activity-call-steps">${esc(String(call.event_count || 0))} étapes</span>
        </div></summary>
        <div class="activity-call-body">
            ${tags.length ? `<div class="activity-tags">${tags.map(tag => `<span>${esc(tag)}</span>`).join('')}</div>` : ''}
            <div class="activity-timeline">${(call.events || []).map(renderActivityStep).join('')}</div>
        </div>
    </details>`;
}

function renderActivityStep(event) {
    const level = ['info', 'warning', 'error'].includes(event.level) ? event.level : 'info';
    const details = event.details ? `<details><summary>Détails sûrs</summary><pre>${esc(JSON.stringify(event, null, 2))}</pre></details>` : '';
    return `<div class="activity-step activity-${level}">
        <span class="activity-step-sequence">${esc(String(event.sequence || '?'))}</span>
        <span class="activity-step-time">${fmtTime(event.timestamp)}</span>
        <code>${esc(event.event || 'unknown')}</code>
        <span class="activity-step-message">${esc(event.message || '')}</span>
        ${details}
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
            if (activityR.status === 'ok') {
                app.activity = activityR.events || [];
                app.activityCalls = activityR.calls || [];
                app.activityStats = activityR.stats || null;
            }
            const content = document.getElementById('logsTabContent');
            if (content) content.innerHTML = renderCurrentLogsTab();
            document.querySelectorAll('[data-log-tab] .count').forEach(count => {
                const tab = count.closest('[data-log-tab]').dataset.logTab;
                count.textContent = tab === 'activity' ? app.activityCalls.filter(call => call.kind === 'tool_call').length : tab === 'audit' ? app.audit.length : app.logs.length;
            });
        } catch {}
    }, interval * 1000);
}
