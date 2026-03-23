/**
 * MCP Tools Admin — Activité & Audit (v2)
 *
 * 2 onglets :
 *   1. Journal d'audit — QUI a fait QUOI (actions métier)
 *   2. Requêtes HTTP — traces HTTP brutes
 */

let _currentLogsTab = 'audit';

// ═══════════════ CHARGEMENT ═══════════════

async function loadLogs() {
    const el = document.getElementById('view-logs');

    try {
        // Charger les deux sources en parallèle
        const [auditR, logsR] = await Promise.all([apiAudit(), apiLogs()]);
        app.audit = (auditR.status === 'ok') ? (auditR.entries || []) : [];
        app.logs = (logsR.status === 'ok') ? (logsR.logs || []) : [];
        el.innerHTML = renderLogsView();
    } catch (e) {
        if (e.message !== 'Unauthorized') {
            el.innerHTML = '<div class="empty-state">⚠️ Erreur de chargement</div>';
        }
    }
}


// ═══════════════ VUE PRINCIPALE ═══════════════

function renderLogsView() {
    let h = '';

    h += `<div class="view-header">
        <div class="view-title">📋 Activité</div>
        <div style="display:flex;gap:0.4rem;align-items:center">
            <label style="font-size:0.72rem;color:#666;display:flex;align-items:center;gap:0.3rem">
                🔄 <select id="logRefreshInterval" onchange="updateLogRefresh()" style="padding:0.2rem 0.4rem;border-radius:4px;border:none;background:rgba(255,255,255,0.1);color:#ccc;font-size:0.72rem">
                    <option value="0">Manuel</option>
                    <option value="5" selected>5s</option>
                    <option value="10">10s</option>
                    <option value="30">30s</option>
                </select>
            </label>
            <button class="btn btn-secondary btn-sm" onclick="loadLogs()">🔄</button>
        </div>
    </div>`;

    // Onglets
    h += `<div class="tabs">
        <button class="tab ${_currentLogsTab === 'audit' ? 'active' : ''}" onclick="switchLogsTab('audit')">
            🔍 Journal d'audit <span class="count">${app.audit.length}</span>
        </button>
        <button class="tab ${_currentLogsTab === 'http' ? 'active' : ''}" onclick="switchLogsTab('http')">
            🌐 Requêtes HTTP <span class="count">${app.logs.length}</span>
        </button>
    </div>`;

    // Contenu
    h += '<div id="logsTabContent">';
    if (_currentLogsTab === 'audit') {
        h += renderAuditTab();
    } else {
        h += renderHttpLogsTab();
    }
    h += '</div>';

    return h;
}

function switchLogsTab(tab) {
    _currentLogsTab = tab;
    const content = document.getElementById('logsTabContent');
    if (content) {
        content.innerHTML = (tab === 'audit') ? renderAuditTab() : renderHttpLogsTab();
    }
    // Mettre à jour les onglets actifs
    document.querySelectorAll('.tabs .tab').forEach(t => {
        const isAudit = t.textContent.includes('audit');
        t.classList.toggle('active', (tab === 'audit') === isAudit);
    });
}


// ═══════════════ ONGLET JOURNAL D'AUDIT ═══════════════

function renderAuditTab() {
    if (app.audit.length === 0) {
        return `<div class="empty-state">
            <div class="empty-state-icon">🔍</div>
            Aucune action enregistrée.<br>
            <span style="font-size:0.75rem;color:#555">Les actions (création/modification/révocation de tokens, exécution d'outils) apparaîtront ici.</span>
        </div>`;
    }

    // Filtres
    let h = `<div class="audit-filters" id="auditFilters">
        <div class="audit-filter-group">
            <label>Acteur</label>
            <select id="auditFilterActor" onchange="filterAudit()">
                <option value="">Tous</option>
                ${getUniqueActors().map(a => `<option value="${esc(a)}">${esc(a)}</option>`).join('')}
            </select>
        </div>
        <div class="audit-filter-group">
            <label>Action</label>
            <select id="auditFilterAction" onchange="filterAudit()">
                <option value="">Toutes</option>
                <option value="token_create">🔑 Création token</option>
                <option value="token_update">✏️ Modification token</option>
                <option value="token_revoke">🗑️ Révocation token</option>
                <option value="token_purge">🧹 Purge tokens</option>
                <option value="tool_run">▶️ Exécution outil</option>
                <option value="login_failed">❌ Échec connexion</option>
            </select>
        </div>
        <div class="audit-filter-group">
            <label>Recherche</label>
            <input type="text" id="auditFilterSearch" placeholder="Rechercher…" oninput="filterAudit()">
        </div>
    </div>`;

    h += '<div id="auditEntries">';
    h += app.audit.map(renderAuditEntry).join('');
    h += '</div>';

    return h;
}

function getUniqueActors() {
    const actors = new Set();
    app.audit.forEach(e => { if (e.actor) actors.add(e.actor); });
    return [...actors].sort();
}

function filterAudit() {
    const actor = document.getElementById('auditFilterActor')?.value || '';
    const action = document.getElementById('auditFilterAction')?.value || '';
    const search = (document.getElementById('auditFilterSearch')?.value || '').toLowerCase();

    const filtered = app.audit.filter(e => {
        if (actor && e.actor !== actor) return false;
        if (action && e.action !== action) return false;
        if (search) {
            const text = `${e.actor} ${e.action} ${e.target} ${e.details}`.toLowerCase();
            if (!text.includes(search)) return false;
        }
        return true;
    });

    const el = document.getElementById('auditEntries');
    if (el) {
        el.innerHTML = filtered.length > 0
            ? filtered.map(renderAuditEntry).join('')
            : '<div class="empty-state" style="padding:1.5rem">Aucun résultat pour ces filtres</div>';
    }
}

function renderAuditEntry(entry) {
    const time = fmtTime(entry.timestamp);
    const date = fmtDateShort(entry.timestamp);
    const actionInfo = getActionInfo(entry.action);
    const statusCls = entry.status === 'error' ? 'audit-error' : 'audit-success';

    return `<div class="audit-entry ${statusCls}" data-actor="${esc(entry.actor)}" data-action="${esc(entry.action)}">
        <div class="audit-entry-time">
            <span class="audit-time">${time}</span>
            <span class="audit-date">${date}</span>
        </div>
        <div class="audit-entry-icon">${actionInfo.icon}</div>
        <div class="audit-entry-body">
            <div class="audit-entry-summary">
                <span class="audit-actor">${esc(entry.actor)}</span>
                <span class="audit-action-label">${actionInfo.label}</span>
                ${entry.target ? `<span class="audit-target">${esc(entry.target)}</span>` : ''}
            </div>
            ${entry.details ? `<div class="audit-entry-details">${esc(entry.details)}</div>` : ''}
        </div>
        ${entry.status === 'error' ? '<div class="audit-entry-status"><span class="badge badge-red">Erreur</span></div>' : ''}
    </div>`;
}

function getActionInfo(action) {
    const map = {
        'token_create': { icon: '🔑', label: 'a créé le token' },
        'token_update': { icon: '✏️', label: 'a modifié le token' },
        'token_revoke': { icon: '🗑️', label: 'a révoqué le token' },
        'token_purge':  { icon: '🧹', label: 'a purgé les tokens expirés' },
        'tool_run':     { icon: '▶️', label: 'a exécuté l\'outil' },
        'login_failed': { icon: '❌', label: 'échec de connexion' },
    };
    return map[action] || { icon: '📌', label: action };
}


// ═══════════════ ONGLET REQUÊTES HTTP ═══════════════

function renderHttpLogsTab() {
    if (app.logs.length === 0) {
        return `<div class="empty-state">
            <div class="empty-state-icon">🌐</div>
            Aucune requête HTTP enregistrée
        </div>`;
    }

    let h = '<div id="logEntries">';
    app.logs.forEach(log => {
        h += renderLogEntry(log);
    });
    h += '</div>';
    return h;
}

function renderLogEntry(log) {
    const time = fmtTime(log.timestamp);
    const method = log.method || '?';
    const methodCls = method;
    const statusCode = log.status || 0;
    let statusCls = 's2xx';
    if (statusCode >= 400 && statusCode < 500) statusCls = 's4xx';
    else if (statusCode >= 500) statusCls = 's5xx';

    return `<div class="log-entry">
        <span class="log-time">${time}</span>
        <span class="log-method ${methodCls}">${method}</span>
        <span class="log-path">${esc(log.path || '')}</span>
        <span class="log-status ${statusCls}">${statusCode}</span>
        <span class="log-duration">${fmtDuration(log.duration_ms || 0)}</span>
        <span class="log-client">${esc(log.client || '')}</span>
    </div>`;
}


// ═══════════════ AUTO-REFRESH ═══════════════

let _logRefreshTimer = null;

function updateLogRefresh() {
    const interval = parseInt(document.getElementById('logRefreshInterval')?.value || '0', 10);

    if (_logRefreshTimer) {
        clearInterval(_logRefreshTimer);
        _logRefreshTimer = null;
    }

    if (interval > 0) {
        _logRefreshTimer = setInterval(async () => {
            if (document.getElementById('view-logs')?.classList.contains('active')) {
                try {
                    const [auditR, logsR] = await Promise.all([apiAudit(), apiLogs()]);

                    if (auditR.status === 'ok') app.audit = auditR.entries || [];
                    if (logsR.status === 'ok') app.logs = logsR.logs || [];

                    // Mise à jour partielle
                    const content = document.getElementById('logsTabContent');
                    if (content) {
                        content.innerHTML = (_currentLogsTab === 'audit')
                            ? renderAuditTab()
                            : renderHttpLogsTab();
                    }

                    // Counts dans les onglets
                    document.querySelectorAll('.tabs .tab .count').forEach((el, i) => {
                        el.textContent = i === 0 ? app.audit.length : app.logs.length;
                    });
                } catch {}
            }
        }, interval * 1000);
    }
}
