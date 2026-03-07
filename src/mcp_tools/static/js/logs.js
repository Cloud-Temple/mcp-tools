/**
 * MCP Tools Admin — Activité / Logs
 */

async function loadLogs() {
    const el = document.getElementById('view-logs');

    try {
        const r = await apiLogs();
        if (r.status === 'ok') {
            app.logs = r.logs || [];
            el.innerHTML = renderLogsView();
        } else {
            el.innerHTML = `<div class="empty-state">❌ ${esc(r.message)}</div>`;
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') {
            el.innerHTML = '<div class="empty-state">⚠️ Erreur de chargement</div>';
        }
    }
}

function renderLogsView() {
    let h = '';

    h += `<div class="view-header">
        <div class="view-title">📋 Activité <span class="count">${app.logs.length}</span></div>
        <div style="display:flex;gap:0.4rem;align-items:center">
            <label style="font-size:0.72rem;color:#666;display:flex;align-items:center;gap:0.3rem">
                🔄 <select id="logRefreshInterval" onchange="updateLogRefresh()" style="padding:0.2rem 0.4rem;border-radius:4px;border:none;background:rgba(255,255,255,0.1);color:#ccc;font-size:0.72rem">
                    <option value="0">Manuel</option>
                    <option value="5" selected>5s</option>
                    <option value="10">10s</option>
                    <option value="30">30s</option>
                </select>
            </label>
            <button class="btn btn-secondary btn-sm" onclick="loadLogs()">🔄 Rafraîchir</button>
        </div>
    </div>`;

    if (app.logs.length === 0) {
        h += `<div class="empty-state">
            <div class="empty-state-icon">📋</div>
            Aucune activité enregistrée
        </div>`;
        return h;
    }

    // Logs
    h += '<div id="logEntries">';
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

// Auto-refresh des logs
let _logRefreshTimer = null;

function updateLogRefresh() {
    const interval = parseInt(document.getElementById('logRefreshInterval')?.value || '0', 10);

    if (_logRefreshTimer) {
        clearInterval(_logRefreshTimer);
        _logRefreshTimer = null;
    }

    if (interval > 0) {
        _logRefreshTimer = setInterval(async () => {
            // Ne rafraîchir que si on est sur la vue logs
            if (document.getElementById('view-logs')?.classList.contains('active')) {
                try {
                    const r = await apiLogs();
                    if (r.status === 'ok') {
                        app.logs = r.logs || [];
                        const entries = document.getElementById('logEntries');
                        if (entries) {
                            entries.innerHTML = app.logs.map(renderLogEntry).join('');
                        }
                        // Mettre à jour le count
                        const countEl = document.querySelector('#view-logs .count');
                        if (countEl) countEl.textContent = app.logs.length;
                    }
                } catch {}
            }
        }, interval * 1000);
    }
}
