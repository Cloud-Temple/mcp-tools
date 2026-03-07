/**
 * MCP Tools Admin — Dashboard
 */

async function loadDashboard() {
    const el = document.getElementById('view-dashboard');

    try {
        const health = await apiHealth();
        app.health = health;

        // Charger aussi les tokens pour les stats
        let tokenStats = { count: 0, expired: 0 };
        try {
            const tokensR = await apiTokensList();
            if (tokensR.status === 'success') {
                tokenStats.count = tokensR.count || 0;
                tokenStats.expired = (tokensR.tokens || []).filter(t => t.expired).length;
                app.tokens = tokensR.tokens || [];
            }
        } catch {}

        el.innerHTML = renderDashboard(health, tokenStats);
        updateStatus('ok');
    } catch (e) {
        if (e.message !== 'Unauthorized') {
            el.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⚠️</div>Erreur de chargement</div>';
            updateStatus('error');
        }
    }
}

function renderDashboard(health, tokenStats) {
    let h = '';

    h += `<div class="view-header">
        <div class="view-title">📊 Dashboard</div>
        <button class="btn btn-secondary btn-sm" onclick="loadDashboard()">🔄 Rafraîchir</button>
    </div>`;

    h += '<div class="cards-grid">';

    // ── Serveur ──
    h += `<div class="card">
        <div class="card-title">🖥️ Serveur</div>
        <div class="card-row"><span>Service</span><span class="val">${esc(health.service || '—')}</span></div>
        <div class="card-row"><span>Version</span><span class="val">${esc(health.version || '—')}</span></div>
        <div class="card-row"><span>Python</span><span class="val">${esc(health.python_version || '—')}</span></div>
        <div class="card-row"><span>Endpoint</span><span class="val">${esc(health.host || '—')}</span></div>
        <div class="card-row"><span>Statut</span><span class="val">${health.status === 'ok' ? '✅ En ligne' : '❌ Erreur'}</span></div>
    </div>`;

    // ── Outils ──
    h += `<div class="card">
        <div class="card-title">🔧 Outils</div>
        <div class="card-row"><span>Nombre total</span><span class="val">${health.tools_count || 0}</span></div>
        <div class="card-row"><span>Sandbox Docker</span><span class="val ${health.sandbox_enabled ? '' : 'warn'}">${health.sandbox_enabled ? '✅ Activée' : '⚠️ Désactivée'}</span></div>
        <div class="card-row"><span>Perplexity AI</span><span class="val ${health.perplexity_configured ? '' : 'muted'}">${health.perplexity_configured ? '✅ Configurée' : '— Non configurée'}</span></div>
    </div>`;

    // ── Tokens ──
    const activeCount = tokenStats.count - tokenStats.expired;
    h += `<div class="card">
        <div class="card-title">🔑 Tokens</div>
        <div class="card-row"><span>Total</span><span class="val">${tokenStats.count}</span></div>
        <div class="card-row"><span>Actifs</span><span class="val">${activeCount}</span></div>
        <div class="card-row"><span>Expirés</span><span class="val ${tokenStats.expired > 0 ? 'warn' : ''}">${tokenStats.expired}</span></div>
        <div class="card-row"><span>S3 Backend</span><span class="val ${health.s3_configured ? '' : 'error'}">${health.s3_configured ? '✅ Connecté' : '❌ Non configuré'}</span></div>
    </div>`;

    // ── Plateforme ──
    h += `<div class="card">
        <div class="card-title">⚙️ Plateforme</div>
        <div class="card-row"><span>OS</span><span class="val">${esc(health.platform || '—')}</span></div>
        <div class="card-row"><span>Transport</span><span class="val">Streamable HTTP</span></div>
        <div class="card-row"><span>WAF</span><span class="val">Caddy + Coraza</span></div>
    </div>`;

    h += '</div>';  // cards-grid

    // ── Quick Actions ──
    h += `<div class="card" style="margin-top: 0.5rem;">
        <div class="card-title">⚡ Actions rapides</div>
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; padding: 0.3rem 0;">
            <button class="btn btn-primary btn-sm" onclick="switchView('tools')">🔧 Tester un outil</button>
            <button class="btn btn-primary btn-sm" onclick="switchView('tokens')">🔑 Gérer les tokens</button>
            <button class="btn btn-primary btn-sm" onclick="switchView('logs')">📋 Voir l'activité</button>
            <button class="btn btn-secondary btn-sm" onclick="quickSystemHealth()">❤️ System Health</button>
            <button class="btn btn-secondary btn-sm" onclick="quickSystemAbout()">ℹ️ System About</button>
        </div>
    </div>`;

    return h;
}

async function quickSystemHealth() {
    try {
        const r = await apiToolsRun('system_health', {});
        if (r.status === 'ok') {
            showModal('❤️ System Health', `<pre style="color:#ccc;font-size:0.78rem;white-space:pre-wrap">${esc(fmtJson(r.result))}</pre>`);
        } else {
            showToast(r.message || 'Erreur', 'error');
        }
    } catch {}
}

async function quickSystemAbout() {
    try {
        const r = await apiToolsRun('system_about', {});
        if (r.status === 'ok') {
            showModal('ℹ️ System About', `<pre style="color:#ccc;font-size:0.78rem;white-space:pre-wrap">${esc(fmtJson(r.result))}</pre>`);
        } else {
            showToast(r.message || 'Erreur', 'error');
        }
    } catch {}
}
