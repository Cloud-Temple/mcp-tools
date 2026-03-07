/**
 * MCP Tools Admin — Gestion des Tokens
 */

let _lastCreatedToken = null;

async function loadTokens() {
    const el = document.getElementById('view-tokens');

    try {
        const r = await apiTokensList();
        if (r.status === 'success') {
            app.tokens = r.tokens || [];
            el.innerHTML = renderTokensView();
        } else {
            el.innerHTML = `<div class="empty-state">❌ ${esc(r.message)}</div>`;
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') {
            el.innerHTML = '<div class="empty-state">⚠️ Erreur de chargement</div>';
        }
    }
}

function renderTokensView() {
    let h = '';

    h += `<div class="view-header">
        <div class="view-title">🔑 Tokens <span class="count">${app.tokens.length}</span></div>
        <div style="display:flex;gap:0.4rem">
            <button class="btn btn-primary btn-sm" onclick="showCreateTokenForm()">+ Nouveau token</button>
            <button class="btn btn-secondary btn-sm" onclick="loadTokens()">🔄 Rafraîchir</button>
        </div>
    </div>`;

    // Alerte si un token vient d'être créé
    if (_lastCreatedToken) {
        h += `<div class="token-created-alert">
            <h3>✅ Token créé pour "${esc(_lastCreatedToken.client_name)}"</h3>
            <div class="token-value" onclick="copyToken(this)" title="Cliquer pour copier">${esc(_lastCreatedToken.token)}</div>
            <div class="warning">⚠️ Ce token ne sera plus affiché. Copiez-le maintenant !</div>
        </div>`;
    }

    // Formulaire de création (caché par défaut)
    h += '<div id="tokenCreateForm"></div>';

    // Table des tokens
    if (app.tokens.length === 0) {
        h += `<div class="empty-state">
            <div class="empty-state-icon">🔑</div>
            Aucun token S3 configuré.<br>
            Seul le bootstrap key (ADMIN_BOOTSTRAP_KEY) est actif.
        </div>`;
    } else {
        h += '<div class="table-wrap"><table>';
        h += `<tr>
            <th>Client</th>
            <th>Permissions</th>
            <th>Tool IDs</th>
            <th>Créé le</th>
            <th>Expire le</th>
            <th>Statut</th>
            <th>Actions</th>
        </tr>`;

        app.tokens.forEach(t => {
            const statusBadge = t.expired
                ? '<span class="badge badge-red">Expiré</span>'
                : '<span class="badge badge-green">Actif</span>';

            const perms = (t.permissions || []).map(p =>
                `<span class="badge ${p === 'admin' ? 'badge-purple' : p === 'write' ? 'badge-orange' : 'badge-teal'}">${esc(p)}</span>`
            ).join(' ');

            const toolIds = (t.tool_ids || []);
            let toolsDisplay;
            if (toolIds.length === 0) {
                toolsDisplay = '<span class="badge badge-gray">Tous</span>';
            } else if (toolIds.length <= 3) {
                toolsDisplay = toolIds.map(id => `<span class="badge badge-blue">${esc(id)}</span>`).join(' ');
            } else {
                toolsDisplay = toolIds.slice(0, 2).map(id => `<span class="badge badge-blue">${esc(id)}</span>`).join(' ')
                    + ` <span class="badge badge-gray">+${toolIds.length - 2}</span>`;
            }

            h += `<tr>
                <td><strong style="color:#fff">${esc(t.client_name)}</strong><br>
                    <span style="font-size:0.65rem;color:#555">${esc(t.token_hash_prefix)}</span>
                </td>
                <td>${perms}</td>
                <td>${toolsDisplay}</td>
                <td style="font-size:0.72rem">${fmtDate(t.created_at)}</td>
                <td style="font-size:0.72rem">${t.expires_at ? fmtDate(t.expires_at) : '—'}</td>
                <td>${statusBadge}</td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="showTokenInfo('${esc(t.client_name)}')">ℹ️</button>
                    <button class="btn btn-danger btn-sm" onclick="confirmRevokeToken('${esc(t.client_name)}')">🗑️</button>
                </td>
            </tr>`;
        });

        h += '</table></div>';
    }

    return h;
}

function showCreateTokenForm() {
    _lastCreatedToken = null;
    const el = document.getElementById('tokenCreateForm');

    // Récupérer la liste des tools pour les checkboxes
    const toolNames = app.tools.length > 0
        ? app.tools.map(t => t.name)
        : [];

    let h = `<div class="tool-exec-panel" style="margin-bottom:1rem">
        <div class="tool-exec-header">
            <div class="tool-exec-name">+ Nouveau Token</div>
            <div class="tool-exec-actions">
                <button class="btn btn-primary" onclick="createToken()" id="createTokenBtn">Créer</button>
                <button class="btn btn-secondary" onclick="hideCreateTokenForm()">✕ Annuler</button>
            </div>
        </div>

        <div class="form-row">
            <div class="form-group">
                <label class="form-label">Nom du client <span class="required">*</span></label>
                <input type="text" class="form-input" id="tokenClientName" placeholder="ex: agent-sre, audit-bot…">
            </div>
            <div class="form-group">
                <label class="form-label">Expiration (jours)</label>
                <input type="number" class="form-input" id="tokenExpiresDays" value="90" min="0">
                <div class="form-hint">0 = jamais</div>
            </div>
        </div>

        <div class="form-group">
            <label class="form-label">Permissions</label>
            <div style="display:flex;gap:0.5rem;flex-wrap:wrap;padding:0.3rem 0">
                <label style="font-size:0.78rem;color:#ccc;display:flex;align-items:center;gap:0.3rem;cursor:pointer">
                    <input type="checkbox" value="read" checked class="perm-cb"> read
                </label>
                <label style="font-size:0.78rem;color:#ccc;display:flex;align-items:center;gap:0.3rem;cursor:pointer">
                    <input type="checkbox" value="write" class="perm-cb"> write
                </label>
                <label style="font-size:0.78rem;color:#ccc;display:flex;align-items:center;gap:0.3rem;cursor:pointer">
                    <input type="checkbox" value="admin" class="perm-cb"> admin
                </label>
            </div>
        </div>

        <div class="form-group">
            <label class="form-label">Tools autorisés <span style="color:#556677;font-weight:400">(vide = tous)</span></label>`;

    if (toolNames.length > 0) {
        h += '<div style="display:flex;gap:0.3rem;flex-wrap:wrap;padding:0.3rem 0;max-height:150px;overflow-y:auto">';
        toolNames.forEach(name => {
            h += `<label style="font-size:0.72rem;color:#ccc;display:flex;align-items:center;gap:0.2rem;cursor:pointer;min-width:140px">
                <input type="checkbox" value="${esc(name)}" class="toolid-cb"> ${esc(name)}
            </label>`;
        });
        h += '</div>';
    } else {
        h += `<input type="text" class="form-input" id="tokenToolIds" placeholder="tool1, tool2, … (vide = tous)">`;
    }

    h += `<div class="form-hint">Cochez les outils accessibles par ce token. Si aucun n'est coché, tous les outils sont accessibles.</div>
        </div>
    </div>`;

    el.innerHTML = h;
    document.getElementById('tokenClientName')?.focus();
}

function hideCreateTokenForm() {
    document.getElementById('tokenCreateForm').innerHTML = '';
}

async function createToken() {
    const btn = document.getElementById('createTokenBtn');
    const clientName = document.getElementById('tokenClientName')?.value.trim();
    const expiresDays = parseInt(document.getElementById('tokenExpiresDays')?.value || '90', 10);

    if (!clientName) {
        showToast('Nom du client requis', 'error');
        return;
    }

    // Permissions
    const permissions = [];
    document.querySelectorAll('.perm-cb:checked').forEach(cb => permissions.push(cb.value));
    if (permissions.length === 0) permissions.push('read');

    // Tool IDs
    let toolIds = [];
    const checkboxes = document.querySelectorAll('.toolid-cb:checked');
    if (checkboxes.length > 0) {
        checkboxes.forEach(cb => toolIds.push(cb.value));
    } else {
        const input = document.getElementById('tokenToolIds');
        if (input && input.value.trim()) {
            toolIds = input.value.split(',').map(s => s.trim()).filter(Boolean);
        }
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Création…';

    try {
        const r = await apiTokensCreate({
            client_name: clientName,
            permissions,
            tool_ids: toolIds,
            expires_days: expiresDays,
        });

        if (r.status === 'success') {
            _lastCreatedToken = { client_name: clientName, token: r.token };
            showToast(`Token créé pour "${clientName}"`, 'success');
            await loadTokens();  // Recharger la vue
        } else {
            showToast(r.message || 'Erreur', 'error');
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') {
            showToast(e.message, 'error');
        }
    } finally {
        btn.disabled = false;
        btn.innerHTML = 'Créer';
    }
}

function copyToken(el) {
    const text = el.textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('Token copié !', 'success');
    }).catch(() => {
        // Fallback
        const range = document.createRange();
        range.selectNodeContents(el);
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(range);
        showToast('Sélectionné — Ctrl+C pour copier', 'info');
    });
}

async function showTokenInfo(name) {
    try {
        const r = await apiTokensInfo(name);
        if (r.status === 'success') {
            let body = `<pre style="color:#ccc;font-size:0.78rem;white-space:pre-wrap">${esc(JSON.stringify(r, null, 2))}</pre>`;
            showModal(`🔑 Token : ${name}`, body);
        } else {
            showToast(r.message || 'Erreur', 'error');
        }
    } catch {}
}

function confirmRevokeToken(name) {
    const body = `
        <p style="color:#ccc;font-size:0.85rem;margin-bottom:1rem">
            Voulez-vous vraiment révoquer le token <strong style="color:#e74c3c">"${esc(name)}"</strong> ?
        </p>
        <p style="color:#888;font-size:0.78rem;margin-bottom:1.2rem">
            Cette action est irréversible. Le client ne pourra plus s'authentifier.
        </p>
        <div style="display:flex;gap:0.5rem;justify-content:flex-end">
            <button class="btn btn-secondary" onclick="hideModal()">Annuler</button>
            <button class="btn btn-danger" onclick="doRevokeToken('${esc(name)}')">🗑️ Révoquer</button>
        </div>
    `;
    showModal('⚠️ Confirmer la révocation', body);
}

async function doRevokeToken(name) {
    hideModal();
    try {
        const r = await apiTokensRevoke(name);
        if (r.status === 'success') {
            showToast(`Token "${name}" révoqué`, 'success');
            _lastCreatedToken = null;
            await loadTokens();
        } else {
            showToast(r.message || 'Erreur', 'error');
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') {
            showToast(e.message, 'error');
        }
    }
}
