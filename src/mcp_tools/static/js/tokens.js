/**
 * MCP Tools Admin — Gestion des Tokens (v2)
 *
 * Fonctionnalités :
 *   - Création avec tool picker intelligent (catégories, tout/rien)
 *   - Modification inline (permissions, tools, email)
 *   - Révocation avec confirmation
 *   - Purge des tokens expirés
 *   - Info token formatée (pas de JSON brut)
 */

let _lastCreatedToken = null;

// ═══════════════ CATALOGUE DES OUTILS ═══════════════

const TOOL_CATEGORIES = {
    '🖥️ Exécution': {
        description: 'Exécution de commandes et calculs',
        tools: ['shell', 'calc'],
    },
    '🌐 Réseau': {
        description: 'Diagnostics réseau et requêtes HTTP',
        tools: ['network', 'http'],
    },
    '🔒 Infrastructure': {
        description: 'SSH et fichiers S3',
        tools: ['ssh', 'files'],
    },
    '🤖 IA': {
        description: 'Recherche et documentation Perplexity',
        tools: ['perplexity_search', 'perplexity_doc'],
    },
    '⚙️ Système': {
        description: 'Santé, informations, dates',
        tools: ['system_health', 'system_about', 'date'],
    },
    '🔑 Administration': {
        description: 'Gestion des tokens (réservé admin)',
        tools: ['token'],
        adminOnly: true,
    },
};

// Descriptions courtes des outils
const TOOL_DESCRIPTIONS = {
    shell: 'Exécuter des commandes dans une sandbox Docker isolée',
    calc: 'Calculer des expressions mathématiques Python',
    network: 'Diagnostics réseau : ping, traceroute, nslookup, dig',
    http: 'Client HTTP/REST avec protection anti-SSRF',
    ssh: 'Commandes SSH, upload/download de fichiers',
    files: 'Opérations fichiers sur S3 Dell ECS',
    perplexity_search: 'Recherche internet via Perplexity AI',
    perplexity_doc: 'Documentation technique via Perplexity AI',
    system_health: 'État de santé du serveur MCP',
    system_about: 'Informations détaillées du serveur',
    date: 'Manipulation de dates et fuseaux horaires',
    token: 'Gestion des tokens d\'authentification (admin)',
};

// Liste complète pour vérification
const ALL_TOOLS = Object.values(TOOL_CATEGORIES).flatMap(c => c.tools);


// ═══════════════ CHARGEMENT ═══════════════

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


// ═══════════════ VUE PRINCIPALE ═══════════════

function renderTokensView() {
    const expiredCount = app.tokens.filter(t => t.expired).length;
    let h = '';

    // Header
    h += `<div class="view-header">
        <div class="view-title">🔑 Tokens <span class="count">${app.tokens.length}</span></div>
        <div style="display:flex;gap:0.4rem;flex-wrap:wrap">
            <button class="btn btn-primary btn-sm" onclick="showCreateTokenForm()">+ Nouveau token</button>`;
    if (expiredCount > 0) {
        h += `<button class="btn btn-danger btn-sm" onclick="confirmPurgeExpired(${expiredCount})">🗑️ Purger ${expiredCount} expiré(s)</button>`;
    }
    h += `<button class="btn btn-secondary btn-sm" onclick="loadTokens()">🔄</button>
        </div>
    </div>`;

    // Aide contextuelle
    h += `<div class="help-banner">
        <div class="help-banner-icon">💡</div>
        <div class="help-banner-text">
            <strong>Modèle de permissions :</strong>
            <span class="badge badge-teal">access</span> = utilisation des outils autorisés |
            <span class="badge badge-purple">admin</span> = accès complet + gestion tokens.
            Le contrôle fin se fait via les <strong>tool_ids</strong> (liste blanche d'outils).
        </div>
    </div>`;

    // Alerte token créé
    if (_lastCreatedToken) {
        h += `<div class="token-created-alert">
            <h3>✅ Token créé pour « ${esc(_lastCreatedToken.client_name)} »</h3>
            <p style="font-size:0.75rem;color:#ccc;margin:0.3rem 0">Cliquez sur le token pour le copier :</p>
            <div class="token-value" onclick="copyToken(this)" title="Cliquer pour copier">${esc(_lastCreatedToken.token)}</div>
            <div class="warning">⚠️ Ce token ne sera plus jamais affiché. Copiez-le et conservez-le en lieu sûr !</div>
            <button class="btn btn-secondary btn-sm" onclick="_lastCreatedToken=null;loadTokens()" style="margin-top:0.5rem">✕ Fermer</button>
        </div>`;
    }

    // Zone formulaire création
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
            <th>Email</th>
            <th>Permissions</th>
            <th>Outils autorisés</th>
            <th>Créé le</th>
            <th>Expire</th>
            <th>Statut</th>
            <th>Actions</th>
        </tr>`;

        app.tokens.forEach(t => {
            const statusBadge = t.expired
                ? '<span class="badge badge-red">Expiré</span>'
                : '<span class="badge badge-green">Actif</span>';

            const perms = (t.permissions || []).map(p =>
                `<span class="badge ${p === 'admin' ? 'badge-purple' : 'badge-teal'}">${esc(p)}</span>`
            ).join(' ');

            const toolIds = t.tool_ids || [];
            let toolsDisplay;
            if (toolIds.length === 0) {
                toolsDisplay = '<span class="badge badge-gray" title="Token admin : accès à tous les outils">Tous (admin)</span>';
            } else if (toolIds.length === ALL_TOOLS.length) {
                toolsDisplay = '<span class="badge badge-blue" title="Tous les 12 outils autorisés">Tous (12)</span>';
            } else if (toolIds.length <= 4) {
                toolsDisplay = toolIds.map(id =>
                    `<span class="badge badge-blue" title="${esc(TOOL_DESCRIPTIONS[id] || '')}">${esc(id)}</span>`
                ).join(' ');
            } else {
                toolsDisplay = toolIds.slice(0, 3).map(id =>
                    `<span class="badge badge-blue">${esc(id)}</span>`
                ).join(' ') + ` <span class="badge badge-gray" title="${toolIds.join(', ')}">+${toolIds.length - 3}</span>`;
            }

            const emailDisplay = t.email
                ? `<span style="font-size:0.72rem;color:#aaa">${esc(t.email)}</span>`
                : '<span style="font-size:0.68rem;color:#555">—</span>';

            h += `<tr class="${t.expired ? 'row-expired' : ''}">
                <td>
                    <strong style="color:#fff">${esc(t.client_name)}</strong><br>
                    <span style="font-size:0.62rem;color:#555;font-family:monospace">${esc(t.token_hash_prefix)}</span>
                </td>
                <td>${emailDisplay}</td>
                <td>${perms}</td>
                <td style="max-width:220px">${toolsDisplay}</td>
                <td style="font-size:0.72rem;white-space:nowrap">
                    ${fmtDate(t.created_at)}<br>
                    <span style="font-size:0.62rem;color:#555">par ${esc(t.created_by || '?')}</span>
                </td>
                <td style="font-size:0.72rem">${t.expires_at ? fmtDate(t.expires_at) : '<span style="color:#555">Jamais</span>'}</td>
                <td>${statusBadge}</td>
                <td style="white-space:nowrap">
                    <button class="btn btn-secondary btn-sm" onclick="showTokenInfo('${esc(t.client_name)}')" title="Détails">ℹ️</button>
                    <button class="btn btn-secondary btn-sm" onclick="showEditTokenForm('${esc(t.client_name)}')" title="Modifier"${t.expired ? ' disabled' : ''}>✏️</button>
                    <button class="btn btn-danger btn-sm" onclick="confirmRevokeToken('${esc(t.client_name)}')" title="Révoquer">🗑️</button>
                </td>
            </tr>`;
        });

        h += '</table></div>';
    }

    return h;
}


// ═══════════════ TOOL PICKER (composant réutilisable) ═══════════════

function renderToolPicker(prefix, selectedTools = [], showAdminOnly = false) {
    const selectedSet = new Set(selectedTools);
    // Filtrer les outils admin-only si pas en mode admin
    const visibleTools = ALL_TOOLS.filter(t => {
        if (!showAdminOnly) {
            for (const cat of Object.values(TOOL_CATEGORIES)) {
                if (cat.adminOnly && cat.tools.includes(t)) return false;
            }
        }
        return true;
    });
    const visibleCount = visibleTools.length;
    const selectedCount = selectedTools.filter(t => visibleTools.includes(t)).length;

    let h = '';

    h += `<div class="tool-picker" id="${prefix}-picker">`;

    // Actions rapides
    h += `<div class="tool-picker-actions">
        <button type="button" class="btn btn-secondary btn-sm" onclick="toolPickerSelectAll('${prefix}')">✅ Tout</button>
        <button type="button" class="btn btn-secondary btn-sm" onclick="toolPickerSelectNone('${prefix}')">⬜ Rien</button>
        <span class="tool-picker-count" id="${prefix}-count">${selectedCount} / ${visibleCount} outils</span>
    </div>`;

    // Catégories
    for (const [catName, catInfo] of Object.entries(TOOL_CATEGORIES)) {
        // Masquer les catégories admin-only si pas en mode admin
        if (catInfo.adminOnly && !showAdminOnly) continue;

        const catTools = catInfo.tools;
        const catSelected = catTools.filter(t => selectedSet.has(t)).length;

        h += `<div class="tool-picker-category">
            <div class="tool-picker-cat-header">
                <span class="tool-picker-cat-name">${catName}</span>
                <span class="tool-picker-cat-desc">${catInfo.description}</span>
                <span class="tool-picker-cat-count">${catSelected}/${catTools.length}</span>
            </div>
            <div class="tool-picker-cat-tools">`;

        catTools.forEach(toolId => {
            const checked = selectedSet.has(toolId) ? 'checked' : '';
            const desc = TOOL_DESCRIPTIONS[toolId] || '';
            h += `<label class="tool-picker-tool" title="${esc(desc)}">
                <input type="checkbox" value="${esc(toolId)}" class="${prefix}-tool-cb" ${checked}
                    onchange="toolPickerUpdate('${prefix}')">
                <span class="tool-picker-tool-name">${esc(toolId)}</span>
            </label>`;
        });

        h += '</div></div>';
    }

    h += '</div>';
    return h;
}

function toolPickerSelectAll(prefix) {
    document.querySelectorAll(`.${prefix}-tool-cb`).forEach(cb => cb.checked = true);
    toolPickerUpdate(prefix);
}

function toolPickerSelectNone(prefix) {
    document.querySelectorAll(`.${prefix}-tool-cb`).forEach(cb => cb.checked = false);
    toolPickerUpdate(prefix);
}

function toolPickerUpdate(prefix) {
    const checked = document.querySelectorAll(`.${prefix}-tool-cb:checked`).length;
    const countEl = document.getElementById(`${prefix}-count`);
    if (countEl) countEl.textContent = `${checked} / ${ALL_TOOLS.length} outils`;

    // Mettre à jour les counts par catégorie
    for (const [catName, catInfo] of Object.entries(TOOL_CATEGORIES)) {
        const catTools = catInfo.tools;
        const catChecked = catTools.filter(t => {
            const cb = document.querySelector(`.${prefix}-tool-cb[value="${t}"]`);
            return cb && cb.checked;
        }).length;
        // Trouver le count span dans cette catégorie
        document.querySelectorAll('.tool-picker-cat-count').forEach(el => {
            const header = el.closest('.tool-picker-cat-header');
            if (header && header.querySelector('.tool-picker-cat-name')?.textContent === catName) {
                el.textContent = `${catChecked}/${catTools.length}`;
            }
        });
    }
}

function toolPickerGetSelected(prefix) {
    const selected = [];
    document.querySelectorAll(`.${prefix}-tool-cb:checked`).forEach(cb => selected.push(cb.value));
    return selected;
}


// ═══════════════ CRÉATION TOKEN ═══════════════

function showCreateTokenForm() {
    _lastCreatedToken = null;
    const el = document.getElementById('tokenCreateForm');

    let h = `<div class="token-form-panel">
        <div class="token-form-header">
            <div class="token-form-title">+ Nouveau Token</div>
            <div class="token-form-actions">
                <button class="btn btn-primary" onclick="createToken()" id="createTokenBtn">✅ Créer le token</button>
                <button class="btn btn-secondary" onclick="hideCreateTokenForm()">✕ Annuler</button>
            </div>
        </div>

        <div class="form-row">
            <div class="form-group">
                <label class="form-label">Nom du client <span class="required">*</span></label>
                <input type="text" class="form-input" id="tokenClientName" placeholder="ex: agent-sre, audit-bot, cline-dev…">
                <div class="form-hint">Identifiant unique pour ce token. Utilisé dans les logs d'audit.</div>
            </div>
            <div class="form-group">
                <label class="form-label">Email propriétaire</label>
                <input type="email" class="form-input" id="tokenEmail" placeholder="ex: admin@cloud-temple.com">
                <div class="form-hint">Optionnel. Pour traçabilité et contact.</div>
            </div>
        </div>

        <div class="form-row">
            <div class="form-group">
                <label class="form-label">Permissions</label>
                <div class="perm-selector">
                    <label class="perm-option" title="Peut utiliser les outils listés dans tool_ids">
                        <input type="radio" name="create-perm" value="access" checked>
                        <span class="perm-label">
                            <span class="badge badge-teal">access</span>
                            <span class="perm-desc">Utilisation des outils autorisés</span>
                        </span>
                    </label>
                    <label class="perm-option" title="Accès complet à tous les outils + gestion des tokens">
                        <input type="radio" name="create-perm" value="admin">
                        <span class="perm-label">
                            <span class="badge badge-purple">admin</span>
                            <span class="perm-desc">Accès complet + gestion tokens</span>
                        </span>
                    </label>
                </div>
            </div>
            <div class="form-group">
                <label class="form-label">Expiration (jours)</label>
                <input type="number" class="form-input" id="tokenExpiresDays" value="90" min="0">
                <div class="form-hint">0 = jamais d'expiration. Recommandé : 90 jours.</div>
            </div>
        </div>

        <div class="form-group">
            <label class="form-label">Outils autorisés <span class="form-label-info">⚠️ Obligatoire pour les tokens non-admin (fail-closed)</span></label>
            <div id="createToolPickerZone">${renderToolPicker('create', ALL_TOOLS.filter(t => t !== 'token'), false)}</div>
        </div>
    </div>`;

    el.innerHTML = h;
    document.getElementById('tokenClientName')?.focus();

    // Écouter le changement de permission pour ajuster le picker
    document.querySelectorAll('input[name="create-perm"]').forEach(radio => {
        radio.addEventListener('change', () => {
            const picker = document.getElementById('create-picker');
            if (radio.value === 'admin') {
                picker.classList.add('picker-disabled');
                picker.title = 'Les tokens admin ont accès à tous les outils';
            } else {
                picker.classList.remove('picker-disabled');
                picker.title = '';
            }
        });
    });
}

function hideCreateTokenForm() {
    document.getElementById('tokenCreateForm').innerHTML = '';
}

async function createToken() {
    const btn = document.getElementById('createTokenBtn');
    const clientName = document.getElementById('tokenClientName')?.value.trim();
    const email = document.getElementById('tokenEmail')?.value.trim() || '';
    const expiresDays = parseInt(document.getElementById('tokenExpiresDays')?.value || '90', 10);

    if (!clientName) {
        showToast('Le nom du client est obligatoire', 'error');
        document.getElementById('tokenClientName')?.focus();
        return;
    }

    // Permission
    const permRadio = document.querySelector('input[name="create-perm"]:checked');
    const perm = permRadio ? permRadio.value : 'access';
    const permissions = perm === 'admin' ? ['admin', 'access'] : ['access'];

    // Tool IDs
    let toolIds;
    if (perm === 'admin') {
        toolIds = [];  // Admin n'a pas besoin de tool_ids
    } else {
        toolIds = toolPickerGetSelected('create');
        if (toolIds.length === 0) {
            showToast('⚠️ Sélectionnez au moins un outil (fail-closed : un token sans outils sera bloqué)', 'error');
            return;
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
            email,
        });

        if (r.status === 'success') {
            _lastCreatedToken = { client_name: clientName, token: r.token };
            showToast(`Token créé pour « ${clientName} »`, 'success');
            hideCreateTokenForm();
            await loadTokens();
        } else {
            showToast(r.message || 'Erreur lors de la création', 'error');
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast(e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '✅ Créer le token';
    }
}


// ═══════════════ MODIFICATION TOKEN ═══════════════

async function showEditTokenForm(clientName) {
    // Charger les infos actuelles
    let tokenData;
    try {
        const r = await apiTokensInfo(clientName);
        if (r.status !== 'success') {
            showToast(r.message || 'Erreur', 'error');
            return;
        }
        tokenData = r;
    } catch (e) {
        showToast('Erreur de chargement', 'error');
        return;
    }

    const currentPerms = tokenData.permissions || [];
    const currentTools = tokenData.tool_ids || [];
    const isAdmin = currentPerms.includes('admin');

    let body = `<div style="max-width:600px">
        <div class="form-group">
            <label class="form-label">Email propriétaire</label>
            <input type="email" class="form-input" id="editEmail" value="${esc(tokenData.email || '')}" placeholder="admin@cloud-temple.com">
        </div>

        <div class="form-group">
            <label class="form-label">Permissions</label>
            <div class="perm-selector">
                <label class="perm-option">
                    <input type="radio" name="edit-perm" value="access" ${!isAdmin ? 'checked' : ''}>
                    <span class="perm-label">
                        <span class="badge badge-teal">access</span>
                        <span class="perm-desc">Utilisation des outils autorisés</span>
                    </span>
                </label>
                <label class="perm-option">
                    <input type="radio" name="edit-perm" value="admin" ${isAdmin ? 'checked' : ''}>
                    <span class="perm-label">
                        <span class="badge badge-purple">admin</span>
                        <span class="perm-desc">Accès complet + gestion tokens</span>
                    </span>
                </label>
            </div>
        </div>

        <div class="form-group">
            <label class="form-label">Outils autorisés</label>
            ${renderToolPicker('edit', currentTools, isAdmin)}
        </div>

        <div style="display:flex;gap:0.5rem;justify-content:flex-end;margin-top:1rem;padding-top:0.8rem;border-top:1px solid rgba(255,255,255,0.05)">
            <button class="btn btn-secondary" onclick="hideModal()">Annuler</button>
            <button class="btn btn-primary" onclick="doUpdateToken('${esc(clientName)}')" id="editTokenBtn">💾 Enregistrer</button>
        </div>
    </div>`;

    showModal(`✏️ Modifier « ${clientName} »`, body);

    // Écouter le changement de permission pour désactiver/activer le picker
    const editPicker = document.getElementById('edit-picker');
    if (isAdmin && editPicker) {
        editPicker.classList.add('picker-disabled');
    }
    document.querySelectorAll('input[name="edit-perm"]').forEach(radio => {
        radio.addEventListener('change', () => {
            if (radio.value === 'admin') {
                editPicker.classList.add('picker-disabled');
                editPicker.title = 'Les tokens admin ont accès à tous les outils';
            } else {
                editPicker.classList.remove('picker-disabled');
                editPicker.title = '';
            }
        });
    });
}

async function doUpdateToken(clientName) {
    const btn = document.getElementById('editTokenBtn');
    if (!btn) return;

    const email = document.getElementById('editEmail')?.value.trim();
    const permRadio = document.querySelector('input[name="edit-perm"]:checked');
    const perm = permRadio ? permRadio.value : 'access';
    const permissions = perm === 'admin' ? ['admin', 'access'] : ['access'];
    const toolIds = perm === 'admin' ? [] : toolPickerGetSelected('edit');

    if (perm !== 'admin' && toolIds.length === 0) {
        showToast('⚠️ Sélectionnez au moins un outil pour un token non-admin', 'error');
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Enregistrement…';

    try {
        const r = await apiTokensUpdate(clientName, {
            permissions,
            tool_ids: toolIds,
            email: email || '',
        });

        if (r.status === 'success') {
            hideModal();
            showToast(`Token « ${clientName} » mis à jour`, 'success');
            await loadTokens();
        } else {
            showToast(r.message || 'Erreur', 'error');
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast(e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '💾 Enregistrer';
    }
}


// ═══════════════ INFO TOKEN ═══════════════

async function showTokenInfo(name) {
    try {
        const r = await apiTokensInfo(name);
        if (r.status !== 'success') {
            showToast(r.message || 'Erreur', 'error');
            return;
        }

        const statusBadge = r.expired
            ? '<span class="badge badge-red">Expiré</span>'
            : '<span class="badge badge-green">Actif</span>';

        const perms = (r.permissions || []).map(p =>
            `<span class="badge ${p === 'admin' ? 'badge-purple' : 'badge-teal'}">${esc(p)}</span>`
        ).join(' ');

        const toolIds = r.tool_ids || [];
        let toolsHtml;
        if (toolIds.length === 0) {
            toolsHtml = '<span style="color:#888">Tous les outils (token admin)</span>';
        } else {
            toolsHtml = `<div style="display:flex;flex-wrap:wrap;gap:0.25rem;margin-top:0.3rem">` +
                toolIds.map(id =>
                    `<span class="badge badge-blue" title="${esc(TOOL_DESCRIPTIONS[id] || '')}">${esc(id)}</span>`
                ).join('') + '</div>';
        }

        const body = `<div class="token-info-grid">
            <div class="token-info-row">
                <span class="token-info-label">Client</span>
                <span class="token-info-value"><strong style="color:#fff">${esc(r.client_name)}</strong></span>
            </div>
            <div class="token-info-row">
                <span class="token-info-label">Email</span>
                <span class="token-info-value">${r.email ? esc(r.email) : '<span style="color:#555">—</span>'}</span>
            </div>
            <div class="token-info-row">
                <span class="token-info-label">Statut</span>
                <span class="token-info-value">${statusBadge}</span>
            </div>
            <div class="token-info-row">
                <span class="token-info-label">Permissions</span>
                <span class="token-info-value">${perms}</span>
            </div>
            <div class="token-info-row">
                <span class="token-info-label">Outils (${toolIds.length})</span>
                <span class="token-info-value">${toolsHtml}</span>
            </div>
            <div class="token-info-row">
                <span class="token-info-label">Créé le</span>
                <span class="token-info-value">${fmtDate(r.created_at)}</span>
            </div>
            <div class="token-info-row">
                <span class="token-info-label">Créé par</span>
                <span class="token-info-value">${esc(r.created_by || '?')}</span>
            </div>
            <div class="token-info-row">
                <span class="token-info-label">Expire le</span>
                <span class="token-info-value">${r.expires_at ? fmtDate(r.expires_at) : '<span style="color:#555">Jamais</span>'}</span>
            </div>
            <div class="token-info-row">
                <span class="token-info-label">Hash</span>
                <span class="token-info-value" style="font-family:monospace;font-size:0.72rem;color:#666">${esc(r.token_hash_prefix)}</span>
            </div>
        </div>
        <div style="display:flex;gap:0.5rem;justify-content:flex-end;margin-top:1rem;padding-top:0.8rem;border-top:1px solid rgba(255,255,255,0.05)">
            <button class="btn btn-secondary" onclick="hideModal()">Fermer</button>
            <button class="btn btn-secondary" onclick="hideModal();showEditTokenForm('${esc(r.client_name)}')" ${r.expired ? 'disabled' : ''}>✏️ Modifier</button>
        </div>`;

        showModal(`🔑 Token « ${name} »`, body);
    } catch {}
}


// ═══════════════ RÉVOCATION TOKEN ═══════════════

function confirmRevokeToken(name) {
    const body = `
        <div style="text-align:center;padding:0.5rem 0">
            <div style="font-size:2.5rem;margin-bottom:0.5rem">⚠️</div>
            <p style="color:#ccc;font-size:0.88rem;margin-bottom:0.5rem">
                Révoquer le token <strong style="color:#e74c3c">« ${esc(name)} »</strong> ?
            </p>
            <p style="color:#888;font-size:0.78rem;margin-bottom:1.5rem">
                Cette action est <strong>irréversible</strong>. Le client ne pourra plus s'authentifier.
                Tous les agents utilisant ce token seront immédiatement déconnectés.
            </p>
            <div style="display:flex;gap:0.5rem;justify-content:center">
                <button class="btn btn-secondary" onclick="hideModal()">Annuler</button>
                <button class="btn btn-danger" onclick="doRevokeToken('${esc(name)}')">🗑️ Révoquer définitivement</button>
            </div>
        </div>
    `;
    showModal('Confirmer la révocation', body);
}

async function doRevokeToken(name) {
    hideModal();
    try {
        const r = await apiTokensRevoke(name);
        if (r.status === 'success') {
            showToast(`Token « ${name} » révoqué`, 'success');
            _lastCreatedToken = null;
            await loadTokens();
        } else {
            showToast(r.message || 'Erreur', 'error');
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast(e.message, 'error');
    }
}


// ═══════════════ PURGE TOKENS EXPIRÉS ═══════════════

function confirmPurgeExpired(count) {
    const body = `
        <div style="text-align:center;padding:0.5rem 0">
            <div style="font-size:2.5rem;margin-bottom:0.5rem">🗑️</div>
            <p style="color:#ccc;font-size:0.88rem;margin-bottom:0.5rem">
                Purger <strong style="color:#f39c12">${count} token(s) expiré(s)</strong> ?
            </p>
            <p style="color:#888;font-size:0.78rem;margin-bottom:1.5rem">
                Les tokens expirés sont déjà inutilisables. Cette opération les supprime
                définitivement de S3 pour nettoyer le registre.
            </p>
            <div style="display:flex;gap:0.5rem;justify-content:center">
                <button class="btn btn-secondary" onclick="hideModal()">Annuler</button>
                <button class="btn btn-danger" onclick="doPurgeExpired()" id="purgeBtn">🗑️ Purger ${count} token(s)</button>
            </div>
        </div>
    `;
    showModal('Purger les tokens expirés', body);
}

async function doPurgeExpired() {
    const btn = document.getElementById('purgeBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Purge…';
    }

    try {
        const r = await apiTokensPurge();
        hideModal();
        if (r.status === 'success') {
            const purged = r.purged || 0;
            showToast(`${purged} token(s) expiré(s) purgé(s)`, 'success');
            await loadTokens();
        } else {
            showToast(r.message || 'Erreur', 'error');
        }
    } catch (e) {
        hideModal();
        if (e.message !== 'Unauthorized') showToast(e.message, 'error');
    }
}


// ═══════════════ COPIER TOKEN ═══════════════

function copyToken(el) {
    const text = el.textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('✅ Token copié dans le presse-papier !', 'success');
    }).catch(() => {
        const range = document.createRange();
        range.selectNodeContents(el);
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(range);
        showToast('Sélectionné — Ctrl+C pour copier', 'info');
    });
}
