/**
 * MCP Tools Admin — Tools (liste + exécution interactive)
 */

async function loadTools() {
    const el = document.getElementById('view-tools');

    try {
        const r = await apiToolsList();
        if (r.status === 'ok') {
            app.tools = r.tools || [];
            el.innerHTML = renderToolsView();
        } else {
            el.innerHTML = `<div class="empty-state">❌ ${esc(r.message)}</div>`;
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') {
            el.innerHTML = '<div class="empty-state">⚠️ Erreur de chargement</div>';
        }
    }
}

function renderToolsView() {
    let h = '';

    h += `<div class="view-header">
        <div class="view-title">🔧 Tools <span class="count">${app.tools.length}</span></div>
        <button class="btn btn-secondary btn-sm" onclick="loadTools()">🔄 Rafraîchir</button>
    </div>`;

    // Barre de recherche
    h += `<div class="search-bar">
        <span class="search-icon">🔍</span>
        <input type="text" class="search-input" id="toolSearch" placeholder="Rechercher un outil…" oninput="filterTools()">
    </div>`;

    // Zone d'exécution (si un tool est sélectionné)
    h += '<div id="toolExecZone"></div>';

    // Grille des outils
    h += '<div class="tool-grid" id="toolGrid">';
    app.tools.forEach(t => {
        h += renderToolCard(t);
    });
    h += '</div>';

    return h;
}

function renderToolCard(tool) {
    const params = tool.parameters || [];
    const paramBadges = params.map(p => {
        const cls = p.required ? 'tool-param-badge required' : 'tool-param-badge';
        return `<span class="${cls}">${esc(p.name)}${p.required ? '*' : ''}</span>`;
    }).join('');

    return `<div class="tool-card" onclick="selectTool('${esc(tool.name)}')" data-tool="${esc(tool.name)}">
        <div class="tool-card-name">${esc(tool.name)}</div>
        <div class="tool-card-desc">${esc(tool.description)}</div>
        ${paramBadges ? `<div class="tool-card-params">${paramBadges}</div>` : ''}
    </div>`;
}

function filterTools() {
    const query = (document.getElementById('toolSearch')?.value || '').toLowerCase();
    document.querySelectorAll('.tool-card').forEach(card => {
        const name = card.dataset.tool || '';
        const desc = card.querySelector('.tool-card-desc')?.textContent || '';
        const match = name.toLowerCase().includes(query) || desc.toLowerCase().includes(query);
        card.style.display = match ? '' : 'none';
    });
}

function selectTool(name) {
    const tool = app.tools.find(t => t.name === name);
    if (!tool) return;
    app.selectedTool = tool;

    // Highlight la carte sélectionnée
    document.querySelectorAll('.tool-card').forEach(c => {
        c.style.borderLeftColor = c.dataset.tool === name ? '#3498db' : '#41a890';
    });

    const zone = document.getElementById('toolExecZone');
    zone.innerHTML = renderToolExecPanel(tool);

    // Focus sur le premier input
    const firstInput = zone.querySelector('input, textarea, select');
    if (firstInput) firstInput.focus();
}

function renderToolExecPanel(tool) {
    const params = tool.parameters || [];
    let h = '';

    h += `<div class="tool-exec-panel">
        <div class="tool-exec-header">
            <div class="tool-exec-name">▶ ${esc(tool.name)}</div>
            <div class="tool-exec-actions">
                <button class="btn btn-primary" onclick="executeTool()" id="execBtn">
                    ▶ Exécuter
                </button>
                <button class="btn btn-secondary" onclick="clearToolExec()">✕ Fermer</button>
            </div>
        </div>`;

    // Description complète
    if (tool.full_description && tool.full_description !== tool.description) {
        h += `<div style="font-size: 0.74rem; color: #888; margin-bottom: 0.8rem; line-height: 1.5;">${esc(tool.full_description)}</div>`;
    }

    // Formulaire de paramètres
    if (params.length > 0) {
        params.forEach(p => {
            h += `<div class="form-group">
                <label class="form-label">
                    ${esc(p.name)}
                    ${p.required ? '<span class="required">*</span>' : ''}
                    <span style="color:#556677; font-weight:400"> — ${esc(p.type)}</span>
                </label>`;

            if (p.enum && p.enum.length > 0) {
                h += `<select class="form-select" id="param-${esc(p.name)}" data-param="${esc(p.name)}">`;
                if (!p.required) h += '<option value="">— Aucun —</option>';
                p.enum.forEach(v => {
                    const sel = p.default === v ? 'selected' : '';
                    h += `<option value="${esc(v)}" ${sel}>${esc(v)}</option>`;
                });
                h += '</select>';
            } else if (p.type === 'integer' || p.type === 'number') {
                h += `<input type="number" class="form-input" id="param-${esc(p.name)}" data-param="${esc(p.name)}"
                    placeholder="${p.default !== undefined && p.default !== null ? 'défaut: ' + p.default : ''}"
                    value="${p.default !== undefined && p.default !== null ? p.default : ''}">`;
            } else if (p.type === 'boolean') {
                h += `<select class="form-select" id="param-${esc(p.name)}" data-param="${esc(p.name)}" data-type="boolean">
                    <option value="">— Défaut —</option>
                    <option value="true">true</option>
                    <option value="false">false</option>
                </select>`;
            } else {
                const isLong = p.description && (p.description.includes('content') || p.description.includes('body') || p.description.includes('script') || p.name === 'command' || p.name === 'content' || p.name === 'expr');
                if (isLong) {
                    h += `<textarea class="form-textarea" id="param-${esc(p.name)}" data-param="${esc(p.name)}"
                        placeholder="${esc(p.description || '')}">${p.default || ''}</textarea>`;
                } else {
                    h += `<input type="text" class="form-input" id="param-${esc(p.name)}" data-param="${esc(p.name)}"
                        placeholder="${esc(p.description || '')}"
                        value="${p.default !== undefined && p.default !== null ? esc(String(p.default)) : ''}">`;
                }
            }

            if (p.description) {
                h += `<div class="form-hint">${esc(p.description)}</div>`;
            }
            h += '</div>';
        });
    } else {
        h += '<div style="font-size: 0.78rem; color: #666; padding: 0.3rem 0;">Aucun paramètre requis</div>';
    }

    // Zone de résultat
    h += '<div id="toolResult"></div>';

    h += '</div>';  // tool-exec-panel

    return h;
}

function clearToolExec() {
    app.selectedTool = null;
    document.getElementById('toolExecZone').innerHTML = '';
    document.querySelectorAll('.tool-card').forEach(c => {
        c.style.borderLeftColor = '#41a890';
    });
}

async function executeTool() {
    if (!app.selectedTool) return;

    const btn = document.getElementById('execBtn');
    const resultEl = document.getElementById('toolResult');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Exécution…';
    resultEl.innerHTML = '';

    // Collecter les paramètres
    const args = {};
    document.querySelectorAll('[data-param]').forEach(el => {
        const name = el.dataset.param;
        let val = el.value;
        if (val === '' || val === null || val === undefined) return;

        // Conversion de type
        const paramDef = app.selectedTool.parameters.find(p => p.name === name);
        if (paramDef) {
            if (paramDef.type === 'integer') val = parseInt(val, 10);
            else if (paramDef.type === 'number') val = parseFloat(val);
            else if (el.dataset.type === 'boolean') val = val === 'true';
        }

        args[name] = val;
    });

    try {
        const r = await apiToolsRun(app.selectedTool.name, args);

        let statusCls, statusText;
        if (r.status === 'ok') {
            statusCls = 'success';
            statusText = '✅ Succès';
        } else {
            statusCls = 'error';
            statusText = '❌ Erreur';
        }

        const content = r.result || r.message || JSON.stringify(r);
        const formatted = fmtJson(content);

        resultEl.innerHTML = `<div class="result-panel">
            <div class="result-header">
                <span class="result-status ${statusCls}">${statusText}</span>
                ${r.duration_ms ? `<span class="result-duration">${fmtDuration(r.duration_ms)}</span>` : ''}
            </div>
            <div class="result-body">${esc(formatted)}</div>
        </div>`;

    } catch (e) {
        if (e.message !== 'Unauthorized') {
            resultEl.innerHTML = `<div class="result-panel">
                <div class="result-header"><span class="result-status error">❌ Erreur</span></div>
                <div class="result-body">${esc(e.message)}</div>
            </div>`;
        }
    } finally {
        btn.disabled = false;
        btn.innerHTML = '▶ Exécuter';
    }
}
