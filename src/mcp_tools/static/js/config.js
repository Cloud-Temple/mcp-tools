/**
 * MCP Tools Admin — Configuration, état global, helpers
 */

const AUTH_TOKEN_KEY = 'mcptools_admin_token';

// État global
const app = {
    health: null,
    tools: [],
    tokens: [],
    logs: [],
    audit: [],
    selectedTool: null,
    refreshTimer: null,
    refreshInterval: 10,  // secondes
    me: null,  // infos du token courant (permissions, tool_ids, is_admin)
};

// ═══════════════ HELPERS ═══════════════

function esc(s) {
    return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function fmtTime(iso) {
    if (!iso) return '';
    try {
        return new Date(iso).toLocaleTimeString('fr-FR', {
            hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
    } catch { return iso; }
}

function fmtDate(iso) {
    if (!iso) return '—';
    try {
        return new Date(iso).toLocaleDateString('fr-FR', {
            day: '2-digit', month: '2-digit', year: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });
    } catch { return iso; }
}

function fmtDateShort(iso) {
    if (!iso) return '';
    try {
        return new Date(iso).toLocaleDateString('fr-FR', {
            day: '2-digit', month: '2-digit'
        });
    } catch { return ''; }
}

function fmtDuration(ms) {
    if (ms < 1000) return Math.round(ms) + 'ms';
    return (ms / 1000).toFixed(1) + 's';
}

function fmtJson(text) {
    try {
        const obj = JSON.parse(text);
        return JSON.stringify(obj, null, 2);
    } catch {
        return text;
    }
}

// ═══════════════ TOAST ═══════════════

function showToast(message, type = 'info') {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => { toast.remove(); }, 3500);
}

// ═══════════════ MODAL ═══════════════

function showModal(title, bodyHtml) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = bodyHtml;
    document.getElementById('modalOverlay').classList.add('visible');
}

function hideModal() {
    document.getElementById('modalOverlay').classList.remove('visible');
}

// ═══════════════ STATUS ═══════════════

function updateStatus(s) {
    const el = document.getElementById('globalStatus');
    if (!el) return;
    const dot = el.querySelector('.dot');
    const txt = el.querySelector('.status-text');
    if (s === 'ok') {
        dot.className = 'dot'; dot.style.background = '#4CAF50';
        txt.textContent = fmtTime(new Date().toISOString());
    } else if (s === 'refresh') {
        dot.className = 'dot'; dot.style.background = '#f39c12';
        txt.textContent = '…';
    } else {
        dot.className = 'dot paused'; dot.style.background = '#e74c3c';
        txt.textContent = 'erreur';
    }
}
