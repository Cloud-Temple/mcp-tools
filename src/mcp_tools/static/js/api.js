/**
 * MCP Tools Admin — API Client
 *
 * Endpoints supportés :
 *   GET  /admin/api/me             → infos token courant
 *   GET  /admin/api/health         → état serveur
 *   GET  /admin/api/tools          → liste outils
 *   POST /admin/api/tools/run      → exécuter un outil
 *   GET  /admin/api/tokens         → lister tokens
 *   POST /admin/api/tokens         → créer un token
 *   GET  /admin/api/tokens/{name}  → info token
 *   PUT  /admin/api/tokens/{name}  → modifier un token
 *   DELETE /admin/api/tokens/{name}→ révoquer un token
 *   POST /admin/api/tokens/purge   → purger les tokens expirés
 *   GET  /admin/api/logs           → logs HTTP
 *   GET  /admin/api/audit          → journal d'audit
 */

function getAuthToken() { return localStorage.getItem(AUTH_TOKEN_KEY); }
function setAuthToken(token) { localStorage.setItem(AUTH_TOKEN_KEY, token); }
function clearAuthToken() { localStorage.removeItem(AUTH_TOKEN_KEY); }

function authHeaders(extra = {}) {
    const token = getAuthToken();
    return token ? { ...extra, 'Authorization': `Bearer ${token}` } : extra;
}

/**
 * Fetch avec gestion auto du 401.
 */
async function adminFetch(url, options = {}) {
    options.headers = authHeaders(options.headers || {});

    let response;
    try {
        response = await fetch(url, options);
    } catch (e) {
        console.error(`[API] Network error: ${url}`, e);
        return { status: 'error', message: 'Erreur réseau' };
    }

    if (response.status === 401) {
        clearAuthToken();
        showLogin('Session expirée.');
        throw new Error('Unauthorized');
    }

    try {
        const text = await response.text();
        if (!text) return { status: 'error', message: 'Réponse vide' };
        return JSON.parse(text);
    } catch (e) {
        console.error(`[API] JSON parse error: ${url}`, e);
        return { status: 'error', message: 'Réponse invalide' };
    }
}

// ═══════════════ ENDPOINTS ═══════════════

async function apiMe() {
    return await adminFetch('/admin/api/me');
}

async function apiHealth() {
    return await adminFetch('/admin/api/health');
}

async function apiToolsList() {
    return await adminFetch('/admin/api/tools');
}

async function apiToolsRun(toolName, args) {
    return await adminFetch('/admin/api/tools/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool_name: toolName, arguments: args }),
    });
}

async function apiTokensList() {
    return await adminFetch('/admin/api/tokens');
}

async function apiTokensCreate(data) {
    return await adminFetch('/admin/api/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
}

async function apiTokensInfo(name) {
    return await adminFetch(`/admin/api/tokens/${encodeURIComponent(name)}`);
}

async function apiTokensUpdate(name, data) {
    return await adminFetch(`/admin/api/tokens/${encodeURIComponent(name)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
}

async function apiTokensRevoke(name) {
    return await adminFetch(`/admin/api/tokens/${encodeURIComponent(name)}`, {
        method: 'DELETE',
    });
}

async function apiTokensPurge() {
    return await adminFetch('/admin/api/tokens/purge', {
        method: 'POST',
    });
}

async function apiLogs() {
    return await adminFetch('/admin/api/logs');
}

async function apiAudit() {
    return await adminFetch('/admin/api/audit');
}
