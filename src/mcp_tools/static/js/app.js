/**
 * MCP Tools Admin — Orchestrateur principal
 * Login → Dashboard → Navigation entre vues
 */

// ═══════════════ AUTH ═══════════════

function showLogin(msg = '') {
    document.getElementById('loginOverlay').classList.remove('hidden');
    document.getElementById('loginError').textContent = msg ? `❌ ${msg}` : '';
    document.getElementById('loginToken').focus();
}

function hideLogin() {
    document.getElementById('loginOverlay').classList.add('hidden');
}

async function doLogin() {
    const input = document.getElementById('loginToken');
    const btn = document.getElementById('loginBtn');
    const err = document.getElementById('loginError');
    const token = input.value.trim();

    if (!token) { err.textContent = '❌ Token requis.'; return; }

    btn.disabled = true;
    btn.textContent = 'Connexion…';
    err.textContent = '';

    try {
        setAuthToken(token);
        const r = await apiHealth();
        if (r.status === 'ok') {
            hideLogin();
            input.value = '';
            showToast('Connecté en tant qu\'admin', 'success');
            await initialLoad();
        } else if (r.status === 'error' && r.message?.includes('Admin')) {
            clearAuthToken();
            err.textContent = '❌ Ce token n\'a pas les droits admin.';
        } else {
            clearAuthToken();
            err.textContent = '❌ Token invalide.';
        }
    } catch (e) {
        clearAuthToken();
        if (e.message === 'Unauthorized') {
            err.textContent = '❌ Token invalide ou non-admin.';
        } else {
            err.textContent = '❌ Serveur injoignable.';
        }
    } finally {
        btn.disabled = false;
        btn.textContent = 'Se connecter';
    }
}

function doLogout() {
    clearAuthToken();
    app.health = null;
    app.tools = [];
    app.tokens = [];
    app.logs = [];
    app.selectedTool = null;
    showLogin();
}

async function checkToken() {
    const token = getAuthToken();
    if (!token) { showLogin(); return; }

    try {
        const r = await apiHealth();
        if (r.status === 'ok') {
            hideLogin();
            await initialLoad();
        } else {
            showLogin('Token expiré.');
        }
    } catch (e) {
        if (e.message === 'Unauthorized') {
            showLogin('Token invalide.');
        } else {
            showLogin('Serveur injoignable.');
        }
    }
}

// ═══════════════ NAVIGATION ═══════════════

function switchView(viewName) {
    // Mettre à jour la navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.view === viewName);
    });

    // Afficher la bonne vue
    document.querySelectorAll('.view').forEach(v => {
        v.classList.toggle('active', v.id === `view-${viewName}`);
    });

    // Charger les données de la vue
    switch (viewName) {
        case 'dashboard': loadDashboard(); break;
        case 'tools': loadTools(); break;
        case 'tokens': loadTokens(); break;
        case 'logs': loadLogs(); break;
    }
}

// ═══════════════ CHARGEMENT INITIAL ═══════════════

async function initialLoad() {
    // Charger le dashboard + liste des tools (pour tokens form)
    await loadDashboard();

    // Pré-charger la liste des tools en background
    try {
        const r = await apiToolsList();
        if (r.status === 'ok') {
            app.tools = r.tools || [];
        }
    } catch {}

    updateStatus('ok');
}

// ═══════════════ INIT ═══════════════

document.addEventListener('DOMContentLoaded', () => {
    // Login
    document.getElementById('loginBtn').addEventListener('click', doLogin);
    document.getElementById('loginToken').addEventListener('keydown', e => {
        if (e.key === 'Enter') doLogin();
    });
    document.getElementById('logoutBtn').addEventListener('click', doLogout);

    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', e => {
            e.preventDefault();
            switchView(item.dataset.view);
        });
    });

    // Modal
    document.getElementById('modalClose').addEventListener('click', hideModal);
    document.getElementById('modalOverlay').addEventListener('click', e => {
        if (e.target === e.currentTarget) hideModal();
    });

    // Escape key
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') hideModal();
    });

    // Go
    checkToken();
});
