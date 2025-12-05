// State
let authToken = localStorage.getItem('authToken') || null;
let currentUser = null;
let currentSite = null;
let currentPath = '';
let currentEditingFile = null;
let tunnelConfig = null;
let tunnelState = null;
let cachedSites = [];
let pendingTwoFactorState = null;
let editingPermissionsTarget = null;

const PAGE_METADATA = {
  dashboard: { label: 'Dashboard', subtitle: 'Overview of system health' },
  createSite: { label: 'Create Site', subtitle: 'Provision a new local site' },
  manageSites: { label: 'Manage Sites', subtitle: 'Review and update existing sites' },
  siteFiles: { label: 'Site Files', subtitle: 'Inspect and edit site files' },
  tunnel: { label: 'Cloudflare Tunnel', subtitle: 'Monitor and configure the tunnel' },
  users: { label: 'User Management', subtitle: 'Create and manage accounts' },
  settings: { label: 'Settings', subtitle: 'Account preferences and security' }
};

const uiFeedback = (() => {
  const stackId = 'toastStack';
  const overlayId = 'globalLoading';
  const overlayLabelId = 'globalLoadingLabel';
  const pendingToasts = [];

  function spawnToast(stack, message, variant, duration) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${variant}`;
    toast.setAttribute('role', 'status');
    toast.textContent = message;
    stack.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('is-visible'));
    const remove = () => {
      toast.classList.remove('is-visible');
      toast.addEventListener('transitionend', () => toast.remove(), { once: true });
    };
    toast.addEventListener('click', remove, { once: true });
    setTimeout(remove, duration);
  }

  function showToast(message, variant = 'info', { duration = 4500 } = {}) {
    if (!message) {
      return;
    }
    const stack = document.getElementById(stackId);
    if (!stack) {
      pendingToasts.push({ message, variant, duration });
      return;
    }
    spawnToast(stack, message, variant, duration);
  }

  window.addEventListener('DOMContentLoaded', () => {
    if (!pendingToasts.length) {
      return;
    }
    const stack = document.getElementById(stackId);
    if (!stack) {
      return;
    }
    pendingToasts.splice(0).forEach(toast => {
      spawnToast(stack, toast.message, toast.variant, toast.duration);
    });
  }, { once: true });

  function setGlobalLoading(active, label = 'Working...') {
    const overlay = document.getElementById(overlayId);
    if (!overlay) {
      return;
    }
    overlay.hidden = !active;
    overlay.setAttribute('aria-hidden', String(!active));
    const labelNode = document.getElementById(overlayLabelId);
    if (labelNode && label) {
      labelNode.textContent = label;
    }
  }

  return { showToast, setGlobalLoading };
})();

const notify = {
  info(message, options) {
    uiFeedback.showToast(message, 'info', options);
  },
  success(message, options) {
    uiFeedback.showToast(message, 'success', options);
  },
  error(message, options) {
    uiFeedback.showToast(message, 'error', options);
  }
};

async function withGlobalLoading(label, action) {
  uiFeedback.setGlobalLoading(true, label);
  try {
    return await action();
  } finally {
    uiFeedback.setGlobalLoading(false);
  }
}

window.nativeAlert = window.alert;
window.alert = message => {
  const normalized = typeof message === 'string' ? message : String(message ?? '');
  const lower = normalized.toLowerCase();
  let variant = 'info';
  if (/(error|fail|denied|invalid|mislukt)/i.test(lower)) {
    variant = 'error';
  } else if (/(success|saved|created|updated|gelukt)/i.test(lower) || normalized.includes('✓')) {
    variant = 'success';
  }
  notify[variant](normalized);
};

window.addEventListener('DOMContentLoaded', () => {
  setupPermissionHandlers();
  refreshSiteSelectors();
  if (authToken) {
    verifyAuth();
  }
});

function updateHeaderAccount() {
  const nameEl = document.getElementById('headerUserName');
  const roleEl = document.getElementById('headerUserRole');

  if (nameEl) {
    nameEl.textContent = currentUser ? currentUser.username : '-';
  }

  if (roleEl) {
    const role = currentUser?.role || '';
    roleEl.textContent = role ? `${role.charAt(0).toUpperCase()}${role.slice(1)}` : '-';
  }
}

function updateNavigationState(activePage) {
  document.querySelectorAll('[data-page]').forEach(btn => {
    btn.classList.toggle('is-active', btn.dataset.page === activePage);
  });

  const titleEl = document.getElementById('workspaceTitle');
  const subtitleEl = document.getElementById('workspaceSubtitle');
  const metadata = PAGE_METADATA[activePage] || {};
  const navButton = document.querySelector(`[data-page="${activePage}"]`);

  const label = navButton?.dataset.pageLabel || metadata.label;
  const subtitle = navButton?.dataset.pageSubtitle || metadata.subtitle;

  if (titleEl && label) {
    titleEl.textContent = label;
  }

  if (subtitleEl) {
    subtitleEl.textContent = subtitle || '';
  }
}

function refreshNavAvailability() {
  const siteFilesButton = document.querySelector('[data-page="siteFiles"]');
  if (siteFilesButton) {
    siteFilesButton.disabled = !currentSite;
  }

  document.querySelectorAll('.nav-link[data-permission]').forEach(btn => {
    const required = btn.dataset.permission;
    const allowed = userHasPermission(required);
    btn.style.display = allowed ? '' : 'none';
  });
}

function buildItemPath(name) {
  return currentPath ? `${currentPath}${name}` : name;
}

function formatDisplayPath(path) {
  if (!path) {
    return '/';
  }
  const trimmed = path.endsWith('/') ? path.slice(0, -1) : path;
  return `/${trimmed}`;
}

function formatDate(value) {
  if (!value) {
    return '';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '';
  }
  return date.toLocaleString();
}

function userHasPermission(permissionKey) {
  if (!currentUser) {
    return false;
  }
  if (currentUser.role === 'admin') {
    return true;
  }
  return Boolean(currentUser.permissions && currentUser.permissions[permissionKey]);
}

function userCanSeeSite(siteName) {
  if (!currentUser) {
    return false;
  }
  if (currentUser.role === 'admin') {
    return true;
  }
  const access = currentUser.permissions?.siteAccess || { mode: 'limited', sites: [] };
  if (access.mode === 'all') {
    return true;
  }
  return Array.isArray(access.sites) && access.sites.includes(siteName);
}

function userCanManageSite(siteName) {
  if (!currentUser || !userHasPermission('canManageSites')) {
    return false;
  }
  if (currentUser.role === 'admin') {
    return true;

    function openPermissionsPanel(user) {
      populatePermissionsPanel(user, true);
    }

    function populatePermissionsPanel(user, revealPanel = false) {
      const panel = document.getElementById('userPermissionsPanel');
      if (!panel) {
        return;
      }

      editingPermissionsTarget = user;

      const title = document.getElementById('permissionsPanelTitle');
      const subtitle = document.getElementById('permissionsPanelSubtitle');
      const idField = document.getElementById('permissionsUserId');
      if (title) {
        title.textContent = `Edit permissions for ${user.username}`;
      }
      if (subtitle) {
        subtitle.textContent = `Role: ${capitalize(user.role)}${user.email ? ` • ${user.email}` : ''}`;
      }
      if (idField) {
        idField.value = user.id;
      }

      const isAdmin = user.role === 'admin';
      const permissions = user.permissions || {};
      const manageSitesCheckbox = document.getElementById('editManageSites');
      const manageTunnelCheckbox = document.getElementById('editManageTunnel');
      const manageMailCheckbox = document.getElementById('editManageMail');

      if (manageSitesCheckbox) {
        manageSitesCheckbox.checked = isAdmin ? true : Boolean(permissions.canManageSites);
        manageSitesCheckbox.disabled = isAdmin;
      }
      if (manageTunnelCheckbox) {
        manageTunnelCheckbox.checked = isAdmin ? true : Boolean(permissions.canManageTunnel);
        manageTunnelCheckbox.disabled = isAdmin;
      }
      if (manageMailCheckbox) {
        manageMailCheckbox.checked = isAdmin ? true : Boolean(permissions.canManageMail);
        manageMailCheckbox.disabled = isAdmin;
      }

      const access = permissions.siteAccess || { mode: 'all', sites: [] };
      const mode = isAdmin ? 'all' : access.mode === 'limited' ? 'limited' : 'all';
      document.querySelectorAll('input[name="editSiteAccess"]').forEach(radio => {
        if (radio.value === mode) {
          radio.checked = true;
        }
        radio.disabled = isAdmin;
      });

      refreshSiteSelectors();

      const siteSelection = document.getElementById('editSiteSelection');
      if (siteSelection) {
        if (isAdmin) {
          siteSelection.innerHTML = '<p class="form-hint">Administrator accounts automatically have access to all sites.</p>';
        }
      }

      if (revealPanel) {
        panel.style.display = 'flex';
      }
    }

    function hidePermissionsPanel() {
      const panel = document.getElementById('userPermissionsPanel');
      if (panel) {
        panel.style.display = 'none';
      }
      editingPermissionsTarget = null;
      const idField = document.getElementById('permissionsUserId');
      if (idField) {
        idField.value = '';
      }
    }

    async function saveUserPermissions() {
      if (!editingPermissionsTarget) {
        return;
      }

      if (editingPermissionsTarget.role === 'admin') {
        notify.info('Administrator accounts already have full access.');
        return;
      }

      const userId = document.getElementById('permissionsUserId')?.value;
      if (!userId) {
        notify.error('Unable to determine which user to update.');
        return;
      }

      const permissions = {
        canManageSites: document.getElementById('editManageSites')?.checked || false,
        canManageTunnel: document.getElementById('editManageTunnel')?.checked || false,
        canManageMail: document.getElementById('editManageMail')?.checked || false,
        canManageUsers: false,
        siteAccess: buildSiteAccessPayload('editSiteAccess', 'editSiteSelection')
      };

      if (permissions.siteAccess.mode === 'limited' && permissions.siteAccess.sites.length === 0) {
        notify.info('Select at least one site or choose "All sites".');
        return;
      }

      try {
        const res = await authFetch(`/api/users/${userId}/permissions`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ permissions })
        });
        const data = await safeJsonParse(res);

        if (!res.ok) {
          throw new Error(data.message || 'Failed to save permissions');
        }

        notify.success(data.message || 'Permissions updated successfully');
        editingPermissionsTarget = data.user;

        if (currentUser.id === data.user.id) {
          currentUser.permissions = data.user.permissions;
          refreshNavAvailability();
        }

        loadUsers();
        refreshNavAvailability();
      } catch (err) {
        notify.error('Error saving permissions: ' + err.message);
      }
    }
  }
  const access = currentUser.permissions?.siteAccess || { mode: 'limited', sites: [] };
  if (access.mode === 'all') {
    return true;
  }
  return Array.isArray(access.sites) && access.sites.includes(siteName);
}

function userCanManageCurrentSite() {
  if (!currentSite) {
    return false;
  }
  return userCanManageSite(currentSite);
}

function setupPermissionHandlers() {
  updateSiteAccessVisibility('newUserSiteAccess', 'newUserSiteSelection');
  updateSiteAccessVisibility('editSiteAccess', 'editSiteSelection');

  document.querySelectorAll('input[name="newUserSiteAccess"]').forEach(radio => {
    radio.addEventListener('change', () => updateSiteAccessVisibility('newUserSiteAccess', 'newUserSiteSelection'));
  });

  document.querySelectorAll('input[name="editSiteAccess"]').forEach(radio => {
    radio.addEventListener('change', () => updateSiteAccessVisibility('editSiteAccess', 'editSiteSelection'));
  });
}

function updateSiteAccessVisibility(groupName, containerId) {
  const container = document.getElementById(containerId);
  if (!container) {
    return;
  }
  const selected = document.querySelector(`input[name="${groupName}"]:checked`);
  const shouldShow = selected && selected.value === 'limited';
  container.style.display = shouldShow ? 'grid' : 'none';
}

function refreshSiteSelectors() {
  const siteNames = cachedSites.map(site => site.name).sort((a, b) => a.localeCompare(b));
  const newUserSelected = new Set(collectSelectedSites('newUserSiteSelection'));
  renderSiteSelection('newUserSiteSelection', siteNames, newUserSelected);

  if (editingPermissionsTarget) {
    const currentSelection = new Set(collectSelectedSites('editSiteSelection'));
    const selectedSites = currentSelection.size
      ? currentSelection
      : new Set(editingPermissionsTarget.permissions?.siteAccess?.sites || []);
    renderSiteSelection('editSiteSelection', siteNames, selectedSites);
  } else {
    const editContainer = document.getElementById('editSiteSelection');
    if (editContainer && !editContainer.dataset.hasPlaceholder) {
      editContainer.innerHTML = '<p class="form-hint">Select a user to edit site access.</p>';
      editContainer.dataset.hasPlaceholder = 'true';
    }
  }

  updateSiteAccessVisibility('newUserSiteAccess', 'newUserSiteSelection');
  updateSiteAccessVisibility('editSiteAccess', 'editSiteSelection');
}

function renderSiteSelection(containerId, siteNames, selectedSet) {
  const container = document.getElementById(containerId);
  if (!container) {
    return;
  }

  container.dataset.hasPlaceholder = '';
  container.innerHTML = '';

  if (!siteNames.length) {
    const hint = document.createElement('p');
    hint.className = 'form-hint';
    hint.textContent = 'No sites available yet.';
    container.appendChild(hint);
    return;
  }

  siteNames.forEach(name => {
    const label = document.createElement('label');
    label.className = 'checkbox';

    const input = document.createElement('input');
    input.type = 'checkbox';
    input.value = name;
    input.checked = selectedSet.has(name);

    const span = document.createElement('span');
    span.textContent = name;

    label.append(input, span);
    container.appendChild(label);
  });
}

function collectSelectedSites(containerId) {
  const container = document.getElementById(containerId);
  if (!container) {
    return [];
  }
  return Array.from(container.querySelectorAll('input[type="checkbox"]:checked')).map(input => input.value);
}

function buildSiteAccessPayload(groupName, containerId) {
  const selected = document.querySelector(`input[name="${groupName}"]:checked`);
  const mode = selected && selected.value === 'limited' ? 'limited' : 'all';
  const sites = mode === 'limited' ? collectSelectedSites(containerId) : [];
  return { mode, sites };
}

function capitalize(value) {
  if (!value) return '';
  return value.charAt(0).toUpperCase() + value.slice(1);
}

// AUTH
async function verifyAuth() {
  try {
    const res = await fetch('/api/auth/verify', {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });

    const data = await safeJsonParse(res);
    if (res.ok && data.valid) {
      currentUser = data.user;
      showApp();
      return;
    }
  } catch (err) {
    console.error('Auth verification failed:', err);
  }
  
  authToken = null;
  localStorage.removeItem('authToken');
  showLogin();
}

function showLogin() {
  document.getElementById('loginBox').style.display = 'block';
  document.getElementById('adminApp').style.display = 'none';
  pendingTwoFactorState = null;
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.reset();
  }
  const resetForm = document.getElementById('resetFlow');
  if (resetForm) {
    resetForm.reset();
  }
  toggleResetView(false);
  resetLoginStep();
  setLoginMessage('');
}

function showApp() {
  document.getElementById('loginBox').style.display = 'none';
  document.getElementById('adminApp').style.display = 'block';
  updateHeaderAccount();
  cachedSites = [];
  refreshNavAvailability();
  
  showPage('dashboard');
  fetchSites();
}

function setLoginMessage(message, mode = 'error') {
  const el = document.getElementById('loginMessage');
  if (!el) return;
  el.textContent = message || '';
  if (mode === 'success') {
    el.classList.add('success');
  } else {
    el.classList.remove('success');
  }
}

function resetLoginStep() {
  pendingTwoFactorState = null;
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const codeInput = document.getElementById('twoFactorCode');
  const twoFactorStep = document.getElementById('twoFactorStep');
  const submitBtn = document.getElementById('loginSubmitBtn');
  const backBtn = document.getElementById('loginBackBtn');

  if (usernameInput) {
    usernameInput.disabled = false;
  }
  if (passwordInput) {
    passwordInput.disabled = false;
    passwordInput.value = '';
  }
  if (codeInput) {
    codeInput.value = '';
  }
  if (twoFactorStep) {
    twoFactorStep.style.display = 'none';
  }
  if (submitBtn) {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Sign in';
  }
  if (backBtn) {
    backBtn.style.display = 'none';
  }
}

function toggleResetView(show) {
  const loginForm = document.getElementById('loginForm');
  const resetForm = document.getElementById('resetFlow');
  if (!loginForm || !resetForm) {
    return;
  }

  if (show) {
    loginForm.style.display = 'none';
    resetForm.style.display = 'flex';
    toggleResetCompletion(false);
    resetForm.reset();
  } else {
    loginForm.style.display = 'flex';
    resetForm.style.display = 'none';
    toggleResetCompletion(false);
  }

  resetLoginStep();
  setLoginMessage('');
}

function toggleResetCompletion(show) {
  const requestStep = document.getElementById('resetRequestStep');
  const completeStep = document.getElementById('resetCompleteStep');
  const codeInput = document.getElementById('resetCode');
  const newPass = document.getElementById('resetNewPassword');
  const confirm = document.getElementById('resetConfirmPassword');

  if (!requestStep || !completeStep) {
    return;
  }

  requestStep.style.display = show ? 'none' : 'block';
  completeStep.style.display = show ? 'block' : 'none';

  if (!show) {
    if (codeInput) codeInput.value = '';
    if (newPass) newPass.value = '';
    if (confirm) confirm.value = '';
  }
}

function enterTwoFactorStep(challengeToken, expiresIn) {
  pendingTwoFactorState = {
    challengeToken,
    expiresAt: expiresIn ? Date.now() + expiresIn : null
  };

  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const twoFactorStep = document.getElementById('twoFactorStep');
  const submitBtn = document.getElementById('loginSubmitBtn');
  const backBtn = document.getElementById('loginBackBtn');
  const codeInput = document.getElementById('twoFactorCode');

  if (usernameInput) usernameInput.disabled = true;
  if (passwordInput) passwordInput.disabled = true;
  if (twoFactorStep) twoFactorStep.style.display = 'flex';
  if (submitBtn) submitBtn.textContent = 'Verify code';
  if (backBtn) backBtn.style.display = 'inline-flex';
  if (codeInput) {
    codeInput.value = '';
    codeInput.focus();
  }

  setLoginMessage('Two-factor authentication required. Enter the 6-digit code from your authenticator.', 'success');
}

async function submitLogin() {
  const submitBtn = document.getElementById('loginSubmitBtn');
  if (submitBtn) {
    submitBtn.disabled = true;
  }

  try {
    if (pendingTwoFactorState) {
      const code = document.getElementById('twoFactorCode')?.value.trim();
      if (!code || !/^\d{6}$/.test(code)) {
        setLoginMessage('Enter the 6-digit verification code.');
        return;
      }

      const res = await fetch('/api/auth/2fa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeToken: pendingTwoFactorState.challengeToken,
          code
        })
      });

      const data = await safeJsonParse(res);
      if (!res.ok) {
        throw new Error(data.message || 'Verification failed');
      }

      completeAuthentication(data);
      return;
    }

    const username = document.getElementById('username')?.value.trim();
    const password = document.getElementById('password')?.value;

    if (!username || !password) {
      setLoginMessage('Please enter username and password.');
      return;
    }

    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    const data = await safeJsonParse(res);

    if (!res.ok) {
      throw new Error(data.message || 'Wrong credentials.');
    }

    if (data.twoFactorRequired) {
      enterTwoFactorStep(data.challengeToken, data.expiresIn);
      return;
    }

    completeAuthentication(data);
  } catch (err) {
    setLoginMessage(err.message || 'Login failed. Please try again.');
    if (!pendingTwoFactorState) {
      resetLoginStep();
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
    }
  }
}

async function requestPasswordReset() {
  const identifier = document.getElementById('resetIdentifier')?.value.trim();
  if (!identifier) {
    setLoginMessage('Enter your username or email to continue.');
    return;
  }

  try {
    const res = await fetch('/api/auth/request-password-reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier })
    });

    const data = await safeJsonParse(res);
    if (!res.ok) {
      throw new Error(data.message || 'Unable to start password reset.');
    }

    setLoginMessage('If the account exists, we sent a reset email with the next steps.', 'success');
    toggleResetCompletion(true);
  } catch (err) {
    setLoginMessage(err.message || 'Unable to start password reset.');
  }
}

async function completePasswordReset() {
  const token = document.getElementById('resetCode')?.value.trim();
  const newPassword = document.getElementById('resetNewPassword')?.value;
  const confirmPassword = document.getElementById('resetConfirmPassword')?.value;

  if (!token) {
    setLoginMessage('Paste the reset code from your email.');
    return;
  }

  if (!newPassword || newPassword.length < 6) {
    setLoginMessage('Choose a password with at least 6 characters.');
    return;
  }

  if (newPassword !== confirmPassword) {
    setLoginMessage('Passwords do not match.');
    return;
  }

  try {
    const res = await fetch('/api/auth/reset-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, newPassword })
    });

    const data = await safeJsonParse(res);
    if (!res.ok) {
      throw new Error(data.message || 'Password reset failed');
    }

    completeAuthentication({ token: data.token, user: data.user });
  } catch (err) {
    setLoginMessage(err.message || 'Password reset failed.');
  }
}

function completeAuthentication(payload) {
  if (!payload || !payload.token || !payload.user) {
    throw new Error('Unexpected login response');
  }

  authToken = payload.token;
  currentUser = payload.user;
  localStorage.setItem('authToken', authToken);
  pendingTwoFactorState = null;
  toggleResetView(false);
  resetLoginStep();
  setLoginMessage('');
  showApp();
}

async function logout() {
  if (authToken) {
    await fetch('/api/auth/logout', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
  }
  
  authToken = null;
  currentUser = null;
  localStorage.removeItem('authToken');
  location.reload();
}

// Helper for authenticated requests
async function authFetch(url, options = {}) {
  if (!authToken) {
    throw new Error('Not authenticated');
  }
  
  options.headers = {
    ...options.headers,
    'Authorization': `Bearer ${authToken}`
  };
  
  const res = await fetch(url, options);
  
  if (res.status === 401) {
    logout();
    throw new Error('Session expired');
  }
  
  return res;
}

// Helper to safely parse JSON responses
async function safeJsonParse(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch (err) {
    console.error('Failed to parse JSON:', text.substring(0, 100));
    throw new Error('Server returned invalid response. Please try again.');
  }
}


// NAVIGATION
function showPage(id) {
  if (!currentUser) {
    return;
  }

  const navItem = document.querySelector(`[data-page="${id}"]`);
  const requiredPermission = navItem?.dataset.permission;
  if (requiredPermission && !userHasPermission(requiredPermission)) {
    id = 'dashboard';
  }

  if (id === 'siteFiles' && !currentSite) {
    id = 'manageSites';
  }

  document.querySelectorAll('.page').forEach(page => {
    page.style.display = 'none';
  });
  const target = document.getElementById(id);
  if (target) {
    target.style.display = 'block';
  }

  updateNavigationState(id);
  refreshNavAvailability();

  if (id === 'dashboard') loadDashboard();
  if (id === 'manageSites') fetchSites();
  if (id === 'siteFiles' && currentSite) loadFiles();
  if (id === 'tunnel') loadTunnelConfig();
  if (id === 'users') loadUsers();
  if (id === 'settings') loadSettings();
}

// DASHBOARD
async function loadDashboard() {
  try {
    const res = await authFetch('/api/status');
    const data = await res.json();
    document.getElementById('ramUsage').textContent = data.ram;
    document.getElementById('errorStatus').textContent = data.errors || "None";
    document.getElementById('tunnelStatus').textContent = data.tunnel || "Unknown";
  } catch (err) {
    document.getElementById('ramUsage').textContent = "Error loading data";
  }
  
  // Update site count
  try {
    const res = await authFetch('/api/sites');
    const data = await res.json();
    document.getElementById('siteCount').textContent = data.sites.length;
  } catch (err) {
    console.error('Error loading site count:', err);
  }
}


// CREATE SITE
async function createSite() {
  if (!userHasPermission('canManageSites')) {
    notify.error('You do not have permission to create sites.');
    return;
  }

  const access = currentUser?.permissions?.siteAccess;
  if (currentUser && currentUser.role !== 'admin' && access && access.mode !== 'all') {
    notify.error('This account cannot create new sites. Ask an administrator to upgrade your access.');
    return;
  }

  const siteName = document.getElementById('siteNameInput').value.trim();
  const port = document.getElementById('sitePortInput').value.trim();
  
  if (!siteName) {
    notify.info('Enter a site name');
    return;
  }

  const body = { siteName };
  if (port) body.port = parseInt(port);

  try {
    const res = await authFetch('/api/sites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || 'Failed to create site');
    }
    notify.success(data.message || 'Site created');
    document.getElementById('siteNameInput').value = "";
    document.getElementById('sitePortInput').value = "";
    fetchSites();
    showPage('manageSites');
  } catch (err) {
    notify.error('Error creating site: ' + err.message);
  }
}

// MANAGE SITES
async function fetchSites() {
  try {
    const res = await authFetch('/api/sites');
    const data = await safeJsonParse(res);
    if (!res.ok) {
      throw new Error(data.message || 'Failed to load sites');
    }
    const list = document.getElementById('siteList');
    if (!list) {
      return;
    }

    list.innerHTML = '';

    cachedSites = Array.isArray(data.sites) ? data.sites : [];
    refreshSiteSelectors();

    if (!cachedSites.length) {
      const empty = document.createElement('p');
      empty.className = 'no-data';
      empty.textContent = 'No sites found. Create your first site.';
      list.appendChild(empty);
      return;
    }

    const canManageSites = userHasPermission('canManageSites');

    cachedSites.forEach(site => {
      const card = document.createElement('article');
      card.className = 'site-card';

      const info = document.createElement('div');
      info.className = 'site-main';

      const name = document.createElement('div');
      name.className = 'site-name';
      name.textContent = site.name;

      const url = document.createElement('div');
      url.className = 'site-url';
      url.textContent = `http://localhost:${site.port}`;

      info.appendChild(name);
      info.appendChild(url);

      const actions = document.createElement('div');
      actions.className = 'site-actions';

      const filesBtn = document.createElement('button');
      filesBtn.className = 'btn secondary';
      filesBtn.textContent = 'Files';
      filesBtn.addEventListener('click', () => openSiteFiles(site.name));

      const openBtn = document.createElement('button');
      openBtn.className = 'btn secondary';
      openBtn.textContent = 'Open site';
      openBtn.addEventListener('click', () => openSite(site.name, site.port));

      actions.append(filesBtn, openBtn);

      if (canManageSites && userCanManageSite(site.name)) {
        const portBtn = document.createElement('button');
        portBtn.className = 'btn secondary';
        portBtn.textContent = 'Change port';
        portBtn.addEventListener('click', () => editSitePort(site.name, site.port));
        actions.appendChild(portBtn);

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn danger';
        deleteBtn.textContent = 'Delete';
        deleteBtn.addEventListener('click', () => deleteSite(site.name));
        actions.appendChild(deleteBtn);
      }

      card.append(info, actions);
      list.appendChild(card);
    });

  } catch (err) {
    console.error('Error fetching sites:', err);
    const list = document.getElementById('siteList');
    if (list) {
      list.innerHTML = `<p class="error">${err.message}</p>`;
    }
  }

}

async function deleteSite(siteName) {
  if (!userCanManageSite(siteName)) {
    notify.error('You do not have permission to delete this site.');
    return;
  }

  if (!confirm(`Delete "${siteName}"?`)) return;

  try {
    const res = await authFetch(`/api/sites/${siteName}`, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || 'Failed to delete site');
    }
    notify.success(data.message || 'Deleted');
    if (currentSite === siteName) {
      currentSite = null;
      currentPath = '';
      currentEditingFile = null;
      const editor = document.getElementById('fileEditorContainer');
      if (editor) {
        editor.style.display = 'none';
      }
      const fileList = document.getElementById('fileList');
      if (fileList) {
        fileList.innerHTML = '';
      }
      const siteNameEl = document.getElementById('currentSiteName');
      if (siteNameEl) {
        siteNameEl.textContent = '';
      }
      const pathEl = document.getElementById('currentPath');
      if (pathEl) {
        pathEl.textContent = '/';
      }
    }
    refreshNavAvailability();
    fetchSites();
  } catch (err) {
    notify.error('Error deleting site: ' + err.message);
  }
}


function openSite(siteName, port) {
  window.open(`http://localhost:${port}`, '_blank');
}

async function editSitePort(siteName, currentPort) {
  if (!userCanManageSite(siteName)) {
    notify.error('You do not have permission to modify this site.');
    return;
  }

  const newPort = prompt(`Enter new port for ${siteName}:`, currentPort);
  if (!newPort || newPort === currentPort.toString()) return;
  
  const port = parseInt(newPort);
  if (port < 1024 || port > 65535) {
    notify.info('Port must be between 1024 and 65535.');
    return;
  }

  try {
    const res = await authFetch(`/api/sites/${siteName}/port`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ port })
    });
    
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || 'Failed to update port');
    }
    notify.success(data.message || 'Port updated');
    fetchSites();
  } catch (err) {
    notify.error('Error updating port: ' + err.message);
  }
}


// FILE BROWSER
function openSiteFiles(siteName) {
  if (!userCanSeeSite(siteName)) {
    notify.error('You do not have access to this site.');
    return;
  }

  currentSite = siteName;
  currentPath = '';
  currentEditingFile = null;
  document.getElementById('currentSiteName').textContent = siteName;
  const pathEl = document.getElementById('currentPath');
  if (pathEl) {
    pathEl.textContent = '/';
  }
  const editor = document.getElementById('fileEditorContainer');
  if (editor) {
    editor.style.display = 'none';
  }
  const editorField = document.getElementById('fileEditor');
  if (editorField) {
    editorField.value = '';
  }
  refreshNavAvailability();
  showPage('siteFiles');
}

async function loadFiles() {
  if (!currentSite) return;

  const canModify = userCanManageCurrentSite();
  ['newFileButton', 'newFolderButton'].forEach(id => {
    const btn = document.getElementById(id);
    if (btn) {
      btn.disabled = !canModify;
    }
  });
  const saveBtn = document.getElementById('saveFileButton');
  if (saveBtn) {
    saveBtn.disabled = !canModify;
  }

  const pathParam = currentPath || '';

  try {
    const res = await authFetch(`/api/sites/${currentSite}/files?path=${encodeURIComponent(pathParam)}`);
    const data = await safeJsonParse(res);
    if (!res.ok) {
      throw new Error(data.message || 'Failed to load files');
    }
    const list = document.getElementById('fileList');
    if (!list) {
      return;
    }

    list.innerHTML = '';
    const pathEl = document.getElementById('currentPath');
    if (pathEl) {
      pathEl.textContent = formatDisplayPath(currentPath);
    }

    if (currentPath) {
      const backRow = document.createElement('div');
      backRow.className = 'file-row directory';

      const info = document.createElement('div');
      info.className = 'file-row-info';

      const name = document.createElement('span');
      name.className = 'file-row-name';
      name.textContent = '..';

      const meta = document.createElement('span');
      meta.className = 'file-row-meta';
      meta.textContent = 'Parent directory';

      info.append(name, meta);

      const actions = document.createElement('div');
      actions.className = 'file-row-actions';

      const upBtn = document.createElement('button');
      upBtn.className = 'btn ghost';
      upBtn.textContent = 'Go up';
      upBtn.addEventListener('click', () => navigateUp());

      actions.appendChild(upBtn);
      backRow.append(info, actions);
      list.appendChild(backRow);
    }

    if (data.type === 'directory' && Array.isArray(data.items)) {
      if (data.items.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'no-data';
        empty.textContent = 'This folder is empty.';
        list.appendChild(empty);
        return;
      }

      data.items.sort((a, b) => {
        if (a.type === b.type) return a.name.localeCompare(b.name);
        return a.type === 'directory' ? -1 : 1;
      });

      data.items.forEach(item => {
        const row = document.createElement('div');
        row.className = `file-row ${item.type}`;

        const info = document.createElement('div');
        info.className = 'file-row-info';

        const name = document.createElement('span');
        name.className = 'file-row-name';
        name.textContent = item.name;
        info.appendChild(name);

        const meta = document.createElement('span');
        meta.className = 'file-row-meta';
        if (item.type === 'file') {
          const size = typeof item.size === 'number' ? formatBytes(item.size) : '';
          const modified = item.modified ? formatDate(item.modified) : '';
          meta.textContent = [size, modified].filter(Boolean).join(' • ');
        } else {
          meta.textContent = 'Directory';
        }
        if (meta.textContent) {
          info.appendChild(meta);
        }

        const actions = document.createElement('div');
        actions.className = 'file-row-actions';

        if (item.type === 'directory') {
          const openBtn = document.createElement('button');
          openBtn.className = 'btn secondary';
          openBtn.textContent = 'Open';
          openBtn.addEventListener('click', () => navigateInto(item.name));
          actions.appendChild(openBtn);

          if (canModify) {
            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'btn danger';
            deleteBtn.textContent = 'Delete';
            deleteBtn.addEventListener('click', () => deleteFileOrFolder(item.name, item.type));
            actions.appendChild(deleteBtn);
          }
        } else {
          const editBtn = document.createElement('button');
          editBtn.className = 'btn secondary';
          editBtn.textContent = canModify ? 'Edit' : 'View';
          editBtn.addEventListener('click', () => editFile(item.name));
          actions.appendChild(editBtn);

          if (canModify) {
            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'btn danger';
            deleteBtn.textContent = 'Delete';
            deleteBtn.addEventListener('click', () => deleteFileOrFolder(item.name, item.type));
            actions.appendChild(deleteBtn);
          }
        }

        row.append(info, actions);
        list.appendChild(row);
      });
    } else {
      const empty = document.createElement('p');
      empty.className = 'no-data';
      empty.textContent = 'This folder is empty.';
      list.appendChild(empty);
    }
  } catch (err) {
    const list = document.getElementById('fileList');
    if (list) {
      list.innerHTML = `<p class="error">Error loading files: ${err.message}</p>`;
    }
  }
}


function navigateInto(dirName) {
  currentPath = currentPath ? `${currentPath}${dirName}/` : `${dirName}/`;
  loadFiles();
}

function navigateUp() {
  if (!currentPath) {
    return;
  }
  const parts = currentPath.split('/').filter(p => p);
  parts.pop();
  currentPath = parts.length ? `${parts.join('/')}/` : '';
  loadFiles();
}

async function createNewFile() {
  if (!userCanManageCurrentSite()) {
    notify.error('You do not have permission to create files in this site.');
    return;
  }

  const fileName = prompt('Enter file name:');
  if (!fileName) return;
  
  const filePath = buildItemPath(fileName);
  
  try {
    const res = await authFetch(`/api/sites/${currentSite}/files/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: filePath, type: 'file', content: '' })
    });
    
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || 'Unable to create file');
    }
    notify.success(data.message || 'File created');
    loadFiles();
  } catch (err) {
    notify.error('Error creating file: ' + err.message);
  }
}

async function createNewFolder() {
  if (!userCanManageCurrentSite()) {
    notify.error('You do not have permission to create folders in this site.');
    return;
  }

  const folderName = prompt('Enter folder name:');
  if (!folderName) return;
  
  const folderPath = buildItemPath(folderName);
  
  try {
    const res = await authFetch(`/api/sites/${currentSite}/files/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: folderPath, type: 'directory' })
    });
    
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || 'Unable to create folder');
    }
    notify.success(data.message || 'Folder created');
    loadFiles();
  } catch (err) {
    notify.error('Error creating folder: ' + err.message);
  }
}

async function deleteFileOrFolder(name, type) {
  if (!userCanManageCurrentSite()) {
    notify.error('You do not have permission to delete items in this site.');
    return;
  }

  if (!confirm(`Delete ${type === 'directory' ? 'folder' : 'file'} "${name}"?`)) return;
  
  const itemPath = buildItemPath(name);
  
  try {
    const res = await authFetch(`/api/sites/${currentSite}/files/delete?path=${encodeURIComponent(itemPath)}`, {
      method: 'DELETE'
    });
    
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || 'Failed to delete');
    }
    notify.success(data.message || 'Deleted');
    loadFiles();
  } catch (err) {
    notify.error('Error deleting: ' + err.message);
  }
}

async function editFile(fileName) {
  const filePath = buildItemPath(fileName);
  currentEditingFile = filePath;
  
  try {
    const res = await authFetch(`/api/sites/${currentSite}/files/read?path=${encodeURIComponent(filePath)}`);
    const data = await res.json();
    const editorContainer = document.getElementById('fileEditorContainer');
    if (editorContainer) {
      editorContainer.style.display = 'block';
    }
    const nameLabel = document.getElementById('editingFileName');
    if (nameLabel) {
      nameLabel.textContent = fileName;
    }
    const editorField = document.getElementById('fileEditor');
    if (editorField) {
      editorField.value = data.content;
      const canModify = userCanManageCurrentSite();
      editorField.readOnly = !canModify;
      const saveBtn = document.getElementById('saveFileButton');
      if (saveBtn) {
        saveBtn.disabled = !canModify;
        saveBtn.title = canModify ? '' : 'You do not have permission to edit this file.';
      }
    }
  } catch (err) {
    notify.error('Error loading file: ' + err.message);
  }
}

async function saveFile() {
  if (!currentEditingFile) return;

  if (!userCanManageCurrentSite()) {
    notify.error('You do not have permission to edit this file.');
    return;
  }
  
  const content = document.getElementById('fileEditor').value;
  
  try {
    const res = await authFetch(`/api/sites/${currentSite}/files/write`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: currentEditingFile, content })
    });
    
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || 'Unable to save file');
    }
    notify.success(data.message || 'File saved');
  } catch (err) {
    notify.error('Error saving file: ' + err.message);
  }
}


function closeEditor() {
  document.getElementById('fileEditorContainer').style.display = 'none';
  currentEditingFile = null;
  const editorField = document.getElementById('fileEditor');
  if (editorField) {
    editorField.value = '';
    editorField.readOnly = false;
  }
  const saveBtn = document.getElementById('saveFileButton');
  if (saveBtn) {
    saveBtn.disabled = false;
    saveBtn.title = '';
  }
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// USER MANAGEMENT
async function loadUsers() {
  if (!userHasPermission('canManageUsers')) {
    return;
  }

  try {
    const res = await authFetch('/api/users');
    const data = await safeJsonParse(res);
    if (!res.ok) {
      throw new Error(data.message || 'Failed to load users');
    }

    const list = document.getElementById('userList');
    if (!list) {
      return;
    }

    list.innerHTML = '';
    const users = Array.isArray(data.users) ? data.users : [];

    if (!users.length) {
      const empty = document.createElement('p');
      empty.className = 'no-data';
      empty.textContent = 'No users found.';
      list.appendChild(empty);
      hidePermissionsPanel();
      return;
    }

    users.forEach(user => {
      const card = document.createElement('div');
      card.className = 'user-card';

      const info = document.createElement('div');
      info.className = 'user-info';

      const name = document.createElement('div');
      name.className = 'user-name';
      name.textContent = user.username;

      const role = document.createElement('div');
      role.className = 'user-role';
      const emailPart = user.email ? ` • ${user.email}` : '';
      const twoFactorPart = user.twoFactorEnabled ? ' • 2FA enabled' : '';
      role.textContent = `${capitalize(user.role)}${emailPart}${twoFactorPart}`;

      info.append(name, role);

      const actions = document.createElement('div');
      actions.className = 'user-actions';

      const passwordBtn = document.createElement('button');
      passwordBtn.className = 'btn secondary';
      passwordBtn.textContent = 'Reset password';
      passwordBtn.addEventListener('click', () => changeUserPassword(user.id, user.username));
      actions.appendChild(passwordBtn);

      if (user.role !== 'admin' || currentUser.role === 'admin') {
        const permissionBtn = document.createElement('button');
        permissionBtn.className = 'btn secondary';
        permissionBtn.textContent = 'Edit permissions';
        permissionBtn.addEventListener('click', () => openPermissionsPanel(user));
        actions.appendChild(permissionBtn);
      }

      if ((user.username !== 'admin') && (user.id !== currentUser.id)) {
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn danger';
        deleteBtn.textContent = 'Delete';
        deleteBtn.addEventListener('click', () => deleteUser(user.id));
        actions.appendChild(deleteBtn);
      }

      card.append(info, actions);
      list.appendChild(card);
    });

    if (editingPermissionsTarget) {
      const updated = users.find(u => u.id === editingPermissionsTarget.id);
      if (updated) {
        populatePermissionsPanel(updated);
      } else {
        hidePermissionsPanel();
      }
    }
  } catch (err) {
    console.error('Error loading users:', err);
    const list = document.getElementById('userList');
    if (list) {
      list.innerHTML = `<p class="error">${err.message}</p>`;
    }
  }
}

async function createUser() {
  if (!userHasPermission('canManageUsers')) {
    notify.error('You do not have permission to create users.');
    return;
  }

  const username = document.getElementById('newUsername').value.trim();
  const password = document.getElementById('newPassword').value.trim();
  const role = document.getElementById('newUserRole').value;
  const email = document.getElementById('newUserEmail').value.trim();
  
  if (!username || !password) {
    notify.info('Username and password required');
    return;
  }

  const permissions = {
    canManageSites: document.getElementById('newUserManageSites')?.checked || false,
    canManageTunnel: document.getElementById('newUserManageTunnel')?.checked || false,
    canManageMail: document.getElementById('newUserManageMail')?.checked || false,
    canManageUsers: role === 'admin',
    siteAccess: buildSiteAccessPayload('newUserSiteAccess', 'newUserSiteSelection')
  };

  if (role === 'admin') {
    permissions.siteAccess = { mode: 'all', sites: [] };
    permissions.canManageSites = true;
    permissions.canManageTunnel = true;
    permissions.canManageMail = true;
  } else if (permissions.siteAccess.mode === 'limited' && permissions.siteAccess.sites.length === 0) {
    notify.info('Select at least one site or choose "All sites".');
    return;
  }
  
  try {
    const res = await authFetch('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, role, email, permissions })
    });
    
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || 'Failed to create user');
    }
    notify.success(data.message || 'User created');
    document.getElementById('newUsername').value = '';
    document.getElementById('newPassword').value = '';
    document.getElementById('newUserEmail').value = '';
  document.getElementById('newUserRole').value = 'user';
    document.getElementById('newUserManageSites').checked = true;
    document.getElementById('newUserManageTunnel').checked = false;
    document.getElementById('newUserManageMail').checked = false;
    document.querySelectorAll('input[name="newUserSiteAccess"]').forEach(radio => {
      radio.checked = radio.value === 'all';
    });
    refreshSiteSelectors();
    loadUsers();
  } catch (err) {
    notify.error('Error creating user: ' + err.message);
  }
}

async function changeUserPassword(userId, username) {
  const newPassword = prompt(`Enter new password for ${username}:`);
  if (!newPassword) return;
  
  try {
    const res = await authFetch(`/api/users/${userId}/password`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ newPassword })
    });
    
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || 'Failed to update password');
    }
    notify.success(data.message || 'Password updated');
  } catch (err) {
    notify.error('Error updating password: ' + err.message);
  }
}

async function deleteUser(userId) {
  if (!confirm('Delete this user?')) return;
  
  try {
    const res = await authFetch(`/api/users/${userId}`, {
      method: 'DELETE'
    });
    
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || 'Failed to delete user');
    }
    notify.success(data.message || 'User deleted');
    loadUsers();
  } catch (err) {
    notify.error('Error deleting user: ' + err.message);
  }
}

// SETTINGS
function loadSettings() {
  if (currentUser) {
    document.getElementById('currentUsername').textContent = currentUser.username;
    document.getElementById('currentUserRole').textContent = currentUser.role;
    document.getElementById('currentUserEmail').textContent = currentUser.email || 'Not set';
    document.getElementById('newEmail').value = currentUser.email || '';
    
    // Load 2FA status
    load2FAStatus();

    const mailPanel = document.getElementById('mailConfigPanel');
    if (mailPanel) {
      if (userHasPermission('canManageMail')) {
        mailPanel.style.display = 'flex';
        loadMailConfig();
      } else {
        mailPanel.style.display = 'none';
      }
    }
  }
}

async function changeOwnPassword() {
  const newPassword = document.getElementById('newOwnPassword').value.trim();
  const confirmPassword = document.getElementById('confirmOwnPassword').value.trim();
  
  if (!newPassword || !confirmPassword) {
    notify.info('Please fill in both password fields');
    return;
  }
  
  if (newPassword !== confirmPassword) {
    notify.info('Passwords do not match');
    return;
  }
  
  if (newPassword.length < 6) {
    notify.info('Password must be at least 6 characters');
    return;
  }
  
  try {
    const res = await authFetch(`/api/users/${currentUser.id}/password`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ newPassword })
    });
    
    const data = await safeJsonParse(res);
    notify.success(data.message || 'Password updated. Please log in again.');
    document.getElementById('newOwnPassword').value = '';
    document.getElementById('confirmOwnPassword').value = '';
    logout();
  } catch (err) {
    notify.error('Error updating password: ' + err.message);
  }
}

async function changeOwnEmail() {
  const newEmail = document.getElementById('newEmail').value.trim();
  
  try {
    const res = await authFetch(`/api/users/${currentUser.id}/email`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: newEmail })
    });
    
    const data = await safeJsonParse(res);
    if (!res.ok) {
      throw new Error(data.message || 'Failed to update email');
    }
    
    notify.success(data.message || 'Email updated successfully');
    currentUser.email = newEmail;
    document.getElementById('currentUserEmail').textContent = newEmail || 'Not set';
  } catch (err) {
    notify.error('Error updating email: ' + err.message);
  }
}

async function loadMailConfig() {
  if (!userHasPermission('canManageMail')) {
    return;
  }

  try {
    const res = await authFetch('/api/mail/config');
    const data = await safeJsonParse(res);
    
    if (!res.ok) {
      console.error('Failed to load mail config');
      return;
    }
    
    document.getElementById('mailEnabled').checked = data.enabled || false;
    document.getElementById('mailHost').value = data.host || '';
    document.getElementById('mailPort').value = data.port || 587;
    document.getElementById('mailSecure').checked = data.secure || false;
    document.getElementById('mailUser').value = data.auth?.user || '';
    document.getElementById('mailFrom').value = data.from || '';
    document.getElementById('mailAppUrl').value = data.appUrl || '';
    document.getElementById('mailAlertDowntime').checked = data.alerts?.downtime !== false;
    // Don't load password for security
  } catch (err) {
    console.error('Error loading mail config:', err);
  }
}

async function saveMailConfig() {
  if (!userHasPermission('canManageMail')) {
    notify.error('You do not have permission to update mail settings.');
    return;
  }

  try {
    const config = {
      enabled: document.getElementById('mailEnabled').checked,
      host: document.getElementById('mailHost').value.trim(),
      port: parseInt(document.getElementById('mailPort').value) || 587,
      secure: document.getElementById('mailSecure').checked,
      auth: {
        user: document.getElementById('mailUser').value.trim(),
        pass: document.getElementById('mailPassword').value
      },
      from: document.getElementById('mailFrom').value.trim(),
      appUrl: document.getElementById('mailAppUrl').value.trim(),
      alerts: {
        downtime: document.getElementById('mailAlertDowntime').checked
      }
    };
    
    const res = await authFetch('/api/mail/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    });
    
    const data = await safeJsonParse(res);
    
    if (!res.ok) {
      throw new Error(data.message || 'Failed to save mail configuration');
    }
    
    notify.success(data.message || 'Mail configuration saved successfully');
    document.getElementById('mailPassword').value = ''; // Clear password field
  } catch (err) {
    notify.error('Error saving mail configuration: ' + err.message);
  }
}

// 2FA Functions
async function load2FAStatus() {
  try {
    const res = await authFetch(`/api/users/${currentUser.id}`);
    const data = await safeJsonParse(res);
    
    if (!res.ok) {
      console.error('Failed to load user details');
      return;
    }
    
    const enabled = data.twoFactorEnabled || false;
  currentUser.twoFactorEnabled = enabled;
    document.getElementById('twoFactorStatus').textContent = enabled ? '✓ Enabled' : '✗ Disabled';
    document.getElementById('twoFactorStatus').style.color = enabled ? 'green' : 'gray';
    
    document.getElementById('twoFactorDisabled').style.display = enabled ? 'none' : 'block';
    document.getElementById('twoFactorEnabled').style.display = enabled ? 'block' : 'none';
    document.getElementById('twoFactorSetup').style.display = 'none';
  } catch (err) {
    console.error('Error loading 2FA status:', err);
  }
}

async function setup2FA() {
  try {
    const res = await authFetch(`/api/users/${currentUser.id}/2fa/setup`, {
      method: 'POST'
    });
    
    const data = await safeJsonParse(res);
    
    if (!res.ok) {
      throw new Error(data.message || 'Failed to setup 2FA');
    }
    
    document.getElementById('qrCodeImage').src = data.qrCode;
    document.getElementById('twoFactorSecret').textContent = data.secret;
    document.getElementById('twoFactorDisabled').style.display = 'none';
    document.getElementById('twoFactorSetup').style.display = 'block';
  } catch (err) {
    notify.error('Error setting up 2FA: ' + err.message);
  }
}

async function verify2FA() {
  const token = document.getElementById('verifyToken').value.trim();
  
  if (!token || token.length !== 6) {
    notify.info('Please enter a valid 6-digit code');
    return;
  }
  
  try {
    const res = await authFetch(`/api/users/${currentUser.id}/2fa/enable`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });
    
    const data = await safeJsonParse(res);
    
    if (!res.ok) {
      throw new Error(data.message || 'Failed to enable 2FA');
    }
    
    notify.success(data.message || '2FA enabled successfully!');
    document.getElementById('verifyToken').value = '';
    load2FAStatus();
  } catch (err) {
    notify.error('Error verifying 2FA: ' + err.message);
  }
}

function cancel2FASetup() {
  document.getElementById('verifyToken').value = '';
  load2FAStatus();
}

async function disable2FA() {
  const token = document.getElementById('disable2FAToken').value.trim();
  
  if (!token || token.length !== 6) {
    notify.info('Please enter a valid 6-digit code');
    return;
  }
  
  if (!confirm('Are you sure you want to disable 2FA? This will reduce your account security.')) {
    return;
  }
  
  try {
    const res = await authFetch(`/api/users/${currentUser.id}/2fa/disable`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });
    
    const data = await safeJsonParse(res);
    
    if (!res.ok) {
      throw new Error(data.message || 'Failed to disable 2FA');
    }
    
    notify.success(data.message || '2FA disabled successfully');
    document.getElementById('disable2FAToken').value = '';
    load2FAStatus();
  } catch (err) {
    notify.error('Error disabling 2FA: ' + err.message);
  }
}


// TUNNEL
async function startTunnel() {
  await withGlobalLoading('Starting tunnel...', async () => {
    try {
      const res = await authFetch('/api/tunnel/start', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || 'Tunnel kon niet starten');
      }
      notify.success(data.message || 'Tunnel started');
      tunnelState = { ...(tunnelState || {}), ...data };
      updateTunnelStatus(tunnelState);
      await loadDashboard();
    } catch (err) {
      notify.error('Error starting tunnel: ' + err.message);
      tunnelState = { ...(tunnelState || {}), running: false, lastError: err.message };
      updateTunnelStatus(tunnelState);
      throw err;
    }
  });
}

async function stopTunnel() {
  await withGlobalLoading('Stopping tunnel...', async () => {
    try {
      const res = await authFetch('/api/tunnel/stop', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || 'Failed to stop tunnel');
      }
      notify.success(data.message || 'Tunnel stopped');
      tunnelState = { ...(tunnelState || {}), running: false, lastError: null };
      updateTunnelStatus(tunnelState);
      await loadDashboard();
    } catch (err) {
      notify.error('Error stopping tunnel: ' + err.message);
      throw err;
    }
  });
}

async function loadTunnelConfig() {
  try {
    const res = await authFetch('/api/tunnel/config');
    if (!res.ok) {
      throw new Error('Kon tunnelconfig niet ophalen');
    }

    const data = await res.json();
  tunnelState = data;
    tunnelConfig = data && data.config ? data.config : { ingress: [] };
    if (!Array.isArray(tunnelConfig.ingress)) {
      tunnelConfig.ingress = [];
    }

    document.getElementById('tunnelId').value = tunnelConfig.tunnel || '';
    document.getElementById('credentialsFile').value = tunnelConfig['credentials-file'] || '';

    updateTunnelStatus(data);
    updateTunnelTokenUI(data.token);
    renderIngressRules();
  } catch (err) {
    console.error('Error loading tunnel config:', err);
    updateTunnelStatus({ running: false, lastError: err.message });
  }
}

function updateTunnelStatus(state) {
  const statusChip = document.getElementById('tunnelStatusChip');
  const modeChip = document.getElementById('tunnelModeChip');
  const errorChip = document.getElementById('tunnelErrorChip');

  if (!statusChip || !modeChip || !errorChip) {
    return;
  }

  const running = Boolean(state && state.running);
  const mode = state && state.mode ? state.mode : 'none';
  const lastError = state && state.lastError ? state.lastError : null;
  statusChip.textContent = running ? 'Status: Running' : 'Status: Stopped';
  statusChip.className = `status-pill ${running ? 'running' : 'stopped'}`;

  const modeLabel = mode === 'token' ? 'Token' : mode === 'config' ? 'Config file' : 'Not configured';
  modeChip.textContent = `Mode: ${modeLabel}`;
  modeChip.className = 'status-pill mode';

  if (lastError) {
    errorChip.style.display = 'inline-flex';
    errorChip.className = 'status-pill alert';
    errorChip.textContent = `Last error: ${lastError}`;
  } else {
    errorChip.style.display = 'none';
    errorChip.textContent = '';
  }
}

function updateTunnelTokenUI(tokenInfo) {
  const statusEl = document.getElementById('tunnelTokenStatus');
  const clearBtn = document.getElementById('clearTunnelTokenBtn');
  const input = document.getElementById('tunnelTokenInput');

  if (!statusEl || !clearBtn || !input) {
    return;
  }

  const configured = tokenInfo && tokenInfo.configured;
  if (configured) {
    clearBtn.style.display = 'inline-flex';
    statusEl.textContent = `Huidige token: ${tokenInfo.masked || '••••'}`;
  } else {
    clearBtn.style.display = 'none';
    statusEl.textContent = 'Geen token geconfigureerd.';
  }

  input.value = '';
}

async function saveTunnelToken() {
  const token = document.getElementById('tunnelTokenInput').value;

  if (!token || !token.trim()) {
    notify.info('Voer een geldige Cloudflare token in.');
    return;
  }

  try {
    const res = await authFetch('/api/tunnel/token', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });

    const data = await safeJsonParse(res);

    if (!res.ok) {
      throw new Error(data.message || 'Token opslaan mislukt');
    }

    notify.success(data.message || 'Token opgeslagen');
    loadTunnelConfig();
    loadDashboard();
  } catch (err) {
    notify.error('Error saving token: ' + err.message);
  }
}

async function clearTunnelToken() {
  if (!confirm('Weet je zeker dat je de token wilt verwijderen?')) {
    return;
  }

  try {
    const res = await authFetch('/api/tunnel/token', { method: 'DELETE' });
    const data = await safeJsonParse(res);
    
    if (!res.ok) {
      throw new Error(data.message || 'Token verwijderen mislukt');
    }

    notify.success(data.message || 'Token verwijderd');
    loadTunnelConfig();
    loadDashboard();
  } catch (err) {
    notify.error('Error removing token: ' + err.message);
  }
}

function renderIngressRules() {
  const list = document.getElementById('ingressList');
  if (!list) {
    return;
  }

  list.innerHTML = '';
  
  if (!tunnelConfig || !Array.isArray(tunnelConfig.ingress)) {
    tunnelConfig = { ingress: [] };
  }

  if (tunnelConfig.ingress.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'no-data';
    empty.textContent = 'No ingress rules configured.';
    list.appendChild(empty);
    return;
  }

  tunnelConfig.ingress.forEach((rule, idx) => {
    const row = document.createElement('div');
    row.className = 'ingress-rule';

    const hostInput = document.createElement('input');
    hostInput.type = 'text';
    hostInput.placeholder = 'Hostname (optional)';
    hostInput.value = rule.hostname || '';
    hostInput.addEventListener('change', event => updateIngressRule(idx, 'hostname', event.target.value));

    const serviceInput = document.createElement('input');
    serviceInput.type = 'text';
    serviceInput.placeholder = 'Service (e.g., http://localhost:8080)';
    serviceInput.value = rule.service || '';
    serviceInput.addEventListener('change', event => updateIngressRule(idx, 'service', event.target.value));

    const removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.className = 'btn ghost';
    removeBtn.textContent = 'Remove';
    removeBtn.addEventListener('click', () => removeIngressRule(idx));

    row.append(hostInput, serviceInput, removeBtn);
    list.appendChild(row);
  });
}

function addIngressRule() {
  if (!tunnelConfig) tunnelConfig = { ingress: [] };
  if (!tunnelConfig.ingress) tunnelConfig.ingress = [];
  
  tunnelConfig.ingress.push({ hostname: '', service: '' });
  renderIngressRules();
}

function removeIngressRule(idx) {
  tunnelConfig.ingress.splice(idx, 1);
  renderIngressRules();
}

function updateIngressRule(idx, field, value) {
  if (field === 'hostname' && !value) {
    delete tunnelConfig.ingress[idx].hostname;
  } else {
    tunnelConfig.ingress[idx][field] = value;
  }
}

async function saveTunnelConfig() {
  if (!tunnelConfig) {
    tunnelConfig = { ingress: [] };
  }

  tunnelConfig.tunnel = document.getElementById('tunnelId').value;
  tunnelConfig['credentials-file'] = document.getElementById('credentialsFile').value;
  
  try {
    const res = await authFetch('/api/tunnel/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(tunnelConfig)
    });
    
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || 'Kon configuratie niet opslaan');
    }

    notify.success(data.message || 'Configuration saved');
  } catch (err) {
    notify.error('Error saving config: ' + err.message);
  }
}
