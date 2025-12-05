const express = require('express');
const fs = require('fs');
const path = require('path');
const os = require('os');
const compression = require('compression');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const tunnel = require('./tunnel');
const provisioner = require('./provisioner');
const auth = require('./auth');
const mailConfig = require('./mailConfig');
const mailer = require('./mailer');
const app = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

const STATIC_CACHE_MAX_AGE = provisioner.isDevelopment ? 0 : 1000 * 60 * 60 * 6; // 6 hours
const JSON_BODY_LIMIT = '1mb';
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024; // 2MB cap for in-browser editor
const SITE_NAME_PATTERN = /^[a-z0-9](?:[a-z0-9-_.]{0,62}[a-z0-9])?$/i;
const SITES_ROOT = provisioner.SITES_DIR;

let lastKnownTunnelState = tunnel.isRunning();

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(cors());
app.use(compression());
app.use(express.json({ limit: JSON_BODY_LIMIT }));
app.use(express.urlencoded({ extended: true, limit: JSON_BODY_LIMIT }));
app.use(morgan(provisioner.isDevelopment ? 'dev' : 'combined'));
app.use(express.static('public', {
  maxAge: STATIC_CACHE_MAX_AGE,
  setHeaders(res, servedPath) {
    if (servedPath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

function createHttpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

function normalizeSiteName(value, { strict = false } = {}) {
  if (typeof value !== 'string') {
    throw createHttpError(400, 'Site name is required');
  }
  const trimmed = value.trim();
  if (!trimmed) {
    throw createHttpError(400, 'Site name is required');
  }
  if (trimmed.includes('\0') || trimmed.includes('..') || /[\\/]/.test(trimmed)) {
    throw createHttpError(400, 'Site name contains invalid characters');
  }
  if (strict && !SITE_NAME_PATTERN.test(trimmed)) {
    throw createHttpError(400, 'Site names may use letters, numbers, "-", "_" or "." and must start/end with a letter or number.');
  }
  return trimmed;
}

function resolveSitePath(siteName, targetPath = '') {
  const safeSite = normalizeSiteName(siteName);
  const siteRoot = path.join(SITES_ROOT, safeSite);
  const normalizedTarget = targetPath ? path.normalize(targetPath) : '';
  const candidate = path.normalize(path.join(siteRoot, normalizedTarget));
  if (!candidate.startsWith(siteRoot)) {
    throw createHttpError(403, 'Access denied');
  }
  return candidate;
}

function coercePort(value) {
  const numeric = Number(value);
  if (!Number.isInteger(numeric) || numeric < 1024 || numeric > 65535) {
    return null;
  }
  return numeric;
}

function findNextAvailablePort() {
  const usedPorts = new Set((sites || []).map(entry => Number(entry.port)).filter(Number.isFinite));
  let candidate = usedPorts.size ? Math.max(...usedPorts) + 1 : 8080;
  if (candidate < 8080) {
    candidate = 8080;
  }
  while (usedPorts.has(candidate) && candidate <= 65535) {
    candidate += 1;
  }
  return candidate <= 65535 ? candidate : null;
}

const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ message: 'Too many authentication attempts. Please try again in a few minutes.' })
});

const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ message: 'Too many reset attempts. Wait a few minutes and retry.' })
});

// Authentication middleware
function requireAuth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  const session = auth.verifySession(token);
  
  if (!session) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const user = auth.getUserById(session.userId);
  if (!user) {
    auth.logout(token);
    return res.status(401).json({ message: 'Unauthorized' });
  }

  req.authToken = token;
  req.session = session;
  req.user = {
    ...user,
    userId: user.id,
    permissions: user.permissions || {}
  };
  next();
}

// Admin middleware
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
}

function userHasPermission(user, permissionKey) {
  if (!user) return false;
  if (user.role === 'admin') return true;
  return Boolean(user.permissions?.[permissionKey]);
}

function requirePermission(permissionKey) {
  return (req, res, next) => {
    if (userHasPermission(req.user, permissionKey)) {
      return next();
    }
    return res.status(403).json({ message: 'Access denied' });
  };
}

function userCanAccessSite(user, siteName) {
  if (!user || !siteName) return false;
  if (user.role === 'admin') return true;

  const access = user.permissions?.siteAccess || { mode: 'limited', sites: [] };
  if (access.mode === 'all') {
    return true;
  }

  return Array.isArray(access.sites) && access.sites.includes(siteName);
}

function userCanManageSite(user, siteName) {
  if (!user) return false;
  if (user.role === 'admin') return true;
  if (!user.permissions?.canManageSites) return false;
  return userCanAccessSite(user, siteName);
}

function ensureSiteReadAccess(req, res, next) {
  try {
    const siteName = normalizeSiteName(req.params.name || req.body.siteName);
    if (!userCanAccessSite(req.user, siteName)) {
      return res.status(403).json({ message: 'Access denied for this site' });
    }
    req.siteName = siteName;
    next();
  } catch (err) {
    res.status(err.status || 400).json({ message: err.message });
  }
}

function ensureSiteManageAccess(req, res, next) {
  try {
    const siteName = normalizeSiteName(req.params.name || req.body.siteName);
    if (!userCanManageSite(req.user, siteName)) {
      return res.status(403).json({ message: 'Management access denied for this site' });
    }
    req.siteName = siteName;
    next();
  } catch (err) {
    res.status(err.status || 400).json({ message: err.message });
  }
}

async function notifyTunnelState(running, meta = {}) {
  lastKnownTunnelState = running;
  try {
    await mailer.notifyTunnelStatusChange({ running, ...meta });
  } catch (err) {
    console.error('Tunnel notification error:', err.message);
  }
}

function scheduleTunnelMonitor() {
  setInterval(async () => {
    try {
      const running = tunnel.isRunning();
      if (running !== lastKnownTunnelState) {
        await notifyTunnelState(running);
      }
    } catch (err) {
      console.error('Tunnel monitor check failed:', err.message);
    }
  }, 60 * 1000);
}

// In-memory "DB"
const SITES_FILE = path.join(__dirname, 'sites.json');

function normalizeSite(entry, idx) {
  if (!entry) {
    return null;
  }

  if (typeof entry === 'string') {
    return { name: entry, port: 8080 + idx };
  }

  const name = typeof entry.name === 'string' && entry.name.trim() ? entry.name.trim() : `site-${idx + 1}`;
  const port = Number(entry.port) || 8080 + idx;

  return { name, port };
}

function loadSitesFromDisk() {
  try {
    if (!fs.existsSync(SITES_FILE)) {
      fs.writeFileSync(SITES_FILE, '[]', 'utf8');
      return [];
    }

    const data = JSON.parse(fs.readFileSync(SITES_FILE, 'utf8'));
    const list = Array.isArray(data) ? data : Object.values(data || {});
    return list
      .map((entry, idx) => normalizeSite(entry, idx))
      .filter(Boolean);
  } catch (err) {
    console.error('Failed to load sites file:', err);
    return [];
  }
}

function persistSites() {
  try {
    fs.writeFileSync(SITES_FILE, JSON.stringify(sites, null, 2));
  } catch (err) {
    console.error('Failed to persist sites:', err);
  }
}

function getSitesResponse() {
  return sites.map((entry, idx) => normalizeSite(entry, idx)).filter(Boolean);
}

let sites = loadSitesFromDisk();
persistSites();

// Authentication endpoints
app.post('/api/auth/login', authLimiter, (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }
  
  try {
    const result = auth.authenticate(username, password);
    
    if (!result) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    res.json(result);
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Login failed' });
  }
});

app.post('/api/auth/2fa/verify', authLimiter, (req, res) => {
  const { challengeToken, code } = req.body || {};

  if (!challengeToken || !code) {
    return res.status(400).json({ message: 'Challenge token and verification code are required' });
  }

  try {
    const result = auth.completeTwoFactor(challengeToken, code);
    res.json(result);
  } catch (err) {
    console.error('2FA verification error:', err);
    res.status(400).json({ message: err.message || 'Verification failed' });
  }
});

app.post('/api/auth/request-password-reset', passwordResetLimiter, async (req, res) => {
  const { identifier } = req.body || {};

  try {
    const { token, user } = auth.initiatePasswordReset(identifier);
    await mailer.sendPasswordResetEmail({
      to: user.email,
      username: user.username,
      token
    });

    res.json({ message: 'Password reset email sent if the account exists.' });
  } catch (err) {
    console.error('Error initiating password reset:', err.message);
    res.status(400).json({ message: err.message });
  }
});

app.get('/api/auth/reset/validate', (req, res) => {
  const { token } = req.query;
  try {
    const user = auth.validatePasswordResetToken(token);
    if (!user) {
      return res.status(404).json({ valid: false });
    }
    res.json({ valid: true, user });
  } catch (err) {
    console.error('Error validating reset token:', err.message);
    res.status(400).json({ message: err.message });
  }
});

app.post('/api/auth/reset-password', passwordResetLimiter, (req, res) => {
  const { token, newPassword } = req.body || {};

  if (!token || !newPassword) {
    return res.status(400).json({ message: 'Token and new password are required' });
  }

  if (typeof newPassword !== 'string' || newPassword.trim().length < 8) {
    return res.status(400).json({ message: 'Choose a password with at least 8 characters.' });
  }

  try {
    const result = auth.resetPasswordWithToken(token, newPassword.trim());
    res.json({ message: 'Password reset successfully', ...result });
  } catch (err) {
    console.error('Error resetting password:', err.message);
    res.status(400).json({ message: err.message });
  }
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  auth.logout(token);
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/auth/verify', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  const session = auth.verifySession(token);
  
  if (!session) {
    return res.status(401).json({ valid: false });
  }
  
  // Get full user details to include email
  const user = auth.getUserById(session.userId);
  if (!user) {
    return res.status(401).json({ valid: false });
  }
  
  res.json({
    valid: true,
    user: {
      id: user.id,
      username: user.username,
      email: user.email || '',
      role: user.role,
      twoFactorEnabled: user.twoFactorEnabled,
      permissions: user.permissions
    }
  });
});

// User management endpoints
app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  try {
    const users = auth.getAllUsers();
    res.json({ users });
  } catch (err) {
    console.error('Error getting users:', err);
    res.status(500).json({ message: 'Failed to get users' });
  }
});

app.post('/api/users', requireAuth, requireAdmin, (req, res) => {
  const { username, password, role, email, permissions } = req.body || {};
  
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }
  
  try {
    const user = auth.createUser({ username, password, role: role || 'user', email, permissions });
    res.json({ message: 'User created successfully', user });
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(400).json({ message: err.message });
  }
});

app.put('/api/users/:userId/password', requireAuth, (req, res) => {
  const { userId } = req.params;
  const { newPassword } = req.body;
  
  if (!newPassword) {
    return res.status(400).json({ message: 'New password required' });
  }
  
  // Users can change their own password, admins can change any password
  if (req.user.id !== userId && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied' });
  }
  
  try {
    auth.updatePassword(userId, newPassword);
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Error updating password:', err);
    res.status(400).json({ message: err.message });
  }
});

app.put('/api/users/:userId/email', requireAuth, (req, res) => {
  const { userId } = req.params;
  const { email } = req.body;
  
  if (email === undefined) {
    return res.status(400).json({ message: 'Email is required' });
  }
  
  // Users can change their own email, admins can change any email
  if (req.user.id !== userId && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied' });
  }
  
  try {
    auth.updateEmail(userId, email);
    res.json({ message: 'Email updated successfully' });
  } catch (err) {
    console.error('Error updating email:', err);
    res.status(400).json({ message: err.message });
  }
});

app.put('/api/users/:userId/permissions', requireAuth, requireAdmin, (req, res) => {
  const { userId } = req.params;
  const { permissions } = req.body || {};

  try {
    const user = auth.updatePermissions(userId, permissions);
    res.json({ message: 'Permissions updated successfully', user });
  } catch (err) {
    console.error('Error updating permissions:', err);
    res.status(400).json({ message: err.message });
  }
});

app.get('/api/users/:userId', requireAuth, (req, res) => {
  const { userId } = req.params;
  
  // Users can view their own profile, admins can view any profile
  if (req.user.id !== userId && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied' });
  }
  
  try {
    const user = auth.getUserById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    console.error('Error getting user:', err);
    res.status(400).json({ message: err.message });
  }
});

// 2FA endpoints
app.post('/api/users/:userId/2fa/setup', requireAuth, (req, res) => {
  const { userId } = req.params;
  
  // Users can only setup 2FA for themselves
  if (req.user.id !== userId) {
    return res.status(403).json({ message: 'Access denied' });
  }
  
  try {
    const setup = auth.setup2FA(userId);
    
    // Generate QR code
    auth.generateQRCode(setup.qrCode).then(qrDataUrl => {
      res.json({
        secret: setup.secret,
        qrCode: qrDataUrl
      });
    }).catch(err => {
      res.status(500).json({ message: 'Failed to generate QR code' });
    });
  } catch (err) {
    console.error('Error setting up 2FA:', err);
    res.status(400).json({ message: err.message });
  }
});

app.post('/api/users/:userId/2fa/enable', requireAuth, (req, res) => {
  const { userId } = req.params;
  const { token } = req.body;
  
  // Users can only enable 2FA for themselves
  if (req.user.id !== userId) {
    return res.status(403).json({ message: 'Access denied' });
  }
  
  if (!token) {
    return res.status(400).json({ message: 'Verification token required' });
  }
  
  try {
    auth.enable2FA(userId, token);
    res.json({ message: '2FA enabled successfully' });
  } catch (err) {
    console.error('Error enabling 2FA:', err);
    res.status(400).json({ message: err.message });
  }
});

app.post('/api/users/:userId/2fa/disable', requireAuth, (req, res) => {
  const { userId } = req.params;
  const { token } = req.body;
  
  // Users can only disable 2FA for themselves
  if (req.user.id !== userId) {
    return res.status(403).json({ message: 'Access denied' });
  }
  
  if (!token) {
    return res.status(400).json({ message: 'Verification token required' });
  }
  
  // Verify token before disabling
  if (!auth.verify2FA(userId, token)) {
    return res.status(400).json({ message: 'Invalid verification code' });
  }
  
  try {
    auth.disable2FA(userId);
    res.json({ message: '2FA disabled successfully' });
  } catch (err) {
    console.error('Error disabling 2FA:', err);
    res.status(400).json({ message: err.message });
  }
});

app.delete('/api/users/:userId', requireAuth, requireAdmin, (req, res) => {
  const { userId } = req.params;
  
  try {
    auth.deleteUser(userId);
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(400).json({ message: err.message });
  }
});

// Get status
app.get('/api/status', requireAuth, (req, res) => {
  const total = os.totalmem() / 1024 / 1024;
  const free = os.freemem() / 1024 / 1024;
  const used = total - free;

  res.json({
    ram: `${used.toFixed(1)} / ${total.toFixed(1)} MB`,
    errors: null,
    tunnel: tunnel.isRunning() ? 'Running' : 'Stopped'
  });
});

// Get sites
app.get('/api/sites', requireAuth, (req, res) => {
  const siteList = getSitesResponse();

  if (req.user.role === 'admin' || req.user.permissions?.siteAccess?.mode === 'all') {
    return res.json({ sites: siteList });
  }

  const allowed = new Set(req.user.permissions?.siteAccess?.sites || []);
  const filtered = siteList.filter(site => allowed.has(site.name));
  res.json({ sites: filtered });
});

// Add site
app.post('/api/sites', requireAuth, requirePermission('canManageSites'), (req, res) => {
  if (req.user.role !== 'admin' && req.user.permissions?.siteAccess?.mode !== 'all') {
    return res.status(403).json({ message: 'Cannot create new sites with limited access' });
  }

  try {
    const siteName = normalizeSiteName(req.body?.siteName, { strict: true });
    const requestedPort = req.body?.port !== undefined ? coercePort(req.body.port) : undefined;

    if (req.body?.port !== undefined && !requestedPort) {
      return res.status(400).json({ message: 'Port must be an integer between 1024 and 65535.' });
    }

    const duplicate = sites.find(entry => entry.name.toLowerCase() === siteName.toLowerCase());
    if (duplicate) {
      return res.status(409).json({ message: 'Site already exists' });
    }

    if (requestedPort && sites.some(entry => Number(entry.port) === requestedPort)) {
      return res.status(409).json({ message: 'Port already allocated to another site.' });
    }

    const sitePort = requestedPort ?? findNextAvailablePort();
    if (!sitePort) {
      return res.status(400).json({ message: 'Unable to find an available port. Specify one manually.' });
    }

    provisioner.provisionSite(siteName, sitePort);
    sites.push({ name: siteName, port: sitePort });
    persistSites();

    res.status(201).json({ message: 'Site created successfully', port: sitePort });
  } catch (err) {
    console.error('Error creating site:', err);
    res.status(err.status || 500).json({ message: 'Failed to create site: ' + err.message });
  }
});

// Delete site
app.delete('/api/sites/:name', requireAuth, requirePermission('canManageSites'), ensureSiteManageAccess, (req, res) => {
  const siteName = req.siteName;
  
  try {
    // Remove site provisioning
    provisioner.removeSite(siteName);
    
    // Remove from sites list
    sites = sites.filter(s => s.name !== siteName);
  persistSites();
    
    res.json({ message: 'Site deleted successfully' });
  } catch (err) {
    console.error('Error deleting site:', err);
    res.status(500).json({ message: 'Failed to delete site: ' + err.message });
  }
});

// Update site port
app.put('/api/sites/:name/port', requireAuth, requirePermission('canManageSites'), ensureSiteManageAccess, (req, res) => {
  const siteName = req.siteName;
  const desiredPort = coercePort(req.body?.port);

  if (!desiredPort) {
    return res.status(400).json({ message: 'Invalid port number' });
  }

  try {
    const site = sites.find(s => s.name === siteName);
    if (!site) {
      return res.status(404).json({ message: 'Site not found' });
    }

    const conflicting = sites.find(entry => entry.name !== siteName && Number(entry.port) === desiredPort);
    if (conflicting) {
      return res.status(409).json({ message: `Port already used by ${conflicting.name}` });
    }

    site.port = desiredPort;
	persistSites();

    provisioner.generateNginxConfig(siteName, desiredPort);
    provisioner.reloadNginx();

    res.json({ message: 'Port updated successfully', port: desiredPort });
  } catch (err) {
    console.error('Error updating port:', err);
    res.status(500).json({ message: 'Failed to update port: ' + err.message });
  }
});

// File management APIs
app.get('/api/sites/:name/files', requireAuth, ensureSiteReadAccess, (req, res) => {
  const siteName = req.siteName;
  const subPath = req.query.path || '';

  try {
    const fullPath = resolveSitePath(siteName, subPath);

    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ message: 'Path not found' });
    }

    const stat = fs.statSync(fullPath);

    if (stat.isDirectory()) {
      const items = fs.readdirSync(fullPath).map(name => {
        const itemPath = path.join(fullPath, name);
        const itemStat = fs.statSync(itemPath);
        return {
          name,
          type: itemStat.isDirectory() ? 'directory' : 'file',
          size: itemStat.size,
          modified: itemStat.mtime
        };
      });
      res.json({ type: 'directory', items });
    } else {
      res.json({
        type: 'file',
        name: path.basename(fullPath),
        size: stat.size,
        modified: stat.mtime
      });
    }
  } catch (err) {
    console.error('Error listing files:', err);
    res.status(err.status || 500).json({ message: 'Failed to list files: ' + err.message });
  }
});

app.get('/api/sites/:name/files/read', requireAuth, ensureSiteReadAccess, (req, res) => {
  const siteName = req.siteName;
  const filePath = req.query.path;
  
  if (!filePath) {
    return res.status(400).json({ message: 'File path required' });
  }
  
  try {
    const fullPath = resolveSitePath(siteName, filePath);

    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ message: 'File not found' });
    }
    
    const content = fs.readFileSync(fullPath, 'utf8');
    res.json({ content });
  } catch (err) {
    console.error('Error reading file:', err);
    res.status(err.status || 500).json({ message: 'Failed to read file: ' + err.message });
  }
});

app.post('/api/sites/:name/files/write', requireAuth, requirePermission('canManageSites'), ensureSiteManageAccess, (req, res) => {
  const siteName = req.siteName;
  const { path: filePath, content } = req.body || {};
  
  if (!filePath || content === undefined) {
    return res.status(400).json({ message: 'File path and content required' });
  }
  
  try {
    const fullPath = resolveSitePath(siteName, filePath);
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const safeContent = typeof content === 'string' ? content : String(content ?? '');
    const size = Buffer.byteLength(safeContent, 'utf8');
    if (size > MAX_FILE_SIZE_BYTES) {
      return res.status(413).json({ message: 'File too large to edit via browser (limit 2 MB).' });
    }
    
    fs.writeFileSync(fullPath, safeContent, 'utf8');
    res.json({ message: 'File saved successfully' });
  } catch (err) {
    console.error('Error writing file:', err);
    res.status(err.status || 500).json({ message: 'Failed to write file: ' + err.message });
  }
});

// Create new file or folder
app.post('/api/sites/:name/files/create', requireAuth, requirePermission('canManageSites'), ensureSiteManageAccess, (req, res) => {
  const siteName = req.siteName;
  const { path: itemPath, type, content } = req.body || {};
  
  if (!itemPath) {
    return res.status(400).json({ message: 'Path required' });
  }
  
  try {
    const fullPath = resolveSitePath(siteName, itemPath);
    
    if (fs.existsSync(fullPath)) {
      return res.status(400).json({ message: 'File or folder already exists' });
    }
    
    if (type === 'directory') {
      fs.mkdirSync(fullPath, { recursive: true });
      return res.json({ message: 'Folder created successfully' });
    }

    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const safeContent = typeof content === 'string' ? content : String(content ?? '');
    const size = Buffer.byteLength(safeContent, 'utf8');
    if (size > MAX_FILE_SIZE_BYTES) {
      return res.status(413).json({ message: 'File too large to create via browser (limit 2 MB).' });
    }

    fs.writeFileSync(fullPath, safeContent, 'utf8');
    res.json({ message: 'File created successfully' });
  } catch (err) {
    console.error('Error creating file/folder:', err);
    res.status(err.status || 500).json({ message: 'Failed to create: ' + err.message });
  }
});

app.delete('/api/sites/:name/files/delete', requireAuth, requirePermission('canManageSites'), ensureSiteManageAccess, (req, res) => {
  const siteName = req.siteName;
  const filePath = req.query.path;
  
  if (!filePath) {
    return res.status(400).json({ message: 'File path required' });
  }
  
  try {
    const fullPath = resolveSitePath(siteName, filePath);

    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ message: 'File not found' });
    }
    
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      fs.rmSync(fullPath, { recursive: true, force: true });
    } else {
      fs.unlinkSync(fullPath);
    }
    
    res.json({ message: 'Deleted successfully' });
  } catch (err) {
    console.error('Error deleting file:', err);
    res.status(err.status || 500).json({ message: 'Failed to delete: ' + err.message });
  }
});

// Mail configuration APIs
app.get('/api/mail/config', requireAuth, requirePermission('canManageMail'), (req, res) => {
  try {
    const config = mailConfig.getMailConfig();
    res.json(config);
  } catch (err) {
    console.error('Error getting mail config:', err);
    res.status(500).json({ message: 'Failed to get mail config: ' + err.message });
  }
});

app.put('/api/mail/config', requireAuth, requirePermission('canManageMail'), (req, res) => {
  try {
    const config = mailConfig.updateMailConfig(req.body);
    res.json({ message: 'Mail configuration updated successfully', config: mailConfig.getMailConfig() });
  } catch (err) {
    console.error('Error updating mail config:', err);
    res.status(500).json({ message: 'Failed to update mail config: ' + err.message });
  }
});

// Tunnel configuration APIs
app.get('/api/tunnel/config', requireAuth, requirePermission('canManageTunnel'), (req, res) => {
  try {
    const settings = tunnel.getSettings();
    res.json(settings);
  } catch (err) {
    console.error('Error getting tunnel config:', err);
    res.status(500).json({ message: 'Failed to get tunnel config: ' + err.message });
  }
});

app.put('/api/tunnel/config', requireAuth, requirePermission('canManageTunnel'), (req, res) => {
  try {
    if (!req.body || typeof req.body !== 'object' || Object.keys(req.body).length === 0) {
      return res.status(400).json({ message: 'Configuration payload is required' });
    }

    tunnel.updateConfig(req.body);
    res.json({ message: 'Tunnel configuration updated successfully' });
  } catch (err) {
    console.error('Error updating tunnel config:', err);
    res.status(500).json({ message: 'Failed to update tunnel config: ' + err.message });
  }
});

app.put('/api/tunnel/token', requireAuth, requirePermission('canManageTunnel'), (req, res) => {
  try {
    const { token } = req.body || {};
    tunnel.updateToken(token);
    res.json({ message: 'Tunnel token saved. Cloudflare will now manage the tunnel.' });
  } catch (err) {
    console.error('Error saving tunnel token:', err);
    res.status(400).json({ message: err.message || 'Failed to save tunnel token' });
  }
});

app.delete('/api/tunnel/token', requireAuth, requirePermission('canManageTunnel'), (req, res) => {
  try {
    tunnel.clearToken();
    res.json({ message: 'Tunnel token removed' });
  } catch (err) {
    console.error('Error clearing tunnel token:', err);
    res.status(500).json({ message: 'Failed to remove tunnel token: ' + err.message });
  }
});

// Tunnel
app.post('/api/tunnel/start', requireAuth, requirePermission('canManageTunnel'), (req, res) => {
  try {
    const result = tunnel.start();
    res.json({ message: 'Tunnel started', ...result });
    notifyTunnelState(tunnel.isRunning(), {
      triggeredBy: req.user.username,
      reason: 'Manual start request'
    });
  } catch (err) {
    console.error('Error starting tunnel:', err);
    notifyTunnelState(false, {
      triggeredBy: req.user.username,
      reason: `Failed manual start: ${err.message || err}`
    });
    res.status(400).json({ message: err.message || 'Failed to start tunnel' });
  }
});

app.post('/api/tunnel/stop', requireAuth, requirePermission('canManageTunnel'), (req, res) => {
  tunnel.stop();
  res.json({ message: 'Tunnel stopped' });
  notifyTunnelState(tunnel.isRunning(), {
    triggeredBy: req.user.username,
    reason: 'Manual stop request'
  });
});

// Error handling middleware - must be defined after all routes
app.use((err, req, res, next) => {
  // Handle body-parser JSON errors
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    console.error('Invalid JSON in request:', err.message);
    return res.status(400).json({ message: 'Invalid JSON in request body' });
  }
  
  // Handle other errors
  console.error('Unhandled error:', err);
  res.status(err.status || 500).json({ 
    message: err.message || 'An unexpected error occurred' 
  });
});

app.listen(PORT, () => {
  console.log(`Admin panel running at http://localhost:${PORT}`);
});

tunnel.startIfConfigured();
scheduleTunnelMonitor();