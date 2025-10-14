const express = require('express');
const fs = require('fs');
const path = require('path');
const os = require('os');
const tunnel = require('./tunnel');
const provisioner = require('./provisioner');
const auth = require('./auth');
const mailConfig = require('./mailConfig');
const mailer = require('./mailer');
const app = express();
const PORT = 3000;

let lastKnownTunnelState = tunnel.isRunning();

app.use(express.static('public'));
app.use(express.json());

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
  const siteName = req.params.name || req.body.siteName;
  if (!siteName) {
    return res.status(400).json({ message: 'Site name required' });
  }
  if (!userCanAccessSite(req.user, siteName)) {
    return res.status(403).json({ message: 'Access denied for this site' });
  }
  next();
}

function ensureSiteManageAccess(req, res, next) {
  const siteName = req.params.name || req.body.siteName;
  if (!siteName) {
    return res.status(400).json({ message: 'Site name required' });
  }
  if (!userCanManageSite(req.user, siteName)) {
    return res.status(403).json({ message: 'Management access denied for this site' });
  }
  next();
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
app.post('/api/auth/login', (req, res) => {
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

app.post('/api/auth/2fa/verify', (req, res) => {
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

app.post('/api/auth/request-password-reset', async (req, res) => {
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

app.post('/api/auth/reset-password', (req, res) => {
  const { token, newPassword } = req.body || {};

  if (!token || !newPassword) {
    return res.status(400).json({ message: 'Token and new password are required' });
  }

  try {
    const result = auth.resetPasswordWithToken(token, newPassword);
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
  const { siteName, port } = req.body;
  if (!siteName) return res.status(400).json({ message: 'Site name required' });

  if (req.user.role !== 'admin' && req.user.permissions?.siteAccess?.mode !== 'all') {
    return res.status(403).json({ message: 'Cannot create new sites with limited access' });
  }

  try {
    const existing = sites.find(s => s.name === siteName);
    if (!existing) {
      // Find next available port if not specified
      const sitePort = port || (sites.length > 0 ? Math.max(...sites.map(s => s.port)) + 1 : 8080);
      
      // Provision the site (create directories, nginx config, samba share)
      provisioner.provisionSite(siteName, sitePort);
      
      // Add to sites list
  sites.push({ name: siteName, port: sitePort });
  persistSites();
      
      res.json({ message: 'Site created successfully', port: sitePort });
    } else {
      res.json({ message: 'Site already exists' });
    }
  } catch (err) {
    console.error('Error creating site:', err);
    res.status(500).json({ message: 'Failed to create site: ' + err.message });
  }
});

// Delete site
app.delete('/api/sites/:name', requireAuth, requirePermission('canManageSites'), ensureSiteManageAccess, (req, res) => {
  const siteName = req.params.name;
  
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
  const siteName = req.params.name;
  const { port } = req.body;
  
  if (!port || port < 1024 || port > 65535) {
    return res.status(400).json({ message: 'Invalid port number' });
  }
  
  try {
    const site = sites.find(s => s.name === siteName);
    if (!site) {
      return res.status(404).json({ message: 'Site not found' });
    }
    
    // Update port
    site.port = port;
  persistSites();
    
    // Regenerate nginx config with new port
    provisioner.generateNginxConfig(siteName, port);
    provisioner.reloadNginx();
    
    res.json({ message: 'Port updated successfully', port });
  } catch (err) {
    console.error('Error updating port:', err);
    res.status(500).json({ message: 'Failed to update port: ' + err.message });
  }
});

// File management APIs
app.get('/api/sites/:name/files', requireAuth, ensureSiteReadAccess, (req, res) => {
  const siteName = req.params.name;
  const subPath = req.query.path || '';
  
  try {
    const sitesDir = provisioner.isDevelopment 
      ? path.join(__dirname, '../sites') 
      : '/opt/lwui/sites';
    const fullPath = path.join(sitesDir, siteName, subPath);
    
    // Security check - ensure path is within site directory
    if (!fullPath.startsWith(path.join(sitesDir, siteName))) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ message: 'Path not found' });
    }
    
    const stat = fs.statSync(fullPath);
    
    if (stat.isDirectory()) {
      // List directory contents
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
      // Return file info
      res.json({ 
        type: 'file',
        name: path.basename(fullPath),
        size: stat.size,
        modified: stat.mtime
      });
    }
  } catch (err) {
    console.error('Error listing files:', err);
    res.status(500).json({ message: 'Failed to list files: ' + err.message });
  }
});

app.get('/api/sites/:name/files/read', requireAuth, ensureSiteReadAccess, (req, res) => {
  const siteName = req.params.name;
  const filePath = req.query.path;
  
  if (!filePath) {
    return res.status(400).json({ message: 'File path required' });
  }
  
  try {
    const sitesDir = provisioner.isDevelopment 
      ? path.join(__dirname, '../sites') 
      : '/opt/lwui/sites';
    const fullPath = path.join(sitesDir, siteName, filePath);
    
    // Security check
    if (!fullPath.startsWith(path.join(sitesDir, siteName))) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ message: 'File not found' });
    }
    
    const content = fs.readFileSync(fullPath, 'utf8');
    res.json({ content });
  } catch (err) {
    console.error('Error reading file:', err);
    res.status(500).json({ message: 'Failed to read file: ' + err.message });
  }
});

app.post('/api/sites/:name/files/write', requireAuth, requirePermission('canManageSites'), ensureSiteManageAccess, (req, res) => {
  const siteName = req.params.name;
  const { path: filePath, content } = req.body;
  
  if (!filePath || content === undefined) {
    return res.status(400).json({ message: 'File path and content required' });
  }
  
  try {
    const sitesDir = provisioner.isDevelopment 
      ? path.join(__dirname, '../sites') 
      : '/opt/lwui/sites';
    const fullPath = path.join(sitesDir, siteName, filePath);
    
    // Security check
    if (!fullPath.startsWith(path.join(sitesDir, siteName))) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    // Ensure directory exists
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(fullPath, content, 'utf8');
    res.json({ message: 'File saved successfully' });
  } catch (err) {
    console.error('Error writing file:', err);
    res.status(500).json({ message: 'Failed to write file: ' + err.message });
  }
});

// Create new file or folder
app.post('/api/sites/:name/files/create', requireAuth, requirePermission('canManageSites'), ensureSiteManageAccess, (req, res) => {
  const siteName = req.params.name;
  const { path: itemPath, type, content } = req.body;
  
  if (!itemPath) {
    return res.status(400).json({ message: 'Path required' });
  }
  
  try {
    const sitesDir = provisioner.isDevelopment 
      ? path.join(__dirname, '../sites') 
      : '/opt/lwui/sites';
    const fullPath = path.join(sitesDir, siteName, itemPath);
    
    // Security check
    if (!fullPath.startsWith(path.join(sitesDir, siteName))) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    if (fs.existsSync(fullPath)) {
      return res.status(400).json({ message: 'File or folder already exists' });
    }
    
    if (type === 'directory') {
      fs.mkdirSync(fullPath, { recursive: true });
      res.json({ message: 'Folder created successfully' });
    } else {
      // Ensure parent directory exists
      const dir = path.dirname(fullPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(fullPath, content || '', 'utf8');
      res.json({ message: 'File created successfully' });
    }
  } catch (err) {
    console.error('Error creating file/folder:', err);
    res.status(500).json({ message: 'Failed to create: ' + err.message });
  }
});

app.delete('/api/sites/:name/files/delete', requireAuth, requirePermission('canManageSites'), ensureSiteManageAccess, (req, res) => {
  const siteName = req.params.name;
  const filePath = req.query.path;
  
  if (!filePath) {
    return res.status(400).json({ message: 'File path required' });
  }
  
  try {
    const sitesDir = provisioner.isDevelopment 
      ? path.join(__dirname, '../sites') 
      : '/opt/lwui/sites';
    const fullPath = path.join(sitesDir, siteName, filePath);
    
    // Security check
    if (!fullPath.startsWith(path.join(sitesDir, siteName))) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
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
    res.status(500).json({ message: 'Failed to delete: ' + err.message });
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