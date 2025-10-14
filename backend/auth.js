const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

const USERS_FILE = path.join(__dirname, 'users.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

const TWO_FACTOR_TTL = 5 * 60 * 1000; // 5 minutes
const pendingTwoFactor = new Map();

function cleanupExpiredChallenges() {
  const now = Date.now();
  for (const [token, payload] of pendingTwoFactor.entries()) {
    if (payload.expiresAt <= now) {
      pendingTwoFactor.delete(token);
    }
  }
}

function getDefaultPermissions(role = 'user') {
  if (role === 'admin') {
    return {
      canManageSites: true,
      canManageTunnel: true,
      canManageMail: true,
      canManageUsers: true,
      siteAccess: { mode: 'all', sites: [] }
    };
  }
  return {
    canManageSites: true,
    canManageTunnel: false,
    canManageMail: false,
    canManageUsers: false,
    siteAccess: { mode: 'limited', sites: [] }
  };
}

function normalizePermissions(permissions, role = 'user') {
  const defaults = getDefaultPermissions(role);

  if (!permissions || typeof permissions !== 'object') {
    return { ...defaults };
  }

  const normalized = {
    canManageSites: permissions.canManageSites !== undefined ? Boolean(permissions.canManageSites) : defaults.canManageSites,
    canManageTunnel: permissions.canManageTunnel !== undefined ? Boolean(permissions.canManageTunnel) : defaults.canManageTunnel,
    canManageMail: permissions.canManageMail !== undefined ? Boolean(permissions.canManageMail) : defaults.canManageMail,
    canManageUsers: permissions.canManageUsers !== undefined ? Boolean(permissions.canManageUsers) : defaults.canManageUsers,
    siteAccess: {
      mode: permissions.siteAccess && permissions.siteAccess.mode === 'all' ? 'all' : 'limited',
      sites: Array.isArray(permissions.siteAccess?.sites)
        ? Array.from(new Set(permissions.siteAccess.sites.map(name => String(name).trim()).filter(Boolean)))
        : []
    }
  };

  if (role === 'admin') {
    return getDefaultPermissions('admin');
  }

  return normalized;
}

function sanitizeUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email || '',
    role: user.role,
    twoFactorEnabled: user.twoFactorEnabled || false,
    permissions: user.permissions ? normalizePermissions(user.permissions, user.role) : getDefaultPermissions(user.role),
    createdAt: user.createdAt
  };
}

// Initialize default admin user if file doesn't exist
function initUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    const defaultUser = {
      id: 'admin',
      username: 'admin',
      password: hashPassword('localpass'),
      email: '',
      role: 'admin',
      twoFactorEnabled: false,
      twoFactorSecret: null,
      createdAt: new Date().toISOString(),
      permissions: getDefaultPermissions('admin')
    };
    fs.writeFileSync(USERS_FILE, JSON.stringify([defaultUser], null, 2));
  }
  
  if (!fs.existsSync(SESSIONS_FILE)) {
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify({}, null, 2));
  }
}

function hashToken(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

// Hash password using SHA-256
function hashPassword(password) {
  return hashToken(password);
}

// Generate session token
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Load users
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    initUsers();
  }
  const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  let needsSave = false;

  for (const user of users) {
    if (!user.permissions) {
      user.permissions = getDefaultPermissions(user.role || 'user');
      needsSave = true;
    } else {
      const normalized = normalizePermissions(user.permissions, user.role || 'user');
      if (JSON.stringify(normalized) !== JSON.stringify(user.permissions)) {
        user.permissions = normalized;
        needsSave = true;
      }
    }
  }

  if (needsSave) {
    saveUsers(users);
  }

  return users;
}

// Save users
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Load sessions
function loadSessions() {
  if (!fs.existsSync(SESSIONS_FILE)) {
    return {};
  }
  return JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
}

// Save sessions
function saveSessions(sessions) {
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions, null, 2));
}

function createSessionForUser(user) {
  const token = generateToken();
  const sessions = loadSessions();
  sessions[token] = {
    userId: user.id,
    username: user.username,
    role: user.role,
    createdAt: new Date().toISOString()
  };
  saveSessions(sessions);
  return token;
}

// Authenticate user
function authenticate(username, password) {
  cleanupExpiredChallenges();

  const users = loadUsers();
  const user = users.find(u => u.username === username);
  
  if (!user) {
    return null;
  }
  
  const hashedPassword = hashPassword(password);
  if (user.password !== hashedPassword) {
    return null;
  }

  if (user.twoFactorEnabled) {
    const challengeToken = generateToken();
    pendingTwoFactor.set(challengeToken, {
      userId: user.id,
      issuedAt: Date.now(),
      expiresAt: Date.now() + TWO_FACTOR_TTL
    });

    return {
      twoFactorRequired: true,
      challengeToken,
      expiresIn: TWO_FACTOR_TTL
    };
  }

  const token = createSessionForUser(user);
  return { token, user: sanitizeUser(user) };
}

function completeTwoFactor(challengeToken, verificationCode) {
  cleanupExpiredChallenges();

  if (!challengeToken || !verificationCode) {
    throw new Error('Verification code is required');
  }

  const challenge = pendingTwoFactor.get(challengeToken);
  if (!challenge) {
    throw new Error('Invalid or expired verification request');
  }

  const users = loadUsers();
  const user = users.find(u => u.id === challenge.userId);

  if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
    pendingTwoFactor.delete(challengeToken);
    throw new Error('Two-factor authentication is not enabled for this user');
  }

  const verified = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token: verificationCode,
    window: 2
  });

  if (!verified) {
    throw new Error('Invalid verification code');
  }

  pendingTwoFactor.delete(challengeToken);

  const sessionToken = createSessionForUser(user);
  return { token: sessionToken, user: sanitizeUser(user) };
}

// Verify session
function verifySession(token) {
  if (!token) return null;
  
  const sessions = loadSessions();
  const session = sessions[token];
  
  if (!session) return null;
  
  // Check if session is expired (24 hours)
  const sessionAge = Date.now() - new Date(session.createdAt).getTime();
  if (sessionAge > 24 * 60 * 60 * 1000) {
    delete sessions[token];
    saveSessions(sessions);
    return null;
  }
  
  return session;
}

// Logout
function logout(token) {
  const sessions = loadSessions();
  delete sessions[token];
  saveSessions(sessions);
}

// Get all users (without passwords)
function getAllUsers() {
  const users = loadUsers();
  return users.map(user => sanitizeUser(user));
}

// Create user
function createUser({ username, password, role = 'user', email = '', permissions } = {}) {
  const users = loadUsers();
  
  if (users.find(u => u.username === username)) {
    throw new Error('Username already exists');
  }

  const normalizedRole = role === 'admin' ? 'admin' : 'user';
  const normalizedPermissions = normalizePermissions(permissions, normalizedRole);
  
  const newUser = {
    id: crypto.randomBytes(16).toString('hex'),
    username,
    password: hashPassword(password),
    email,
    role: normalizedRole,
    permissions: normalizedPermissions,
    twoFactorEnabled: false,
    twoFactorSecret: null,
    createdAt: new Date().toISOString()
  };
  
  users.push(newUser);
  saveUsers(users);
  
  return sanitizeUser(newUser);
}

// Update user password
function updatePassword(userId, newPassword) {
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    throw new Error('User not found');
  }
  
  user.password = hashPassword(newPassword);
  if (user.passwordReset) {
    delete user.passwordReset;
  }
  saveUsers(users);
}

// Update user email
function updateEmail(userId, newEmail) {
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    throw new Error('User not found');
  }
  
  user.email = (newEmail || '').trim();
  saveUsers(users);
}

// Get user by ID
function getUserById(userId) {
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return null;
  }
  
  return sanitizeUser(user);
}

// Delete user
function deleteUser(userId) {
  const users = loadUsers();
  const filtered = users.filter(u => u.id !== userId);
  
  if (filtered.length === users.length) {
    throw new Error('User not found');
  }
  
  // Don't allow deleting the last admin
  const admins = filtered.filter(u => u.role === 'admin');
  if (admins.length === 0) {
    throw new Error('Cannot delete the last admin user');
  }
  
  saveUsers(filtered);

  const sessions = loadSessions();
  let mutated = false;
  for (const [token, session] of Object.entries(sessions)) {
    if (session.userId === userId) {
      delete sessions[token];
      mutated = true;
    }
  }
  if (mutated) {
    saveSessions(sessions);
  }

  for (const [token, details] of pendingTwoFactor.entries()) {
    if (details.userId === userId) {
      pendingTwoFactor.delete(token);
    }
  }
}

// Setup 2FA for user
function setup2FA(userId) {
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    throw new Error('User not found');
  }
  
  // Generate secret
  const secret = speakeasy.generateSecret({
    name: `LWUI (${user.username})`,
    length: 32
  });
  
  // Store temporary secret (not enabled until verified)
  user.twoFactorSecret = secret.base32;
  user.twoFactorTempSecret = secret.base32;
  saveUsers(users);
  
  return {
    secret: secret.base32,
    qrCode: secret.otpauth_url
  };
}

// Verify and enable 2FA
function enable2FA(userId, token) {
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    throw new Error('User not found');
  }
  
  if (!user.twoFactorTempSecret) {
    throw new Error('2FA setup not initiated');
  }
  
  // Verify the token
  const verified = speakeasy.totp.verify({
    secret: user.twoFactorTempSecret,
    encoding: 'base32',
    token: token,
    window: 2
  });
  
  if (!verified) {
    throw new Error('Invalid verification code');
  }
  
  // Enable 2FA
  user.twoFactorEnabled = true;
  user.twoFactorSecret = user.twoFactorTempSecret;
  delete user.twoFactorTempSecret;
  saveUsers(users);

  for (const [token, details] of pendingTwoFactor.entries()) {
    if (details.userId === userId) {
      pendingTwoFactor.delete(token);
    }
  }
  
  return true;
}

// Disable 2FA
function disable2FA(userId) {
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    throw new Error('User not found');
  }
  
  user.twoFactorEnabled = false;
  user.twoFactorSecret = null;
  delete user.twoFactorTempSecret;
  saveUsers(users);

  for (const [token, details] of pendingTwoFactor.entries()) {
    if (details.userId === userId) {
      pendingTwoFactor.delete(token);
    }
  }
}

// Verify 2FA token
function verify2FA(userId, token) {
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
    return false;
  }
  
  return speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token: token,
    window: 2
  });
}

// Generate QR code as data URL
async function generateQRCode(otpauthUrl) {
  try {
    return await qrcode.toDataURL(otpauthUrl);
  } catch (err) {
    throw new Error('Failed to generate QR code');
  }
}

function updatePermissions(userId, permissions) {
  const users = loadUsers();
  const user = users.find(u => u.id === userId);

  if (!user) {
    throw new Error('User not found');
  }

  user.permissions = normalizePermissions(permissions, user.role || 'user');
  saveUsers(users);

  return sanitizeUser(user);
}

function getAdminEmails() {
  const users = loadUsers();
  return users
    .filter(user => (user.role === 'admin') && user.email)
    .map(user => ({ id: user.id, email: user.email, username: user.username }));
}

function getUserByUsername(username) {
  const users = loadUsers();
  const user = users.find(u => u.username === username);
  return user ? sanitizeUser(user) : null;
}

function getInternalUserByUsername(username) {
  const users = loadUsers();
  return users.find(u => u.username === username) || null;
}

function initiatePasswordReset(identifier) {
  const users = loadUsers();
  const trimmedIdentifier = (identifier || '').trim().toLowerCase();

  if (!trimmedIdentifier) {
    throw new Error('Identifier is required');
  }

  const user = users.find(u => (u.username && u.username.toLowerCase() === trimmedIdentifier) || (u.email && u.email.toLowerCase() === trimmedIdentifier));

  if (!user) {
    throw new Error('User not found');
  }

  if (!user.email) {
    throw new Error('User does not have an email address configured');
  }

  const token = crypto.randomBytes(24).toString('hex');
  user.passwordReset = {
    token: hashToken(token),
    expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour
    requestedAt: new Date().toISOString()
  };

  saveUsers(users);

  return { token, user: sanitizeUser(user) };
}

function validatePasswordResetToken(token) {
  if (!token) {
    return null;
  }

  const users = loadUsers();
  const hashed = hashToken(token);
  const now = Date.now();

  const user = users.find(u => u.passwordReset && u.passwordReset.token === hashed && u.passwordReset.expiresAt > now);

  return user ? sanitizeUser(user) : null;
}

function resetPasswordWithToken(token, newPassword) {
  if (!token || !newPassword) {
    throw new Error('Reset token and new password are required');
  }

  const users = loadUsers();
  const hashed = hashToken(token);
  const now = Date.now();

  const user = users.find(u => u.passwordReset && u.passwordReset.token === hashed && u.passwordReset.expiresAt > now);

  if (!user) {
    throw new Error('Invalid or expired password reset token');
  }

  user.password = hashPassword(newPassword);
  delete user.passwordReset;
  saveUsers(users);

  const sessionToken = createSessionForUser(user);
  return { token: sessionToken, user: sanitizeUser(user) };
}

// Initialize on module load
initUsers();

module.exports = {
  authenticate,
  verifySession,
  logout,
  getAllUsers,
  createUser,
  updatePassword,
  updateEmail,
  getUserById,
  deleteUser,
  setup2FA,
  enable2FA,
  disable2FA,
  verify2FA,
  generateQRCode,
  completeTwoFactor,
  updatePermissions,
  getAdminEmails,
  getUserByUsername,
  initiatePasswordReset,
  validatePasswordResetToken,
  resetPasswordWithToken
};