const nodemailer = require('nodemailer');
const auth = require('./auth');
const mailConfig = require('./mailConfig');

let cachedTransporter = null;
let cachedSignature = null;
let lastVerifyTimestamp = 0;

function getConfigSignature(config) {
  return JSON.stringify({
    enabled: config.enabled,
    host: config.host,
    port: config.port,
    secure: config.secure,
    authUser: config.auth?.user,
    authPass: config.auth?.pass,
    from: config.from
  });
}

function normalizeRecipients(recipients) {
  if (!recipients) return [];
  if (Array.isArray(recipients)) {
    return recipients.filter(Boolean);
  }
  if (typeof recipients === 'string') {
    return recipients.split(',').map(entry => entry.trim()).filter(Boolean);
  }
  return [];
}

async function ensureTransporter() {
  const config = mailConfig.loadMailConfig();

  if (!config.enabled) {
    throw new Error('Mail server is disabled');
  }

  if (!config.host) {
    throw new Error('Mail server host is not configured');
  }

  const authBlock = config.auth || {};
  if ((config.secure || authBlock.user || authBlock.pass) && (!authBlock.user || !authBlock.pass)) {
    throw new Error('Mail server credentials are incomplete');
  }

  const signature = getConfigSignature(config);

  if (!cachedTransporter || cachedSignature !== signature) {
    cachedTransporter = nodemailer.createTransport({
      host: config.host,
      port: Number(config.port) || 587,
      secure: Boolean(config.secure),
      auth: authBlock.user ? { user: authBlock.user, pass: authBlock.pass } : undefined
    });
    cachedSignature = signature;
    lastVerifyTimestamp = 0;
  }

  // Re-verify transporter at most every five minutes to avoid excessive overhead
  if (Date.now() - lastVerifyTimestamp > 5 * 60 * 1000) {
    try {
      await cachedTransporter.verify();
      lastVerifyTimestamp = Date.now();
    } catch (err) {
      throw new Error(`Failed to verify mail transporter: ${err.message}`);
    }
  }

  const from = config.from || authBlock.user;
  if (!from) {
    throw new Error('Mail sender address is not configured');
  }

  return { transporter: cachedTransporter, config, from };
}

async function sendMail({ to, subject, text, html }) {
  const { transporter, config, from } = await ensureTransporter();
  const recipients = normalizeRecipients(to);

  if (recipients.length === 0) {
    throw new Error('No recipients specified for email');
  }

  const mailOptions = {
    from,
    to: recipients.join(', '),
    subject,
    text,
    html
  };

  await transporter.sendMail(mailOptions);
  return { messageId: mailOptions.messageId || null, attemptedRecipients: recipients, from: config.from || config.auth.user };
}

async function sendPasswordResetEmail({ to, username, token }) {
  const recipients = normalizeRecipients(to);

  if (recipients.length === 0) {
    throw new Error('Password reset email requires a recipient');
  }

  const config = mailConfig.loadMailConfig();
  const baseUrl = (config.appUrl || '').trim().replace(/\/?$/, '');
  const resetLink = baseUrl ? `${baseUrl}?resetToken=${token}` : null;

  const subject = 'LWUI password reset';
  const textLines = [
    `Hi ${username || 'there'},`,
    '',
    'We received a request to reset your LWUI administrative account password.',
    `Reset code: ${token}`,
    resetLink ? `Reset link: ${resetLink}` : '',
    '',
    'If you did not request this reset you can ignore this email.'
  ].filter(Boolean);

  const html = `
    <p>Hi ${username || 'there'},</p>
    <p>We received a request to reset your LWUI administrative account password.</p>
    <p><strong>Reset code:</strong> ${token}</p>
    ${resetLink ? `<p>You can also use the following link: <a href="${resetLink}">${resetLink}</a></p>` : ''}
    <p>If you did not request this reset you can ignore this email.</p>
  `;

  await sendMail({
    to: recipients,
    subject,
    text: textLines.join('\n'),
    html
  });
}

async function notifyTunnelStatusChange({ running, reason, triggeredBy, timestamp = new Date().toISOString() }) {
  const config = mailConfig.loadMailConfig();

  if (!config.enabled || config.alerts?.downtime === false) {
    return;
  }

  const adminRecipients = auth.getAdminEmails().map(entry => entry.email).filter(Boolean);

  if (adminRecipients.length === 0) {
    return;
  }

  const statusLabel = running ? 'restored' : 'offline';
  const subject = `Cloudflare tunnel ${statusLabel}`;

  const detailLines = [
    `Status: ${running ? 'Online' : 'Offline'}`,
    `Timestamp: ${timestamp}`,
    triggeredBy ? `Triggered by: ${triggeredBy}` : null,
    reason ? `Notes: ${reason}` : null
  ].filter(Boolean);

  const text = detailLines.join('\n');
  const html = detailLines.map(line => `<p>${line}</p>`).join('');

  try {
    await sendMail({
      to: adminRecipients,
      subject,
      text,
      html
    });
  } catch (err) {
    console.error('Failed to dispatch tunnel status notification:', err.message);
  }
}

function isConfigured() {
  try {
    const config = mailConfig.loadMailConfig();
    return Boolean(config.enabled && config.host && (config.from || config.auth.user));
  } catch (err) {
    return false;
  }
}

module.exports = {
  sendMail,
  sendPasswordResetEmail,
  notifyTunnelStatusChange,
  isConfigured
};