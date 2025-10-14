const fs = require('fs');
const path = require('path');

const MAIL_CONFIG_FILE = path.join(__dirname, 'mailConfig.json');

// Initialize mail config file if it doesn't exist
function initMailConfig() {
  if (!fs.existsSync(MAIL_CONFIG_FILE)) {
    const defaultConfig = {
      enabled: false,
      host: '',
      port: 587,
      secure: false,
      auth: {
        user: '',
        pass: ''
      },
      from: '',
      appUrl: '',
      alerts: {
        downtime: true
      }
    };
    fs.writeFileSync(MAIL_CONFIG_FILE, JSON.stringify(defaultConfig, null, 2));
  }
}

// Load mail configuration
function loadMailConfig() {
  if (!fs.existsSync(MAIL_CONFIG_FILE)) {
    initMailConfig();
  }
  const config = JSON.parse(fs.readFileSync(MAIL_CONFIG_FILE, 'utf8'));

  let mutated = false;

  if (!config.auth) {
    config.auth = { user: '', pass: '' };
    mutated = true;
  } else {
    config.auth.user = config.auth.user || '';
    config.auth.pass = config.auth.pass || '';
  }

  if (config.enabled === undefined) {
    config.enabled = false;
    mutated = true;
  }

  if (!config.alerts) {
    config.alerts = { downtime: true };
    mutated = true;
  } else if (config.alerts.downtime === undefined) {
    config.alerts.downtime = true;
    mutated = true;
  }

  if (config.appUrl === undefined) {
    config.appUrl = '';
    mutated = true;
  }

  if (config.from === undefined) {
    config.from = '';
    mutated = true;
  }

  if (mutated) {
    saveMailConfig(config);
  }

  return config;
}

// Save mail configuration
function saveMailConfig(config) {
  fs.writeFileSync(MAIL_CONFIG_FILE, JSON.stringify(config, null, 2));
}

// Update mail configuration
function updateMailConfig(updates) {
  const config = loadMailConfig();
  const newConfig = {
    ...config,
    ...updates,
    auth: {
      ...config.auth,
      ...(updates.auth || {})
    },
    alerts: {
      ...config.alerts,
      ...(updates.alerts || {})
    }
  };
  saveMailConfig(newConfig);
  return newConfig;
}

// Get mail configuration (without password)
function getMailConfig() {
  const config = loadMailConfig();
  return {
    enabled: config.enabled,
    host: config.host,
    port: config.port,
    secure: config.secure,
    auth: {
      user: config.auth.user
    },
    from: config.from,
    appUrl: config.appUrl,
    alerts: config.alerts
  };
}

// Initialize on module load
initMailConfig();

module.exports = {
  loadMailConfig,
  saveMailConfig,
  updateMailConfig,
  getMailConfig
};