const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

let proc = null;
let lastError = null;

const configPath = path.join(__dirname, '../cloudflared/config.yml');
const tokenPath = path.join(__dirname, '../cloudflared/token.json');

function readTokenFile() {
  try {
    if (!fs.existsSync(tokenPath)) {
      return null;
    }
    const raw = fs.readFileSync(tokenPath, 'utf8');
    const payload = JSON.parse(raw);
    return typeof payload.token === 'string' && payload.token.trim() ? payload.token.trim() : null;
  } catch (err) {
    console.error('Error reading tunnel token:', err);
    return null;
  }
}

function writeTokenFile(token) {
  const data = JSON.stringify({ token: token.trim() }, null, 2);
  fs.mkdirSync(path.dirname(tokenPath), { recursive: true });
  fs.writeFileSync(tokenPath, data, 'utf8');
}

function clearTokenFile() {
  if (fs.existsSync(tokenPath)) {
    fs.unlinkSync(tokenPath);
  }
}

function buildCommand() {
  const token = readTokenFile();
  const hasConfig = fs.existsSync(configPath);

  if (token) {
    return {
      mode: 'token',
      args: ['tunnel', '--no-autoupdate', 'run', '--token', token]
    };
  }

  if (hasConfig) {
    return {
      mode: 'config',
      args: ['tunnel', '--no-autoupdate', '--config', configPath]
    };
  }

  return { mode: 'none', args: null };
}

function markProcessExit() {
  proc = null;
}

function startProcess(args) {
  proc = spawn('cloudflared', args, {
    stdio: 'ignore',
    detached: true
  });

  proc.on('exit', markProcessExit);
  proc.on('error', err => {
    lastError = err;
    markProcessExit();
    console.error('cloudflared failed to start:', err);
  });

  proc.unref();
  lastError = null;
}

function getConfig() {
  try {
    if (fs.existsSync(configPath)) {
      const content = fs.readFileSync(configPath, 'utf8');
      return yaml.load(content);
    }
    return null;
  } catch (err) {
    console.error('Error reading tunnel config:', err);
    throw err;
  }
}

function updateConfig(config) {
  try {
    const yamlStr = yaml.dump(config);
    fs.writeFileSync(configPath, yamlStr, 'utf8');

    if (proc) {
      module.exports.stop();
      setTimeout(() => {
        try {
          module.exports.start();
        } catch (err) {
          console.error('Failed to restart cloudflared after config update:', err);
        }
      }, 1000);
    }
  } catch (err) {
    console.error('Error updating tunnel config:', err);
    throw err;
  }
}

function updateToken(token) {
  if (!token || typeof token !== 'string' || !token.trim()) {
    throw new Error('Tunnel token is required');
  }

  writeTokenFile(token);

  if (proc) {
    module.exports.stop();
  }

  try {
    module.exports.start();
  } catch (err) {
    console.error('Failed to start cloudflared after token update:', err);
  }
}

module.exports = {
  start: () => {
    if (proc) {
      return { started: false, message: 'Tunnel already running' };
    }

    const command = buildCommand();

    if (!command.args) {
      throw new Error('No tunnel token or configuration found. Please add a Cloudflare token or config.');
    }

    try {
  startProcess(command.args);
  return { started: true, mode: command.mode, running: true };
    } catch (err) {
      lastError = err;
      throw err;
    }
  },
  stop: () => {
    if (proc) {
      try {
        process.kill(-proc.pid);
      } catch (err) {
        console.error('Failed to stop cloudflared:', err);
      }
      proc = null;
    }
  },
  isRunning: () => !!proc,
  getLastError: () => lastError,
  getConfig,
  updateConfig,
  updateToken,
  clearToken: () => {
    clearTokenFile();
    if (proc) {
      module.exports.stop();
    }
  },
  getSettings: () => {
    const token = readTokenFile();
    const config = getConfig();
    const mode = buildCommand().mode;
    const maskedToken = token
      ? token.length <= 8
        ? token
        : `${token.slice(0, 4)}…${token.slice(-4)}`
      : null;
    return {
      running: module.exports.isRunning(),
      mode,
      token: token
        ? {
            configured: true,
            masked: maskedToken
          }
        : { configured: false, masked: null },
      config,
      lastError: lastError ? lastError.message : null
    };
  },
  startIfConfigured: () => {
    if (!module.exports.isRunning()) {
      const command = buildCommand();
      if (command.args) {
        try {
          startProcess(command.args);
        } catch (err) {
          lastError = err;
          console.error('Failed to auto-start cloudflared:', err);
        }
      }
    }
  }
};