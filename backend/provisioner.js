const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Detect if running in development mode (not in /opt/lwui)
const isDevelopment = !__dirname.startsWith('/opt/lwui');

const SITES_DIR = isDevelopment ? path.join(__dirname, '../sites') : '/opt/lwui/sites';
const SMB_DIR = isDevelopment ? path.join(__dirname, '../smb') : '/mnt/smb';
const NGINX_AVAILABLE = isDevelopment ? path.join(__dirname, '../nginx-configs') : '/etc/nginx/sites-available';
const NGINX_ENABLED = isDevelopment ? path.join(__dirname, '../nginx-enabled') : '/etc/nginx/sites-enabled';
const NGINX_TEMPLATE = path.join(__dirname, '../nginx/template.conf');

// Ensure development directories exist
if (isDevelopment) {
  [SITES_DIR, SMB_DIR, NGINX_AVAILABLE, NGINX_ENABLED].forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });
}

function createSiteDirectory(siteName) {
  const sitePath = path.join(SITES_DIR, siteName);
  const smbPath = path.join(SMB_DIR, siteName);
  
  // Create site directory
  if (!fs.existsSync(sitePath)) {
    fs.mkdirSync(sitePath, { recursive: true });
    
    // Create default index.html
    const defaultHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${siteName}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .container {
            text-align: center;
            padding: 2rem;
        }
        h1 { font-size: 3rem; margin-bottom: 1rem; }
        p { font-size: 1.2rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎉 ${siteName}</h1>
        <p>Your site is now live!</p>
        <p>Edit files via SMB share to customize this page.</p>
    </div>
</body>
</html>`;
    fs.writeFileSync(path.join(sitePath, 'index.html'), defaultHTML);
  }
  
  // Create SMB symlink
  if (!fs.existsSync(smbPath)) {
    try {
      fs.symlinkSync(sitePath, smbPath, 'dir');
    } catch (err) {
      console.error(`Failed to create symlink for SMB share: ${err.message}`);
      try {
        fs.cpSync(sitePath, smbPath, { recursive: true });
      } catch (copyErr) {
        console.error(`Fallback copy for SMB share failed: ${copyErr.message}`);
      }
    }
  }
  
  return sitePath;
}

function generateNginxConfig(siteName, port = 80) {
  try {
    const template = fs.readFileSync(NGINX_TEMPLATE, 'utf8');
    let config = template.replace(/{{SITE_NAME}}/g, siteName);
    
    // Update listen port
    config = config.replace(/listen 80;/, `listen ${port};`);
    
    const configPath = path.join(NGINX_AVAILABLE, siteName);
    
    fs.writeFileSync(configPath, config);
    
    // Create symlink to enable site
    const enabledPath = path.join(NGINX_ENABLED, siteName);
    if (!fs.existsSync(enabledPath)) {
      try {
        if (isDevelopment) {
          // In development, just copy the file
          fs.copyFileSync(configPath, enabledPath);
        } else {
          execSync(`ln -s "${configPath}" "${enabledPath}"`);
        }
      } catch (err) {
        console.error(`Failed to enable nginx site: ${err.message}`);
      }
    }
    
    return true;
  } catch (err) {
    console.error(`Failed to generate nginx config: ${err.message}`);
    return false;
  }
}

function reloadNginx() {
  if (isDevelopment) {
    console.log('Development mode: Skipping nginx reload');
    return true;
  }
  
  try {
    execSync('nginx -t', { stdio: 'ignore' });
    execSync('systemctl reload nginx', { stdio: 'ignore' });
    return true;
  } catch (err) {
    console.error(`Failed to reload nginx: ${err.message}`);
    return false;
  }
}

function configureSambaShare(siteName) {
  if (isDevelopment) {
    console.log('Development mode: Skipping Samba configuration');
    return true;
  }
  
  const smbConfPath = '/etc/samba/smb.conf';
  
  try {
    let smbConf = '';
    if (fs.existsSync(smbConfPath)) {
      smbConf = fs.readFileSync(smbConfPath, 'utf8');
    }
    
    // Check if share already exists
    const shareSection = `[${siteName}]`;
    if (smbConf.includes(shareSection)) {
      return true; // Already configured
    }
    
    // Add share configuration
    const shareConfig = `

[${siteName}]
   path = /mnt/smb/${siteName}
   browseable = yes
   read only = no
   guest ok = yes
   create mask = 0644
   directory mask = 0755
`;
    
    fs.appendFileSync(smbConfPath, shareConfig);
    
    // Reload Samba
    try {
      execSync('systemctl reload smbd', { stdio: 'ignore' });
    } catch (err) {
      // Samba might not be running, that's ok
      console.log('Note: Samba service not running or not installed');
    }
    
    return true;
  } catch (err) {
    console.error(`Failed to configure Samba: ${err.message}`);
    return false;
  }
}

function removeSite(siteName) {
  const sitePath = path.join(SITES_DIR, siteName);
  const smbPath = path.join(SMB_DIR, siteName);
  const nginxConfig = path.join(NGINX_AVAILABLE, siteName);
  const nginxEnabled = path.join(NGINX_ENABLED, siteName);
  
  // Remove nginx config
  try {
    if (fs.existsSync(nginxEnabled)) {
      fs.unlinkSync(nginxEnabled);
    }
    if (fs.existsSync(nginxConfig)) {
      fs.unlinkSync(nginxConfig);
    }
    reloadNginx();
  } catch (err) {
    console.error(`Failed to remove nginx config: ${err.message}`);
  }
  
  // Remove SMB symlink/directory
  try {
    if (fs.existsSync(smbPath)) {
      if (isDevelopment) {
        fs.rmSync(smbPath, { recursive: true, force: true });
      } else {
        fs.unlinkSync(smbPath);
      }
    }
  } catch (err) {
    console.error(`Failed to remove SMB link: ${err.message}`);
  }
  
  // Remove Samba share from config
  if (!isDevelopment) {
    try {
      const smbConfPath = '/etc/samba/smb.conf';
      if (fs.existsSync(smbConfPath)) {
        let smbConf = fs.readFileSync(smbConfPath, 'utf8');
        const shareRegex = new RegExp(`\\n\\[${siteName}\\][\\s\\S]*?(?=\\n\\[|$)`, 'g');
        smbConf = smbConf.replace(shareRegex, '');
        fs.writeFileSync(smbConfPath, smbConf);
        
        try {
          execSync('systemctl reload smbd', { stdio: 'ignore' });
        } catch (err) {
          // Ignore
        }
      }
    } catch (err) {
      console.error(`Failed to remove Samba share: ${err.message}`);
    }
  }
}

function provisionSite(siteName, port = 80) {
  console.log(`Provisioning site: ${siteName} on port ${port} (${isDevelopment ? 'development' : 'production'} mode)`);
  
  // Create directories
  createSiteDirectory(siteName);
  
  // Generate nginx config
  generateNginxConfig(siteName, port);
  
  // Configure Samba share
  configureSambaShare(siteName);
  
  // Reload nginx
  reloadNginx();
  
  console.log(`Site ${siteName} provisioned successfully on port ${port}`);
}

module.exports = {
  provisionSite,
  removeSite,
  createSiteDirectory,
  generateNginxConfig,
  reloadNginx,
  configureSambaShare,
  isDevelopment,
  SITES_DIR: isDevelopment ? path.join(__dirname, '../sites') : '/opt/lwui/sites'
};