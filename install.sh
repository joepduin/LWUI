#!/bin/bash

# LWUI Installation Script
# This script installs and configures Local Website UI

set -e

echo "========================================="
echo "  Local Website UI - Installation"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root (use sudo)"
  exit 1
fi

# Variables
INSTALL_DIR="/opt/lwui"
SITES_DIR="$INSTALL_DIR/sites"
SMB_DIR="/mnt/smb"
SERVICE_USER="lwui"

echo "[1/7] Installing system dependencies..."
apt-get update -qq
apt-get install -y nginx samba curl sudo > /dev/null 2>&1

# Install Node.js if not present
if ! command -v node &> /dev/null; then
    echo "Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
fi

# Install cloudflared if not present
if ! command -v cloudflared &> /dev/null; then
    echo "Installing cloudflared..."
    curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
    dpkg -i cloudflared.deb
    rm cloudflared.deb
fi

echo "[2/7] Creating directory structure..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$SITES_DIR"
mkdir -p "$SMB_DIR"
mkdir -p /etc/nginx/sites-available
mkdir -p /etc/nginx/sites-enabled

echo "[3/7] Copying application files..."
cp -r $(pwd)/* "$INSTALL_DIR/"
cd "$INSTALL_DIR"

echo "[4/7] Installing Node.js dependencies..."
npm install --production > /dev/null 2>&1

echo "[5/7] Creating system user..."
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /bin/false "$SERVICE_USER"
fi

echo "[6/7] Setting up systemd service..."
cat > /etc/systemd/system/lwui.service << 'EOF'
[Unit]
Description=Local Website UI Admin Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/lwui
ExecStart=/usr/bin/node /opt/lwui/backend/server.js
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lwui

echo "[7/7] Setting permissions..."
chown -R root:root "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"
chmod 755 "$SITES_DIR"
chmod 755 "$SMB_DIR"

echo ""
echo "========================================="
echo "  Installation Complete!"
echo "========================================="
echo ""
echo "To start the service:"
echo "  sudo systemctl start lwui"
echo ""
echo "To access the admin panel:"
echo "  http://localhost:3000"
echo ""
echo "Default credentials:"
echo "  Username: admin"
echo "  Password: localpass"
echo ""
echo "NOTE: Configure Cloudflare Tunnel in:"
echo "  $INSTALL_DIR/cloudflared/config.yml"
echo ""
