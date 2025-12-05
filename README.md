# 🌐 Local Website UI (LWUI)

[![Status](https://img.shields.io/badge/status-active--development-orange?style=for-the-badge)]()
[![License](https://img.shields.io/badge/license-AGPLv3-blue?style=for-the-badge)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-green?style=for-the-badge&logo=node.js)]()
[![Cloudflare Tunnel](https://img.shields.io/badge/Cloudflare-Tunnel-orange?style=for-the-badge&logo=cloudflare)]()

---

## 🧩 Overview

**Local Website UI (LWUI)** is a self-hosted tool to **run and manage local websites** with **secure public access** through **Cloudflare Tunnels**.  
It provides an **admin panel** to easily create sites, manage Cloudflare settings, and edit files directly in your browser.

---

## ✨ Key Features

- ✅ Host **multiple local websites**
- 🔒 Secure exposure via **Cloudflare Tunnel**
- ⚙️ **Admin panel** for sites, tunnels, and settings
- 📂 In-browser **file management**
- 🔄 Auto-generate & update **NGINX configs**
- 📊 Monitor **server & tunnel status**
- 👥 **Role-based user management**
- 🔐 **2FA (TOTP)** and **password reset**
- 📧 **Email notifications** for critical events
- 🛡️ **Hardened API layer** with Helmet, compression, smart rate limiting, and sandboxed file writes
- 🔔 **Responsive toast UX** and global loading states so every action feels instant and transparent

---

## 🧰 Tech Stack

| Component        | Technology                        |
|------------------|------------------------------------|
| **Admin Panel**  | Node.js + Express                  |
| **Web Server**   | NGINX                              |
| **Public Access**| Cloudflare Tunnel (`cloudflared`)  |
| **Auth**         | Sessions, SHA-256, TOTP            |
| **Frontend**     | Vanilla ES modules                 |
| **Storage**      | JSON files on disk                 |
| **OS**           | Linux (Ubuntu / Debian)            |

---

## 🚀 Getting Started

> **Requirements:**  
> Linux (systemd), Node.js 18+, Cloudflare account, root privileges (for production install)

1. **Clone the repo**
   ```bash
   git clone https://github.com/joepduin/LWUI.git
   cd lwui

2. **Run the installer**

   ```bash
   sudo ./install.sh
   ```

3. **Start the service**

   ```bash
   sudo systemctl start lwui
   ```

4. **Access the Admin Panel**

   ```
   http://localhost:3000
   ```

5. **Login credentials**

   * Username: `admin`
   * Password: `localpass`
     ⚠️ *Change the password immediately!*

---


## 🖥️ Admin Panel Overview

| Section               | Description                                    |
| --------------------- | ---------------------------------------------- |
| **Dashboard**         | View RAM usage, tunnel status, and logs        |
| **Sites**             | Create, edit, and delete websites              |
| **Files**             | Browse and edit files directly                 |
| **Cloudflare Tunnel** | Configure tunnel credentials and ingress rules |
| **Users**             | Manage accounts and permissions                |
| **Settings**          | Change passwords, enable 2FA, configure SMTP   |

---

## ⚙️ Configuration

### 🌩️ Cloudflare Tunnel

1. Authenticate:

   ```bash
   sudo cloudflared tunnel login
   ```
2. Create a tunnel:

   ```bash
   sudo cloudflared tunnel create lwui
   ```
3. In the Admin Panel → **Cloudflare Tunnel**:

   * Enter **Tunnel ID** and **credentials path**
   * Manage **ingress rules** directly

---

### 📧 SMTP Mail

Go to **Settings → Mail Server Configuration** and set:

* Host, port, TLS
* Username, password *(use app password if possible)*
* “From” address and app URL

---


## 🗂️ Directory Structure

```
/opt/lwui/
├── sites/           # Website files
├── backend/         # Backend server code
├── public/          # Frontend files
├── nginx/           # NGINX templates
├── cloudflared/     # Cloudflare configs
└── data/            # User & site data
```

---

## 🔒 Security Guidelines

* Restrict **admin panel** access (localhost / VPN)
* Change default credentials ASAP
* Enable **2FA** for admins
* Use **app passwords** for SMTP
* Keep your system updated
* Monitor logs regularly
* LWUI now ships with **Helmet**, strict JSON limits, per-route rate limiting, and safer file sandboxing—keep these protections enabled

Supports **Cloudflare Zero Trust** for enhanced protection.

---

## 🤝 Contributing

We welcome all contributions!

* 🐛 Report bugs or request features via **GitHub Issues**
* 🔧 Submit **Pull Requests**
* 📩 Contact: [info@joepduin.dev](mailto:info@joepduin.dev)

See [DEVELOPMENT.md](https://github.com/joepduin/LWUI/wiki/Development) for contribution guidelines.

---

## 📜 License

**GNU Affero General Public License v3.0**
See [LICENSE](LICENSE) for full details.

---

## 👤 Author

* 🌐 GitHub: [@joepduin](https://github.com/joepduin)
* ✉️ Email: [info@joepduin.dev](mailto:info@joepduin.dev)

