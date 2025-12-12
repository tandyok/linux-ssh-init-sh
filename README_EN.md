# Linux Server Init & SSH Hardening Script (linux-ssh-init-sh)

<p align="center">
  <img src="https://img.shields.io/badge/Shell-POSIX_sh-blue?style=flat-square" alt="POSIX Shell">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/github/v/release/247like/linux-ssh-init-sh?style=flat-square" alt="Release">
  <img src="https://img.shields.io/github/stars/247like/linux-ssh-init-sh?style=flat-square" alt="Stars">
</p>

<p align="center">
  <strong>
    <a href="README.md">🇨🇳 中文文档</a> | 🇺🇸 English
  </strong>
</p>

---

A production-ready, POSIX-compliant shell script designed to initialize Linux servers and harden SSH security in minutes.

It safely handles **SSH key deployment**, **port changing**, **user creation**, **TCP BBR enablement**, and **system updates**, while ensuring compatibility across Debian, Ubuntu, CentOS, RHEL, and Alpine Linux.

### ✨ Key Features

* **Universal Compatibility**: Works flawlessly on **Debian 10/11/12**, **Ubuntu**, **CentOS 7/8/9**, **Alma/Rocky**, and **Alpine Linux**.
* **POSIX Compliant**: Written in pure `/bin/sh`. No `bash` dependency. Runs perfectly on `dash` (Debian) and `ash` (Alpine/Busybox).
* **Safety Architecture**:
    * **Managed Config Block**: Inserts configuration at the **top** of `sshd_config` to strictly override vendor defaults (bypasses the Debian 12 `Include` trap).
    * **Atomic Verification**: Validates config with `sshd -t` before restarting. Automatically rolls back on failure to prevent downtime.
    * **Anti-Lockout**: If SSH keys fail to deploy, it **will not** disable password login, ensuring you don't lose access.
    * **Firewall Awareness**: Automatically detects and configures `ufw` or `firewalld` if port is changed.
* **Smart Interactions**:
    * Fetches public keys from **GitHub**, **URL**, or **Direct Paste**.
    * **Random High Port**: Generates a random port between 20000-60000 and checks for availability using `ss`/`netstat`.
    * **System Update** & **TCP BBR**: Optional one-click optimization.

### 🚀 Quick Start

Run the following command as **root**.

#### Standard Run (Interactive)
```bash
curl -fsSL [https://raw.githubusercontent.com/247like/linux-ssh-init-sh/main/init.sh](https://raw.githubusercontent.com/247like/linux-ssh-init-sh/main/init.sh) -o init.sh && chmod +x init.sh && ./init.sh
```

#### Force English UI
```bash
./init.sh --lang=en
```

### ⚙️ Command Line Arguments

The script accepts the following arguments to control its behavior:

| Argument | Description |
| :--- | :--- |
| `--lang=en` | Force the interactive interface to use **English**. |
| `--lang=zh` | Force the interactive interface to use **Chinese** (Default behavior asks if not specified). |
| `--strict` | **Strict Mode**. If enabled, the script will **exit immediately** if any critical step (like downloading keys or generating a port) fails, instead of falling back to defaults. Recommended for CI/CD or automated pipelines. |

### ⚙️ Strict Mode vs. Normal Mode

| Feature | Normal Mode (Default) | Strict Mode (`--strict`) |
| :--- | :--- | :--- |
| **Philosophy** | **"Don't Lockout"** (Best Effort) | **"Compliance First"** (Zero Tolerance) |
| **Key Failure** | If key download fails, script **keeps Password Auth enabled** and warns you. | Script **exits immediately**. No changes applied. |
| **Port Failure** | If random port generation fails, it falls back to **Port 22**. | Script **exits immediately**. |
| **Use Case** | Manual setup, unstable networks. | CI/CD pipelines, high-security requirements. |

### 💡 Examples

**1. Standard interactive installation (English):**
```bash
./init.sh --lang=en
```

**2. Strict mode for high-security requirements:**
*If the GitHub key cannot be downloaded, the script will abort rather than falling back to password login.*
```bash
./init.sh --strict
```

### 🛠️ Technical Logic

1.  **Dependency Check**: Auto-detects package manager (`apt`, `yum`, `apk`) and installs minimal dependencies (`curl`, `sudo`, `openssh-server`).
2.  **User Setup**: Creates the specified user (if not root) and grants password-less `sudo` privileges.
3.  **Key Deployment**: Fetches keys, validates format, fixes `.ssh` permissions (SELinux context safe), and writes to `authorized_keys`.
4.  **Config Writing**: 
    * Backs up `sshd_config`.
    * Removes old script-managed blocks.
    * Writes a new block at the **beginning** of the file to ensure priority over `Include` directives.
5.  **Finalization**: Validates config syntax, restarts SSH service, and applies BBR/Updates if requested.

---

### ⚠️ Disclaimer

This script modifies critical system configurations (SSH). While it includes multiple safety checks and automatic rollback mechanisms, **please ensure you have an alternative access method** (such as a VNC/KVM Console) to your server to prevent lockout in case of network interruptions or unexpected configuration errors.

### 📄 License

This project is released under the [MIT License](LICENSE).

---

<div align="center">

If you found this tool helpful, please give it a ⭐ Star!

[Report Bug](https://github.com/247like/linux-ssh-init-sh/issues) · [Request Feature](https://github.com/247like/linux-ssh-init-sh/issues)

</div>
