# Linux Server Init & SSH Hardening Script (linux-ssh-init-sh)

<p align="center">
  <img src="https://img.shields.io/badge/Shell-POSIX_sh-blue?style=flat-square" alt="POSIX Shell">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/github/v/release/247like/linux-ssh-init-sh?style=flat-square" alt="Release">
</p>

<p align="center">
  <strong>
    <a href="#-english">📖 English</a> | <a href="#-中文文档">📖 中文文档</a>
  </strong>
</p>

---

<div id="-english"></div>

## 📖 English

A production-ready, POSIX-compliant shell script designed to initialize Linux servers and harden SSH security in minutes.

### ✨ Key Features

* **Universal Compatibility**: Works flawlessly on **Debian 10/11/12**, **Ubuntu**, **CentOS 7/8/9**, **Alma/Rocky**, and **Alpine Linux**.
* **POSIX Compliant**: Written in pure `/bin/sh`. No `bash` dependency.
* **Safety Architecture**:
    * **Managed Config Block**: Inserts configuration at the **top** of `sshd_config` to strictly override vendor defaults (bypasses the Debian 12 `Include` trap).
    * **Anti-Lockout**: Smart fallback mechanisms to prevent locking yourself out (see *Strict Mode* below).
    * **Firewall Awareness**: Automatically configures `ufw` or `firewalld` when changing ports.
* **Automation**:
    * **SSH Keys**: Imports from GitHub/URL/Paste.
    * **Random Port**: Generates valid random high ports (20000-60000).
    * **Optimization**: One-click System Update & TCP BBR.

### 🚀 Quick Start

Run as **root**:

```bash
curl -fsSL [https://raw.githubusercontent.com/247like/linux-ssh-init-sh/main/init.sh](https://raw.githubusercontent.com/247like/linux-ssh-init-sh/main/init.sh) -o init.sh && chmod +x init.sh && ./init.sh
