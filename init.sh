#!/bin/sh
# =========================================================
# linux-ssh-init-sh
# Server Init & SSH Hardening Script
#
# Author:  247like
# GitHub:  https://github.com/247like/linux-ssh-init-sh
# License: MIT
#
# Release: v4.6.2 (Fortress Pro - Final Audit Fix)
#
# POSIX sh compatible (Debian dash / CentOS / Alpine / Ubuntu)
#
# Changelog v4.6.2:
#   - [SEC] Fix: deploy_keys() now refuses symlinks (local privilege escalation)
#   - [SEC] Fix: Removed chown -R (symlink traversal risk)
#   - [SEC] Fix: Added KbdInteractiveAuthentication no for true key-only auth
#   - Fix: cleanup_old_backups() awk logic bug (was deleting all backups)
#   - Fix: Use 127.0.0.1 instead of localhost in tests (IPv6 mismatch)
#   - Fix: Removed rsa-sha2-256/512 from key type regex
#   - Fix: --delay-restart now skips listen/connection tests
#   - Fix: safe_configure_sudo grep prefix match issue
#   - Fix: Case-insensitive sshd_config directive matching
#   - Fix: Replaced awk IGNORECASE with tolower() for mawk/BusyBox compatibility
#   - Fix: Changed chown user:user to chown user: for default group handling
# =========================================================

set -u
SCRIPT_START_TIME=$(date +%s)

# ---------------- Configuration ----------------
LANG_CUR="zh"
LOG_FILE="/var/log/server-init.log"
AUDIT_FILE="/var/log/server-init-audit.log"
BACKUP_REPO="/var/backups/ssh-config"
SSH_CONF="/etc/ssh/sshd_config"
SSH_CONF_D="/etc/ssh/sshd_config.d"
DEFAULT_USER="deploy"
BLOCK_BEGIN="# BEGIN SERVER-INIT MANAGED BLOCK"
BLOCK_END="# END SERVER-INIT MANAGED BLOCK"

# ---------------- [SEC] Atomic Secure Temp Directory ----------------
old_umask=$(umask)
umask 077
TMP_DIR=""
if command -v mktemp >/dev/null 2>&1; then
  TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t ssh-init-XXXXXX 2>/dev/null || echo "")
fi
if [ -z "$TMP_DIR" ]; then
  rand_suffix=""
  if [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
    rand_suffix=$(od -An -N4 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
  fi
  [ -z "$rand_suffix" ] && rand_suffix="$$"
  TMP_DIR="/tmp/ssh-init.${$}.${rand_suffix}.$(date +%s 2>/dev/null || echo 0)"
  # [SEC-FIX] Use mkdir without -p to avoid reusing existing directories
  mkdir "$TMP_DIR" 2>/dev/null || {
    # Retry with different name
    TMP_DIR="/tmp/ssh-init.${rand_suffix}.$$"
    mkdir "$TMP_DIR" 2>/dev/null || { echo "FATAL: Cannot create temp directory: $TMP_DIR" >&2; exit 1; }
  }
fi
chmod 700 "$TMP_DIR" 2>/dev/null || true
umask "$old_umask"

# ---------------- [SEC] State & Lock Management ----------------
RUNTIME_DIR=""
for try_dir in "/run/server-init" "/var/lib/server-init"; do
  if mkdir -p "$try_dir" 2>/dev/null; then
    RUNTIME_DIR="$try_dir"
    break
  fi
done

if [ -z "$RUNTIME_DIR" ]; then
  rand_rt=""
  if [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
    rand_rt=$(od -An -N4 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
  fi
  [ -z "$rand_rt" ] && rand_rt="$$"
  RUNTIME_DIR="/tmp/server-init.${rand_rt}.$(date +%s 2>/dev/null || echo 0)"
  # [SEC-FIX] Use mkdir without -p
  if ! mkdir "$RUNTIME_DIR" 2>/dev/null; then
    if command -v mktemp >/dev/null 2>&1; then
      RUNTIME_DIR=$(mktemp -d /tmp/server-init.XXXXXX 2>/dev/null || echo "")
    fi
  fi
  [ -n "$RUNTIME_DIR" ] && [ -d "$RUNTIME_DIR" ] || { echo "FATAL: Cannot create runtime directory" >&2; exit 1; }
fi
chmod 700 "$RUNTIME_DIR" 2>/dev/null || true

STATE_FILE="$RUNTIME_DIR/state-$(id -u)"
LOCK_DIR="$RUNTIME_DIR/locks-$(id -u)"

[ -L "$STATE_FILE" ] && rm -f "$STATE_FILE" 2>/dev/null || true
if [ -e "$LOCK_DIR" ] && [ ! -d "$LOCK_DIR" ]; then
  rm -f "$LOCK_DIR" 2>/dev/null || true
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ---------------- Initialize Variables ----------------
TARGET_USER=""
SSH_PORT="22"
KEY_OK="n"
PORT_OPT="1"
KEY_TYPE=""
KEY_VAL=""
DO_UPDATE="n"
DO_BBR="n"
OPENSSH_VER_MAJOR=0
OPENSSH_VER_MINOR=0

KEX_LINE=""
CIPHERS_LINE=""
MACS_LINE=""
CRYPTO_MODE="skip"
IPV6_ENABLED="n"
ROOT_KEY_PRESENT="n"
SUPPORTS_KBD_INTERACTIVE="n"

# ---------------- Automation Variables ----------------
ARG_USER=""
ARG_PORT=""
ARG_KEY_TYPE=""
ARG_KEY_VAL=""
ARG_UPDATE=""
ARG_BBR=""
AUTO_CONFIRM="n"
STRICT_MODE="n"
ARG_DELAY_RESTART="n"

# Parse Arguments
for a in "$@"; do
  case "$a" in
    --lang=zh)     LANG_CUR="zh" ;;
    --lang=en)     LANG_CUR="en" ;;
    --strict)      STRICT_MODE="y" ;;
    --yes)         AUTO_CONFIRM="y" ;;
    --user=*)      ARG_USER="${a#*=}" ;;
    --port=random) ARG_PORT="random" ;;
    --port=*)      ARG_PORT="${a#*=}" ;;
    --key-gh=*)    ARG_KEY_TYPE="gh";  ARG_KEY_VAL="${a#*=}" ;;
    --key-url=*)   ARG_KEY_TYPE="url"; ARG_KEY_VAL="${a#*=}" ;;
    --key-raw=*)   ARG_KEY_TYPE="raw"; ARG_KEY_VAL="${a#*=}" ;;
    --update)      ARG_UPDATE="y" ;;
    --no-update)   ARG_UPDATE="n" ;;
    --bbr)         ARG_BBR="y" ;;
    --no-bbr)      ARG_BBR="n" ;;
    --delay-restart) ARG_DELAY_RESTART="y" ;;
  esac
done

# ---------------- Internationalization ----------------
msg() {
  key="$1"
  if [ "$LANG_CUR" = "zh" ]; then
    case "$key" in
      MUST_ROOT)    echo "必须以 root 权限运行此脚本" ;;
      BANNER)       echo "服务器初始化 & SSH 安全加固 (v4.6.2 Fortress Pro)" ;;
      STRICT_ON)    echo "STRICT 模式已开启：任何关键错误将直接退出" ;;
      ASK_USER)     echo "SSH 登录用户 (默认 " ;;
      ERR_USER_INV) echo "❌ 用户名无效 (仅限小写字母/数字/下划线，且避开系统保留名)" ;;
      ASK_PORT_T)   echo "SSH 端口配置：" ;;
      OPT_PORT_1)   echo "1) 使用 22 (默认)" ;;
      OPT_PORT_2)   echo "2) 随机高端口 (49152+, 自动避开 K8s)" ;;
      OPT_PORT_3)   echo "3) 手动指定" ;;
      SELECT)       echo "请选择 [1-3]: " ;;
      INPUT_PORT)   echo "请输入端口号 (1024-65535): " ;;
      PORT_ERR)     echo "❌ 端口输入无效 (非数字或超范围)" ;;
      PORT_RES)     echo "❌ 端口被系统保留或不建议使用 (如 80, 443, 3306 等)" ;;
      PORT_K8S)     echo "⚠️  警告: 此端口位于 Kubernetes NodePort 常用范围 (30000-32767)，可能冲突" ;;
      ASK_KEY_T)    echo "SSH 公钥来源：" ;;
      OPT_KEY_1)    echo "1) GitHub 用户导入" ;;
      OPT_KEY_2)    echo "2) URL 下载" ;;
      OPT_KEY_3)    echo "3) 手动粘贴" ;;
      INPUT_GH)     echo "请输入 GitHub 用户名: " ;;
      INPUT_URL)    echo "请输入公钥 URL: " ;;
      INPUT_RAW)    echo "请粘贴公钥内容 (空行结束输入): " ;;
      ASK_UPD)      echo "是否更新系统软件包? [y/n] (默认 n): " ;;
      ASK_BBR)      echo "是否开启 BBR 加速? [y/n] (默认 n): " ;;
      CONFIRM_T)    echo "---------------- 执行确认 ----------------" ;;
      C_USER)       echo "登录用户: " ;;
      C_PORT)       echo "端口模式: " ;;
      C_KEY)        echo "密钥来源: " ;;
      C_UPD)        echo "系统更新: " ;;
      C_BBR)        echo "开启 BBR: " ;;
      WARN_FW)      echo "⚠ 注意：修改端口前，请确认云厂商防火墙/安全组已放行对应 TCP 端口" ;;
      ASK_SURE)     echo "确认执行? [y/n]: " ;;
      CANCEL)       echo "已取消操作" ;;
      I_INSTALL)    echo "正在安装基础依赖..." ;;
      I_UPD)        echo "正在更新系统..." ;;
      I_BBR)        echo "正在配置 BBR..." ;;
      I_USER)       echo "正在配置用户..." ;;
      I_SSH_INSTALL) echo "未检测到 OpenSSH，正在安装..." ;;
      I_KEY_OK)     echo "公钥部署成功" ;;
      W_KEY_FAIL)   echo "公钥部署失败，将启用安全回退策略以避免失联" ;;
      I_BACKUP)     echo "已全量备份配置 (SSH/User/Firewall): " ;;
      E_SSHD_CHK)   echo "sshd 配置校验失败，正在回滚..." ;;
      E_GREP_FAIL)  echo "配置验证失败：关键参数未生效，正在回滚..." ;;
      E_RESTART)    echo "SSH 服务重启失败，正在回滚..." ;;
      W_RESTART)    echo "无法自动重启 SSH 服务，请手动重启" ;;
      W_LISTEN_FAIL) echo "SSHD 已重启但端口未监听，可能启动失败，正在回滚..." ;;
      DONE_T)       echo "================ 完成 ================" ;;
      DONE_MSG1)    echo "请【不要关闭】当前窗口。" ;;
      DONE_MSG2)    echo "请新开一个终端窗口测试登录：" ;;
      DONE_FW)      echo "⚠ 若无法连接，请再次检查防火墙设置" ;;
      AUTO_SKIP)    echo "检测到参数输入，跳过询问: " ;;
      RB_START)     echo "脚本执行出现关键错误，开始自动回滚..." ;;
      RB_DONE)      echo "回滚完成。系统状态已恢复。" ;;
      RB_FAIL)      echo "致命错误：回滚失败！请立即手动检查 /etc/ssh/sshd_config" ;;
      SELINUX_DET)  echo "检测到 SELinux Enforcing 模式，正在配置端口规则..." ;;
      SELINUX_OK)   echo "SELinux 端口规则添加成功" ;;
      SELINUX_FAIL) echo "SELinux 规则添加失败，请手动执行: semanage port -a -t ssh_port_t -p tcp PORT" ;;
      SELINUX_INS)  echo "正在安装 SELinux 管理工具..." ;;
      CLEAN_D)      echo "检测到冲突的配置片段，已备份并移除: " ;;
      TEST_CONN)    echo "正在进行 SSH 连接测试 (IPv4/Local)..." ;;
      TEST_OK)      echo "SSH 连接测试通过" ;;
      TEST_FAIL)    echo "SSH 连接测试全部失败！新配置可能无法连接，正在回滚..." ;;
      IPV6_CFG)     echo "检测到全局 IPv6 环境，已添加 :: 监听支持" ;;
      SYS_PROT)     echo "正在添加 systemd 服务防误杀保护..." ;;
      MOTD_UPD)     echo "正在更新登录提示信息 (MotD)..." ;;
      COMPAT_WARN)  echo "检测到兼容性限制，已自动调整配置..." ;;
      AUDIT_START)  echo "开始执行审计记录..." ;;
      BOX_TITLE)    echo "初始化完成 - 安全配置已生效" ;;
      BOX_SSH)      echo "SSH 连接信息:" ;;
      BOX_KEY_ON)   echo "🔐 密钥认证: 已启用 (密码登录已禁用)" ;;
      BOX_KEY_OFF)  echo "⚠️ 密钥认证: 未启用 (密码登录保持可用/回退策略已启用)" ;;
      BOX_PORT)     echo "📍 端口变更: 22 → " ;;
      BOX_FW)       echo "⚠️  请确认防火墙已开放 TCP 端口" ;;
      BOX_WARN)     echo "重要: 请在新窗口中测试连接，确认成功后再关闭此窗口！" ;;
      BOX_K8S_WARN) echo "⚠️  注意: 使用了 Kubernetes NodePort 范围端口" ;;
      ERR_MISSING)  echo "❌ 缺少必要命令，无法继续: " ;;
      ERR_MISSING_SSHD) echo "❌ 未找到 sshd 命令，请先安装 OpenSSH Server" ;;
      WARN_DISK)    echo "⚠️  磁盘空间不足: " ;;
      WARN_MEM)     echo "⚠️  可用内存不足: " ;;
      WARN_RESUME)  echo "检测到未完成的初始化，可能上次执行异常终止" ;;
      ASK_RESUME)   echo "检测到未完成的操作，是否继续? [y/N]: " ;;
      ERR_BACKUP_DIR) echo "❌ 无法创建备份目录:" ;;
      ERR_BACKUP_DIR_ALT) echo "❌ 无法创建备用备份目录" ;;
      ERR_BACKUP_SUBDIR) echo "❌ 无法创建备份子目录:" ;;
      INFO_BACKUP_CREATED) echo "✅ 备份已创建:" ;;
      INFO_CLEANING_BACKUPS) echo "🧹 正在清理" ;;
      INFO_OLD_BACKUPS) echo "个旧备份..." ;;
      ERR_LOCK_DIR) echo "❌ 无法创建锁目录:" ;;
      WARN_LOCK_DIR_PERM) echo "⚠️ 无法设置锁目录权限，继续尝试..." ;;
      WARN_CLEAN_LOCKS) echo "⚠️ 清理旧的锁文件..." ;;
      WARN_INVALID_KEY) echo "⚠️ 跳过无效的SSH密钥行" ;;
      WARN_SHORT_RSA_KEY) echo "⚠️ RSA密钥过短:" ;;
      WARN_SHORT_ED25519_KEY) echo "⚠️ Ed25519密钥过短:" ;;
      WARN_SHORT_DSA_KEY) echo "⚠️ DSA密钥过短:" ;;
      ERR_INVALID_KEY_FORMAT) echo "❌ SSH密钥格式无效" ;;
      ERR_MISSING_BASE64) echo "❌ SSH密钥缺少base64部分" ;;
      ERR_INVALID_BASE64) echo "❌ SSH密钥base64编码无效" ;;
      WARN_NO_BASE64_SKIPLEN) echo "⚠️ 未检测到 base64 命令：将跳过密钥长度校验，仅做格式校验" ;;
      WARN_USER_SHELL) echo "⚠️ 用户shell不允许登录:" ;;
      ASK_CHANGE_SHELL) echo "是否更改用户的shell为/bin/bash? [y/N]: " ;;
      WARN_CHANGE_SHELL_FAIL) echo "⚠️ 更改shell失败" ;;
      WARN_UNUSUAL_SHELL) echo "⚠️ 用户使用非常规shell:" ;;
      WARN_HOME_OWNER) echo "⚠️ 用户家目录所有者异常:" ;;
      WARN_HOME_NOT_WRITABLE) echo "⚠️ 用户家目录不可写" ;;
      ERR_USER_CREATE_FAIL) echo "❌ 创建用户失败" ;;
      ERR_USER_VERIFY_FAIL) echo "❌ 用户创建后验证失败" ;;
      WARN_NO_SUDOERS_DIR) echo "⚠️ 没有/etc/sudoers.d目录，跳过sudo配置" ;;
      INFO_SUDO_EXISTS) echo "ℹ️ 用户已配置sudo权限" ;;
      ERR_SUDOERS_SYNTAX) echo "❌ sudoers文件语法错误，已删除" ;;
      ERR_SUDOERS_PERM) echo "❌ 无法设置sudoers文件权限" ;;
      INFO_SUDO_CONFIGURED) echo "✅ 为用户配置了sudo权限" ;;
      WARN_SSH_PROTOCOL) echo "⚠️ SSH协议握手失败或超时" ;;
      INFO_SSH_PROTOCOL_OK) echo "✅ SSH协议握手成功" ;;
      WARN_PORT_OPEN_BUT_FAIL) echo "⚠️ 端口已打开，但SSH客户端连接失败(通常因无私钥或默认私钥不匹配)。此非错误，请务必人工测试连接！" ;;
      WARN_X11_FORWARDING) echo "⚠️ X11转发已启用，可能存在安全风险" ;;
      WARN_EMPTY_PASSWORDS) echo "⚠️ 允许空密码，存在安全风险" ;;
      WARN_INSECURE_OPTIONS) echo "⚠️ 检测到非关键的不安全选项 (仅提示，不影响安装)" ;;
      ERR_DEADLOCK) echo "❌ 致命错误：密码和密钥认证同时被禁用，将导致锁定！" ;;
      ERR_PASSWORD_NO_KEY) echo "❌ 致命错误：密码认证已禁用但未成功部署SSH密钥" ;;
      ERR_ROOT_NO_KEY) echo "❌ 致命错误：root密码登录已禁用但未部署SSH密钥" ;;
      WARN_PORT_MISMATCH) echo "⚠️ 配置中的端口与目标端口不匹配" ;;
      ERR_CANNOT_RESERVE_PORT) echo "❌ 无法预留端口，端口可能已被占用" ;;
      INFO_OLD_SSH_SKIP_ALGO) echo "ℹ️ OpenSSH较旧或无法检测支持列表：跳过现代加密算法强制配置" ;;
      INFO_SANITIZE_DUP) echo "ℹ️ 清理原配置文件中的重复指令..." ;;
      INFO_MATCH_INSERT) echo "ℹ️ 检测到 Match 块：托管配置将插入到首个 Match 之前，以避免语法/作用域问题" ;;
      ERR_NO_BANNER) echo "❌ 未能获取 SSH-2.0 协议 banner，服务可能未正常启动" ;;
      INFO_KEYS_DEPLOYED) echo "✅ 成功部署密钥数量:" ;;
      WARN_NO_VALID_KEYS) echo "⚠️ 没有有效的SSH密钥被部署" ;;
      ERR_HOME_SYMLINK) echo "❌ 拒绝：用户家目录是符号链接" ;;
      ERR_SSH_DIR_SYMLINK) echo "❌ 拒绝：.ssh 目录是符号链接" ;;
      ERR_AUTH_KEYS_SYMLINK) echo "❌ 拒绝：authorized_keys 是符号链接" ;;
      ERR_HOME_NOT_DIR) echo "❌ 拒绝：用户家目录不是目录" ;;
      ERR_SSH_DIR_NOT_DIR) echo "❌ 拒绝：.ssh 存在但不是目录" ;;
      ERR_AUTH_KEYS_NOT_FILE) echo "❌ 拒绝：authorized_keys 存在但不是普通文件" ;;
      DELAY_RESTART_MSG) echo "⚠️ 延迟重启模式：配置已写入，请手动重启 sshd 并测试连接" ;;
      *) echo "$key" ;;
    esac
  else
    case "$key" in
      MUST_ROOT)    echo "Must be run as root" ;;
      BANNER)       echo "Server Init & SSH Hardening (v4.6.2 Fortress Pro)" ;;
      STRICT_ON)    echo "STRICT mode ON: Critical errors will abort" ;;
      ASK_USER)     echo "SSH Login User (default " ;;
      ERR_USER_INV) echo "❌ Invalid username (lowercase/digits/underscore only, no reserved words)" ;;
      ASK_PORT_T)   echo "SSH Port Configuration:" ;;
      OPT_PORT_1)   echo "1) Use 22 (Default)" ;;
      OPT_PORT_2)   echo "2) Random High Port (49152+, avoids K8s)" ;;
      OPT_PORT_3)   echo "3) Manual Input" ;;
      SELECT)       echo "Select [1-3]: " ;;
      INPUT_PORT)   echo "Enter Port (1024-65535): " ;;
      PORT_ERR)     echo "❌ Invalid port (not numeric or out of range)" ;;
      PORT_RES)     echo "❌ Port is reserved (e.g. 80, 443, 3306)" ;;
      PORT_K8S)     echo "⚠️  Warning: Port falls in Kubernetes NodePort range (30000-32767)" ;;
      ASK_KEY_T)    echo "SSH Public Key Source:" ;;
      OPT_KEY_1)    echo "1) GitHub User" ;;
      OPT_KEY_2)    echo "2) URL Download" ;;
      OPT_KEY_3)    echo "3) Manual Paste" ;;
      INPUT_GH)     echo "Enter GitHub Username: " ;;
      INPUT_URL)    echo "Enter Key URL: " ;;
      INPUT_RAW)    echo "Paste Key (Empty line to finish): " ;;
      ASK_UPD)      echo "Update system packages? [y/n] (default n): " ;;
      ASK_BBR)      echo "Enable TCP BBR? [y/n] (default n): " ;;
      CONFIRM_T)    echo "---------------- Confirmation ----------------" ;;
      C_USER)       echo "User: " ;;
      C_PORT)       echo "Port: " ;;
      C_KEY)        echo "Key Source: " ;;
      C_UPD)        echo "Update: " ;;
      C_BBR)        echo "Enable BBR: " ;;
      WARN_FW)      echo "⚠ WARNING: Ensure Cloud Firewall/Security Group allows the new TCP port" ;;
      ASK_SURE)     echo "Proceed? [y/n]: " ;;
      CANCEL)       echo "Cancelled." ;;
      I_INSTALL)    echo "Installing dependencies..." ;;
      I_UPD)        echo "Updating system..." ;;
      I_BBR)        echo "Configuring BBR..." ;;
      I_USER)       echo "Configuring user..." ;;
      I_SSH_INSTALL) echo "OpenSSH not found, installing..." ;;
      I_KEY_OK)     echo "SSH Key deployed successfully" ;;
      W_KEY_FAIL)   echo "Key deployment failed; enabling fallback policy to avoid lockout" ;;
      I_BACKUP)     echo "Full backup created (SSH/User/Firewall): " ;;
      E_SSHD_CHK)   echo "sshd config validation failed, rolling back..." ;;
      E_GREP_FAIL)  echo "Config validation failed: Critical settings not active. Rolling back..." ;;
      E_RESTART)    echo "SSH service restart failed, rolling back..." ;;
      W_RESTART)    echo "Could not restart sshd automatically. Please restart manually." ;;
      W_LISTEN_FAIL) echo "SSHD restarted but port is not listening. Rolling back..." ;;
      DONE_T)       echo "================ DONE ================" ;;
      DONE_MSG1)    echo "Please DO NOT close this window yet." ;;
      DONE_MSG2)    echo "Open a NEW terminal to test login:" ;;
      DONE_FW)      echo "⚠ If connection fails, check your Firewall settings." ;;
      AUTO_SKIP)    echo "Argument detected, skipping prompt: " ;;
      RB_START)     echo "Critical error. Starting automatic rollback..." ;;
      RB_DONE)      echo "Rollback complete. System state restored." ;;
      RB_FAIL)      echo "FATAL: Rollback failed! Manually check /etc/ssh/sshd_config" ;;
      SELINUX_DET)  echo "SELinux Enforcing detected. Configuring port rules..." ;;
      SELINUX_OK)   echo "SELinux port rule added successfully." ;;
      SELINUX_FAIL) echo "SELinux rule failed. Manually run: semanage port -a -t ssh_port_t -p tcp PORT" ;;
      SELINUX_INS)  echo "Installing SELinux management tools..." ;;
      CLEAN_D)      echo "Detected conflicting config fragment, backed up and removed: " ;;
      TEST_CONN)    echo "Testing SSH connection (IPv4/Local)..." ;;
      TEST_OK)      echo "SSH connection test passed." ;;
      TEST_FAIL)    echo "SSH connection test FAILED! Rolling back..." ;;
      IPV6_CFG)     echo "Global IPv6 detected. Added listen address :: support." ;;
      SYS_PROT)     echo "Adding systemd service protection (anti-kill)..." ;;
      MOTD_UPD)     echo "Updating Message of the Day (MotD)..." ;;
      COMPAT_WARN)  echo "Compatibility limits detected; adjusted configuration automatically..." ;;
      AUDIT_START)  echo "Starting audit logging..." ;;
      BOX_TITLE)    echo "Init Complete - Security Applied" ;;
      BOX_SSH)      echo "SSH Connection Info:" ;;
      BOX_KEY_ON)   echo "🔐 Key Auth: ENABLED (Password Disabled)" ;;
      BOX_KEY_OFF)  echo "⚠️ Key Auth: DISABLED (Password/Fallback Enabled)" ;;
      BOX_PORT)     echo "📍 Port Change: 22 → " ;;
      BOX_FW)       echo "⚠️  Verify Firewall Open for TCP Port" ;;
      BOX_WARN)     echo "IMPORTANT: Test connection in NEW window before closing this one!" ;;
      BOX_K8S_WARN) echo "⚠️  NOTE: Using K8s NodePort range" ;;
      ERR_MISSING)  echo "❌ Missing essential commands: " ;;
      ERR_MISSING_SSHD) echo "❌ sshd command not found, please install OpenSSH Server first" ;;
      WARN_DISK)    echo "⚠️  Low disk space: " ;;
      WARN_MEM)     echo "⚠️  Low memory: " ;;
      WARN_RESUME)  echo "Detected incomplete initialization, last execution may have crashed" ;;
      ASK_RESUME)   echo "Detected incomplete operation, continue? [y/N]: " ;;
      ERR_BACKUP_DIR) echo "❌ Cannot create backup directory:" ;;
      ERR_BACKUP_DIR_ALT) echo "❌ Cannot create alternative backup directory" ;;
      ERR_BACKUP_SUBDIR) echo "❌ Cannot create backup subdirectory:" ;;
      INFO_BACKUP_CREATED) echo "✅ Backup created:" ;;
      INFO_CLEANING_BACKUPS) echo "🧹 Cleaning" ;;
      INFO_OLD_BACKUPS) echo "old backups..." ;;
      ERR_LOCK_DIR) echo "❌ Cannot create lock directory:" ;;
      WARN_LOCK_DIR_PERM) echo "⚠️ Cannot set lock directory permissions, continuing..." ;;
      WARN_CLEAN_LOCKS) echo "⚠️ Cleaning old lock files..." ;;
      WARN_INVALID_KEY) echo "⚠️ Skipping invalid SSH key line" ;;
      WARN_SHORT_RSA_KEY) echo "⚠️ RSA key too short:" ;;
      WARN_SHORT_ED25519_KEY) echo "⚠️ Ed25519 key too short:" ;;
      WARN_SHORT_DSA_KEY) echo "⚠️ DSA key too short:" ;;
      ERR_INVALID_KEY_FORMAT) echo "❌ SSH key format invalid" ;;
      ERR_MISSING_BASE64) echo "❌ SSH key missing base64 part" ;;
      ERR_INVALID_BASE64) echo "❌ SSH key base64 encoding invalid" ;;
      WARN_NO_BASE64_SKIPLEN) echo "⚠️ base64 not found: skipping key length checks (format-only validation)" ;;
      WARN_USER_SHELL) echo "⚠️ User shell does not allow login:" ;;
      ASK_CHANGE_SHELL) echo "Change user's shell to /bin/bash? [y/N]: " ;;
      WARN_CHANGE_SHELL_FAIL) echo "⚠️ Failed to change shell" ;;
      WARN_UNUSUAL_SHELL) echo "⚠️ User uses unusual shell:" ;;
      WARN_HOME_OWNER) echo "⚠️ User home directory owner mismatch:" ;;
      WARN_HOME_NOT_WRITABLE) echo "⚠️ User home directory not writable" ;;
      ERR_USER_CREATE_FAIL) echo "❌ Failed to create user" ;;
      ERR_USER_VERIFY_FAIL) echo "❌ User verification failed after creation" ;;
      WARN_NO_SUDOERS_DIR) echo "⚠️ No /etc/sudoers.d directory, skipping sudo config" ;;
      INFO_SUDO_EXISTS) echo "ℹ️ User already has sudo permissions" ;;
      ERR_SUDOERS_SYNTAX) echo "❌ sudoers file syntax error, deleted" ;;
      ERR_SUDOERS_PERM) echo "❌ Cannot set sudoers file permissions" ;;
      INFO_SUDO_CONFIGURED) echo "✅ Configured sudo permissions for user" ;;
      WARN_SSH_PROTOCOL) echo "⚠️ SSH protocol handshake failed or timed out" ;;
      INFO_SSH_PROTOCOL_OK) echo "✅ SSH protocol handshake successful" ;;
      WARN_PORT_OPEN_BUT_FAIL) echo "⚠️ Port is open, but SSH connection failed (likely due to missing/mismatched private key). This is NOT an error. Please verify connection manually!" ;;
      WARN_X11_FORWARDING) echo "⚠️ X11 forwarding enabled, potential security risk" ;;
      WARN_EMPTY_PASSWORDS) echo "⚠️ Empty passwords allowed, security risk" ;;
      WARN_INSECURE_OPTIONS) echo "⚠️ Found non-critical insecure options (Info only, proceeding)" ;;
      ERR_DEADLOCK) echo "❌ FATAL: Both password and key authentication disabled, will cause lockout!" ;;
      ERR_PASSWORD_NO_KEY) echo "❌ FATAL: Password auth disabled but no SSH key deployed" ;;
      ERR_ROOT_NO_KEY) echo "❌ FATAL: Root password login disabled but no SSH key deployed" ;;
      WARN_PORT_MISMATCH) echo "⚠️ Port in config does not match target port" ;;
      ERR_CANNOT_RESERVE_PORT) echo "❌ Cannot reserve port, port may be occupied" ;;
      INFO_OLD_SSH_SKIP_ALGO) echo "ℹ️ Old OpenSSH or unable to detect supported lists: skipping forced crypto algorithms" ;;
      INFO_SANITIZE_DUP) echo "ℹ️ Sanitizing duplicate directives in original config..." ;;
      INFO_MATCH_INSERT) echo "ℹ️ Match blocks detected: inserting managed block before first Match to avoid scope issues" ;;
      ERR_NO_BANNER) echo "❌ Failed to get SSH-2.0 protocol banner, service may not be running properly" ;;
      INFO_KEYS_DEPLOYED) echo "✅ Number of keys deployed:" ;;
      WARN_NO_VALID_KEYS) echo "⚠️ No valid SSH keys were deployed" ;;
      ERR_HOME_SYMLINK) echo "❌ Refuse: user home is symlink" ;;
      ERR_SSH_DIR_SYMLINK) echo "❌ Refuse: .ssh is symlink" ;;
      ERR_AUTH_KEYS_SYMLINK) echo "❌ Refuse: authorized_keys is symlink" ;;
      ERR_HOME_NOT_DIR) echo "❌ Refuse: user home is not a directory" ;;
      ERR_SSH_DIR_NOT_DIR) echo "❌ Refuse: .ssh exists but is not a directory" ;;
      ERR_AUTH_KEYS_NOT_FILE) echo "❌ Refuse: authorized_keys exists but is not a regular file" ;;
      DELAY_RESTART_MSG) echo "⚠️ Delay restart mode: config written, please manually restart sshd and test" ;;
      *) echo "$key" ;;
    esac
  fi
}

# ---------------- Logging & Audit ----------------
init_log_files() {
  for logfile in "$LOG_FILE" "$AUDIT_FILE"; do
    if [ -f "$logfile" ]; then
      if [ ! -w "$logfile" ]; then
        logfile_new="${logfile}.$(date +%s)"
        if touch "$logfile_new" 2>/dev/null; then
          chmod 600 "$logfile_new" 2>/dev/null || true
          if [ "$logfile" = "$LOG_FILE" ]; then
            LOG_FILE="$logfile_new"
          else
            AUDIT_FILE="$logfile_new"
          fi
        fi
      fi
    else
      touch "$logfile" 2>/dev/null || true
      chmod 600 "$logfile" 2>/dev/null || true
    fi
  done
}

init_log_files

log() { echo "$(date '+%F %T') $*" >>"$LOG_FILE" 2>/dev/null || true; }

audit_log() {
  action="$1"
  details="$2"
  {
    echo "=== $(date '+%F %T') ==="
    echo "ACTION: $action"
    echo "USER: $(whoami 2>/dev/null || echo root)"
    echo "DETAILS: $details"
    echo "---"
  } >> "$AUDIT_FILE" 2>/dev/null || true
  log "[AUDIT] $action - $details"
}

info() { printf "${BLUE}[INFO]${NC} %s\n" "$*"; log "[INFO] $*"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; log "[WARN] $*"; }
err()  { printf "${RED}[ERR ]${NC} %s\n" "$*"; log "[ERR ] $*"; }
ok()   { printf "${GREEN}[ OK ]${NC} %s\n" "$*"; log "[OK] $*"; }
die() { err "$*"; exit 1; }

# =========================================================
# Core Logic Functions
# =========================================================

preflight_checks() {
  essential_cmds="cat grep awk sed cp mv chmod chown mkdir rm id"
  extended_cmds="wc tr head cut touch find sleep date df uname tail"

  missing_cmds=""
  for cmd in $essential_cmds; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing_cmds="$missing_cmds $cmd"
    fi
  done
  if [ -n "$missing_cmds" ]; then
    die "$(msg ERR_MISSING)$missing_cmds"
  fi

  for cmd in $extended_cmds; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      warn "Optional command not found: $cmd (some features may be limited)"
    fi
  done

  available_kb=$(df -k / 2>/dev/null | awk 'NR==2 {print $4}' 2>/dev/null || echo "")
  if [ -n "$available_kb" ] && [ "$available_kb" -lt 5120 ] 2>/dev/null; then
    warn "$(msg WARN_DISK)${available_kb}KB"
  fi

  if [ -f /proc/meminfo ]; then
    mem_avail=$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print $2}' 2>/dev/null || echo "")
    if [ -n "$mem_avail" ] && [ "$mem_avail" -lt 51200 ] 2>/dev/null; then
      warn "$(msg WARN_MEM)${mem_avail}KB"
    fi
  fi

  if ! command -v base64 >/dev/null 2>&1; then
    warn "$(msg WARN_NO_BASE64_SKIPLEN)"
  fi
}

# ---------------- Package Manager ----------------
detect_pm() {
  [ -f /etc/alpine-release ] && { echo apk; return; }
  [ -f /etc/debian_version ] && { echo apt; return; }
  [ -f /etc/redhat-release ] && { echo yum; return; }
  echo unknown
}

PM="$(detect_pm)"
APT_UPDATED="n"
APK_UPDATED="n"
YUM_PREPARED="n"

pm_prepare_once() {
  case "$PM" in
    apt) [ "$APT_UPDATED" != "y" ] && { apt-get update -y >>"$LOG_FILE" 2>&1 || true; APT_UPDATED="y"; } ;;
    apk) [ "$APK_UPDATED" != "y" ] && { apk update >>"$LOG_FILE" 2>&1 || true; APK_UPDATED="y"; } ;;
    yum) [ "$YUM_PREPARED" != "y" ] && {
         if command -v dnf >/dev/null 2>&1; then dnf makecache -y >>"$LOG_FILE" 2>&1 || true;
         else yum makecache -y >>"$LOG_FILE" 2>&1 || true; fi
         YUM_PREPARED="y"; } ;;
  esac
}

install_pkg() {
  case "$PM" in
    apt) pm_prepare_once; DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >>"$LOG_FILE" 2>&1 ;;
    yum) pm_prepare_once;
         if command -v dnf >/dev/null 2>&1; then dnf install -y "$@" >>"$LOG_FILE" 2>&1;
         else yum install -y "$@" >>"$LOG_FILE" 2>&1; fi ;;
    apk) pm_prepare_once; apk add --no-cache "$@" >>"$LOG_FILE" 2>&1 ;;
    *) return 1 ;;
  esac
}

install_pkg_try() {
  for p in "$@"; do
    if install_pkg "$p" >/dev/null 2>&1; then return 0; fi
  done
  return 1
}

update_system() {
  case "$PM" in
    apt) pm_prepare_once; DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >>"$LOG_FILE" 2>&1 ;;
    yum) pm_prepare_once;
         if command -v dnf >/dev/null 2>&1; then dnf upgrade -y >>"$LOG_FILE" 2>&1;
         else yum update -y >>"$LOG_FILE" 2>&1; fi ;;
    apk) pm_prepare_once; apk upgrade >>"$LOG_FILE" 2>&1 ;;
  esac
}

# ---------------- SSHD Restart ----------------
restart_sshd() {
  if [ "$ARG_DELAY_RESTART" = "y" ]; then
    warn "DELAY RESTART: Please manually restart sshd later."
    return 0
  fi

  res=1
  if command -v systemctl >/dev/null 2>&1; then
    # [兼容性优化] 尝试停止 socket。
    # 如果系统没有 ssh.socket (如 CentOS)，命令会失败，但 || true 会让脚本继续执行，不会报错退出。
    systemctl stop ssh.socket >/dev/null 2>&1 || true
    systemctl disable ssh.socket >/dev/null 2>&1 || true
    
    # 原有的重启逻辑
    systemctl restart sshd >>"$LOG_FILE" 2>&1 || systemctl restart ssh >>"$LOG_FILE" 2>&1
    res=$?
  elif command -v rc-service >/dev/null 2>&1; then
    rc-service sshd restart >>"$LOG_FILE" 2>&1
    res=$?
  elif command -v service >/dev/null 2>&1; then
    service sshd restart >>"$LOG_FILE" 2>&1 || service ssh restart >>"$LOG_FILE" 2>&1
    res=$?
  else
    if [ -x /etc/init.d/sshd ]; then /etc/init.d/sshd restart >>"$LOG_FILE" 2>&1 && res=0; fi
    if [ -x /etc/init.d/ssh  ]; then /etc/init.d/ssh  restart >>"$LOG_FILE" 2>&1 && res=0; fi
  fi

  return "$res"
}

# ---------------- Robust Rollback ----------------
ROLLBACK_DIR="$TMP_DIR/rollback"

update_state() {
  phase="$1"
  details="${2:-}"
  {
    echo "PHASE=$phase"
    echo "TIMESTAMP=$(date +%s)"
    echo "USER=${TARGET_USER:-unknown}"
    echo "PORT=${SSH_PORT:-22}"
    echo "KEY_OK=${KEY_OK:-n}"
    echo "DETAILS=$details"
  } > "$STATE_FILE" 2>/dev/null || true
  chmod 600 "$STATE_FILE" 2>/dev/null || true
}

parse_state_value() {
  key="$1"
  file="$2"
  if [ -f "$file" ] && [ -r "$file" ]; then
    sed -n "s/^${key}=//p" "$file" 2>/dev/null | head -n 1 | tr -d '\r'
  fi
}

check_previous_state() {
  if [ -f "$STATE_FILE" ]; then
    state_owner=""
    if stat -c "%u" "$STATE_FILE" >/dev/null 2>&1; then
      state_owner=$(stat -c "%u" "$STATE_FILE" 2>/dev/null)
    else
      state_owner=$(ls -ln "$STATE_FILE" 2>/dev/null | awk '{print $3}')
    fi
    
    current_uid=$(id -u)
    if [ "$state_owner" != "$current_uid" ] 2>/dev/null; then
      warn "State file owned by different user, ignoring"
      rm -f "$STATE_FILE" 2>/dev/null || true
      return 0
    fi
    
    warn "$(msg WARN_RESUME)"
    
    prev_phase=$(parse_state_value "PHASE" "$STATE_FILE")
    prev_user=$(parse_state_value "USER" "$STATE_FILE")
    prev_port=$(parse_state_value "PORT" "$STATE_FILE")
    
    if [ "$AUTO_CONFIRM" != "y" ]; then
      printf "%s" "$(msg ASK_RESUME)"
      read -r continue_resume
      if [ "${continue_resume:-n}" != "y" ]; then
        rm -f "$STATE_FILE" 2>/dev/null || true
        exit 1
      fi
    fi
    
    [ -n "$prev_user" ] && [ -z "$ARG_USER" ] && TARGET_USER="$prev_user"
    [ -n "$prev_port" ] && [ -z "$ARG_PORT" ] && SSH_PORT="$prev_port"
  fi
}

cleanup_state() { rm -f "$STATE_FILE" 2>/dev/null || true; }

cleanup_locks() {
  if [ -n "${LOCK_DIR:-}" ] && [ -d "$LOCK_DIR" ]; then
    rm -rf "$LOCK_DIR" 2>/dev/null || true
  fi
}

rollback_handler() {
  RET=$?
  trap - INT TERM EXIT HUP

  if [ "$RET" -ne 0 ]; then
    warn ""
    warn "$(msg RB_START)"

    if [ -f "$ROLLBACK_DIR/sshd_config" ]; then
      cp -p "$ROLLBACK_DIR/sshd_config" "$SSH_CONF" 2>/dev/null || true
      chmod 600 "$SSH_CONF" 2>/dev/null || true
    fi

    if [ -d "$ROLLBACK_DIR/sshd_config.d" ] && [ -d "$SSH_CONF_D" ]; then
      for f in "$ROLLBACK_DIR/sshd_config.d"/*; do
        [ -f "$f" ] || continue
        cp -p "$f" "$SSH_CONF_D"/ 2>/dev/null || true
      done
    fi

    restart_sshd >/dev/null 2>&1 || true
    warn "$(msg RB_DONE)"
    audit_log "ROLLBACK" "System rolled back due to error code $RET"
  else
    rm -rf "$TMP_DIR" 2>/dev/null || true
  fi

  cleanup_locks
  exit "$RET"
}

setup_rollback() {
  mkdir -p "$ROLLBACK_DIR" 2>/dev/null || true

  check_previous_state
  update_state "setup" "Init"

  [ -f "$SSH_CONF" ] && cp -p "$SSH_CONF" "$ROLLBACK_DIR/sshd_config" 2>/dev/null || true
  if [ -d "$SSH_CONF_D" ]; then
    mkdir -p "$ROLLBACK_DIR/sshd_config.d" 2>/dev/null || true
    for f in "$SSH_CONF_D"/*; do
      [ -f "$f" ] || continue
      cp -p "$f" "$ROLLBACK_DIR/sshd_config.d/" 2>/dev/null || true
    done
  fi

  if command -v iptables-save >/dev/null 2>&1; then
    iptables-save > "$ROLLBACK_DIR/iptables.backup" 2>/dev/null || true
  fi

  trap 'rollback_handler' INT TERM EXIT HUP
}

# ---------------- Persistent Backup ----------------
# [SEC-FIX] Fixed cleanup_old_backups awk logic bug
cleanup_old_backups() {
  keep_count=10
  if [ -d "$BACKUP_REPO" ]; then
    backup_list=$(ls -dt "$BACKUP_REPO"/*/ 2>/dev/null) || return 0
    count=$(echo "$backup_list" | grep -c . 2>/dev/null || echo 0)
    if [ -n "$count" ] && [ "$count" -gt "$keep_count" ] 2>/dev/null; then
      to_rm=$((count - keep_count))
      info "$(msg INFO_CLEANING_BACKUPS) $to_rm $(msg INFO_OLD_BACKUPS)"
      # [SEC-FIX] Use tail -n to get oldest backups (last in sorted list)
      echo "$backup_list" | tail -n "$to_rm" | while IFS= read -r d; do
        [ -n "$d" ] && [ -d "$d" ] && rm -rf "$d" 2>/dev/null || true
      done
    fi
  fi
}

backup_config_persistent() {
  timestamp=$(date +%Y%m%d_%H%M%S)
  if command -v date >/dev/null 2>&1 && date --version 2>&1 | grep -q GNU; then
    timestamp=$(date +%Y%m%d_%H%M%S%N 2>/dev/null || echo "$timestamp")
  fi

  backup_dir="$BACKUP_REPO/$timestamp"

  if ! mkdir -p "$BACKUP_REPO" 2>/dev/null; then
    warn "$(msg ERR_BACKUP_DIR) $BACKUP_REPO"
    BACKUP_REPO="/tmp/server-init-backups"
    backup_dir="$BACKUP_REPO/$timestamp"
    mkdir -p "$BACKUP_REPO" 2>/dev/null || {
      warn "$(msg ERR_BACKUP_DIR_ALT)"
      return 1
    }
  fi

  if ! mkdir -p "$backup_dir" 2>/dev/null; then
    warn "$(msg ERR_BACKUP_SUBDIR) $backup_dir"
    return 1
  fi

  chmod 700 "$backup_dir" 2>/dev/null || true

  if [ -f "$SSH_CONF" ]; then
    cp -p "$SSH_CONF" "$backup_dir/sshd_config" 2>/dev/null || true
    chmod 600 "$backup_dir/sshd_config" 2>/dev/null || true
  fi

  {
    echo "=== Server Init Backup ==="
    echo "Time: $(date)"
    echo "Version: 4.6.1"
    echo "User: ${TARGET_USER:-unknown}"
    echo "Port: ${SSH_PORT:-unknown}"
    echo "OpenSSH: ${OPENSSH_VER_MAJOR}.${OPENSSH_VER_MINOR}"
    echo "--- System ---"
    uname -a 2>/dev/null || true
  } > "$backup_dir/backup.info" 2>/dev/null || true

  cat > "$backup_dir/restore.sh" <<'EOF'
#!/bin/sh
set -e
BACKUP_DIR=$(dirname "$0")
SSH_CONFIG="/etc/ssh/sshd_config"
echo "Restoring SSH Config..."
[ -f "$BACKUP_DIR/sshd_config" ] || exit 1
cp -p "$SSH_CONFIG" "$SSH_CONFIG.bak-$(date +%s)" 2>/dev/null || true
cp -p "$BACKUP_DIR/sshd_config" "$SSH_CONFIG"
chmod 600 "$SSH_CONFIG" 2>/dev/null || true
systemctl restart sshd 2>/dev/null || service sshd restart 2>/dev/null || true
echo "Done."
EOF
  chmod +x "$backup_dir/restore.sh" 2>/dev/null || true

  (cd "$backup_dir" && sha256sum * 2>/dev/null > checksums.sha256) || true

  cleanup_old_backups
  info "$(msg INFO_BACKUP_CREATED) $backup_dir"
  return 0
}

# ---------------- BBR ----------------
enable_bbr() {
  command -v sysctl >/dev/null 2>&1 || return 0
  if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
    warn "Kernel does not support BBR, skipping."
    return 0
  fi
  sysctl_conf="/etc/sysctl.conf"
  grep -q '^net.core.default_qdisc=fq$' "$sysctl_conf" 2>/dev/null || echo 'net.core.default_qdisc=fq' >>"$sysctl_conf"
  grep -q '^net.ipv4.tcp_congestion_control=bbr$' "$sysctl_conf" 2>/dev/null || echo 'net.ipv4.tcp_congestion_control=bbr' >>"$sysctl_conf"
  sysctl -p >>"$LOG_FILE" 2>&1 || true
}

# ---------------- SSHD Helpers ----------------
ensure_ssh_server() {
  if [ -f "$SSH_CONF" ] && command -v sshd >/dev/null 2>&1; then
    return 0
  fi
  info "$(msg I_SSH_INSTALL)"
  case "$PM" in
    apk) install_pkg openssh openssh-server ;;
    *)   install_pkg openssh-server ;;
  esac

  if ! command -v sshd >/dev/null 2>&1; then
    die "$(msg ERR_MISSING_SSHD)"
  fi
  [ -f "$SSH_CONF" ] || die "OpenSSH Install Failed"
}

protect_sshd_service() {
  if command -v systemctl >/dev/null 2>&1; then
    info "$(msg SYS_PROT)"
    systemctl enable ssh sshd 2>/dev/null || true
    systemctl unmask ssh sshd 2>/dev/null || true
    mkdir -p /etc/systemd/system/sshd.service.d/ 2>/dev/null || true
    cat > /etc/systemd/system/sshd.service.d/override.conf <<EOF
[Service]
Restart=on-failure
RestartSec=5s
OOMScoreAdjust=-500
EOF
    systemctl daemon-reload >>"$LOG_FILE" 2>&1 || true
  fi
}

detect_openssh_version() {
  OPENSSH_VER_MAJOR=0
  OPENSSH_VER_MINOR=0
  ver_str=""

  if command -v sshd >/dev/null 2>&1; then
    ver_str=$(sshd -V 2>&1 | sed -n 's/.*OpenSSH_\([0-9]*\)\.\([0-9]*\).*/\1.\2/p' | head -1)
  fi

  if [ -z "$ver_str" ] && command -v ssh >/dev/null 2>&1; then
    ver_str=$(ssh -V 2>&1 | sed -n 's/.*OpenSSH_\([0-9]*\)\.\([0-9]*\).*/\1.\2/p' | head -1)
  fi

  if [ -n "$ver_str" ]; then
    OPENSSH_VER_MAJOR=$(echo "$ver_str" | cut -d. -f1 2>/dev/null || echo 0)
    OPENSSH_VER_MINOR=$(echo "$ver_str" | cut -d. -f2 2>/dev/null || echo 0)
  fi

  case "$OPENSSH_VER_MAJOR" in
    ''|*[!0-9]*) OPENSSH_VER_MAJOR=7 ;;
  esac
  case "$OPENSSH_VER_MINOR" in
    ''|*[!0-9]*) OPENSSH_VER_MINOR=0 ;;
  esac
  [ "$OPENSSH_VER_MAJOR" -eq 0 ] 2>/dev/null && OPENSSH_VER_MAJOR=7
}

openssh_version_ge() {
  req_major="$1"
  req_minor="${2:-0}"

  [ "$OPENSSH_VER_MAJOR" -gt "$req_major" ] && return 0
  [ "$OPENSSH_VER_MAJOR" -eq "$req_major" ] && [ "$OPENSSH_VER_MINOR" -ge "$req_minor" ] && return 0
  return 1
}

# [SEC-FIX] Detect if sshd supports KbdInteractiveAuthentication
detect_kbd_interactive_support() {
  SUPPORTS_KBD_INTERACTIVE="n"
  if command -v sshd >/dev/null 2>&1; then
    if sshd -T 2>/dev/null | grep -qi '^kbdinteractiveauthentication'; then
      SUPPORTS_KBD_INTERACTIVE="y"
    fi
  fi
}

# ---------------- Firewall / SELinux ----------------
allow_firewall_port() {
  p="$1"
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${p}/tcp" >>"$LOG_FILE" 2>&1 || true
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${p}/tcp" >>"$LOG_FILE" 2>&1 || true
    firewall-cmd --reload >>"$LOG_FILE" 2>&1 || true
  elif command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$p" -j ACCEPT 2>>"$LOG_FILE" || true
  fi

  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport "$p" -j ACCEPT 2>>"$LOG_FILE" || true
  fi
}

handle_selinux() {
  port="$1"
  if command -v getenforce >/dev/null 2>&1; then
    if getenforce 2>/dev/null | grep -qi "Enforcing"; then
      info "$(msg SELINUX_DET)"
      if ! command -v semanage >/dev/null 2>&1; then
        info "$(msg SELINUX_INS)"
        case "$PM" in
          yum) install_pkg_try policycoreutils-python-utils policycoreutils-python ;;
          apt) install_pkg_try policycoreutils python3-policycoreutils ;;
        esac
      fi
      if command -v semanage >/dev/null 2>&1; then
        if semanage port -a -t ssh_port_t -p tcp "$port" >>"$LOG_FILE" 2>&1 || \
           semanage port -m -t ssh_port_t -p tcp "$port" >>"$LOG_FILE" 2>&1; then
          ok "$(msg SELINUX_OK)"
        else
          warn "$(msg SELINUX_FAIL)"
        fi
      else
        warn "$(msg SELINUX_FAIL)"
      fi
    fi
  fi
}

# ---------------- Port Logic ----------------
is_hard_reserved() {
  case "$1" in
    53|80|443|3306)
      return 0 ;;
  esac
  return 1
}

is_k8s_nodeport() { [ "$1" -ge 30000 ] && [ "$1" -le 32767 ]; }

rand_u16() {
  if [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
    od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' '
  elif command -v shuf >/dev/null 2>&1; then
    shuf -i 1024-65535 -n 1
  else
    echo $(( ( $(date +%s 2>/dev/null || echo 12345) + $$ ) % 65536 ))
  fi
}

ensure_port_tools() {
  # === [新增] 强制安装 nc (netcat) ===
  if ! command -v nc >/dev/null 2>&1; then
    echo "Installing missing dependency: netcat..."
    case "$PM" in
      apt) install_pkg netcat-openbsd ;;
      yum) install_pkg nc ;;
      apk) install_pkg netcat-openbsd ;;
    esac
  fi
  # ==============================

  # 原有的 ss/netstat 检查保持不变
  command -v ss >/dev/null 2>&1 && return 0
  command -v netstat >/dev/null 2>&1 && return 0
  case "$PM" in
    apt) install_pkg_try iproute2 >/dev/null 2>&1 || true ;;
    yum) install_pkg_try iproute  >/dev/null 2>&1 || true ;;
    apk) install_pkg_try iproute2 iproute2-ss >/dev/null 2>&1 || true ;;
  esac
  install_pkg_try net-tools >/dev/null 2>&1 || true
}

is_port_free() {
  p="$1"

  if command -v ss >/dev/null 2>&1; then
    if ss -lnt 2>/dev/null | awk -v port="$p" '
      NR > 1 {
        n = split($4, parts, ":")
        if (parts[n] == port) { exit 0 }
      }
      END { exit 1 }
    '; then
      return 1
    fi
    return 0
  fi

  if command -v netstat >/dev/null 2>&1; then
    if netstat -lnt 2>/dev/null | awk -v port="$p" '
      NR > 2 {
        n = split($4, parts, ":")
        if (parts[n] == port) { exit 0 }
      }
      END { exit 1 }
    '; then
      return 1
    fi
    return 0
  fi

  return 1
}

pick_random_port() {
  ensure_port_tools
  i=0

  if ! mkdir -p "$LOCK_DIR" 2>/dev/null; then
    warn "$(msg ERR_LOCK_DIR) $LOCK_DIR"
    return 1
  fi
  chmod 700 "$LOCK_DIR" 2>/dev/null || warn "$(msg WARN_LOCK_DIR_PERM)"
  find "$LOCK_DIR" -name "port-*.lock" -mmin +5 -delete 2>/dev/null || true

  while [ "$i" -lt 100 ]; do
    r="$(rand_u16)"
    p=$(( 49152 + (r % (65535 - 49152)) ))
    lockfile="$LOCK_DIR/port-$p.lock"
    if mkdir "$lockfile" 2>/dev/null; then
      if is_port_free "$p"; then
        echo "$p"
        return 0
      else
        rmdir "$lockfile" 2>/dev/null || true
      fi
    fi
    i=$((i+1))
  done

  warn "$(msg ERR_CANNOT_RESERVE_PORT)"
  return 1
}

validate_port() {
  port="$1"
  
  case "$port" in
    ''|*[!0-9]*) return 1 ;;
  esac
  
  [ "$port" -ge 1 ] 2>/dev/null && [ "$port" -le 65535 ] 2>/dev/null || return 1
  
  if [ "$port" -lt 1024 ] && [ "$port" != "22" ]; then
    return 1
  fi
  
  return 0
}

# ---------------- User & Sudo ----------------
validate_username() {
  raw="$1"
  # [UX-FIX] 自动去除首尾空格，并将大写转小写(可选，这里主要去空格)
  u=$(echo "$raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  
  # 必须将清洗后的变量回写给全局变量，否则后续 useradd 还是会用带空格的
  TARGET_USER="$u"
  
  [ "$u" = "root" ] && return 0
  
  len=${#u}
  [ "$len" -ge 2 ] && [ "$len" -le 32 ] || return 1
  echo "$u" | grep -Eq '^[a-z_][a-z0-9_-]*$' || return 1
  
  case "$u" in bin|daemon|adm|lp|sync|shutdown|halt|mail|operator|games|ftp|nobody) return 1 ;; esac
  return 0
}

# [SEC-FIX] Fixed grep prefix match - require whitespace or end after username
safe_configure_sudo() {
  user="$1"
  if [ ! -d /etc/sudoers.d ]; then warn "$(msg WARN_NO_SUDOERS_DIR)"; return 0; fi
  # [SEC-FIX] Match user followed by whitespace to avoid prefix matching
  if grep -Eq "^[[:space:]]*${user}[[:space:]]" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then 
    info "$(msg INFO_SUDO_EXISTS)"
    return 0
  fi

  timestamp=$(date +%Y%m%d%H%M%S)
  sudoers_file="/etc/sudoers.d/server-init-$user-$timestamp"
  cat > "$sudoers_file" <<EOF
# Generated by server-init
$user ALL=(ALL) NOPASSWD:ALL
Defaults:$user !requiretty
Defaults:$user env_keep += "SSH_AUTH_SOCK"
EOF

  if command -v visudo >/dev/null 2>&1; then
    if ! visudo -c -f "$sudoers_file" >/dev/null 2>&1; then
      rm -f "$sudoers_file"
      err "$(msg ERR_SUDOERS_SYNTAX)"
      return 1
    fi
  fi
  chmod 440 "$sudoers_file" 2>/dev/null || { rm -f "$sudoers_file"; err "$(msg ERR_SUDOERS_PERM)"; return 1; }
  info "$(msg INFO_SUDO_CONFIGURED)"
  return 0
}

get_user_home() {
  user="$1"
  home=""

  if command -v getent >/dev/null 2>&1; then
    home=$(getent passwd "$user" 2>/dev/null | cut -d: -f6)
  fi

  if [ -z "$home" ] && [ -r /etc/passwd ]; then
    home=$(awk -F: -v u="$user" '$1==u {print $6}' /etc/passwd 2>/dev/null)
  fi

  if [ -z "$home" ]; then
    if [ "$user" = "root" ]; then
      home="/root"
    else
      home="/home/$user"
    fi
  fi

  echo "$home"
}

get_user_shell() {
  user="$1"
  shell=""

  if command -v getent >/dev/null 2>&1; then
    shell=$(getent passwd "$user" 2>/dev/null | cut -d: -f7)
  fi

  if [ -z "$shell" ] && [ -r /etc/passwd ]; then
    shell=$(awk -F: -v u="$user" '$1==u {print $7}' /etc/passwd 2>/dev/null)
  fi

  echo "$shell"
}

safe_ensure_user() {
  user="$1"
  [ "$user" = "root" ] && return 0

  if id "$user" >/dev/null 2>&1; then
    shell=$(get_user_shell "$user")
    home_dir=$(get_user_home "$user")

    case "$shell" in
      /bin/bash|/bin/sh|/usr/bin/bash|/usr/bin/sh|/bin/dash|/bin/ash) ;;
      /sbin/nologin|/bin/false|/usr/sbin/nologin)
        warn "$(msg WARN_USER_SHELL) $shell"
        if [ "$AUTO_CONFIRM" != "y" ]; then
          printf "%s" "$(msg ASK_CHANGE_SHELL)"
          read -r change_shell
          if [ "${change_shell:-n}" = "y" ]; then
            new_shell="/bin/sh"
            for try_shell in /bin/bash /bin/ash /bin/sh; do
              [ -x "$try_shell" ] && { new_shell="$try_shell"; break; }
            done
            if command -v chsh >/dev/null 2>&1; then
              chsh -s "$new_shell" "$user" 2>>"$LOG_FILE" || warn "$(msg WARN_CHANGE_SHELL_FAIL)"
            elif command -v usermod >/dev/null 2>&1; then
              usermod -s "$new_shell" "$user" 2>>"$LOG_FILE" || warn "$(msg WARN_CHANGE_SHELL_FAIL)"
            else
              warn "$(msg WARN_CHANGE_SHELL_FAIL)"
            fi
          fi
        fi
        ;;
      "") ;;
      *) warn "$(msg WARN_UNUSUAL_SHELL) $shell" ;;
    esac

    if [ -n "$home_dir" ] && [ -d "$home_dir" ]; then
      dir_owner=""
      if stat -c "%U" "$home_dir" >/dev/null 2>&1; then
        dir_owner=$(stat -c "%U" "$home_dir" 2>/dev/null)
      else
        dir_owner=$(ls -ld "$home_dir" 2>/dev/null | awk '{print $3}')
      fi
      [ -n "$dir_owner" ] && [ "$dir_owner" != "$user" ] && warn "$(msg WARN_HOME_OWNER) $dir_owner"
      [ ! -w "$home_dir" ] && warn "$(msg WARN_HOME_NOT_WRITABLE)"
    fi
    return 0
  fi

  info "$(msg I_USER) $user"
  shell="/bin/sh"
  for test_shell in /bin/bash /usr/bin/bash /bin/ash /bin/sh /usr/bin/sh /bin/dash; do
    if [ -x "$test_shell" ]; then shell="$test_shell"; break; fi
  done

  user_created=0
  if command -v useradd >/dev/null 2>&1; then
    useradd -m -s "$shell" "$user" >>"$LOG_FILE" 2>&1 && user_created=1
  elif command -v adduser >/dev/null 2>&1; then
    adduser -D -s "$shell" "$user" >>"$LOG_FILE" 2>&1 && user_created=1
  fi

  [ "$user_created" -eq 1 ] || { err "$(msg ERR_USER_CREATE_FAIL)"; return 1; }
  id "$user" >/dev/null 2>&1 || { err "$(msg ERR_USER_VERIFY_FAIL)"; return 1; }

  # [FIX] 解锁用户账户，防止因 shadow 密码锁定导致 sudo NOPASSWD 失效
  # 使用 passwd -d 清除密码（变为无密码状态），配合 SSH Key 使用是安全的，且能让 PAM 通过账户检查
  passwd -d "$user" >/dev/null 2>&1 || usermod -U "$user" >/dev/null 2>&1 || true

  safe_configure_sudo "$user" || true
  return 0
}

# ---------------- Keys ----------------
fetch_keys() {
  mode="$1"
  val="$2"
  url=""

  case "$mode" in
    gh)  url="https://github.com/$val.keys" ;;
    url) url="$val" ;;
    raw) printf "%s\n" "$val"; return 0 ;;
    *) return 1 ;;
  esac

  if [ "$mode" = "url" ]; then
    echo "$url" | grep -Eq '^https://|^http://' || { warn "Invalid URL scheme (must be http/https)"; return 1; }
  fi

  retries=0
  max_retries=3
  while [ "$retries" -lt "$max_retries" ]; do
    if command -v curl >/dev/null 2>&1; then
      if curl -fsSL --connect-timeout 10 --max-time 30 "$url" 2>>"$LOG_FILE"; then
        return 0
      fi
    elif command -v wget >/dev/null 2>&1; then
      if wget -qO- --timeout=30 "$url" 2>>"$LOG_FILE"; then
        return 0
      fi
    else
      warn "Need curl or wget to fetch keys"
      return 1
    fi
    retries=$((retries+1))
    [ "$retries" -lt "$max_retries" ] && sleep 2
  done

  warn "Failed to fetch keys after $max_retries attempts"
  return 1
}

# [SEC-FIX] Removed rsa-sha2-256/512 from key type regex (they are signature algorithms, not key types)
validate_ssh_key_line() {
  line="$1"

  line=$(printf '%s' "$line" | tr -d '\000-\037\177' | sed 's/[[:space:]]*#.*$//')
  [ -z "$line" ] && return 1

  # [SEC-FIX] Tightened regex: removed rsa-sha2-256/512, restricted ecdsa to known curves
  if ! printf '%s' "$line" | grep -Eq '^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com|ssh-(rsa|dss|ed25519)-cert-v01@openssh\.com|ecdsa-sha2-nistp(256|384|521)-cert-v01@openssh\.com)[[:space:]]+[A-Za-z0-9+/]+=*([[:space:]]+.*)?$'; then
    return 1
  fi

  key_part=$(printf '%s' "$line" | awk '{print $2}')
  [ -n "$key_part" ] || return 1

  if command -v base64 >/dev/null 2>&1; then
    if ! printf '%s' "$key_part" | base64 -d >/dev/null 2>&1; then
      return 1
    fi
    key_type=$(printf '%s' "$line" | awk '{print $1}')
    key_bytes=$(printf '%s' "$key_part" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
    case "$key_type" in
      ssh-rsa)
        [ -n "$key_bytes" ] && [ "$key_bytes" -ge 256 ] 2>/dev/null || return 1 ;;
      ssh-ed25519|sk-ssh-ed25519@openssh.com)
        [ -n "$key_bytes" ] && [ "$key_bytes" -ge 32 ] 2>/dev/null || return 1 ;;
      ssh-dss)
        [ -n "$key_bytes" ] && [ "$key_bytes" -ge 40 ] 2>/dev/null || return 1 ;;
    esac
  fi

  # [SEC-FIX] Optional: use ssh-keygen for stronger validation if available
  if command -v ssh-keygen >/dev/null 2>&1; then
    tmpk="$TMP_DIR/keycheck.$$"
    printf "%s\n" "$line" > "$tmpk"
    if ! ssh-keygen -l -f "$tmpk" >/dev/null 2>&1; then
      rm -f "$tmpk" 2>/dev/null || true
      return 1
    fi
    rm -f "$tmpk" 2>/dev/null || true
  fi

  printf "%s\n" "$line"
  return 0
}

# [SEC-FIX] Completely rewritten deploy_keys with symlink protection
deploy_keys() {
  user="$1"
  keys="$2"
  home=$(get_user_home "$user")
  dir="$home/.ssh"
  auth="$dir/authorized_keys"

  # [SEC-FIX] Refuse symlink home directory (local privilege escalation prevention)
  [ -z "$home" ] && { err "$(msg ERR_HOME_NOT_DIR)"; return 1; }
  if [ -L "$home" ]; then
    err "$(msg ERR_HOME_SYMLINK): $home"
    return 1
  fi
  if [ ! -d "$home" ]; then
    err "$(msg ERR_HOME_NOT_DIR): $home"
    return 1
  fi

  # [SEC-FIX] Refuse symlink .ssh directory
  if [ -L "$dir" ]; then
    err "$(msg ERR_SSH_DIR_SYMLINK): $dir"
    return 1
  fi
  if [ -e "$dir" ] && [ ! -d "$dir" ]; then
    err "$(msg ERR_SSH_DIR_NOT_DIR): $dir"
    return 1
  fi

  mkdir -p "$dir" 2>/dev/null || return 1
  chmod 700 "$dir" 2>/dev/null || true

  # [SEC-FIX] Refuse symlink authorized_keys
  if [ -L "$auth" ]; then
    err "$(msg ERR_AUTH_KEYS_SYMLINK): $auth"
    return 1
  fi
  if [ -e "$auth" ] && [ ! -f "$auth" ]; then
    err "$(msg ERR_AUTH_KEYS_NOT_FILE): $auth"
    return 1
  fi

  touch "$auth" 2>/dev/null || return 1
  chmod 600 "$auth" 2>/dev/null || true

  # [SEC-FIX] Only chown specific paths, no -R (symlink traversal risk)
  chown "${user}:" "$dir" "$auth" 2>/dev/null || chown "$user" "$dir" "$auth" 2>/dev/null || true

  valid_keys_file="$TMP_DIR/valid_keys.$$"
  deployed_count=0
  
  : > "$valid_keys_file"

  printf "%s\n" "$keys" | while IFS= read -r line; do
    [ -z "$line" ] && continue
    clean_line=$(validate_ssh_key_line "$line")
    if [ -n "$clean_line" ]; then
      printf "%s\n" "$clean_line" >> "$valid_keys_file"
    fi
  done

  if [ ! -s "$valid_keys_file" ]; then
    warn "$(msg WARN_NO_VALID_KEYS)"
    rm -f "$valid_keys_file" 2>/dev/null || true
    return 1
  fi

  while IFS= read -r key; do
    [ -z "$key" ] && continue
    if ! grep -qxF "$key" "$auth" 2>/dev/null; then
      printf "%s\n" "$key" >> "$auth"
    fi
    if grep -qxF "$key" "$auth" 2>/dev/null; then
      deployed_count=$((deployed_count + 1))
    fi
  done < "$valid_keys_file"

  rm -f "$valid_keys_file" 2>/dev/null || true

  if [ "$deployed_count" -gt 0 ]; then
    info "$(msg INFO_KEYS_DEPLOYED) $deployed_count"
    return 0
  else
    warn "$(msg WARN_NO_VALID_KEYS)"
    return 1
  fi
}

# ---------------- sshd_config management ----------------
# [SEC-FIX] Case-insensitive directive matching
cleanup_sshd_config_d() {
  if [ -d "$SSH_CONF_D" ]; then
    for conf in "$SSH_CONF_D"/*.conf; do
      [ -f "$conf" ] || continue
      # [SEC-FIX] Case-insensitive matching
      if awk '{line=tolower($0)} line ~ /^[[:space:]]*(port|permitrootlogin|passwordauthentication|pubkeyauthentication|challengeresponseauthentication|kbdinteractiveauthentication|kexalgorithms|ciphers|macs|addressfamily|listenaddress)[[:space:]]/ {exit 0} END{exit 1}' "$conf" 2>/dev/null; then
        mv "$conf" "${conf}.bak_server_init" 2>/dev/null || true
        warn "$(msg CLEAN_D) $conf"
      fi
    done
  fi
}

remove_managed_block() {
  tmp_in="$TMP_DIR/sshd_config.in"
  tmp_out="$TMP_DIR/sshd_config.out"
  cp -p "$SSH_CONF" "$tmp_in" 2>/dev/null || true
  awk -v b="$BLOCK_BEGIN" -v e="$BLOCK_END" '
    $0==b {skip=1; next}
    $0==e {skip=0; next}
    skip!=1 {print}
  ' "$tmp_in" >"$tmp_out"
  if [ -s "$tmp_out" ]; then
    cat "$tmp_out" > "$SSH_CONF"
  fi
}

# [SEC-FIX] Case-insensitive sanitization
sanitize_sshd_config() {
  info "$(msg INFO_SANITIZE_DUP)"
  tmp_san="$TMP_DIR/sshd_config.sanitized"

  # [SEC-FIX] Use case-insensitive matching with tolower()
  awk '
    {
      low = tolower($0)
    }
    low ~ /^[[:space:]]*port[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*permitrootlogin[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*passwordauthentication[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*pubkeyauthentication[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*challengeresponseauthentication[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*kbdinteractiveauthentication[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*kexalgorithms[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*ciphers[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*macs[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*addressfamily[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*listenaddress[[:space:]]/ { print "# [server-init disabled] " $0; next }
    { print }
' "$SSH_CONF" > "$tmp_san"

  if [ -s "$tmp_san" ]; then
    cat "$tmp_san" > "$SSH_CONF"
  fi
}

has_global_ipv6() {
  if command -v ip >/dev/null 2>&1; then
    ip -6 addr show scope global 2>/dev/null | grep -q inet6 && return 0
  fi
  
  if [ -f /proc/net/if_inet6 ]; then
    awk '$4 == "00" && $6 != "lo" { found=1; exit } END { exit !found }' /proc/net/if_inet6 2>/dev/null && return 0
  fi
  
  if command -v ifconfig >/dev/null 2>&1; then
    ifconfig 2>/dev/null | grep -i 'inet6.*global' >/dev/null 2>&1 && return 0
  fi
  
  return 1
}

# ----- Crypto selection -----
csv_contains() {
  csv="$1"
  item="$2"
  case ",$csv," in
    *,"$item",*) return 0 ;;
    *) return 1 ;;
  esac
}

csv_intersect_ordered() {
  pref="$1"
  supp="$2"
  result=""
  
  result=$(
    IFS=,
    for a in $pref; do
      if [ -n "$a" ] && csv_contains "$supp" "$a"; then
        printf "%s\n" "$a"
      fi
    done
  )
  
  echo "$result" | tr '\n' ',' | sed 's/,$//'
}

get_sshd_T_value() {
  key="$1"
  v=""
  
  if openssh_version_ge 6 8; then
    v=$(sshd -T -C user=root,host=localhost,addr=127.0.0.1 -f "$SSH_CONF" 2>/dev/null | awk -v k="$key" 'tolower($1)==k {print $2; exit}')
  fi
  
  if [ -z "$v" ]; then
    v=$(sshd -T -f "$SSH_CONF" 2>/dev/null | awk -v k="$key" 'tolower($1)==k {print $2; exit}')
  fi
  
  echo "$v"
}

compute_crypto_lines() {
  KEX_LINE=""
  CIPHERS_LINE=""
  MACS_LINE=""
  CRYPTO_MODE="skip"

  if ! command -v sshd >/dev/null 2>&1; then
    CRYPTO_MODE="skip"
    return 0
  fi

  supp_kex=$(get_sshd_T_value "kexalgorithms")
  supp_ciphers=$(get_sshd_T_value "ciphers")
  supp_macs=$(get_sshd_T_value "macs")

  pref_kex="curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512"
  pref_ciphers="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
  pref_macs="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com"

  if [ -n "$supp_kex" ] || [ -n "$supp_ciphers" ] || [ -n "$supp_macs" ]; then
    sel_kex=$(csv_intersect_ordered "$pref_kex" "$supp_kex")
    sel_ciphers=$(csv_intersect_ordered "$pref_ciphers" "$supp_ciphers")
    sel_macs=$(csv_intersect_ordered "$pref_macs" "$supp_macs")

    [ -n "$sel_kex" ] && KEX_LINE="KexAlgorithms $sel_kex"
    [ -n "$sel_ciphers" ] && CIPHERS_LINE="Ciphers $sel_ciphers"
    [ -n "$sel_macs" ] && MACS_LINE="MACs $sel_macs"

    if [ -n "$KEX_LINE" ] || [ -n "$CIPHERS_LINE" ] || [ -n "$MACS_LINE" ]; then
      CRYPTO_MODE="filtered"
    else
      CRYPTO_MODE="skip"
    fi
    return 0
  fi

  if openssh_version_ge 6 5; then
    KEX_LINE="KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
    CIPHERS_LINE="Ciphers chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    MACS_LINE="MACs hmac-sha2-512,hmac-sha2-256"
    CRYPTO_MODE="fallback"
  else
    CRYPTO_MODE="skip"
  fi
}

build_block() {
  file="$1"
  {
    echo "$BLOCK_BEGIN"
    echo "# Managed by server-init v4.6.2"
    echo "# Generated: $(date)"
    echo "# OpenSSH: ${OPENSSH_VER_MAJOR}.${OPENSSH_VER_MINOR}"
    echo "# Do NOT edit inside this block. Changes will be overwritten."
    echo ""

    echo "Port $SSH_PORT"

    [ -n "$KEX_LINE" ] && echo "$KEX_LINE"
    [ -n "$CIPHERS_LINE" ] && echo "$CIPHERS_LINE"
    [ -n "$MACS_LINE" ] && echo "$MACS_LINE"

    if [ "$IPV6_ENABLED" = "y" ]; then
      echo "AddressFamily any"
      # [FIX-AWS] Debian 12 Socket Activation 冲突修复: 不显式指定监听地址
      # echo "ListenAddress ::"
      # echo "ListenAddress 0.0.0.0"
    else
      echo "AddressFamily inet"
      # echo "ListenAddress 0.0.0.0"
    fi

    if [ "$KEY_OK" = "y" ]; then
      echo "PasswordAuthentication no"
      echo "PermitEmptyPasswords no"
      echo "ChallengeResponseAuthentication no"
      echo "PubkeyAuthentication yes"
      # [SEC-FIX] Add KbdInteractiveAuthentication no for true key-only auth
      if [ "$SUPPORTS_KBD_INTERACTIVE" = "y" ]; then
        echo "KbdInteractiveAuthentication no"
      fi
    else
      echo "PasswordAuthentication yes"
      echo "PubkeyAuthentication yes"
    fi

    if [ "$TARGET_USER" = "root" ]; then
      if [ "$KEY_OK" = "y" ]; then
        if openssh_version_ge 7 0; then
          echo "PermitRootLogin prohibit-password"
        else
          echo "PermitRootLogin without-password"
        fi
      else
        echo "PermitRootLogin yes"
      fi
    else
      if [ "$KEY_OK" = "y" ]; then
        echo "PermitRootLogin no"
      else
        if [ "$ROOT_KEY_PRESENT" = "y" ]; then
          if openssh_version_ge 7 0; then
            echo "PermitRootLogin prohibit-password"
          else
            echo "PermitRootLogin without-password"
          fi
        else
          echo "PermitRootLogin yes"
        fi
      fi
    fi

    echo ""
    echo "$BLOCK_END"
  } >"$file"
}

install_managed_block() {
  block="$1"
  tmp="$TMP_DIR/sshd_config.merge"

  match_line=$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*Match[[:space:]]/ {print NR; exit}' "$SSH_CONF" 2>/dev/null)

  if [ -z "$match_line" ]; then
    cat "$SSH_CONF" "$block" > "$tmp"
  else
    info "$(msg INFO_MATCH_INSERT)"
    awk -v ml="$match_line" -v bf="$block" '
      NR < ml { print }
      NR == ml {
        while ((getline line < bf) > 0) print line
        close(bf)
        print
      }
      NR > ml { print }
    ' "$SSH_CONF" > "$tmp"
  fi

  chmod 600 "$tmp" 2>/dev/null || true
  mv "$tmp" "$SSH_CONF"
}

verify_sshd_listening() {
  port="$1"
  timeout_s=30  # [FIX] 延长至 30 秒，适应 Vultr 等慢速机器
  elapsed=0

  ensure_port_tools

  while [ "$elapsed" -lt "$timeout_s" ]; do
    if ! is_port_free "$port"; then
      return 0
    fi
    if command -v nc >/dev/null 2>&1; then
      # [SEC-FIX] Use 127.0.0.1 instead of localhost
      # [兼容性优化]
      # 1. 尝试 IPv4 本地回环 (大多数系统的标准情况)
      # 2>/dev/null 屏蔽了不支持 IPv4 时的报错
      nc -z -w 1 127.0.0.1 "$port" 2>/dev/null && return 0
      # 2. 尝试 IPv6 本地回环 (针对 Debian 12 默认开启 bindv6only 的情况)
      # 如果系统不支持 IPv6，这行命令会静默失败，不会中断脚本
      nc -z -w 1 ::1 "$port" >/dev/null 2>&1 && return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

# [SEC-FIX] Use 127.0.0.1 instead of localhost to avoid IPv6 mismatch
enhanced_ssh_test() {
  port="$1"
  user="$2"
  info "$(msg TEST_CONN)"

  if ! verify_sshd_listening "$port"; then
    err "SSHD not listening on port $port"
    return 1
  fi

  banner_ok=0
  if command -v nc >/dev/null 2>&1; then
    proto=""
    # [SEC-FIX] Use 127.0.0.1 instead of localhost
    if command -v timeout >/dev/null 2>&1; then
      proto=$(printf "SSH-2.0-TEST\r\n" | timeout 3 nc 127.0.0.1 "$port" 2>/dev/null || true)
    else
      proto=$(printf "SSH-2.0-TEST\r\n" | nc -w 3 127.0.0.1 "$port" 2>/dev/null || true)
    fi
    
    if echo "$proto" | grep -q "SSH-2.0"; then
      ok "$(msg INFO_SSH_PROTOCOL_OK)"
      banner_ok=1
    else
      err "$(msg ERR_NO_BANNER)"
    fi
  else
    warn "nc not available, skipping banner check"
    banner_ok=1
  fi

  if [ "$banner_ok" -ne 1 ]; then
    return 1
  fi

  attempts=1
  max_attempts=3
  success=0
  while [ "$attempts" -le "$max_attempts" ]; do
    if command -v ssh >/dev/null 2>&1; then
      # [SEC-FIX] Use -4 flag and 127.0.0.1
      if ssh -4 -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
           -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null \
           -p "$port" "$user@127.0.0.1" "exit 0" >/dev/null 2>&1; then
        success=1
        break
      fi
      # 尝试 1: IPv4 回环 (主流情况)
      if ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
             -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null \
             -p "$port" "$user@127.0.0.1" "exit 0" >/dev/null 2>&1; then
           success=1
           break
      fi
      # 尝试 2: IPv6 回环 (针对纯 IPv6 环境的备选)
      if ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
             -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null \
             -p "$port" "$user@::1" "exit 0" >/dev/null 2>&1; then
           success=1
           break
      fi
    fi
    attempts=$((attempts + 1))
    [ "$attempts" -le "$max_attempts" ] && sleep 1
  done

  if [ "$success" -eq 1 ]; then
    ok "$(msg TEST_OK)"
  else
    warn "$(msg WARN_PORT_OPEN_BUT_FAIL)"
  fi
  
  return 0
}

update_motd() {
  info "$(msg MOTD_UPD)"
  
  # ---------------------------------------------------------
  # 1. 清理旧的静态 MOTD
  # ---------------------------------------------------------
  motd="/etc/motd"
  if [ -f "$motd" ]; then
    cp -p "$motd" "${motd}.bak" 2>/dev/null
    # 清理旧的 Server Init 遗留信息
    grep -vE "Server Init|Login User:|SSH Port:|Auth Type:|Firewall:|={10,}" "$motd" > "${motd}.clean" 2>/dev/null
    cat "${motd}.clean" > "$motd"
    rm -f "${motd}.clean" "${motd}.bak" 2>/dev/null
  fi

  # ---------------------------------------------------------
  # 2. 创建动态脚本 (生成到 /etc/profile.d/)
  # ---------------------------------------------------------
  mkdir -p /etc/profile.d

  # 使用 'EOF' 防止变量在写入文件时被提前解析
  cat > "/etc/profile.d/z99-ssh-init-banner.sh" <<'EOF'
#!/bin/sh
# 动态获取当前真实的 SSH 配置
SSH_CONF="/etc/ssh/sshd_config"
REAL_PORT="22"
AUTH_TYPE="Unknown"
REAL_USER=$(whoami 2>/dev/null || echo "unknown")

# 如果有读取权限（通常是 root），则尝试动态刷新显示最新配置
if [ -r "$SSH_CONF" ]; then
    CONF_PORT=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2}' "$SSH_CONF" | tail -n 1)
    [ -n "$CONF_PORT" ] && REAL_PORT="$CONF_PORT"
    
    if grep -Ei '^[[:space:]]*PasswordAuthentication[[:space:]]+yes' "$SSH_CONF" >/dev/null 2>&1; then
        AUTH_TYPE="Password/Key"
    else
        AUTH_TYPE="Key Only (Secure)"
    fi
fi

# 颜色定义 (ANSI)
C_RESET="\033[0m"
C_CYAN="\033[0;36m"
C_GREEN="\033[1;32m"
C_YELLOW="\033[1;33m"

# 打印横幅
printf "\n"
printf "${C_CYAN}===============================================================================${C_RESET}\n"
printf "${C_CYAN}                       Server Init Managed - SSH Hardened${C_RESET}\n"
printf "${C_CYAN}===============================================================================${C_RESET}\n"
printf " Login User: ${C_GREEN}%s${C_RESET}\n" "$REAL_USER"
printf " SSH Port:   ${C_GREEN}%s${C_RESET} (Dynamic Check)\n" "$REAL_PORT"
printf " Auth Type:  %s\n" "$AUTH_TYPE"
printf " Firewall:   Please ensure TCP/${C_YELLOW}%s${C_RESET} is allowed.\n" "$REAL_PORT"
printf "${C_CYAN}===============================================================================${C_RESET}\n"
printf "\n"
EOF

  # ---------------------------------------------------------
  # 3. [修复核心] 注入当前脚本已知的正确变量 (解决权限导致的显示问题)
  # ---------------------------------------------------------
  # 根据当前脚本执行状态确定认证类型
  [ "$KEY_OK" = "y" ] && FINAL_AUTH="Key Only (Secure)" || FINAL_AUTH="Password/Key"
  
  # 使用 | 作为 sed 定界符，防止 FINAL_AUTH 中的 / 引起语法错误
  # 将 REAL_PORT 和 AUTH_TYPE 的默认值直接修改为本次脚本执行的真实值
  sed -i "s|REAL_PORT=\"22\"|REAL_PORT=\"$SSH_PORT\"|" "/etc/profile.d/z99-ssh-init-banner.sh"
  sed -i "s|AUTH_TYPE=\"Unknown\"|AUTH_TYPE=\"$FINAL_AUTH\"|" "/etc/profile.d/z99-ssh-init-banner.sh"
  
  chmod 644 "/etc/profile.d/z99-ssh-init-banner.sh"
}

generate_health_report() {
  report_file="/var/log/server-init-health.log"
  end_time=$(date +%s)
  duration=$((end_time - SCRIPT_START_TIME))
  sys_uptime=$(uptime -p 2>/dev/null || uptime 2>/dev/null | awk -F, '{print $1}')

  {
    echo "=== Server Init Health Report ==="
    echo "Generated: $(date)"
    echo "Version: v4.6.2 Fortress Pro"
    echo "Execution Time: ${duration}s"
    echo ""
    echo "--- System ---"
    echo "Uptime: $sys_uptime"
    echo "OpenSSH: ${OPENSSH_VER_MAJOR}.${OPENSSH_VER_MINOR}"
    echo ""
    echo "--- SSH Config ---"
    echo "Port: $SSH_PORT"
    echo "User: $TARGET_USER"
    echo "KeyAuth: $([ "$KEY_OK" = "y" ] && echo "YES" || echo "NO")"
    echo ""
    echo "--- Network ---"
    echo "IPv6: $([ "$IPV6_ENABLED" = "y" ] && echo "Enabled" || echo "Disabled")"
    echo "Port Status: $(is_port_free "$SSH_PORT" && echo "NOT LISTENING (Error)" || echo "LISTENING (OK)")"
    echo "Crypto Mode: $CRYPTO_MODE"
  } > "$report_file" 2>/dev/null || true
  chmod 600 "$report_file" 2>/dev/null || true
  info "Health report saved to: $report_file"
}

print_final_summary() {
  public_ip=""
  if command -v curl >/dev/null 2>&1; then
    public_ip=$(curl -4fsSL --max-time 2 https://api.ipify.org 2>/dev/null || echo "")
  fi

  local_ip=""
  if command -v hostname >/dev/null 2>&1; then
    local_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  if [ -z "$local_ip" ] && command -v ip >/dev/null 2>&1; then
    local_ip=$(ip -4 addr show 2>/dev/null | awk '
      /inet / {
        ip=$2
        sub(/\/.*/, "", ip)
        if (ip !~ /^127\./) { print ip; exit }
      }
    ')
  fi

  end_time=$(date +%s)
  duration=$((end_time - SCRIPT_START_TIME))

  echo ""
  echo "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
  printf "${CYAN}║ %-66s ║${NC}\n" "$(msg BOX_TITLE)"
  echo "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
  printf "${CYAN}║ %-66s ║${NC}\n" " $(msg BOX_SSH)"
  [ -n "$public_ip" ] && printf "${CYAN}║     Public: ssh -p %-5s %s@%s %-16s ║${NC}\n" "$SSH_PORT" "$TARGET_USER" "$public_ip" ""
  [ -n "$local_ip" ] && printf "${CYAN}║     Local:  ssh -p %-5s %s@%s %-16s ║${NC}\n" "$SSH_PORT" "$TARGET_USER" "$local_ip" ""
  echo "${CYAN}║                                                                    ║${NC}"

  if [ "$KEY_OK" = "y" ]; then
    printf "${CYAN}║ %-66s ║${NC}\n" " $(msg BOX_KEY_ON)"
  else
    printf "${CYAN}║ %-66s ║${NC}\n" " $(msg BOX_KEY_OFF)"
  fi

  if [ "$SSH_PORT" != "22" ]; then
    printf "${CYAN}║ %-66s ║${NC}\n" " $(msg BOX_PORT)$SSH_PORT"
    printf "${CYAN}║ %-66s ║${NC}\n" " $(msg BOX_FW)"
    if is_k8s_nodeport "$SSH_PORT"; then
      printf "${CYAN}║ %-66s ║${NC}\n" " $(msg BOX_K8S_WARN)"
    fi
  fi

  echo "${CYAN}║                                                                    ║${NC}"
  printf "${CYAN}║ %-66s ║${NC}\n" " $(msg BOX_WARN)"
  echo "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo "Log: $LOG_FILE"
  echo "Audit: $AUDIT_FILE"
  echo "Time: ${duration}s"
}

validate_ssh_config_comprehensive() {
  config_file="$1"
  user="$2"
  key_ok="$3"

  if ! sshd -t -f "$config_file" 2>>"$LOG_FILE"; then
    err "SSH Config Syntax Error"
    return 1
  fi

  password_auth=$(grep -Ei '^[[:space:]]*PasswordAuthentication[[:space:]]' "$config_file" 2>/dev/null | awk '{print $NF}' | tr -d '\r' | tail -1)
  pubkey_auth=$(grep -Ei '^[[:space:]]*PubkeyAuthentication[[:space:]]' "$config_file" 2>/dev/null | awk '{print $NF}' | tr -d '\r' | tail -1)
  port_setting=$(grep -Ei '^[[:space:]]*Port[[:space:]]' "$config_file" 2>/dev/null | awk '{print $NF}' | tr -d '\r' | tail -1)

  [ -n "$password_auth" ] || password_auth="yes"
  [ -n "$pubkey_auth" ] || pubkey_auth="yes"
  [ -n "$port_setting" ] || port_setting="22"

  # Normalize to lowercase for comparison
  password_auth=$(echo "$password_auth" | tr '[:upper:]' '[:lower:]')
  pubkey_auth=$(echo "$pubkey_auth" | tr '[:upper:]' '[:lower:]')

  if [ "$password_auth" = "no" ] && [ "$pubkey_auth" = "no" ]; then
    die "$(msg ERR_DEADLOCK)"
  fi
  if [ "$password_auth" = "no" ] && [ "$key_ok" != "y" ]; then
    die "$(msg ERR_PASSWORD_NO_KEY)"
  fi
  if [ "$user" = "root" ] && [ "$password_auth" = "no" ] && [ "$key_ok" != "y" ]; then
    die "$(msg ERR_ROOT_NO_KEY)"
  fi
  if [ "$port_setting" != "$SSH_PORT" ]; then
    warn "$(msg WARN_PORT_MISMATCH) ($port_setting vs $SSH_PORT)"
  fi

  insecure_options=0
  if grep -qi "^[[:space:]]*X11Forwarding[[:space:]]*yes" "$config_file" 2>/dev/null; then
    warn "$(msg WARN_X11_FORWARDING)"
    insecure_options=$((insecure_options + 1))
  fi
  if grep -qi "^[[:space:]]*PermitEmptyPasswords[[:space:]]*yes" "$config_file" 2>/dev/null; then
    warn "$(msg WARN_EMPTY_PASSWORDS)"
    insecure_options=$((insecure_options + 1))
  fi
  [ "$insecure_options" -gt 0 ] && warn "$(msg WARN_INSECURE_OPTIONS) $insecure_options"

  return 0
}

# =========================================================
# Entry
# =========================================================
[ "$(id -u)" -eq 0 ] || { echo "$(msg MUST_ROOT)"; exit 1; }
audit_log "START" "Script started with args: $*"

if command -v clear >/dev/null 2>&1; then clear; fi
echo "================================================="
msg BANNER
echo "================================================="
[ "$STRICT_MODE" = "y" ] && msg STRICT_ON

preflight_checks

# Phase 1: Input
if [ -n "$ARG_USER" ]; then
  TARGET_USER="$ARG_USER"
  validate_username "$TARGET_USER" || die "$(msg ERR_USER_INV): $TARGET_USER"
  printf "%s%s\n" "$(msg AUTO_SKIP)" "$TARGET_USER"
else
  while :; do
    printf "%s%s): " "$(msg ASK_USER)" "$DEFAULT_USER"
    read -r TARGET_USER
    [ -z "$TARGET_USER" ] && TARGET_USER="$DEFAULT_USER"
    validate_username "$TARGET_USER" && break
    msg ERR_USER_INV
  done
fi

if [ -n "$ARG_PORT" ]; then
  case "$ARG_PORT" in
    22) PORT_OPT="1"; SSH_PORT="22" ;;
    random) PORT_OPT="2"; SSH_PORT="22" ;;
    *)
      if ! validate_port "$ARG_PORT"; then
        die "$(msg PORT_ERR): $ARG_PORT"
      fi
      if is_hard_reserved "$ARG_PORT"; then
        die "$(msg PORT_RES): $ARG_PORT"
      fi
      if is_k8s_nodeport "$ARG_PORT"; then
        warn "$(msg PORT_K8S)"
      fi
      PORT_OPT="3"; SSH_PORT="$ARG_PORT"
      ;;
  esac
  printf "%s%s\n" "$(msg AUTO_SKIP)" "$ARG_PORT (Mode $PORT_OPT)"
else
  echo ""
  msg ASK_PORT_T; msg OPT_PORT_1; msg OPT_PORT_2; msg OPT_PORT_3
  printf "%s" "$(msg SELECT)"; read -r PORT_OPT
  [ -z "$PORT_OPT" ] && PORT_OPT="1"
  SSH_PORT="22"
  if [ "$PORT_OPT" = "3" ]; then
    while :; do
      printf "%s" "$(msg INPUT_PORT)"
      read -r MANUAL_PORT
      echo "$MANUAL_PORT" | grep -Eq '^[0-9]+$' || { msg PORT_ERR; continue; }
      [ "$MANUAL_PORT" -ge 1024 ] 2>/dev/null && [ "$MANUAL_PORT" -le 65535 ] 2>/dev/null || { msg PORT_ERR; continue; }
      if is_hard_reserved "$MANUAL_PORT"; then
        msg PORT_RES
        continue
      elif is_k8s_nodeport "$MANUAL_PORT"; then
        msg PORT_K8S
        printf "%s" "$(msg ASK_SURE)"
        read -r force_port
        [ "${force_port:-n}" = "y" ] || continue
      fi
      SSH_PORT="$MANUAL_PORT"
      break
    done
  fi
fi

if [ -n "$ARG_KEY_TYPE" ]; then
  KEY_OPT="auto"; KEY_TYPE="$ARG_KEY_TYPE"; KEY_VAL="$ARG_KEY_VAL"
  printf "%s%s\n" "$(msg AUTO_SKIP)" "$KEY_TYPE ($KEY_VAL)"
else
  echo ""
  msg ASK_KEY_T; msg OPT_KEY_1; msg OPT_KEY_2; msg OPT_KEY_3
  printf "%s" "$(msg SELECT)"; read -r KEY_OPT
  case "$KEY_OPT" in
    1) KEY_TYPE="gh";  printf "%s" "$(msg INPUT_GH)"; read -r KEY_VAL ;;
    2) KEY_TYPE="url"; printf "%s" "$(msg INPUT_URL)"; read -r KEY_VAL ;;
    3) KEY_TYPE="raw"; msg INPUT_RAW; raw=""; while IFS= read -r l; do [ -z "$l" ] && break; raw="${raw}${l}\n"; done; KEY_VAL="$(printf "%b" "$raw")" ;;
    *) die "Invalid Option" ;;
  esac
fi

if [ -n "$ARG_UPDATE" ]; then DO_UPDATE="$ARG_UPDATE"; printf "%s%s\n" "$(msg AUTO_SKIP)" "Update=$DO_UPDATE"; else printf "%s" "$(msg ASK_UPD)"; read -r DO_UPDATE; [ -z "$DO_UPDATE" ] && DO_UPDATE="n"; fi
if [ -n "$ARG_BBR" ]; then DO_BBR="$ARG_BBR"; printf "%s%s\n" "$(msg AUTO_SKIP)" "BBR=$DO_BBR"; else printf "%s" "$(msg ASK_BBR)"; read -r DO_BBR; [ -z "$DO_BBR" ] && DO_BBR="n"; fi

# Phase 2: Confirm
if [ "$AUTO_CONFIRM" = "y" ]; then
  echo ""; info "Auto-Confirm: Skipping interactive confirmation."
else
  echo ""
  msg CONFIRM_T
  echo "$(msg C_USER)$TARGET_USER"
  echo "$(msg C_PORT)$SSH_PORT (Mode: $PORT_OPT)"
  echo "$(msg C_KEY)$KEY_TYPE"
  echo "$(msg C_UPD)$DO_UPDATE"
  echo "$(msg C_BBR)$DO_BBR"
  [ "$PORT_OPT" != "1" ] && msg WARN_FW
  printf "%s" "$(msg ASK_SURE)"
  read -r CONFIRM
  [ "${CONFIRM:-n}" = "y" ] || die "$(msg CANCEL)"
fi

# Phase 3: Execute
msg AUDIT_START
setup_rollback
backup_config_persistent || true

info "$(msg I_INSTALL)"
ensure_ssh_server

detect_openssh_version
detect_kbd_interactive_support
info "OpenSSH Version: ${OPENSSH_VER_MAJOR}.${OPENSSH_VER_MINOR}"

install_pkg_try curl >/dev/null 2>&1 || true
install_pkg_try wget >/dev/null 2>&1 || true

# === [新增] 补充常用管理工具 ===
if ! command -v sudo >/dev/null 2>&1; then
  info "Installing missing dependency: sudo..."
  install_pkg sudo >/dev/null 2>&1 || true
fi

if ! command -v hostname >/dev/null 2>&1; then
  # Debian/Ubuntu 下 hostname 命令通常在 hostname 包或 net-tools 中
  install_pkg hostname >/dev/null 2>&1 || true
fi

if [ "$DO_UPDATE" = "y" ]; then info "$(msg I_UPD)"; update_system; fi
if [ "$DO_BBR" = "y" ]; then info "$(msg I_BBR)"; enable_bbr; fi

if [ "$PORT_OPT" = "2" ]; then
  p="$(pick_random_port 2>/dev/null || true)"
  if [ -n "$p" ]; then
    SSH_PORT="$p"
    info "Random Port: $SSH_PORT"
  else
    [ "$STRICT_MODE" = "y" ] && die "STRICT: Random port failed"
    warn "Random port failed, fallback to 22"
    SSH_PORT="22"
  fi
fi

if [ "$SSH_PORT" != "22" ]; then
  allow_firewall_port "$SSH_PORT"
  handle_selinux "$SSH_PORT"
fi

safe_ensure_user "$TARGET_USER" || die "User setup failed"

root_home=$(get_user_home root)
[ -s "$root_home/.ssh/authorized_keys" ] && ROOT_KEY_PRESENT="y" || ROOT_KEY_PRESENT="n"

KEY_OK="n"
KEY_DATA="$(fetch_keys "$KEY_TYPE" "$KEY_VAL" 2>/dev/null || true)"
if [ -n "$KEY_DATA" ] && deploy_keys "$TARGET_USER" "$KEY_DATA"; then
  KEY_OK="y"
  info "$(msg I_KEY_OK)"
else
  [ "$STRICT_MODE" = "y" ] && die "STRICT: Key deploy failed"
  warn "$(msg W_KEY_FAIL)"
fi

if has_global_ipv6; then
  IPV6_ENABLED="y"
  info "$(msg IPV6_CFG)"
else
  IPV6_ENABLED="n"
fi

compute_crypto_lines
if [ "$CRYPTO_MODE" = "skip" ]; then
  info "$(msg INFO_OLD_SSH_SKIP_ALGO)"
elif [ "$CRYPTO_MODE" = "fallback" ]; then
  warn "$(msg COMPAT_WARN)"
fi

info "$(msg I_BACKUP)$SSH_CONF"
cleanup_sshd_config_d
remove_managed_block
sanitize_sshd_config

tmp="$TMP_DIR/sshd_block_final"
build_block "$tmp"

install_managed_block "$tmp"

if [ "$ARG_DELAY_RESTART" != "y" ]; then protect_sshd_service; fi

if ! sshd -t -f "$SSH_CONF" 2>>"$LOG_FILE"; then die "$(msg E_SSHD_CHK)"; fi
validate_ssh_config_comprehensive "$SSH_CONF" "$TARGET_USER" "$KEY_OK"

# [SEC-FIX] Handle --delay-restart properly: skip restart and tests
if [ "$ARG_DELAY_RESTART" = "y" ]; then
  warn "$(msg DELAY_RESTART_MSG)"
  update_motd
  generate_health_report
  
  trap - INT TERM EXIT HUP
  cleanup_state
  cleanup_locks
  rm -rf "$TMP_DIR" 2>/dev/null || true
  
  print_final_summary
  audit_log "DONE" "Completed (delay-restart). user=$TARGET_USER port=$SSH_PORT key_ok=$KEY_OK"
  exit 0
fi

if ! restart_sshd; then
  die "$(msg E_RESTART)"
fi

grep -Eq "^[[:space:]]*Port[[:space:]]+$SSH_PORT([[:space:]]|\$)" "$SSH_CONF" 2>/dev/null || die "$(msg E_GREP_FAIL)"
verify_sshd_listening "$SSH_PORT" || die "$(msg W_LISTEN_FAIL)"
enhanced_ssh_test "$SSH_PORT" "$TARGET_USER" || die "$(msg TEST_FAIL)"

update_motd
generate_health_report

trap - INT TERM EXIT HUP
cleanup_state
cleanup_locks
rm -rf "$TMP_DIR" 2>/dev/null || true

print_final_summary
audit_log "DONE" "Completed successfully. user=$TARGET_USER port=$SSH_PORT key_ok=$KEY_OK"
exit 0
