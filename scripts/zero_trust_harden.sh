#!/bin/bash
# Autonomous Zero-Trust Hardening Script
# Target: Ubuntu/Debian based systems
# Run as root

set -e
export DEBIAN_FRONTEND=noninteractive

wait_for_apt_lock() {
	local lock_files=(
		/var/lib/dpkg/lock-frontend
		/var/lib/dpkg/lock
		/var/lib/apt/lists/lock
		/var/cache/apt/archives/lock
	)
	local retries=30
	local sleep_seconds=5

	echo "[*] Waiting for apt/dpkg locks to clear (max $((retries * sleep_seconds))s)..."
	for ((i=1; i<=retries; i++)); do
		local locked=0
		for lock_file in "${lock_files[@]}"; do
			if fuser "$lock_file" >/dev/null 2>&1; then
				locked=1
				break
			fi
		done

		if [ "$locked" -eq 0 ]; then
			echo "[*] Package manager locks are clear."
			return 0
		fi

		echo "[*] apt/dpkg is busy (attempt $i/$retries). Retrying in ${sleep_seconds}s..."
		sleep "$sleep_seconds"
	done

	echo "[!] Timed out waiting for apt/dpkg lock. Try again after current package task finishes."
	return 1
}

echo "============================================="
echo " Initiating Zero-Trust Server Hardening... "
echo "============================================="

# 1. Update and Upgrade Packages
echo "[*] Updating package index and installing required hardening tools..."
wait_for_apt_lock
apt-get update -y
# Do not run full upgrade here; it can pull thousands of distro packages and fail on mirror blocks.
apt-get install -y --no-install-recommends \
	ufw \
	fail2ban \
	auditd \
	audispd-plugins \
	libpam-google-authenticator \
	openssh-server \
	ca-certificates \
	curl || apt-get install -y --fix-missing --no-install-recommends \
	ufw \
	fail2ban \
	auditd \
	audispd-plugins \
	libpam-google-authenticator \
	openssh-server \
	ca-certificates \
	curl

# 2. Secure SSH Configuration
echo "[*] Hardening SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
if [ "${KEEP_SSH_PASSWORD_AUTH:-false}" = "true" ]; then
	echo "[*] Keeping SSH password authentication enabled for managed password-based access..."
	sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
	sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
else
	sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
	sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
fi
sed -i 's/^#X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/^#MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd

# 3. Configure UFW (Uncomplicated Firewall)
echo "[*] Configuring Firewall (Default Deny)..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
# Add your application ports here (e.g., ufw allow 443/tcp)
ufw --force enable

# 4. Fail2Ban Configuration
echo "[*] Setting up Fail2Ban..."
cat <<EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF
systemctl restart fail2ban
systemctl enable fail2ban

# 5. Kernel Hardening via sysctl
echo "[*] Applying Kernel Hardening Parameters..."
cat <<EOF > /etc/sysctl.d/99-security.conf
# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Disable IPv6 (if not used in infrastructure)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
# Enable TCP SYN Cookie Protection
net.ipv4.tcp_syncookies = 1
# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
EOF
sysctl -p /etc/sysctl.d/99-security.conf

# 6. Auditing & Logging
echo "[*] Enabling Auditing..."
systemctl enable auditd
systemctl start auditd
# Persist identity watch rules and load them safely (idempotent)
cat <<EOF > /etc/audit/rules.d/aztih-identity.rules
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
EOF
augenrules --load >/dev/null 2>&1 || true

# Runtime check for visibility in immediate verification output
if ! auditctl -l 2>/dev/null | grep -q "-w /etc/passwd -p wa -k identity"; then
	auditctl -w /etc/passwd -p wa -k identity || true
fi
if ! auditctl -l 2>/dev/null | grep -q "-w /etc/shadow -p wa -k identity"; then
	auditctl -w /etc/shadow -p wa -k identity || true
fi

echo "============================================="
echo " Zero-Trust Baseline Applied Successfully! "
echo " Next Steps: Integrate with n8n and OpenClaw."
echo "============================================="
