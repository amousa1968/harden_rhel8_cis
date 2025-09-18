#!/bin/bash
# RHEL 8 CIS Level 1 Baseline Hardening & Compliance Check
# Must be run as root

LOG="/var/log/cis_rhel8_level1.log"
REPORT="/var/log/cis_rhel8_level1_report.txt"
> "$REPORT" || true

log() {
  echo "$(date '+%F %T') : $1" | tee -a "$LOG"
}

check_result() {
  if [ "$1" -eq 0 ]; then
    echo "[PASS] $2" | tee -a "$REPORT"
  else
    echo "[FAIL] $2" | tee -a "$REPORT"
  fi
}

log "Starting CIS RHEL 8 Level 1 Hardening and Compliance Checks"

############################################
# 1. Initial Setup
############################################

# 1.1 Ensure mounting of cramfs, squashfs, udf is disabled
for fs in cramfs squashfs udf; do
  echo "Checking $fs filesystem disable..."
  if ! grep -q "$fs" /etc/modprobe.d/*.conf 2>/dev/null; then
    echo "install $fs /bin/true" >> /etc/modprobe.d/cis_disabled_filesystems.conf
    /sbin/rmmod $fs 2>/dev/null
  fi
  lsmod | grep -q $fs
  check_result $? "Filesystem $fs disabled"
done

############################################
# 2. Services
############################################

# 2.2 Ensure xinetd is not installed
if rpm -q xinetd &>/dev/null; then
  yum remove -y xinetd
fi
if rpm -q xinetd &>/dev/null; then
  check_result 1 "xinetd not installed"
else
  check_result 0 "xinetd not installed"
fi

# 2.3 Ensure telnet is not installed
if rpm -q telnet &>/dev/null; then
  yum remove -y telnet
fi
if rpm -q telnet &>/dev/null; then
  check_result 1 "telnet not installed"
else
  check_result 0 "telnet not installed"
fi

############################################
# 3. Network Configuration
############################################

# 3.1 Ensure IP forwarding is disabled
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.conf.all.forwarding=0
grep -q "net.ipv4.ip_forward = 0" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
grep -q "net.ipv6.conf.all.forwarding = 0" /etc/sysctl.conf || echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.conf
sysctl net.ipv4.ip_forward | grep -q "0"
check_result $? "IPv4 forwarding disabled"

# 3.2 Ensure packet redirect sending is disabled
for key in net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects; do
  sysctl -w $key=0
  grep -q "$key = 0" /etc/sysctl.conf || echo "$key = 0" >> /etc/sysctl.conf
done
sysctl net.ipv4.conf.all.send_redirects | grep -q "0"
check_result $? "ICMP redirect sending disabled"

############################################
# 4. Logging & Auditing
############################################

# 4.1 Ensure auditd service is enabled
systemctl enable auditd
systemctl is-enabled auditd | grep -q "enabled"
check_result $? "auditd enabled"

# 4.2 Ensure rsyslog is installed and enabled
rpm -q rsyslog &>/dev/null || yum install -y rsyslog
systemctl enable rsyslog
systemctl is-enabled rsyslog | grep -q "enabled"
check_result $? "rsyslog enabled"

############################################
# 5. Access, Authentication & Authorization
############################################

# 5.1 Ensure password hashing algorithm is SHA-512
authselect current | grep -q sha512 || authselect select sssd with-sha512 --force
grep -q "sha512" /etc/libuser.conf
check_result $? "Password hashing set to SHA-512"

# 5.2 Ensure password expiration is 365 days or less
chage --maxdays 365 root
PASS_MAX_DAYS=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
if [ "$PASS_MAX_DAYS" -le 365 ]; then
  check_result 0 "Password max days <= 365"
else
  check_result 1 "Password max days not set correctly"
fi

############################################
# 6. System Maintenance
############################################

# 6.1 Ensure permissions on /etc/passwd
chmod 644 /etc/passwd
stat -c "%a" /etc/passwd | grep -q "644"
check_result $? "/etc/passwd permissions"

# 6.2 Ensure permissions on /etc/shadow
chmod 600 /etc/shadow
stat -c "%a" /etc/shadow | grep -q "600"
check_result $? "/etc/shadow permissions"

############################################
# Finished
############################################
log "CIS RHEL8 Level 1 Checks Completed"
echo "Compliance report saved to $REPORT"
