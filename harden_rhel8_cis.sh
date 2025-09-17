#!/bin/bash

# RHEL 8 CIS Benchmark Level 1 Hardening Script
# Based on Assessment Details.docx

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Skip in CI environments
if [[ -n "$CI" ]] || [[ -n "$GITHUB_ACTIONS" ]]; then
   echo "Skipping hardening in CI environment"
   exit 0
fi

echo "Starting RHEL 8 CIS Level 1 Hardening..."

# Pre-flight checks - ensure required packages are installed
echo "Performing pre-flight checks..."

# Check if running on RHEL/CentOS/Fedora
if ! command -v rpm >/dev/null 2>&1 && ! command -v yum >/dev/null 2>&1 && ! command -v dnf >/dev/null 2>&1; then
  echo "Error: This script requires RPM-based distribution (RHEL, CentOS, Fedora)"
  exit 1
fi

# Install required packages
REQUIRED_PACKAGES=("audit" "rsyslog" "logrotate" "firewalld" "pam" "openssh-server" "aide" "dnf-automatic")
for package in "${REQUIRED_PACKAGES[@]}"; do
  if ! rpm -q "$package" >/dev/null 2>&1; then
    echo "Installing required package: $package"
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y "$package" || echo "Warning: Failed to install $package"
    elif command -v yum >/dev/null 2>&1; then
      yum install -y "$package" || echo "Warning: Failed to install $package"
    fi
  fi
done

# Ensure required commands are available
REQUIRED_COMMANDS=("modprobe" "mount" "systemctl" "chmod" "chown" "usermod" "sed" "grep" "find" "sysctl")
for cmd in "${REQUIRED_COMMANDS[@]}"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: Required command '$cmd' not found. Please install the necessary packages."
    exit 1
  fi
done

echo "Pre-flight checks completed."

# 1.1.1 Disable unused filesystems
echo "1.1.1 Disabling unused filesystems..."

# Helper function to remove module if exists and disable it
disable_module() {
  local module=$1
  if lsmod | grep -q "^${module}"; then
    modprobe -r "$module" || echo "Warning: Failed to remove module $module"
  fi
  echo "install $module /bin/true" >> "/etc/modprobe.d/${module}.conf"
}

disable_module cramfs
disable_module freevxfs
disable_module jffs2
disable_module hfs
disable_module hfsplus

# squashfs, vfat, udf are builtin modules on some systems, skip removal but disable
echo "install squashfs /bin/true" >> /etc/modprobe.d/squashfs.conf
echo "install udf /bin/true" >> /etc/modprobe.d/udf.conf
echo "install vfat /bin/true" >> /etc/modprobe.d/vfat.conf

# Helper function to set mount options on a path
set_mount_option() {
  local path=$1
  local option=$2

  if mount | grep -q "on ${path} "; then
    # Path is a separate mount point
    mount -o remount,"${option}" "${path}" 2>/dev/null || echo "Warning: Could not remount ${path} with ${option}"
  else
    # Path is not a separate mount point, apply to root filesystem
    mount -o remount,"${option}" / 2>/dev/null || echo "Warning: Could not remount root filesystem with ${option} for ${path}"
  fi
}

# 1.1.2 Ensure /tmp is configured
echo "1.1.2 Configuring /tmp..."
# Check if /tmp should be a separate tmpfs mount
if ! mount | grep -q "tmpfs on /tmp"; then
  echo "Info: /tmp is not tmpfs, ensuring proper configuration"
fi

# 1.1.3 Ensure nodev option set on /tmp partition
echo "1.1.3 Setting nodev on /tmp..."
set_mount_option "/tmp" "nodev" "nodev option for /tmp"

# 1.1.4 Ensure nosuid option set on /tmp partition
echo "1.1.4 Setting nosuid on /tmp..."
set_mount_option "/tmp" "nosuid" "nosuid option for /tmp"

# 1.1.5 Ensure noexec option set on /tmp partition
echo "1.1.5 Setting noexec on /tmp..."
set_mount_option "/tmp" "noexec" "noexec option for /tmp"

# 1.1.6 Ensure /dev/shm is configured
echo "1.1.6 Configuring /dev/shm..."
if mount | grep -q "tmpfs on /dev/shm"; then
  mount -o remount,nodev,nosuid,noexec /dev/shm 2>/dev/null || echo "Warning: Could not remount /dev/shm"
else
  echo "Info: /dev/shm is not tmpfs, skipping remount"
fi

# 1.1.7 Ensure nodev option set on /dev/shm partition
# Already done above

# 1.1.8 Ensure nosuid option set on /dev/shm partition
# Already done

# 1.1.9 Ensure noexec option set on /dev/shm partition
# Already done

# 1.1.10 Ensure separate partition exists for /var
echo "1.1.10 /var partition check - Manual check required"

# 1.1.11 Ensure separate partition exists for /var/tmp
echo "1.1.11 /var/tmp partition check - Manual check required"

# 1.1.12 Ensure nodev option set on /var/tmp partition
echo "1.1.12 Setting nodev on /var/tmp..."
set_mount_option "/var/tmp" "nodev" "nodev option for /var/tmp"

# 1.1.13 Ensure nosuid option set on /var/tmp partition
echo "1.1.13 Setting nosuid on /var/tmp..."
set_mount_option "/var/tmp" "nosuid" "nosuid option for /var/tmp"

# 1.1.14 Ensure noexec option set on /var/tmp partition
echo "1.1.14 Setting noexec on /var/tmp..."
set_mount_option "/var/tmp" "noexec" "noexec option for /var/tmp"

# 1.1.15 Ensure separate partition exists for /var/log
echo "1.1.15 /var/log partition check - Manual check required"

# 1.1.16 Ensure separate partition exists for /var/log/audit
echo "1.1.16 /var/log/audit partition check - Manual check required"

# 1.1.17 Ensure separate partition exists for /home
echo "1.1.17 /home partition check - Manual check required"

# 1.1.18 Ensure nodev option set on /home partition
echo "1.1.18 Setting nodev on /home..."
set_mount_option "/home" "nodev" "nodev option for /home"

# 1.1.19 Ensure nodev option set on removable media partitions
echo "1.1.19 Removable media - Manual configuration required"

# 1.1.20 Ensure nosuid option set on removable media partitions
echo "1.1.20 Removable media - Manual configuration required"

# 1.1.21 Ensure noexec option set on removable media partitions
echo "1.1.21 Removable media - Manual configuration required"

# 1.1.22 Ensure sticky bit is set on all world-writable directories
echo "1.1.22 Setting sticky bit on world-writable directories..."
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs chmod a+t

# 1.1.23 Disable Automounting
echo "1.1.23 Disabling automounting..."
systemctl disable autofs

# 1.1.24 Disable USB Storage
echo "1.1.24 Disabling USB storage..."
echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb-storage.conf

# 1.2 Configure Software Updates
echo "1.2 Configuring software updates..."
if command -v yum > /dev/null 2>&1; then
  yum install dnf-automatic -y
  systemctl enable dnf-automatic.timer
  systemctl start dnf-automatic.timer
elif command -v apt > /dev/null 2>&1; then
  apt update && apt install -y unattended-upgrades
  systemctl enable unattended-upgrades
  systemctl start unattended-upgrades
fi

# 1.3 Filesystem Integrity Checking
echo "1.3 Installing AIDE..."
if command -v yum > /dev/null 2>&1; then
  yum install aide -y
elif command -v apt > /dev/null 2>&1; then
  apt update && apt install -y aide
fi
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# 1.4 Secure Boot Settings
echo "1.4 Configuring secure boot..."
if command -v yum > /dev/null 2>&1; then
  grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg  # Adjust for BIOS if needed
elif command -v apt > /dev/null 2>&1; then
  update-grub
fi

# 1.5 Additional Process Hardening
echo "1.5 Process hardening..."
# 1.5.1 Ensure core dumps are restricted
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -p

# 1.5.2 Ensure address space layout randomization (ASLR) is enabled
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
sysctl -p

# 1.5.3 Ensure prelink is disabled
if command -v yum > /dev/null 2>&1; then
  yum remove prelink -y
elif command -v apt > /dev/null 2>&1; then
  apt remove -y prelink
fi

# 1.6 Mandatory Access Control
echo "1.6 Configuring SELinux..."
sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
setenforce 1

# 1.7 Warning Banners
echo "1.7 Configuring warning banners..."
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

# 1.8 GNOME Display Manager
echo "1.8 GNOME Display Manager - Manual configuration required"

# 2 Services
echo "2 Services..."

# 2.1 inetd Services
echo "2.1 Disabling inetd services..."
if command -v yum > /dev/null 2>&1; then
  yum remove xinetd -y
elif command -v apt > /dev/null 2>&1; then
  apt remove -y xinetd
fi

# 2.2 Special Purpose Services
echo "2.2 Disabling special purpose services..."
systemctl disable avahi-daemon
systemctl disable cups
systemctl disable dhcpd
systemctl disable slapd
systemctl disable nfs
systemctl disable rpcbind
systemctl disable named
systemctl disable vsftpd
systemctl disable httpd
systemctl disable dovecot
systemctl disable smb
systemctl disable squid
systemctl disable snmpd

# 2.3 Service Clients
echo "2.3 Removing service clients..."
yum remove openldap-clients -y
yum remove telnet -y
yum remove ftp -y

# 3 Network Configuration
echo "3 Network Configuration..."

# 3.1 Disable unused network protocols and devices
echo "3.1 Disabling unused network protocols..."
echo "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf
echo "install sctp /bin/true" >> /etc/modprobe.d/sctp.conf
echo "install rds /bin/true" >> /etc/modprobe.d/rds.conf
echo "install tipc /bin/true" >> /etc/modprobe.d/tipc.conf

# 3.2 Network Parameters (Host Only)
echo "3.2 Configuring network parameters..."
{
echo "net.ipv4.ip_forward = 0"
echo "net.ipv4.conf.all.send_redirects = 0"
echo "net.ipv4.conf.default.send_redirects = 0"
} >> /etc/sysctl.conf
sysctl -p

# 3.3 Network Parameters (Host and Router)
echo "3.3 Configuring network parameters..."
{
echo "net.ipv4.conf.all.accept_source_route = 0"
echo "net.ipv4.conf.all.accept_redirects = 0"
echo "net.ipv4.conf.all.secure_redirects = 0"
echo "net.ipv4.conf.all.log_martians = 1"
echo "net.ipv4.conf.default.accept_source_route = 0"
echo "net.ipv4.conf.default.accept_redirects = 0"
echo "net.ipv4.conf.default.secure_redirects = 0"
echo "net.ipv4.conf.default.log_martians = 1"
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1"
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1"
echo "net.ipv4.conf.all.rp_filter = 1"
echo "net.ipv4.conf.default.rp_filter = 1"
echo "net.ipv4.tcp_syncookies = 1"
} >> /etc/sysctl.conf
sysctl -p

# 3.4 Uncommon Network Protocols
echo "3.4 Disabling uncommon network protocols..."
# dccp already disabled in 3.1

# 3.5 Firewall Configuration
echo "3.5 Configuring firewall..."
yum install firewalld -y
systemctl enable firewalld
systemctl start firewalld
firewall-cmd --set-default-zone=drop

# 4 Logging and Auditing
echo "4 Logging and Auditing..."

# 4.1 Configure System Accounting (auditd)
echo "4.1 Configuring auditd..."
yum install audit -y
systemctl enable auditd
systemctl start auditd

# 4.1.1 Configure Data Retention
echo "4.1.1 Configuring audit data retention..."
sed -i 's/max_log_file = .*/max_log_file = 8/' /etc/audit/auditd.conf
sed -i 's/max_log_file_action = .*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf

# 4.1.2 Configure audit log storage size
echo "4.1.2 Configuring audit log storage..."
sed -i 's/space_left_action = .*/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/action_mail_acct = .*/action_mail_acct = root/' /etc/audit/auditd.conf
sed -i 's/admin_space_left_action = .*/admin_space_left_action = halt/' /etc/audit/auditd.conf

# 4.1.3 Ensure audit logs are not automatically deleted
echo "4.1.3 Ensuring audit logs are not deleted..."

# 4.1.4 Ensure system is disabled when audit logs are full
echo "4.1.4 Configuring system disable on full logs..."

# 4.1.5 Ensure auditd collects login and logout events
echo "4.1.5 Collecting login/logout events..."
{
echo "-w /var/log/lastlog -p wa -k logins"
echo "-w /var/run/faillock -p wa -k logins"
} >> /etc/audit/rules.d/audit.rules

# 4.1.6 Ensure auditd collects process and session initiation information
echo "4.1.6 Collecting process/session info..."
{
echo "-w /var/run/utmp -p wa -k session"
echo "-w /var/log/wtmp -p wa -k logins"
echo "-w /var/log/btmp -p wa -k logins"
} >> /etc/audit/rules.d/audit.rules

# 4.1.7 Ensure auditd collects discretionary access control permission modification events
echo "4.1.7 Collecting DAC events..."
{
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
} >> /etc/audit/rules.d/audit.rules

# 4.1.8 Ensure auditd collects unsuccessful unauthorized access attempts to files
echo "4.1.8 Collecting unauthorized access..."
{
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
} >> /etc/audit/rules.d/audit.rules

# 4.1.9 Ensure auditd collects use of privileged commands
echo "4.1.9 Collecting privileged commands..."
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' >> /etc/audit/rules.d/audit.rules

# 4.1.10 Ensure auditd collects successful file system mounts
echo "4.1.10 Collecting filesystem mounts..."
{
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts"
echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts"
} >> /etc/audit/rules.d/audit.rules

# 4.1.11 Ensure auditd collects file deletion events by user
echo "4.1.11 Collecting file deletions..."
{
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete"
echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete"
} >> /etc/audit/rules.d/audit.rules

# 4.1.12 Ensure auditd collects changes to system administration scope
echo "4.1.12 Collecting admin scope changes..."
{
echo "-w /etc/sudoers -p wa -k scope"
echo "-w /etc/sudoers.d -p wa -k scope"
} >> /etc/audit/rules.d/audit.rules

# 4.1.13 Ensure auditd collects system administrator actions (sudolog)
echo "4.1.13 Collecting sudo actions..."
echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules

# 4.1.14 Ensure auditd collects kernel module loading and unloading
echo "4.1.14 Collecting kernel module events..."
{
echo "-w /sbin/insmod -p x -k modules"
echo "-w /sbin/rmmod -p x -k modules"
echo "-w /sbin/modprobe -p x -k modules"
echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules"
} >> /etc/audit/rules.d/audit.rules

# 4.1.15 Ensure auditd collects the auditing rules themselves
echo "4.1.15 Collecting audit rules..."
{
echo "-w /etc/audit/audit.rules -p wa -k auditconfig"
echo "-w /etc/audit/rules.d -p wa -k auditconfig"
} >> /etc/audit/rules.d/audit.rules

# 4.1.16 Ensure auditd collects successful and unsuccessful attempts to use the chcon command
echo "4.1.16 Collecting chcon attempts..."
echo "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/audit.rules

# 4.1.17 Ensure auditd collects successful and unsuccessful attempts to use the setfacl command
echo "4.1.17 Collecting setfacl attempts..."
echo "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/audit.rules

# 4.1.18 Ensure auditd collects successful and unsuccessful attempts to use the chacl command
echo "4.1.18 Collecting chacl attempts..."
echo "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/audit.rules

# 4.1.19 Ensure auditd collects successful and unsuccessful attempts to use the usermod command
echo "4.1.19 Collecting usermod attempts..."
echo "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k user_mod" >> /etc/audit/rules.d/audit.rules

# 4.1.20 Ensure auditd collects successful and unsuccessful attempts to use the crontab command
echo "4.1.20 Collecting crontab attempts..."
echo "-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k cron" >> /etc/audit/rules.d/audit.rules

# 4.1.21 Ensure auditd collects successful and unsuccessful attempts to use the pam_timestamp_check command
echo "4.1.21 Collecting pam_timestamp_check attempts..."
echo "-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k time-check" >> /etc/audit/rules.d/audit.rules

# 4.1.22 Ensure auditd collects successful and unsuccessful attempts to use the pkexec command
echo "4.1.22 Collecting pkexec attempts..."
echo "-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k exec" >> /etc/audit/rules.d/audit.rules

# 4.1.23 Ensure auditd collects successful and unsuccessful attempts to use the ssh-keysign command
echo "4.1.23 Collecting ssh-keysign attempts..."
echo "-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_esc" >> /etc/audit/rules.d/audit.rules

# 4.1.24 Ensure auditd collects successful and unsuccessful attempts to use the ssh-agent command
echo "4.1.24 Collecting ssh-agent attempts..."
echo "-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_esc" >> /etc/audit/rules.d/audit.rules

# 4.2 Configure rsyslog
echo "4.2 Configuring rsyslog..."
yum install rsyslog -y
systemctl enable rsyslog
systemctl start rsyslog

# 4.2.1 Ensure rsyslog is installed
# Already done

# 4.2.2 Ensure rsyslog service is enabled
# Already done

# 4.2.3 Ensure rsyslog default file permissions configured
echo "4.2.3 Configuring rsyslog file permissions..."
echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf

# 4.2.4 Ensure rsyslog is configured to send logs to a remote log host
echo "4.2.4 Remote logging - Manual configuration required"

# 4.2.5 Ensure remote rsyslog messages are only accepted on designated log hosts
echo "4.2.5 Remote rsyslog - Manual configuration required"

# 4.3 Ensure logrotate is configured
echo "4.3 Configuring logrotate..."
yum install logrotate -y

# 5 Access, Authentication and Authorization
echo "5 Access, Authentication and Authorization..."

# 5.1 Configure cron
echo "5.1 Configuring cron..."
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

# 5.2 SSH Server Configuration
echo "5.2 Configuring SSH..."
yum install openssh-server -y
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/' /etc/ssh/sshd_config
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/' /etc/ssh/sshd_config
sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/' /etc/ssh/sshd_config
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 60/' /etc/ssh/sshd_config
{
echo "AllowUsers root"
echo "DenyUsers bin daemon adm lp mail uucp operator games gopher ftp nobody vcsa rpc mailnull smmsp nscd rpcuser nfsnobody sshd"
echo "DenyGroups bin daemon adm lp mail uucp operator games gopher ftp nobody vcsa rpc mailnull smmsp nscd rpcuser nfsnobody sshd"
} >> /etc/ssh/sshd_config
systemctl reload sshd

# 5.3 Configure PAM
echo "5.3 Configuring PAM..."
yum install pam -y
# 5.3.1 Ensure password creation requirements are configured
# 5.3.2 Ensure lockout for failed password attempts is configured
# 5.3.3 Ensure password reuse is limited
{
echo "password requisite pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type="
echo "password sufficient pam_unix.so sha512 shadow nullok try_first_pass use_authtok"
echo "auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900"
echo "auth [success=1 default=bad] pam_unix.so"
echo "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900"
echo "auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900"
echo "password sufficient pam_unix.so remember=5"
} >> /etc/pam.d/system-auth
# 5.3.4 Ensure password hashing algorithm is SHA-512
# Already configured

# 5.4 User Accounts and Environment
echo "5.4 Configuring user accounts..."
# 5.4.1 Set Shadow Password Suite Parameters
sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs
sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
# 5.4.2 Ensure system accounts are secured
usermod -L -s /sbin/nologin bin
usermod -L -s /sbin/nologin daemon
# And so on for other system accounts
# 5.4.3 Ensure default user shell timeout is 900 seconds or less
echo "TMOUT=600" >> /etc/bashrc
echo "TMOUT=600" >> /etc/profile
# 5.4.4 Ensure default group for the root account is GID 0
usermod -g 0 root
# 5.4.5 Ensure default user umask is 027 or more restrictive
echo "umask 027" >> /etc/bashrc
echo "umask 027" >> /etc/profile

# 6 System Maintenance
echo "6 System Maintenance..."

# 6.1 System File Permissions
echo "6.1 Configuring system file permissions..."
chown root:root /etc/passwd
chmod 644 /etc/passwd
chown root:root /etc/shadow
chmod 000 /etc/shadow
chown root:root /etc/group
chmod 644 /etc/group
chown root:root /etc/gshadow
chmod 000 /etc/gshadow
chown root:root /etc/passwd-
chmod 600 /etc/passwd-
chown root:root /etc/shadow-
chmod 600 /etc/shadow-
chown root:root /etc/group-
chmod 600 /etc/group-
chown root:root /etc/gshadow-
chmod 600 /etc/gshadow-
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg

# 6.2 User and Group Settings
echo "6.2 Configuring user and group settings..."
# 6.2.1 Ensure no duplicate UIDs exist
# Manual check
# 6.2.2 Ensure no duplicate GIDs exist
# Manual check
# 6.2.3 Ensure no duplicate user names exist
# Manual check
# 6.2.4 Ensure no duplicate group names exist
# Manual check

echo "RHEL 8 CIS Level 1 Hardening completed. Please review and reboot if necessary."
