#!/bin/bash

# RHEL 9.6.0_HVM-20250618-x86_64-0-Hourly2-GP3 Hardening Script
# Implements CIS Level 1 and Level 2 High/Critical Controls
# Excludes SSH and Active Directory domain joining controls
# Run as root or with sudo

# Function to log actions
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log "Starting RHEL hardening script"

# CIS 1.1.1.1 - Ensure mounting of cramfs filesystems is disabled
log "Disabling cramfs filesystem"
sudo sh -c 'echo "install cramfs /bin/true" >> /etc/modprobe.d/cramfs.conf'
sudo rmmod cramfs 2>/dev/null || true

# CIS 1.1.1.2 - Ensure mounting of freevxfs filesystems is disabled
log "Disabling freevxfs filesystem"
sudo sh -c 'echo "install freevxfs /bin/true" >> /etc/modprobe.d/freevxfs.conf'
sudo rmmod freevxfs 2>/dev/null || true

# CIS 1.1.1.3 - Ensure mounting of jffs2 filesystems is disabled
log "Disabling jffs2 filesystem"
sudo sh -c 'echo "install jffs2 /bin/true" >> /etc/modprobe.d/jffs2.conf'
sudo rmmod jffs2 2>/dev/null || true

# CIS 1.1.1.4 - Ensure mounting of hfs filesystems is disabled
log "Disabling hfs filesystem"
sudo sh -c 'echo "install hfs /bin/true" >> /etc/modprobe.d/hfs.conf'
sudo rmmod hfs 2>/dev/null || true

# CIS 1.1.1.5 - Ensure mounting of hfsplus filesystems is disabled
log "Disabling hfsplus filesystem"
sudo sh -c 'echo "install hfsplus /bin/true" >> /etc/modprobe.d/hfsplus.conf'
sudo rmmod hfsplus 2>/dev/null || true

# CIS 1.1.1.6 - Ensure mounting of squashfs filesystems is disabled
log "Disabling squashfs filesystem"
sudo sh -c 'echo "install squashfs /bin/true" >> /etc/modprobe.d/squashfs.conf'
sudo rmmod squashfs 2>/dev/null || true

# CIS 1.1.1.7 - Ensure mounting of udf filesystems is disabled
log "Disabling udf filesystem"
sudo sh -c 'echo "install udf /bin/true" >> /etc/modprobe.d/udf.conf'
sudo rmmod udf 2>/dev/null || true

# CIS 1.1.1.8 - Ensure mounting of FAT filesystems is disabled
log "Disabling FAT filesystem"
sudo sh -c 'echo "install vfat /bin/true" >> /etc/modprobe.d/vfat.conf'
sudo rmmod vfat 2>/dev/null || true

# CIS 1.1.2.1 - Ensure /tmp is configured
log "Configuring /tmp"
if ! grep -q "/tmp" /etc/fstab; then
    sudo sh -c 'echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab'
fi

# CIS 1.1.2.2 - Ensure /dev/shm is configured
log "Configuring /dev/shm"
if ! grep -q "/dev/shm" /etc/fstab; then
    sudo sh -c 'echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab'
fi

# CIS 1.1.2.3 - Ensure /var is configured
log "Configuring /var"
if ! grep -q "/var" /etc/fstab; then
    sudo sh -c 'echo "LABEL=var /var ext4 defaults,nodev 1 2" >> /etc/fstab'
fi

# CIS 1.1.2.4 - Ensure /var/tmp is configured
log "Configuring /var/tmp"
if ! grep -q "/var/tmp" /etc/fstab; then
    sudo sh -c 'echo "tmpfs /var/tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab'
fi

# CIS 1.1.2.5 - Ensure /var/log is configured
log "Configuring /var/log"
if ! grep -q "/var/log" /etc/fstab; then
    sudo sh -c 'echo "LABEL=log /var/log ext4 defaults,nodev 1 2" >> /etc/fstab'
fi

# CIS 1.1.2.6 - Ensure /var/log/audit is configured
log "Configuring /var/log/audit"
if ! grep -q "/var/log/audit" /etc/fstab; then
    sudo sh -c 'echo "LABEL=audit /var/log/audit ext4 defaults,nodev 1 2" >> /etc/fstab'
fi

# CIS 1.1.3 - Ensure gpgcheck is globally activated
log "Enabling gpgcheck globally"
if [ -f /etc/dnf/dnf.conf ]; then
    sed -i 's/^gpgcheck\s*=.*/gpgcheck=1/' /etc/dnf/dnf.conf
fi

# CIS 1.1.4 - Ensure AIDE is installed
log "Installing AIDE"
if command -v dnf > /dev/null; then
    sudo dnf install -y aide
fi
if command -v aide > /dev/null; then
    sudo aide --init
    sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
fi

# CIS 1.1.5 - Ensure filesystem integrity is regularly checked
log "Configuring filesystem integrity check"
sudo sh -c 'echo "0 5 * * * root /usr/sbin/aide --check" >> /etc/crontab'

# CIS 1.2.1 - Ensure package manager repositories are configured
log "Configuring package manager repositories"
if command -v dnf > /dev/null; then
    sudo dnf config-manager --set-enabled rhui-client-config-server-9
fi

# CIS 1.2.2 - Ensure GPG keys are configured
log "Configuring GPG keys"
if command -v rpm > /dev/null && [ -f /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release ]; then
    sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
fi

# CIS 1.3.1 - Ensure sudo is installed
log "Ensuring sudo is installed"
if command -v dnf > /dev/null; then
    sudo dnf install -y sudo
fi

# CIS 1.3.2 - Ensure sudo commands use pty
log "Configuring sudo to use pty"
sudo sh -c 'echo "Defaults use_pty" >> /etc/sudoers'

# CIS 1.3.3 - Ensure sudo log file exists
log "Configuring sudo log file"
sudo sh -c 'echo "Defaults logfile=\"/var/log/sudo.log\"" >> /etc/sudoers'

# CIS 1.4.1 - Ensure AIDE is installed (already done above)

# CIS 1.4.2 - Ensure filesystem integrity is regularly checked (already done above)

# CIS 1.5.1 - Ensure core dumps are restricted
log "Restricting core dumps"
sudo sh -c 'echo "* hard core 0" >> /etc/security/limits.conf'
sudo sh -c 'echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 1.5.2 - Ensure address space layout randomization (ASLR) is enabled
log "Enabling ASLR"
sudo sh -c 'echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 1.5.3 - Ensure prelink is disabled
log "Disabling prelink"
if command -v dnf > /dev/null; then
    sudo dnf remove -y prelink
fi

# CIS 1.6.1 - Ensure SELinux is installed
log "Ensuring SELinux is installed"
if command -v dnf > /dev/null; then
    sudo dnf install -y libselinux
fi

# CIS 1.6.2 - Ensure SELinux is not disabled in bootloader configuration
log "Configuring SELinux in bootloader"
if [ -f /etc/default/grub ]; then
    sudo sed -i 's/selinux=0/selinux=1/' /etc/default/grub
fi
if command -v grub2-mkconfig > /dev/null; then
    sudo grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
fi

# CIS 1.6.3 - Ensure SELinux policy is configured
log "Configuring SELinux policy"
if command -v setsebool > /dev/null; then
    sudo setsebool -P httpd_can_network_connect=0
    sudo setsebool -P httpd_can_network_connect_db=0
fi

# CIS 1.7.1 - Ensure message of the day is configured properly
log "Configuring message of the day"
sudo sh -c 'echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd'

# CIS 1.7.2 - Ensure local login warning banner is configured properly
log "Configuring local login warning banner"
sudo sh -c 'echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue'

# CIS 1.7.3 - Ensure remote login warning banner is configured properly
log "Configuring remote login warning banner"
sudo sh -c 'echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net'

# CIS 1.7.4 - Ensure permissions on /etc/motd are configured
log "Setting permissions on /etc/motd"
sudo chmod 644 /etc/motd

# CIS 1.7.5 - Ensure permissions on /etc/issue are configured
log "Setting permissions on /etc/issue"
sudo chmod 644 /etc/issue

# CIS 1.7.6 - Ensure permissions on /etc/issue.net are configured
log "Setting permissions on /etc/issue.net"
sudo chmod 644 /etc/issue.net

# CIS 1.8.1 - Ensure GNOME Display Manager is removed
log "Removing GNOME Display Manager"
if command -v dnf > /dev/null; then
    sudo dnf remove -y gdm
fi

# CIS 1.8.2 - Ensure GDM login banner is configured
log "Configuring GDM login banner"
# This is handled by /etc/issue

# CIS 1.9.1 - Ensure updates, patches, and additional security software are installed
log "Installing updates and security software"
if command -v dnf > /dev/null; then
    sudo dnf update -y
    sudo dnf install -y yum-utils
fi

# CIS 1.9.2 - Ensure Red Hat Subscription Manager connection is configured
log "Configuring Red Hat Subscription Manager"
# Assuming subscription is already configured in AWS

# CIS 1.10.1 - Ensure system-wide crypto policy is not legacy
log "Configuring system-wide crypto policy"
if command -v update-crypto-policies > /dev/null; then
    sudo update-crypto-policies --set DEFAULT
fi

# CIS 1.10.2 - Ensure system-wide crypto policy is FUTURE or FIPS
log "Ensuring crypto policy is FUTURE or FIPS"
if command -v update-crypto-policies > /dev/null; then
    sudo update-crypto-policies --set FUTURE
fi

# CIS 2.1.1 - Ensure time synchronization is in use
log "Configuring time synchronization"
if command -v dnf > /dev/null; then
    sudo dnf install -y chrony
fi
if systemctl list-unit-files | grep -q chronyd; then
    sudo systemctl enable chronyd
    sudo systemctl start chronyd
fi

# CIS 2.1.2 - Ensure chrony is configured
log "Configuring chrony"
sudo sh -c 'echo "server time.aws.com iburst" >> /etc/chrony.conf'
sudo systemctl restart chronyd

# CIS 2.2.1 - Ensure xinetd is not installed
log "Removing xinetd"
if command -v dnf > /dev/null; then
    sudo dnf remove -y xinetd
fi

# CIS 2.2.2 - Ensure openbsd-inetd is not installed
log "Removing openbsd-inetd"
if command -v dnf > /dev/null; then
    sudo dnf remove -y openbsd-inetd
fi

# CIS 2.2.3 - Ensure time synchronization is in use (already done)

# CIS 2.2.4 - Ensure chrony is configured (already done)

# CIS 2.2.5 - Ensure ntp is not installed
log "Removing ntp"
if command -v dnf > /dev/null; then
    sudo dnf remove -y ntp
fi

# CIS 2.2.6 - Ensure chrony is not installed (wait, we installed it above, but CIS says ensure it's configured properly)

# CIS 2.3.1 - Ensure Avahi Server is not installed
log "Removing Avahi Server"
if command -v dnf > /dev/null; then
    sudo dnf remove -y avahi
fi

# CIS 2.3.2 - Ensure CUPS is not installed
log "Removing CUPS"
if command -v dnf > /dev/null; then
    sudo dnf remove -y cups
fi

# CIS 2.3.3 - Ensure DHCP Server is not installed
log "Removing DHCP Server"
if command -v dnf > /dev/null; then
    sudo dnf remove -y dhcp-server
fi

# CIS 2.3.4 - Ensure LDAP server is not installed
log "Removing LDAP server"
if command -v dnf > /dev/null; then
    sudo dnf remove -y openldap-servers
fi

# CIS 2.3.5 - Ensure NFS is not installed
log "Removing NFS"
if command -v dnf > /dev/null; then
    sudo dnf remove -y nfs-utils
fi

# CIS 2.3.6 - Ensure DNS server is not installed
log "Removing DNS server"
if command -v dnf > /dev/null; then
    sudo dnf remove -y bind
fi

# CIS 2.3.7 - Ensure FTP server is not installed
log "Removing FTP server"
if command -v dnf > /dev/null; then
    sudo dnf remove -y vsftpd
fi

# CIS 2.3.8 - Ensure HTTP server is not installed
log "Removing HTTP server"
if command -v dnf > /dev/null; then
    sudo dnf remove -y httpd
fi

# CIS 2.3.9 - Ensure IMAP and POP3 server is not installed
log "Removing IMAP and POP3 server"
if command -v dnf > /dev/null; then
    sudo dnf remove -y dovecot
fi

# CIS 2.3.10 - Ensure Samba is not installed
log "Removing Samba"
if command -v dnf > /dev/null; then
    sudo dnf remove -y samba
fi

# CIS 2.3.11 - Ensure HTTP Proxy Server is not installed
log "Removing HTTP Proxy Server"
if command -v dnf > /dev/null; then
    sudo dnf remove -y squid
fi

# CIS 2.3.12 - Ensure net-snmp is not installed
log "Removing net-snmp"
if command -v dnf > /dev/null; then
    sudo dnf remove -y net-snmp
fi

# CIS 2.3.13 - Ensure NIS server is not installed
log "Removing NIS server"
if command -v dnf > /dev/null; then
    sudo dnf remove -y ypserv
fi

# CIS 3.1.1 - Ensure IP forwarding is disabled
log "Disabling IP forwarding"
sudo sh -c 'echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sh -c 'echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 3.1.2 - Ensure packet redirect sending is disabled
log "Disabling packet redirect sending"
sudo sh -c 'echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sh -c 'echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 3.2.1 - Ensure source routed packets are not accepted
log "Disabling source routed packets"
sudo sh -c 'echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sh -c 'echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 3.2.2 - Ensure ICMP redirects are not accepted
log "Disabling ICMP redirects"
sudo sh -c 'echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sh -c 'echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 3.2.3 - Ensure secure ICMP redirects are not accepted
log "Disabling secure ICMP redirects"
sudo sh -c 'echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sh -c 'echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 3.2.4 - Ensure suspicious packets are logged
log "Logging suspicious packets"
sudo sh -c 'echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/99-sysctl.conf'
sudo sh -c 'echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 3.2.5 - Ensure broadcast ICMP requests are ignored
log "Ignoring broadcast ICMP requests"
sudo sh -c 'echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 3.2.6 - Ensure bogus ICMP responses are ignored
log "Ignoring bogus ICMP responses"
sudo sh -c 'echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 3.2.7 - Ensure Reverse Path Filtering is enabled
log "Enabling Reverse Path Filtering"
sudo sh -c 'echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/99-sysctl.conf'
sudo sh -c 'echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 3.2.8 - Ensure TCP SYN Cookies is enabled
log "Enabling TCP SYN Cookies"
sudo sh -c 'echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 3.3.1 - Ensure IPv6 router advertisements are not accepted
log "Disabling IPv6 router advertisements"
sudo sh -c 'echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sh -c 'echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 3.3.2 - Ensure IPv6 redirects are not accepted
log "Disabling IPv6 redirects"
sudo sh -c 'echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sh -c 'echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 3.3.3 - Ensure IPv6 is disabled
log "Disabling IPv6"
sudo sh -c 'echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.d/99-sysctl.conf'
sudo sh -c 'echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.d/99-sysctl.conf'
sudo sysctl -p

# CIS 3.4.1 - Ensure TCP Wrappers is installed
log "Installing TCP Wrappers"
if command -v dnf > /dev/null; then
    sudo dnf install -y tcp_wrappers
fi

# CIS 3.4.2 - Ensure /etc/hosts.allow is configured
log "Configuring /etc/hosts.allow"
sudo sh -c 'echo "ALL: LOCAL" > /etc/hosts.allow'

# CIS 3.4.3 - Ensure /etc/hosts.deny is configured
log "Configuring /etc/hosts.deny"
sudo sh -c 'echo "ALL: ALL" > /etc/hosts.deny'

# CIS 3.4.4 - Ensure permissions on /etc/hosts.allow are configured
log "Setting permissions on /etc/hosts.allow"
sudo chmod 644 /etc/hosts.allow

# CIS 3.4.5 - Ensure permissions on /etc/hosts.deny are configured
log "Setting permissions on /etc/hosts.deny"
sudo chmod 644 /etc/hosts.deny

# CIS 4.1.1 - Ensure auditd is installed
log "Installing auditd"
if command -v dnf > /dev/null; then
    sudo dnf install -y audit
fi

# CIS 4.1.2 - Ensure auditd service is enabled
log "Enabling auditd service"
if systemctl list-unit-files | grep -q auditd; then
    sudo systemctl enable auditd
fi

# CIS 4.1.3 - Ensure auditing for processes that start prior to auditd is enabled
log "Enabling auditing for processes prior to auditd"
if command -v grubby > /dev/null; then
    sudo grubby --update-kernel ALL --args "audit=1"
fi

# CIS 4.1.4 - Ensure audit_backlog_limit is sufficient
log "Configuring audit_backlog_limit"
if command -v grubby > /dev/null; then
    sudo grubby --update-kernel ALL --args "audit_backlog_limit=8192"
fi

# CIS 4.1.5 - Ensure auditd collects login and logout events
log "Configuring auditd to collect login/logout events"
if [ -d /etc/audit/rules.d ]; then
    sudo sh -c 'echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules'
    sudo sh -c 'echo "-w /var/run/faillock -p wa -k logins" >> /etc/audit/rules.d/audit.rules'
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.6 - Ensure auditd collects process and session initiation information
log "Configuring auditd to collect process/session info"
if [ -d /etc/audit/rules.d ]; then
    {
    echo "-w /var/run/utmp -p wa -k session"
    echo "-w /var/log/wtmp -p wa -k logins"
    echo "-w /var/log/btmp -p wa -k logins"
    } >> /etc/audit/rules.d/audit.rules
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.7 - Ensure auditd collects discretionary access control permission modification events
log "Configuring auditd for DAC permission modifications"
if [ -d /etc/audit/rules.d ]; then
    sudo sh -c 'echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules'
    sudo sh -c 'echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules'
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.8 - Ensure auditd collects unsuccessful unauthorized access attempts to files
log "Configuring auditd for unsuccessful file access"
if [ -d /etc/audit/rules.d ]; then
    sudo sh -c 'echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules'
    sudo sh -c 'echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules'
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.9 - Ensure auditd collects use of privileged commands
log "Configuring auditd for privileged commands"
if [ -d /etc/audit/rules.d ]; then
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' >> /etc/audit/rules.d/audit.rules
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.10 - Ensure auditd collects successful file system mounts
log "Configuring auditd for successful filesystem mounts"
if [ -d /etc/audit/rules.d ]; then
    sudo sh -c 'echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules'
    sudo sh -c 'echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules'
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.11 - Ensure auditd collects file deletion events by user
log "Configuring auditd for file deletion events"
if [ -d /etc/audit/rules.d ]; then
    sudo sh -c 'echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules'
    sudo sh -c 'echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules'
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.12 - Ensure auditd collects changes to system administration scope
log "Configuring auditd for system administration scope changes"
if [ -d /etc/audit/rules.d ]; then
    sudo sh -c 'echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/audit.rules'
    sudo sh -c 'echo "-w /etc/sudoers.d -p wa -k scope" >> /etc/audit/rules.d/audit.rules'
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.13 - Ensure auditd collects system administrator actions
log "Configuring auditd for system administrator actions"
if [ -d /etc/audit/rules.d ]; then
    sudo sh -c 'echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules'
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.14 - Ensure auditd collects kernel module loading and unloading
log "Configuring auditd for kernel module loading/unloading"
if [ -d /etc/audit/rules.d ]; then
    {
    echo "-w /sbin/insmod -p x -k modules"
    echo "-w /sbin/rmmod -p x -k modules"
    echo "-w /sbin/modprobe -p x -k modules"
    } >> /etc/audit/rules.d/audit.rules
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.15 - Ensure auditd collects information on the use of special rights
log "Configuring auditd for special rights usage"
if [ -d /etc/audit/rules.d ]; then
    sudo sh -c 'echo "-a always,exit -F arch=b64 -S setuid -F auid>=1000 -F auid!=4294967295 -k special" >> /etc/audit/rules.d/audit.rules'
    sudo sh -c 'echo "-a always,exit -F arch=b32 -S setuid -F auid>=1000 -F auid!=4294967295 -k special" >> /etc/audit/rules.d/audit.rules'
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.16 - Ensure auditd collects information on exporting to media
log "Configuring auditd for media export"
if [ -d /etc/audit/rules.d ]; then
    sudo sh -c 'echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k export" >> /etc/audit/rules.d/audit.rules'
    sudo sh -c 'echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k export" >> /etc/audit/rules.d/audit.rules'
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.17 - Ensure auditd collects filesystem mounts
log "Configuring auditd for filesystem mounts"
if [ -d /etc/audit/rules.d ]; then
    sudo sh -c 'echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules'
    sudo sh -c 'echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules'
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.18 - Ensure auditd collects user and group information
log "Configuring auditd for user/group information"
if [ -d /etc/audit/rules.d ]; then
    {
    echo "-w /etc/group -p wa -k identity"
    echo "-w /etc/passwd -p wa -k identity"
    echo "-w /etc/gshadow -p wa -k identity"
    echo "-w /etc/shadow -p wa -k identity"
    echo "-w /etc/security/opasswd -p wa -k identity"
    } >> /etc/audit/rules.d/audit.rules
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.19 - Ensure auditd collects information on the use of special rights
log "Configuring auditd for special rights usage (duplicate, already done)"

# CIS 4.1.20 - Ensure auditd collects information on exporting to media (duplicate, already done)

# CIS 4.1.21 - Ensure auditd collects filesystem mounts (duplicate, already done)

# CIS 4.1.22 - Ensure auditd collects user and group information (duplicate, already done)

# CIS 4.1.23 - Ensure auditd collects attempts to alter time through adjtimex
log "Configuring auditd for time alteration attempts"
if [ -d /etc/audit/rules.d ]; then
    sudo sh -c 'echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules'
    sudo sh -c 'echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules'
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.24 - Ensure auditd collects attempts to alter time through settimeofday
log "Configuring auditd for settimeofday attempts (duplicate)"

# CIS 4.1.25 - Ensure auditd collects attempts to alter time through stime
log "Configuring auditd for stime attempts"
if [ -d /etc/audit/rules.d ]; then
    sudo sh -c 'echo "-a always,exit -F arch=b32 -S stime -k time-change" >> /etc/audit/rules.d/audit.rules'
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.26 - Ensure auditd collects attempts to alter time through clock_settime
log "Configuring auditd for clock_settime attempts (duplicate)"

# CIS 4.1.27 - Ensure auditd collects attempts to alter time through /etc/localtime
log "Configuring auditd for /etc/localtime alterations"
if [ -d /etc/audit/rules.d ]; then
    sudo sh -c 'echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules'
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

# CIS 4.1.94 - Ensure auditd configuration is immutable
log "Making auditd configuration immutable"
if [ -d /etc/audit/rules.d ]; then
    sudo sh -c 'echo "-e 2" >> /etc/audit/rules.d/audit.rules'
else
    log "Warning: /etc/audit/rules.d directory does not exist, skipping audit rules configuration"
fi

log "RHEL 9.6.0 hardening script completed successfully"
