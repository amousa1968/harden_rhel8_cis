# RHEL 8 CIS Benchmark Level 1 Hardening Script

## Overview

This Bash script (`harden_rhel8_cis.sh`) automates the implementation of OS hardening controls for Red Hat Enterprise Linux 8 (RHEL 8) based on the CIS (Center for Internet Security) Benchmark Level 1 requirements. The script applies security configurations to enhance system security posture.

## Prerequisites

- **Operating System**: Red Hat Enterprise Linux 8 (RHEL 8)
- **Permissions**: Root access (run with `sudo` or as root user)
- **Backup**: Ensure system backup before execution, as changes may affect system behavior
- **Network**: Internet access for package installations (dnf commands)

## Usage

1. Download or copy the script to your RHEL 8 system
2. Make the script executable:
   ```bash
   chmod +x harden_rhel8_cis.sh
   ```
3. Run the script as root:
   ```bash
   sudo ./harden_rhel8_cis.sh
   ```

## What the Script Does

The script implements hardening controls across multiple security domains:

### 1. Filesystem Configuration
- Disables unused filesystems (cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf)
- Configures mount options for /tmp, /var/tmp, /home, /dev/shm (nodev, nosuid, noexec)
- Sets sticky bit on world-writable directories
- Disables automounting

### 2. Software Updates
- Enables GPG signature verification for packages
- Installs and configures AIDE (Advanced Intrusion Detection Environment)
- Sets up regular filesystem integrity checks

### 3. Bootloader Security
- Secures GRUB2 bootloader configuration
- Sets bootloader password
- Restricts single-user mode access

### 4. Core System Security
- Restricts core dumps
- Enables Address Space Layout Randomization (ASLR)
- Disables prelink
- Configures SELinux

### 5. Service Management
- Disables unnecessary services (inetd, Avahi, CUPS, DHCP, LDAP, NFS, DNS, FTP, HTTP, IMAP/POP3, Samba, HTTP Proxy, SNMP, NIS, rsh, talk, telnet, tftp, rsync)
- Configures mail transfer agent for local-only mode

### 6. Network Security
- Disables IP forwarding, packet redirects, source routing
- Enables SYN cookies, reverse path filtering
- Ignores suspicious packets and bogus ICMP responses
- Disables IPv6
- Configures TCP Wrappers (/etc/hosts.allow, /etc/hosts.deny)
- Sets up basic iptables firewall rules

### 7. Logging
- Enables and configures rsyslog
- Sets appropriate log file permissions
- Configures remote logging (requires customization)

### 8. Cron and SSH Hardening
- Secures cron configuration
- Hardens SSH daemon (disables root login, sets protocol 2, configures timeouts, etc.)
- Restricts at/cron access

### 9. Password Policies
- Configures password quality requirements
- Sets password expiration policies
- Enables password reuse limitations
- Configures account lockout for failed attempts

### 10. User and Group Settings
- Sets secure file permissions for /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow
- Configures default user umask
- Restricts su command access

## Manual Configurations Required

Some controls require manual intervention or customization:

- **NTP/Chrony Servers**: Update `<remote-server>` with actual NTP server addresses
- **Firewall Rules**: Customize iptables rules for open ports
- **SSH Allowed Users**: Specify allowed SSH users in /etc/ssh/sshd_config
- **Remote Log Host**: Configure actual remote logging server
- **Hosts Allow/Deny**: Specify allowed networks in /etc/hosts.allow
- **Manual Checks**: Several sections include comments for manual verification (e.g., duplicate UIDs/GIDs, legacy entries)

## Post-Execution Steps

1. **Reboot**: Some changes (e.g., kernel parameters, IPv6 disable) require system reboot
2. **Verify**: Check system logs for any errors during execution
3. **Test**: Verify critical services still function after hardening
4. **Customize**: Adjust configurations based on your environment's specific requirements
5. **Audit**: Use CIS compliance tools to verify implementation

## Important Notes

- **Testing**: Test the script in a non-production environment first
- **Compatibility**: Script is designed specifically for RHEL 8; may not work on other distributions
- **Updates**: Review and update the script when new CIS benchmarks are released
- **Support**: This script is provided as-is; consult official CIS documentation for detailed explanations
- **Compliance**: Achieving CIS compliance may require additional manual steps beyond this script

## Troubleshooting

- If packages fail to install, ensure repositories are configured correctly
- Check /var/log/messages or journalctl for error messages
- Some services may not exist on minimal installations; script handles this gracefully
- For SELinux issues, review /var/log/audit/audit.log

## References

- [CIS Red Hat Enterprise Linux 8 Benchmark v1.0.0](https://www.cisecurity.org/benchmark/red_hat_linux/)
- Assessment Details.docx (source document for this script)

## Version

Version 1.0 - Initial implementation based on CIS RHEL 8 Benchmark Level 1
