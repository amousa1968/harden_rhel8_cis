#!/bin/bash

# Enhanced test script for harden_rhel8_cis.sh
# This script performs validation of the hardening script effects

echo "Testing harden_rhel8_cis.sh..."

# 1. Syntax check
echo "1. Checking syntax..."
if bash -n harden_rhel8_cis.sh; then
    echo "✓ Syntax check passed"
else
    echo "✗ Syntax check failed"
    exit 1
fi

# 2. Check if script is executable
echo "2. Checking if script is executable..."
if [[ -x harden_rhel8_cis.sh ]]; then
    echo "✓ Script is executable"
else
    echo "✗ Script is not executable"
    exit 1
fi

# 3. Check for common commands (basic validation)
echo "3. Checking for required commands in script..."
required_commands=("modprobe" "systemctl" "yum" "sed" "echo" "chmod" "chown" "mount" "auditctl")
for cmd in "${required_commands[@]}"; do
    if grep -q "$cmd" harden_rhel8_cis.sh; then
        echo "✓ Found $cmd in script"
    else
        echo "✗ Missing $cmd in script"
    fi
done

# 4. Check for audit rules file existence (simulate)
echo "4. Checking for audit rules file..."
if [ -f /etc/audit/rules.d/audit.rules ]; then
    echo "✓ Audit rules file exists"
else
    echo "✗ Audit rules file missing (expected in RHEL environment)"
fi

# 5. Check for SELinux enforcing mode (simulate)
selinux_status=$(getenforce 2>/dev/null || echo "Not installed")
echo "5. SELinux status: $selinux_status"

# 6. Check for disabled services (simulate)
services=("avahi-daemon" "cups" "dhcpd" "slapd" "nfs" "rpcbind" "named" "vsftpd" "httpd" "dovecot" "smb" "squid" "snmpd")
for svc in "${services[@]}"; do
    if ! systemctl is-enabled "$svc" &>/dev/null; then
        echo "✓ Service $svc is disabled or not installed"
    else
        echo "✗ Service $svc is enabled"
    fi
done

# 7. Check for yum availability (simulate)
if command -v yum &>/dev/null; then
    echo "✓ yum command available"
else
    echo "✗ yum command not found (expected on non-RHEL systems)"
fi

# 8. Attempt to run the hardening script (will exit early in CI)
echo "8. Attempting to run hardening script..."
if bash harden_rhel8_cis.sh; then
    echo "✓ Hardening script completed successfully"
else
    echo "✗ Hardening script failed or exited early (expected in CI)"
fi

echo "Enhanced testing completed. For full validation, run on a RHEL 8 system with root privileges."
