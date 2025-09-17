#!/bin/bash

# Test script for harden_rhel8_cis.sh
# This script performs basic validation of the hardening script

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
required_commands=("modprobe" "systemctl" "yum" "sed" "echo" "chmod" "chown")
for cmd in "${required_commands[@]}"; do
    if grep -q "$cmd" harden_rhel8_cis.sh; then
        echo "✓ Found $cmd in script"
    else
        echo "✗ Missing $cmd in script"
    fi
done

# 4. Simulate dry run (echo commands instead of executing)
echo "4. Simulating dry run..."
# This would require modifying the script to have a dry-run mode
# For now, just check if script starts correctly
if head -5 harden_rhel8_cis.sh | grep -q "#!/bin/bash"; then
    echo "✓ Script has proper shebang"
else
    echo "✗ Script missing shebang"
fi

echo "Basic testing completed. For full testing, run in a RHEL 8 VM with root privileges."
