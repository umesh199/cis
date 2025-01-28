import os
import subprocess

def run_command(command):
    """Run a shell command and return its output."""
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        return result.stdout.strip()
    except Exception as e:
        return str(e)

def check_control(control):
    """Check if a control is in place."""
    command = control_checks.get(control)
    if command:
        output = run_command(command)
        return output
    else:
        return "Check not defined"

# Define CIS controls and their corresponding checks for Level 1, Level 2, Filesystem, and other categories
control_checks = {
    # Initial Setup
    "Ensure bootloader password is set": "grep 'set superusers' /boot/grub2/grub.cfg",
    "Ensure address space layout randomization (ASLR) is enabled": "sysctl kernel.randomize_va_space",
    
    # Services
    "Ensure unnecessary services are disabled": "systemctl list-unit-files --type=service --state=enabled",
    "Ensure xinetd is not installed": "rpm -q xinetd",

    # Network Configuration
    "Ensure IP forwarding is disabled": "sysctl net.ipv4.ip_forward",
    "Ensure packet redirect sending is disabled": "sysctl net.ipv4.conf.all.send_redirects",
    "Ensure source routed packets are not accepted": "sysctl net.ipv4.conf.all.accept_source_route",

    # Logging
    "Ensure rsyslog is installed": "rpm -q rsyslog",
    "Ensure rsyslog service is enabled": "systemctl is-enabled rsyslog",
    "Ensure logrotate is configured": "grep rotate /etc/logrotate.conf",

    # Auditing
    "Ensure auditd is installed": "rpm -q audit",
    "Ensure auditd service is enabled": "systemctl is-enabled auditd",
    "Ensure audit rules exist for file modifications": "auditctl -l | grep -E '/etc/passwd|/etc/shadow|/etc/group'",

    # Access, Authentication, and Authorization
    "Ensure password expiration is set": "grep PASS_MAX_DAYS /etc/login.defs",
    "Ensure password change minimum days is set": "grep PASS_MIN_DAYS /etc/login.defs",
    "Ensure password complexity requirements are configured": "grep -E 'minlen|dcredit|ucredit|ocredit|lcredit' /etc/security/pwquality.conf",
    "Ensure root login is restricted to system console": "cat /etc/securetty",

    # System Maintenance
    "Ensure filesystem integrity is regularly checked": "grep 'aide' /etc/crontab",
    "Ensure updates and patches are applied": "yum check-update",
    "Ensure system file permissions are audited": "find / -xdev -type f \( -perm -0002 -a ! -perm -1000 \)",

    # Filesystem
    "Ensure separate partition exists for /tmp": "findmnt /tmp",
    "Ensure nodev option is set on /tmp partition": "findmnt -n /tmp | grep -q nodev",
    "Ensure nosuid option is set on /tmp partition": "findmnt -n /tmp | grep -q nosuid",
    "Ensure noexec option is set on /tmp partition": "findmnt -n /tmp | grep -q noexec",
    "Ensure separate partition exists for /var": "findmnt /var",
    "Ensure separate partition exists for /var/tmp": "findmnt /var/tmp",
    "Ensure nodev option is set on /var/tmp partition": "findmnt -n /var/tmp | grep -q nodev",
    "Ensure nosuid option is set on /var/tmp partition": "findmnt -n /var/tmp | grep -q nosuid",
    "Ensure noexec option is set on /var/tmp partition": "findmnt -n /var/tmp | grep -q noexec",
    "Ensure separate partition exists for /home": "findmnt /home",
    "Ensure nodev option is set on /home partition": "findmnt -n /home | grep -q nodev",
    "Ensure separate partition exists for /var/log": "findmnt /var/log",
    "Ensure separate partition exists for /var/log/audit": "findmnt /var/log/audit",
    "Ensure nodev option is set on /dev/shm": "findmnt -n /dev/shm | grep -q nodev",
    "Ensure nosuid option is set on /dev/shm": "findmnt -n /dev/shm | grep -q nosuid",
    "Ensure noexec option is set on /dev/shm": "findmnt -n /dev/shm | grep -q noexec",
}

not_implemented = []

print("Starting CIS Level 1, Level 2, Filesystem, and Additional Checks for RHEL 8")

for control in control_checks:
    result = check_control(control)
    if result == "":
        print(f"[IN PLACE] {control}")
    else:
        print(f"[NOT IMPLEMENTED] {control}")
        not_implemented.append({"control": control, "reason": ""})

# Output not implemented controls and provide a place to enter reasons
if not_implemented:
    print("\nThe following controls are not implemented:")
    for item in not_implemented:
        print(f"- {item['control']}")
        item['reason'] = input(f"Enter reason for not implementing '{item['control']}': ")

# Save the results to a file
with open("cis_check_results.txt", "w") as f:
    f.write("CIS Level 1, Level 2, Filesystem, and Additional Checks Results\n")
    f.write("============================================================\n")
    for control in control_checks:
        status = "IN PLACE" if control not in [c['control'] for c in not_implemented] else "NOT IMPLEMENTED"
        f.write(f"{control}: {status}\n")
    
    if not_implemented:
        f.write("\nNot Implemented Controls:\n")
        for item in not_implemented:
            f.write(f"{item['control']}: {item['reason']}\n")

print("\nCIS check completed. Results saved to 'cis_check_results.txt'.")
