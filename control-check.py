import os
import subprocess
import pandas as pd

# Function to run shell commands and return the output
def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, text=True).strip()
        return result if result else "Not Implemented"
    except subprocess.CalledProcessError:
        return "Not Implemented"

# Function to check the status and determine control in place
def check_status(description, command):
    result = run_command(command)
    if "Not Implemented" in result or "no" in result.lower():
        return description, "We cannot implement"
    return description, "Control in place"

# List of checks to perform
checks = [
    ("Status of the cramfs kernel module available in any installed kernel", "lsmod | grep cramfs"),
    ("Status of 'install cramfs' setting", "grep -R 'install cramfs' /lib/modprobe.d /etc/modprobe.d /run/modprobe.d"),
    ("Status of 'blacklist cramfs' setting", "grep -R 'blacklist cramfs' /lib/modprobe.d /etc/modprobe.d /run/modprobe.d"),
    ("Status of the freevxfs kernel module available in any installed kernel", "lsmod | grep freevxfs"),
    ("Status of 'install freevxfs' setting", "grep -R 'install freevxfs' /lib/modprobe.d /etc/modprobe.d /run/modprobe.d"),
    ("Status of 'blacklist freevxfs' setting", "grep -R 'blacklist freevxfs' /lib/modprobe.d /etc/modprobe.d /run/modprobe.d"),
    ("Status of the hfs kernel module available in any installed kernel", "lsmod | grep hfs"),
    ("Status of 'install hfs' setting", "grep -R 'install hfs' /lib/modprobe.d /etc/modprobe.d /run/modprobe.d"),
    ("Status of 'blacklist hfs' setting", "grep -R 'blacklist hfs' /lib/modprobe.d /etc/modprobe.d /run/modprobe.d"),
    ("Status of the 'chrony' package", "rpm -q chrony"),
    ("Status of 'pool|server' in /etc/chrony.conf", "grep -E 'pool|server' /etc/chrony.conf /etc/chrony.d/*.conf"),
    ("Status of the 'OPTIONS' setting within '/etc/sysconfig/chronyd' file", "grep OPTIONS /etc/sysconfig/chronyd"),
    ("Status of the autofs services are not in use", "systemctl is-enabled autofs"),
    ("Status of autofs service using systemctl", "systemctl is-active autofs"),
    ("Status of the 'avahi' package", "rpm -q avahi"),
    ("Status of the 'avahi-daemon.socket' service", "systemctl status avahi-daemon.socket"),
    ("Status of the avahi daemon services are not in use", "systemctl is-active avahi-daemon"),
    ("Status of the wireless interfaces are disabled", "nmcli radio all"),
    ("Status of the loaded wireless interfaces", "iwconfig"),
    ("Status of the blacklisted wireless interfaces", "grep -R 'blacklist' /lib/modprobe.d /etc/modprobe.d /run/modprobe.d"),
    ("Status of bluez package in the host", "rpm -q bluez"),
    ("Status of service 'Bluetooth' using systemd", "systemctl is-active bluetooth"),
    ("Status of the 'bluetooth' service using systemctl", "systemctl status bluetooth"),
    ("Status of the current setting for 'net.ipv4.ip_forward' network parameter", "sysctl net.ipv4.ip_forward"),
    ("Status of net.ipv4.ip_forward in all config files", "grep -R 'net.ipv4.ip_forward' /etc/sysctl.conf /etc/sysctl.d/*.conf"),
    ("Status of the crond service", "systemctl is-enabled crond"),
    ("Status of crond service is active using systemctl", "systemctl is-active crond"),
]

# Perform the checks and store results
results = []
for description, command in checks:
    status, control = check_status(description, command)
    results.append({"Check": description, "Status": status, "Control": control})

# Save the results to an Excel file
output_file = "control_checks.xlsx"
df = pd.DataFrame(results)
df.to_excel(output_file, index=False)

print(f"Results saved to {output_file}")
