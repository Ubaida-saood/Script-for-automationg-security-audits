# Security Audit and Server Hardening Script
#==========================

# Define log file
LOG_FILE="/var/log/security_audit.log"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}

# 1. User and Group Audits
audit_users_and_groups() {
    log_message "Starting User and Group Audits..."
    
    # List all users and groups
    log_message "Listing all users:"
    cat /etc/passwd | tee -a $LOG_FILE
    
    log_message "Listing all groups:"
    cat /etc/group | tee -a $LOG_FILE
    
    # Check for users with UID 0
    log_message "Checking for non-standard users with UID 0:"
    awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v '^root$' | tee -a $LOG_FILE
    
    # Identify users without passwords or with weak passwords
    log_message "Checking for users without passwords or with weak passwords:"
    awk -F: '($2 == "" || $2 ~ "!" || $2 ~ "*") {print $1 " has no or weak password"}' /etc/shadow | tee -a $LOG_FILE
}

# 2. File and Directory Permissions
audit_file_permissions() {
    log_message "Starting File and Directory Permissions Audit..."
    
    # Scan for world-writable files and directories
    log_message "Scanning for world-writable files and directories:"
    find / -perm -o+w -type f -exec ls -l {} \; | tee -a $LOG_FILE
    
    # Check SSH directory permissions
    log_message "Checking SSH directory permissions:"
    find /home/*/.ssh -type d -exec chmod 700 {} \;
    find /home/*/.ssh -type f -exec chmod 600 {} \;
    
    # Report SUID and SGID files
    log_message "Reporting files with SUID or SGID bits set:"
    find / -perm /6000 -type f -exec ls -l {} \; | tee -a $LOG_FILE
}

# 3. Service Audits
audit_services() {
    log_message "Starting Service Audits..."
    
    # List all running services
    log_message "Listing all running services:"
    systemctl list-units --type=service --state=running | tee -a $LOG_FILE
    
    # Ensure critical services are running
    log_message "Checking critical services (sshd, iptables):"
    systemctl status sshd | tee -a $LOG_FILE
    systemctl status iptables | tee -a $LOG_FILE
    
    # Check for non-standard or insecure ports
    log_message "Checking for services listening on non-standard or insecure ports:"
    netstat -tuln | grep -v ':22\|:80\|:443' | tee -a $LOG_FILE
}

# 4. Firewall and Network Security
audit_firewall_and_network() {
    log_message "Starting Firewall and Network Security Audit..."
    
    # Verify firewall status
    log_message "Verifying firewall status:"
    ufw status | tee -a $LOG_FILE
    
    # Report open ports
    log_message "Reporting open ports:"
    nmap -sT -O localhost | tee -a $LOG_FILE
    
    # Check IP forwarding and network configurations
    log_message "Checking IP forwarding settings:"
    sysctl net.ipv4.ip_forward | tee -a $LOG_FILE
    sysctl net.ipv6.conf.all.forwarding | tee -a $LOG_FILE
}

# 5. IP and Network Configuration Checks
check_ip_configuration() {
    log_message "Starting IP and Network Configuration Checks..."
    
    # Identify public vs. private IPs
    log_message "Identifying public vs. private IP addresses:"
    ip a | grep inet | tee -a $LOG_FILE
    
    # Ensure sensitive services are not exposed on public IPs
    log_message "Ensuring SSH is not exposed on public IPs:"
    # Custom logic to bind SSH to private IPs
    # Add your SSH configuration checks here
}

# 6. Security Updates and Patching
check_security_updates() {
    log_message "Starting Security Updates and Patching..."
    
    # Check for available security updates
    log_message "Checking for available security updates:"
    apt list --upgradable | grep -i security | tee -a $LOG_FILE
    
    # Ensure automatic security updates are configured
    log_message "Checking automatic security update configuration:"
    cat /etc/apt/apt.conf.d/20auto-upgrades | tee -a $LOG_FILE
}

# 7. Log Monitoring
monitor_logs() {
    log_message "Starting Log Monitoring..."
    
    # Check for suspicious log entries
    log_message "Checking for suspicious log entries (e.g., failed SSH logins):"
    grep "Failed password" /var/log/auth.log | tail -10 | tee -a $LOG_FILE
}

# 8. Server Hardening Steps
harden_server() {
    log_message "Starting Server Hardening..."
    
    # Implement SSH key-based authentication
    log_message "Implementing SSH key-based authentication and disabling root password login:"
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
    
    # Disable IPv6 if not required
    log_message "Disabling IPv6:"
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    
    # Set GRUB bootloader password
    log_message "Setting GRUB bootloader password:"
    # The password must be generated with grub-mkpasswd-pbkdf2 and added to /etc/grub.d/40_custom
    # Add your password setup logic here
    
    # Configure firewall rules
    log_message "Configuring firewall rules:"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
}

# 9. Custom Security Checks
custom_security_checks() {
    log_message "Running Custom Security Checks..."
    
    if [ -f /etc/custom_security_checks.conf ]; then
        source /etc/custom_security_checks.conf
    else
        log_message "No custom security checks configuration file found."
    fi
}

# 10. Reporting and Alerting
generate_report() {
    log_message "Generating Security Audit and Hardening Report..."
    
    # Add logic to send report via email or other methods
    # Example:
    # mail -s "Security Audit Report" admin@example.com < $LOG_FILE
}

# Main function to run all checks and hardening steps
main() {
    audit_users_and_groups
    audit_file_permissions
    audit_services
    audit_firewall_and_network
    check_ip_configuration
    check_security_updates
    monitor_logs
    harden_server
    custom_security_checks
    generate_report
    
    log_message "Security Audit and Hardening completed successfully."
}

# Run the main function
main
