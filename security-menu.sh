#!/bin/bash

################################################################################
# System Security Management Script
# This script provides a menu-driven interface for various security tasks
# Supports: Debian/Ubuntu, RedHat/CentOS/Fedora, Arch, Alpine
################################################################################

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
OS_NAME=""
OS_VERSION=""
PACKAGE_MANAGER=""

################################################################################
# Function: Detect OS
################################################################################
detect_os() {
    echo -e "${BLUE}[*] Detecting operating system...${NC}"
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$ID
        OS_VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS_NAME="rhel"
        OS_VERSION=$(cat /etc/redhat-release | grep -oP '\d+\.\d+' | head -1)
    elif [ -f /etc/debian_version ]; then
        OS_NAME="debian"
        OS_VERSION=$(cat /etc/debian_version)
    else
        echo -e "${RED}[!] Unable to detect OS${NC}"
        exit 1
    fi
    
    # Detect package manager
    if command -v apt-get &> /dev/null; then
        PACKAGE_MANAGER="apt"
    elif command -v dnf &> /dev/null; then
        PACKAGE_MANAGER="dnf"
    elif command -v yum &> /dev/null; then
        PACKAGE_MANAGER="yum"
    elif command -v pacman &> /dev/null; then
        PACKAGE_MANAGER="pacman"
    elif command -v apk &> /dev/null; then
        PACKAGE_MANAGER="apk"
    else
        echo -e "${RED}[!] Unable to detect package manager${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] OS Detected: $OS_NAME (v$OS_VERSION)${NC}"
    echo -e "${GREEN}[+] Package Manager: $PACKAGE_MANAGER${NC}"
}

################################################################################
# Function: Check if running as root
################################################################################
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}[!] This script must be run as root${NC}"
        exit 1
    fi
}

################################################################################
# Function: General System Hardening
################################################################################
system_hardening() {
    echo -e "\n${BLUE}=== General System Hardening ===${NC}\n"
    
    echo "[1] Update system packages"
    case $PACKAGE_MANAGER in
        apt)
            apt-get update && apt-get upgrade -y
            ;;
        dnf|yum)
            $PACKAGE_MANAGER update -y
            ;;
        pacman)
            pacman -Syu --noconfirm
            ;;
        apk)
            apk update && apk upgrade
            ;;
    esac
    echo -e "${GREEN}[+] System packages updated${NC}\n"
    
    echo "[2] Installing essential security tools"
    case $PACKAGE_MANAGER in
        apt)
            apt-get install -y fail2ban ufw aide auditd
            ;;
        dnf|yum)
            $PACKAGE_MANAGER install -y fail2ban firewalld aide audit
            ;;
        pacman)
            pacman -S --noconfirm fail2ban ufw aide
            ;;
        apk)
            apk add fail2ban aide audit
            ;;
    esac
    echo -e "${GREEN}[+] Security tools installed${NC}\n"
    
    echo "[3] Configuring firewall"
    case $PACKAGE_MANAGER in
        apt)
            ufw --force enable
            ufw default deny incoming
            ufw default allow outgoing
            echo -e "${GREEN}[+] UFW firewall configured${NC}"
            ;;
        dnf|yum)
            systemctl enable firewalld
            systemctl start firewalld
            firewall-cmd --set-default-zone=public
            firewall-cmd --permanent --set-target=DROP
            firewall-cmd --reload
            echo -e "${GREEN}[+] Firewalld configured${NC}"
            ;;
    esac
    echo ""
    
    echo "[4] Disabling unnecessary services"
    systemctl disable avahi-daemon &>/dev/null || true
    systemctl disable cups &>/dev/null || true
    systemctl disable isc-dhcp-server &>/dev/null || true
    echo -e "${GREEN}[+] Unnecessary services disabled${NC}\n"
    
    echo "[5] Setting up automatic security updates"
    case $PACKAGE_MANAGER in
        apt)
            apt-get install -y unattended-upgrades
            dpkg-reconfigure -plow unattended-upgrades
            ;;
        dnf|yum)
            $PACKAGE_MANAGER install -y yum-cron
            systemctl enable yum-cron
            systemctl start yum-cron
            ;;
    esac
    echo -e "${GREEN}[+] Automatic updates configured${NC}\n"
    
    echo "[6] Hardening system parameters"
    cat >> /etc/sysctl.conf << 'EOF'

# IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Ignore ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Accept source routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 0

# Ignore bogus error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 0
EOF
    sysctl -p > /dev/null 2>&1
    echo -e "${GREEN}[+] System parameters hardened${NC}\n"
    
    echo "[7] Setting up file integrity monitoring with AIDE"
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    echo -e "${GREEN}[+] AIDE initialized${NC}\n"
    
    echo -e "${GREEN}[✓] System hardening complete!${NC}\n"
}

################################################################################
# Function: Security Audit
################################################################################
security_audit() {
    echo -e "\n${BLUE}=== Security Audit ===${NC}\n"
    
    echo "[1] Checking listening ports"
    echo -e "${YELLOW}Open ports and services:${NC}"
    netstat -tuln | grep LISTEN || ss -tuln | grep LISTEN
    echo ""
    
    echo "[2] Checking running services"
    echo -e "${YELLOW}Running services:${NC}"
    systemctl list-units --type=service --state=running | head -20
    echo ""
    
    echo "[3] Checking user accounts"
    echo -e "${YELLOW}System users:${NC}"
    awk -F: '$3 >= 1000 {print $1 " (UID: " $3 ")"}' /etc/passwd
    echo ""
    
    echo "[4] Checking file permissions on critical files"
    echo -e "${YELLOW}Critical file permissions:${NC}"
    for file in /etc/passwd /etc/shadow /etc/group /etc/sudoers /root/.ssh/authorized_keys; do
        if [ -e "$file" ]; then
            ls -l "$file"
        fi
    done
    echo ""
    
    echo "[5] Checking sudo access"
    echo -e "${YELLOW}Users with sudo privileges:${NC}"
    getent group sudo &>/dev/null && getent group sudo | cut -d: -f4
    getent group wheel &>/dev/null && getent group wheel | cut -d: -f4
    echo ""
    
    echo "[6] Checking SSH configuration"
    echo -e "${YELLOW}SSH Configuration:${NC}"
    grep -E "^PermitRootLogin|^PasswordAuthentication|^PubkeyAuthentication|^Protocol" /etc/ssh/sshd_config || echo "Default SSH config"
    echo ""
    
    echo "[7] Checking failed login attempts"
    echo -e "${YELLOW}Recent failed login attempts:${NC}"
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10 || grep "Failed password" /var/log/secure 2>/dev/null | tail -10 || echo "No auth log found"
    echo ""
    
    echo "[8] Checking firewall status"
    echo -e "${YELLOW}Firewall status:${NC}"
    if command -v ufw &> /dev/null; then
        ufw status
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --list-all
    fi
    echo ""
    
    echo -e "${GREEN}[✓] Security audit complete!${NC}\n"
}

################################################################################
# Function: Application Security
################################################################################
application_security() {
    echo -e "\n${BLUE}=== Application Security ===${NC}\n"
    
    echo "[1] Checking installed web servers (Apache, Nginx)"
    if systemctl is-active --quiet apache2 || systemctl is-active --quiet httpd; then
        echo -e "${YELLOW}Apache is running${NC}"
        echo "    [a] Disable Apache modules"
        echo "    [b] Enable SSL/TLS"
        echo "    [c] Configure security headers"
        read -p "    Select option (a/b/c): " apache_option
        case $apache_option in
            a)
                a2dismod php* &>/dev/null || true
                a2dismod autoindex &>/dev/null || true
                echo -e "${GREEN}[+] Apache modules disabled${NC}"
                ;;
            b)
                a2enmod ssl &>/dev/null || true
                a2enmod rewrite &>/dev/null || true
                echo -e "${GREEN}[+] SSL/TLS modules enabled${NC}"
                ;;
            c)
                echo "[+] Add security headers to Apache config"
                ;;
        esac
    fi
    
    if systemctl is-active --quiet nginx; then
        echo -e "${YELLOW}Nginx is running${NC}"
        echo "    [a] Enable SSL/TLS"
        echo "    [b] Configure security headers"
        read -p "    Select option (a/b): " nginx_option
        case $nginx_option in
            a)
                echo "[+] Configure SSL/TLS in nginx.conf"
                ;;
            b)
                echo "[+] Add security headers to nginx config"
                ;;
        esac
    fi
    echo ""
    
    echo "[2] Checking databases (MySQL, PostgreSQL)"
    if systemctl is-active --quiet mysql || systemctl is-active --quiet mysqld; then
        echo -e "${YELLOW}MySQL is running${NC}"
        echo "[+] Recommendations:"
        echo "    - Change default root password"
        echo "    - Remove anonymous users"
        echo "    - Disable remote root login"
        echo "    - Run mysql_secure_installation"
    fi
    
    if systemctl is-active --quiet postgresql; then
        echo -e "${YELLOW}PostgreSQL is running${NC}"
        echo "[+] Recommendations:"
        echo "    - Configure pg_hba.conf for authentication"
        echo "    - Use strong passwords"
        echo "    - Encrypt connections with SSL"
    fi
    echo ""
    
    echo "[3] Checking for vulnerable packages"
    case $PACKAGE_MANAGER in
        apt)
            echo "[+] Running security advisory check..."
            apt-cache policy | grep security || true
            ;;
        dnf|yum)
            echo "[+] Checking for security updates..."
            $PACKAGE_MANAGER check-update --security || true
            ;;
    esac
    echo ""
    
    echo -e "${GREEN}[✓] Application security review complete!${NC}\n"
}

################################################################################
# Function: User & Access Control
################################################################################
user_access_control() {
    echo -e "\n${BLUE}=== User & Access Control ===${NC}\n"
    
    echo "[1] Configuring SSH security"
    SSH_CONFIG="/etc/ssh/sshd_config"
    echo "    [a] Disable root SSH login"
    echo "    [b] Disable password authentication"
    echo "    [c] Change SSH port"
    echo "    [d] Enable public key authentication"
    read -p "    Select option (a/b/c/d/all): " ssh_option
    
    case $ssh_option in
        a|all)
            sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' $SSH_CONFIG
            sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' $SSH_CONFIG
            echo -e "${GREEN}[+] Root SSH login disabled${NC}"
            ;;
    esac
    
    if [ "$ssh_option" = "b" ] || [ "$ssh_option" = "all" ]; then
        sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' $SSH_CONFIG
        sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' $SSH_CONFIG
        echo -e "${GREEN}[+] Password authentication disabled${NC}"
    fi
    
    if [ "$ssh_option" = "c" ] || [ "$ssh_option" = "all" ]; then
        read -p "    Enter new SSH port (default 22): " ssh_port
        ssh_port=${ssh_port:-22}
        sed -i "s/^#Port 22/Port $ssh_port/" $SSH_CONFIG
        sed -i "s/^Port 22/Port $ssh_port/" $SSH_CONFIG
        echo -e "${GREEN}[+] SSH port changed to $ssh_port${NC}"
    fi
    
    if [ "$ssh_option" = "d" ] || [ "$ssh_option" = "all" ]; then
        sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication yes/' $SSH_CONFIG
        sed -i 's/^PubkeyAuthentication no/PubkeyAuthentication yes/' $SSH_CONFIG
        echo -e "${GREEN}[+] Public key authentication enabled${NC}"
    fi
    
    systemctl restart sshd
    echo -e "${GREEN}[+] SSH daemon restarted${NC}\n"
    
    echo "[2] Configuring password policies"
    if command -v apt-get &> /dev/null; then
        apt-get install -y libpam-pwquality
    elif command -v dnf &> /dev/null || command -v yum &> /dev/null; then
        $PACKAGE_MANAGER install -y libpwquality
    fi
    
    if [ -f /etc/security/pwquality.conf ]; then
        cat >> /etc/security/pwquality.conf << 'EOF'

# Enforce strong password policies
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
gecoscheck = 1
difok = 4
EOF
        echo -e "${GREEN}[+] Password quality rules applied${NC}\n"
    fi
    
    echo "[3] Checking sudoers configuration"
    echo -e "${YELLOW}Current sudoers entries:${NC}"
    grep -v '^#' /etc/sudoers | grep -v '^$' | head -10
    echo ""
    
    echo "[4] Enabling account lockout policy"
    echo "    Configuring failed login lockout (after 5 attempts, 15 min lockout)..."
    
    if [ -f /etc/pam.d/common-auth ]; then
        echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth
    elif [ -f /etc/pam.d/system-auth ]; then
        echo "auth required pam_faillock.so preauth silent deny=5 unlock_time=900" >> /etc/pam.d/system-auth
    fi
    echo -e "${GREEN}[+] Account lockout policy configured${NC}\n"
    
    echo "[5] Setting up audit logging"
    if command -v auditctl &> /dev/null; then
        auditctl -w /etc/sudoers -p wa -k sudoers_changes
        auditctl -w /etc/ssh/sshd_config -p wa -k sshd_config_changes
        echo -e "${GREEN}[+] Audit rules configured${NC}\n"
    fi
    
    echo -e \"${GREEN}[✓] User & access control configuration complete!${NC}\\n\"
}

################################################################################
# Function: System & Network Tuning
################################################################################
system_network_tuning() {
    echo -e \"\\n${BLUE}=== System & Network Tuning ===${NC}\\n\"
    
    echo "Select tuning profile:"
    echo "  [1] High Performance (Low Latency)"
    echo "  [2] Balanced (Default)"
    echo "  [3] Power Saving"
    echo "  [4] Web Server Optimization"
    echo "  [5] Database Server Optimization"
    echo "  [6] Streaming/Media Server"
    echo "  [7] File Hosting Server"
    echo "  [8] Torrenting Server"
    read -p \"Select profile (1-8): \" profile_choice
    
    case \$profile_choice in
        1)
            tune_high_performance
            ;;
        2)
            tune_balanced
            ;;
        3)
            tune_power_saving
            ;;
        4)
            tune_web_server
            ;;
        5)
            tune_database_server
            ;;
        6)
            tune_streaming_server
            ;;
        7)
            tune_file_hosting_server
            ;;
        8)
            tune_torrenting_server
            ;;
        *)
            echo -e \"${RED}[!] Invalid option${NC}\"
            return
            ;;
    esac
}

################################################################################
# Tuning Profiles
################################################################################

tune_high_performance() {
    echo -e \"\\n${BLUE}[*] Applying High Performance profile...${NC}\\n\"
    
    # CPU Governor
    echo \"[1] Setting CPU governor to performance...\"
    for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo \"performance\" > \"\$gov\" 2>/dev/null || true
    done
    echo -e \"${GREEN}[+] CPU governor set to performance${NC}\\n\"
    
    # Network tuning
    echo \"[2] Optimizing network stack...\"
    sysctl -w net.ipv4.tcp_tw_reuse=1
    sysctl -w net.ipv4.tcp_fin_timeout=30
    sysctl -w net.core.somaxconn=32768
    sysctl -w net.ipv4.tcp_max_syn_backlog=16384
    sysctl -w net.core.netdev_max_backlog=5000
    echo -e \"${GREEN}[+] Network optimized for low latency${NC}\\n\"
    
    # Disable power saving
    echo \"[3] Disabling power saving features...\"
    sysctl -w kernel.sched_migration_cost_ns=5000000
    echo -e \"${GREEN}[+] Power saving disabled${NC}\\n\"
    
    echo -e \"${GREEN}[✓] High Performance profile applied!${NC}\\n\"
}

tune_balanced() {
    echo -e \"\\n${BLUE}[*] Applying Balanced profile...${NC}\\n\"
    
    # CPU Governor
    echo \"[1] Setting CPU governor to schedutil...\"
    for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo \"schedutil\" > \"\$gov\" 2>/dev/null || echo \"ondemand\" > \"\$gov\" 2>/dev/null || true
    done
    echo -e \"${GREEN}[+] CPU governor set to balanced${NC}\\n\"
    
    # Network tuning
    echo \"[2] Optimizing network stack...\"
    sysctl -w net.ipv4.tcp_tw_reuse=1
    sysctl -w net.ipv4.tcp_fin_timeout=60
    sysctl -w net.core.somaxconn=4096
    sysctl -w net.ipv4.tcp_max_syn_backlog=2048
    echo -e \"${GREEN}[+] Network optimized for balance${NC}\\n\"
    
    # Memory
    echo \"[3] Setting memory parameters...\"
    sysctl -w vm.swappiness=30
    sysctl -w vm.dirty_ratio=15
    sysctl -w vm.dirty_background_ratio=5
    echo -e \"${GREEN}[+] Memory parameters optimized${NC}\\n\"
    
    echo -e \"${GREEN}[✓] Balanced profile applied!${NC}\\n\"
}

tune_power_saving() {
    echo -e \"\\n${BLUE}[*] Applying Power Saving profile...${NC}\\n\"
    
    # CPU Governor
    echo \"[1] Setting CPU governor to powersave...\"
    for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo \"powersave\" > \"\$gov\" 2>/dev/null || true
    done
    echo -e \"${GREEN}[+] CPU governor set to powersave${NC}\\n\"
    
    # Network tuning
    echo \"[2] Optimizing for power saving...\"
    sysctl -w net.ipv4.tcp_tw_reuse=1
    sysctl -w net.ipv4.tcp_fin_timeout=120
    sysctl -w net.ipv4.tcp_keepalive_time=900
    echo -e \"${GREEN}[+] Network optimized for power saving${NC}\\n\"
    
    # Memory
    echo \"[3] Setting memory parameters for low power...\"
    sysctl -w vm.swappiness=60
    sysctl -w vm.dirty_ratio=30
    sysctl -w vm.dirty_background_ratio=10
    sysctl -w kernel.sched_migration_cost_ns=500000
    echo -e \"${GREEN}[+] Memory parameters optimized${NC}\\n\"
    
    echo -e \"${GREEN}[✓] Power Saving profile applied!${NC}\\n\"
}

tune_web_server() {
    echo -e \"\\n${BLUE}[*] Applying Web Server Optimization profile...${NC}\\n\"
    
    echo \"[1] Optimizing for web server workload...\"
    
    # TCP optimization
    sysctl -w net.ipv4.tcp_tw_reuse=1
    sysctl -w net.ipv4.tcp_fin_timeout=30
    sysctl -w net.core.somaxconn=65535
    sysctl -w net.ipv4.tcp_max_syn_backlog=65535
    sysctl -w net.core.netdev_max_backlog=10000
    sysctl -w net.ipv4.ip_local_port_range=\"1024 65535\"
    
    # File descriptors
    echo -e \"${GREEN}[+] Increasing file descriptor limits...${NC}\"
    echo \"* soft nofile 100000\" >> /etc/security/limits.conf
    echo \"* hard nofile 100000\" >> /etc/security/limits.conf
    
    # Buffer optimization
    sysctl -w net.ipv4.tcp_rmem=\"4096 87380 16777216\"
    sysctl -w net.ipv4.tcp_wmem=\"4096 65536 16777216\"
    
    # CPU Governor
    for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo \"performance\" > \"\$gov\" 2>/dev/null || true
    done
    
    echo -e \"${GREEN}[+] CPU governor set to performance${NC}\"
    echo -e \"${GREEN}[✓] Web Server Optimization profile applied!${NC}\\n\"
}

tune_database_server() {
    echo -e \"\\n${BLUE}[*] Applying Database Server Optimization profile...${NC}\\n\"
    
    echo \"[1] Optimizing for database workload...\"
    
    # Memory optimization
    sysctl -w vm.swappiness=10
    sysctl -w vm.dirty_ratio=10
    sysctl -w vm.dirty_background_ratio=2
    sysctl -w vm.dirty_writeback_centisecs=500
    sysctl -w vm.page-cluster=3
    
    # Shared memory for database
    TOTAL_MEM=\$(grep MemTotal /proc/meminfo | awk '{print \$2}')
    SHMMAX=\$((\$TOTAL_MEM * 1024 * 75 / 100))
    sysctl -w kernel.shmmax=\$SHMMAX
    sysctl -w kernel.shmall=\$((\$SHMMAX / 4096))
    
    # Network optimization
    sysctl -w net.ipv4.tcp_tw_reuse=1
    sysctl -w net.core.somaxconn=4096
    sysctl -w net.ipv4.tcp_max_syn_backlog=4096
    
    # File descriptors
    echo \"* soft nofile 65535\" >> /etc/security/limits.conf
    echo \"* hard nofile 65535\" >> /etc/security/limits.conf
    
    # CPU Governor
    for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo \"performance\" > \"\$gov\" 2>/dev/null || true
    done
    
    echo -e \"${GREEN}[+] Database server optimized${NC}\"
    echo -e \"${GREEN}[✓] Database Server Optimization profile applied!${NC}\\n\"
}

tune_streaming_server() {
    echo -e \"\\n${BLUE}[*] Applying Streaming/Media Server Optimization profile...${NC}\\n\"
    
    echo \"[1] Optimizing for streaming workload...\"
    
    # Large buffer sizes
    sysctl -w net.ipv4.tcp_rmem=\"131072 262144 16777216\"
    sysctl -w net.ipv4.tcp_wmem=\"131072 262144 16777216\"
    sysctl -w net.core.rmem_max=16777216
    sysctl -w net.core.wmem_max=16777216
    
    # Connection handling
    sysctl -w net.ipv4.tcp_tw_reuse=1
    sysctl -w net.core.somaxconn=65535
    sysctl -w net.ipv4.tcp_max_syn_backlog=65535
    sysctl -w net.ipv4.ip_local_port_range=\"1024 65535\"
    
    # Congestion control
    sysctl -w net.ipv4.tcp_congestion_control=bbr
    sysctl -w net.core.default_qdisc=fq
    
    # Memory
    sysctl -w vm.swappiness=20
    sysctl -w vm.dirty_ratio=20
    sysctl -w vm.dirty_background_ratio=5
    
    # CPU Governor
    for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo \"performance\" > \"\$gov\" 2>/dev/null || true
    done
    
    # File descriptors
    echo \"* soft nofile 200000\" >> /etc/security/limits.conf
    echo \"* hard nofile 200000\" >> /etc/security/limits.conf
    
    echo -e \"${GREEN}[+] Streaming server optimized${NC}\"
    echo -e \"${GREEN}[✓] Streaming/Media Server Optimization profile applied!${NC}\\n\"
}

################################################################################
# Function: File Hosting Server Tuning
################################################################################
tune_file_hosting_server() {
    echo -e \"\\n${BLUE}[*] Applying File Hosting Server Optimization profile...${NC}\\n\"
    
    echo \"[1] Optimizing for file hosting workload...\"
    
    # Large file handling - optimize buffers
    sysctl -w net.ipv4.tcp_rmem=\"262144 524288 33554432\"
    sysctl -w net.ipv4.tcp_wmem=\"262144 524288 33554432\"
    sysctl -w net.core.rmem_max=33554432
    sysctl -w net.core.wmem_max=33554432
    echo -e \"${GREEN}[+] Large file buffers configured (32MB)${NC}\\n\"
    
    # Connection handling
    echo \"[2] Optimizing TCP connections...\"
    sysctl -w net.ipv4.tcp_tw_reuse=1
    sysctl -w net.ipv4.tcp_fin_timeout=20
    sysctl -w net.core.somaxconn=65535
    sysctl -w net.ipv4.tcp_max_syn_backlog=32768
    sysctl -w net.core.netdev_max_backlog=65535
    sysctl -w net.ipv4.ip_local_port_range=\"1024 65535\"
    echo -e \"${GREEN}[+] TCP optimized for high concurrency${NC}\\n\"
    
    # File descriptor limits
    echo \"[3] Setting high file descriptor limits...\"
    sysctl -w fs.file-max=4000000
    echo -e \"${GREEN}[+] System file-max set to 4M${NC}\\n\"
    
    # Filesystem optimization
    echo \"[4] Optimizing filesystem caching...\"
    sysctl -w vm.swappiness=15
    sysctl -w vm.dirty_ratio=20
    sysctl -w vm.dirty_background_ratio=5
    sysctl -w vm.dirty_writeback_centisecs=500
    echo -e \"${GREEN}[+] Filesystem caching optimized${NC}\\n\"
    
    # Connection tracking
    sysctl -w net.netfilter.nf_conntrack_max=1000000
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=432000
    
    # CPU performance
    for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo \"performance\" > \"\$gov\" 2>/dev/null || true
    done
    echo -e \"${GREEN}[+] CPU and connection tracking optimized${NC}\"
    echo -e \"${GREEN}[✓] File Hosting Server Optimization profile applied!${NC}\\n\"
}

################################################################################
# Function: Torrenting Server Tuning
################################################################################
tune_torrenting_server() {
    echo -e \"\\n${BLUE}[*] Applying Torrenting Server Optimization profile...${NC}\\n\"
    
    echo \"[1] Optimizing for high peer connections...\"
    
    # Massive connection handling for torrenting
    sysctl -w net.ipv4.tcp_tw_reuse=1
    sysctl -w net.ipv4.tcp_tw_recycle=1
    sysctl -w net.ipv4.tcp_fin_timeout=15
    sysctl -w net.core.somaxconn=65535
    sysctl -w net.ipv4.tcp_max_syn_backlog=65535
    sysctl -w net.core.netdev_max_backlog=65535
    sysctl -w net.ipv4.ip_local_port_range=\"1024 65535\"
    echo -e \"${GREEN}[+] TCP configured for extreme concurrency${NC}\\n\"
    
    echo \"[2] Configuring network buffers...\"
    # Medium-sized buffers for many connections
    sysctl -w net.ipv4.tcp_rmem=\"65536 131072 8388608\"
    sysctl -w net.ipv4.tcp_wmem=\"65536 131072 8388608\"
    sysctl -w net.core.rmem_max=16777216
    sysctl -w net.core.wmem_max=16777216
    echo -e \"${GREEN}[+] Network buffers optimized for many peers${NC}\\n\"
    
    echo \"[3] Setting extremely high file descriptor limits...\"
    sysctl -w fs.file-max=10000000
    echo -e \"${GREEN}[+] System file-max set to 10M${NC}\\n\"
    
    echo \"[4] Optimizing connection tracking...\"
    sysctl -w net.netfilter.nf_conntrack_max=2000000
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=60
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=600
    echo -e \"${GREEN}[+] Connection tracking for massive peer swarms${NC}\\n\"
    
    echo \"[5] Memory optimization...\"
    sysctl -w vm.swappiness=5
    sysctl -w vm.dirty_ratio=10
    sysctl -w vm.dirty_background_ratio=2
    sysctl -w vm.vfs_cache_pressure=100
    echo -e \"${GREEN}[+] Memory optimized with minimal swap${NC}\\n\"
    
    echo \"[6] Congestion control...\"
    sysctl -w net.ipv4.tcp_congestion_control=bbr
    sysctl -w net.core.default_qdisc=fq
    echo -e \"${GREEN}[+] BBR congestion control enabled${NC}\\n\"
    
    # CPU performance
    for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo \"performance\" > \"\$gov\" 2>/dev/null || true
    done
    echo -e \"${GREEN}[+] CPU set to performance mode${NC}\"
    echo -e \"${GREEN}[✓] Torrenting Server Optimization profile applied!${NC}\\n\"
}

################################################################################
# Function: Display Menu
################################################################################
display_menu() {
    echo -e "\n${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   System Security Management Tool      ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}\n"
    
    echo "System Information:"
    echo "  OS: $OS_NAME (v$OS_VERSION)"
    echo "  Package Manager: $PACKAGE_MANAGER"
    echo ""
    echo "Select an option:"
    echo "  [1] General System Hardening"
    echo "  [2] Security Audit"
    echo "  [3] Application Security"
    echo "  [4] User & Access Control"
    echo "  [5] System & Network Tuning"
    echo "  [6] Exit"
    echo ""
}

################################################################################
# Main Menu Loop
################################################################################
main() {
    check_root
    detect_os
    
    while true; do
        display_menu
        read -p "Enter your choice (1-6): " choice
        
        case $choice in
            1)
                system_hardening
                ;;
            2)
                security_audit
                ;;
            3)
                application_security
                ;;
            4)
                user_access_control
                ;;
            5)
                system_network_tuning
                ;;
            6)
                echo -e "${GREEN}[*] Exiting...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Invalid option. Please try again.${NC}"
                ;;
        esac
        
        read -p "Press Enter to continue..."
    done
}

# Run main function
main
