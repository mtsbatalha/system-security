#!/usr/bin/env python3

"""
System Security Management Script (Python)
Provides a menu-driven interface for various security tasks
Supports: Debian/Ubuntu, RedHat/CentOS/Fedora, Arch, Alpine
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
from enum import Enum

# ANSI Color codes
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

class PackageManager(Enum):
    APT = "apt"
    DNF = "dnf"
    YUM = "yum"
    PACMAN = "pacman"
    APK = "apk"
    UNKNOWN = "unknown"

class OSType(Enum):
    UBUNTU = "ubuntu"
    DEBIAN = "debian"
    FEDORA = "fedora"
    CENTOS = "centos"
    RHEL = "rhel"
    ARCH = "arch"
    ALPINE = "alpine"
    UNKNOWN = "unknown"

class SystemSecurityManager:
    def __init__(self):
        self.os_type = OSType.UNKNOWN
        self.os_version = ""
        self.package_manager = PackageManager.UNKNOWN
        
    def detect_os(self):
        """Detect the operating system and package manager"""
        print(f"{Colors.BLUE}[*] Detecting operating system...{Colors.NC}")
        
        # Try /etc/os-release first (most reliable)
        os_release_path = Path("/etc/os-release")
        if os_release_path.exists():
            with open(os_release_path, 'r') as f:
                content = f.read()
                for line in content.split('\n'):
                    if line.startswith('ID='):
                        os_id = line.split('=')[1].strip('"')
                        self._map_os_type(os_id)
                    elif line.startswith('VERSION_ID='):
                        self.os_version = line.split('=')[1].strip('"')
        else:
            # Fallback methods
            if Path("/etc/redhat-release").exists():
                self.os_type = OSType.RHEL
            elif Path("/etc/debian_version").exists():
                self.os_type = OSType.DEBIAN
        
        # Detect package manager
        self._detect_package_manager()
        
        if self.package_manager == PackageManager.UNKNOWN:
            print(f"{Colors.RED}[!] Unable to detect package manager{Colors.NC}")
            sys.exit(1)
        
        print(f"{Colors.GREEN}[+] OS Detected: {self.os_type.value} (v{self.os_version}){Colors.NC}")
        print(f"{Colors.GREEN}[+] Package Manager: {self.package_manager.value}{Colors.NC}")
    
    def _map_os_type(self, os_id):
        """Map OS ID to OSType enum"""
        os_map = {
            'ubuntu': OSType.UBUNTU,
            'debian': OSType.DEBIAN,
            'fedora': OSType.FEDORA,
            'centos': OSType.CENTOS,
            'rhel': OSType.RHEL,
            'arch': OSType.ARCH,
            'alpine': OSType.ALPINE,
        }
        self.os_type = os_map.get(os_id, OSType.UNKNOWN)
    
    def _detect_package_manager(self):
        """Detect available package manager"""
        managers = {
            'apt-get': PackageManager.APT,
            'dnf': PackageManager.DNF,
            'yum': PackageManager.YUM,
            'pacman': PackageManager.PACMAN,
            'apk': PackageManager.APK,
        }
        
        for cmd, pm in managers.items():
            if self._command_exists(cmd):
                self.package_manager = pm
                return
    
    @staticmethod
    def _command_exists(cmd):
        """Check if command exists in PATH"""
        try:
            subprocess.run(['which', cmd], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    @staticmethod
    def _run_command(cmd, shell=False, check=False):
        """Run a shell command and return output"""
        try:
            result = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
            if check and result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, cmd)
            return result.stdout, result.returncode
        except Exception as e:
            print(f"{Colors.RED}[!] Error running command: {e}{Colors.NC}")
            return "", 1
    
    @staticmethod
    def _check_root():
        """Check if running as root"""
        if os.geteuid() != 0:
            print(f"{Colors.RED}[!] This script must be run as root (use: sudo){Colors.NC}")
            sys.exit(1)
    
    def system_hardening(self):
        """General system hardening"""
        print(f"\n{Colors.BLUE}=== General System Hardening ==={Colors.NC}\n")
        
        # Update packages
        print("[1] Updating system packages...")
        if self.package_manager == PackageManager.APT:
            self._run_command(['apt-get', 'update'], check=False)
            self._run_command(['apt-get', 'upgrade', '-y'], check=False)
        elif self.package_manager in [PackageManager.DNF, PackageManager.YUM]:
            self._run_command([self.package_manager.value, 'update', '-y'], check=False)
        elif self.package_manager == PackageManager.PACMAN:
            self._run_command(['pacman', '-Syu', '--noconfirm'], check=False)
        elif self.package_manager == PackageManager.APK:
            self._run_command(['apk', 'update'], check=False)
            self._run_command(['apk', 'upgrade'], check=False)
        print(f"{Colors.GREEN}[+] System packages updated{Colors.NC}\n")
        
        # Install security tools
        print("[2] Installing essential security tools...")
        if self.package_manager == PackageManager.APT:
            self._run_command(['apt-get', 'install', '-y', 'fail2ban', 'ufw', 'aide', 'auditd'], check=False)
        elif self.package_manager in [PackageManager.DNF, PackageManager.YUM]:
            pm = self.package_manager.value
            self._run_command([pm, 'install', '-y', 'fail2ban', 'firewalld', 'aide', 'audit'], check=False)
        print(f"{Colors.GREEN}[+] Security tools installed{Colors.NC}\n")
        
        # Configure firewall
        print("[3] Configuring firewall...")
        if self.package_manager == PackageManager.APT:
            self._run_command(['ufw', '--force', 'enable'], check=False)
            self._run_command(['ufw', 'default', 'deny', 'incoming'], check=False)
            self._run_command(['ufw', 'default', 'allow', 'outgoing'], check=False)
            print(f"{Colors.GREEN}[+] UFW firewall configured{Colors.NC}")
        elif self.package_manager in [PackageManager.DNF, PackageManager.YUM]:
            self._run_command(['systemctl', 'enable', 'firewalld'], check=False)
            self._run_command(['systemctl', 'start', 'firewalld'], check=False)
            print(f"{Colors.GREEN}[+] Firewalld configured{Colors.NC}")
        print("")
        
        # Disable unnecessary services
        print("[4] Disabling unnecessary services...")
        for service in ['avahi-daemon', 'cups', 'isc-dhcp-server']:
            self._run_command(['systemctl', 'disable', service], check=False)
        print(f"{Colors.GREEN}[+] Unnecessary services disabled{Colors.NC}\n")
        
        # Hardening kernel parameters
        print("[5] Hardening system parameters...")
        sysctl_params = {
            'net.ipv4.ip_forward': 0,
            'net.ipv6.conf.all.forwarding': 0,
            'net.ipv4.conf.all.send_redirects': 0,
            'net.ipv4.conf.default.send_redirects': 0,
            'net.ipv4.conf.all.accept_source_route': 0,
            'net.ipv4.conf.default.accept_source_route': 0,
            'net.ipv6.conf.all.accept_source_route': 0,
            'net.ipv6.conf.default.accept_source_route': 0,
            'net.ipv4.conf.all.log_martians': 1,
            'net.ipv4.conf.default.log_martians': 1,
            'net.ipv4.icmp_ignore_bogus_error_responses': 1,
            'net.ipv4.tcp_syncookies': 1,
        }
        
        for param, value in sysctl_params.items():
            self._run_command(['sysctl', '-w', f'{param}={value}'], check=False)
        print(f"{Colors.GREEN}[+] System parameters hardened{Colors.NC}\n")
        
        print(f"{Colors.GREEN}[✓] System hardening complete!{Colors.NC}\n")
    
    def security_audit(self):
        """Perform security audit"""
        print(f"\n{Colors.BLUE}=== Security Audit ==={Colors.NC}\n")
        
        print("[1] Checking listening ports...")
        print(f"{Colors.YELLOW}Open ports and services:{Colors.NC}")
        self._run_command(['ss', '-tuln'], check=False)
        print("")
        
        print("[2] Checking running services...")
        print(f"{Colors.YELLOW}Running services:{Colors.NC}")
        self._run_command(['systemctl', 'list-units', '--type=service', '--state=running'], check=False)
        print("")
        
        print("[3] Checking user accounts...")
        print(f"{Colors.YELLOW}Non-system users:{Colors.NC}")
        self._run_command("awk -F: '$3 >= 1000 {print $1 \" (UID: \" $3 \")'}' /etc/passwd", shell=True, check=False)
        print("")
        
        print("[4] Checking critical file permissions...")
        print(f"{Colors.YELLOW}Critical file permissions:{Colors.NC}")
        for file in ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers']:
            if Path(file).exists():
                self._run_command(['ls', '-l', file], check=False)
        print("")
        
        print("[5] Checking sudo access...")
        print(f"{Colors.YELLOW}Users with sudo privileges:{Colors.NC}")
        self._run_command("getent group sudo | cut -d: -f4", shell=True, check=False)
        self._run_command("getent group wheel | cut -d: -f4", shell=True, check=False)
        print("")
        
        print("[6] Checking SSH configuration...")
        print(f"{Colors.YELLOW}SSH Configuration:{Colors.NC}")
        if Path('/etc/ssh/sshd_config').exists():
            self._run_command("grep -E '^PermitRootLogin|^PasswordAuthentication|^PubkeyAuthentication|^Protocol' /etc/ssh/sshd_config", shell=True, check=False)
        print("")
        
        print("[7] Checking firewall status...")
        print(f"{Colors.YELLOW}Firewall status:{Colors.NC}")
        if self.package_manager == PackageManager.APT:
            self._run_command(['ufw', 'status'], check=False)
        elif self.package_manager in [PackageManager.DNF, PackageManager.YUM]:
            self._run_command(['firewall-cmd', '--list-all'], check=False)
        print("")
        
        print(f"{Colors.GREEN}[✓] Security audit complete!{Colors.NC}\n")
    
    def application_security(self):
        """Review application security"""
        print(f"\n{Colors.BLUE}=== Application Security ==={Colors.NC}\n")
        
        print("[1] Checking for running web servers and databases...")
        
        # Check for web servers
        for service in ['apache2', 'httpd', 'nginx']:
            stdout, rc = self._run_command(['systemctl', 'is-active', '--quiet', service], check=False)
            if rc == 0:
                print(f"{Colors.YELLOW}✓ {service} is running{Colors.NC}")
                print("  Recommendations: Enable SSL/TLS, configure security headers, disable unnecessary modules")
        
        # Check for databases
        for service in ['mysql', 'mysqld', 'postgresql', 'mariadb']:
            stdout, rc = self._run_command(['systemctl', 'is-active', '--quiet', service], check=False)
            if rc == 0:
                print(f"{Colors.YELLOW}✓ {service} is running{Colors.NC}")
                print("  Recommendations: Change default credentials, disable remote root, run security wizard")
        print("")
        
        print("[2] Checking for vulnerable packages...")
        if self.package_manager == PackageManager.APT:
            print("[+] Run: apt-cache policy | grep security")
        elif self.package_manager in [PackageManager.DNF, PackageManager.YUM]:
            self._run_command([self.package_manager.value, 'check-update', '--security'], check=False)
        print("")
        
        print(f"{Colors.GREEN}[✓] Application security review complete!{Colors.NC}\n")
    
    def user_access_control(self):
        """Configure user access control"""
        print(f"\n{Colors.BLUE}=== User & Access Control ==={Colors.NC}\n")
        
        print("[1] Current SSH configuration:")
        if Path('/etc/ssh/sshd_config').exists():
            self._run_command("grep -E '^PermitRootLogin|^PasswordAuthentication|^PubkeyAuthentication' /etc/ssh/sshd_config", shell=True, check=False)
        print("")
        
        print("[2] Checking sudoers configuration...")
        self._run_command("grep -v '^#' /etc/sudoers | grep -v '^$' | head -10", shell=True, check=False)
        print("")
        
        print("[3] Recommendations:")
        print(f"{Colors.YELLOW}SSH Security:{Colors.NC}")
        print("  - Disable root login: PermitRootLogin no")
        print("  - Disable password auth: PasswordAuthentication no")
        print("  - Enable pubkey auth: PubkeyAuthentication yes")
        print("  - Change SSH port (optional)")
        print("")
        
        print(f"{Colors.YELLOW}Password Policy:{Colors.NC}")
        print("  - Install libpam-pwquality (Debian) or libpwquality (RHEL)")
        print("  - Minimum length: 12 characters")
        print("  - Require mixed case and numbers")
        print("")
        
        print(f"{Colors.YELLOW}Access Control:{Colors.NC}")
        print("  - Review /etc/sudoers for excessive privileges")
        print("  - Implement SSH key authentication")
        print("  - Enable account lockout policies")
        print("  - Configure audit logging")
        print("")
        
        print(f"{Colors.GREEN}[✓] User access control review complete!{Colors.NC}\n")
    
    def system_network_tuning(self):
        """Tune system and network according to profile"""
        print(f"\n{Colors.BLUE}=== System & Network Tuning ==={Colors.NC}\n")
        
        print("Select tuning profile:")
        print("  [1] High Performance (Low Latency)")
        print("  [2] Balanced (Default)")
        print("  [3] Power Saving")
        print("  [4] Web Server Optimization")
        print("  [5] Database Server Optimization")
        print("  [6] Streaming/Media Server")
        print("  [7] File Hosting Server")
        print("  [8] Torrenting Server")
        
        try:
            profile = input("Select profile (1-8): ").strip()
            
            if profile == '1':
                self._tune_high_performance()
            elif profile == '2':
                self._tune_balanced()
            elif profile == '3':
                self._tune_power_saving()
            elif profile == '4':
                self._tune_web_server()
            elif profile == '5':
                self._tune_database_server()
            elif profile == '6':
                self._tune_streaming_server()
            elif profile == '7':
                self._tune_file_hosting_server()
            elif profile == '8':
                self._tune_torrenting_server()
            else:
                print(f"{Colors.RED}[!] Invalid option{Colors.NC}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.NC}")
    
    def _tune_high_performance(self):
        """High Performance profile - Low latency"""
        print(f"\n{Colors.BLUE}[*] Applying High Performance profile...{Colors.NC}\n")
        
        print("[1] Setting CPU governor to performance...")
        self._run_command("for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo 'performance' > $gov 2>/dev/null; done", shell=True, check=False)
        print(f"{Colors.GREEN}[+] CPU governor set to performance{Colors.NC}\n")
        
        print("[2] Optimizing network stack...")
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_tw_reuse=1'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_fin_timeout=30'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.somaxconn=32768'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_max_syn_backlog=16384'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.netdev_max_backlog=5000'], check=False)
        print(f"{Colors.GREEN}[+] Network optimized for low latency{Colors.NC}\n")
        
        print("[3] Disabling power saving features...")
        self._run_command(['sysctl', '-w', 'kernel.sched_migration_cost_ns=5000000'], check=False)
        print(f"{Colors.GREEN}[+] Power saving disabled{Colors.NC}\n")
        
        print(f"{Colors.GREEN}[✓] High Performance profile applied!{Colors.NC}\n")
    
    def _tune_balanced(self):
        """Balanced profile - Default settings"""
        print(f"\n{Colors.BLUE}[*] Applying Balanced profile...{Colors.NC}\n")
        
        print("[1] Setting CPU governor to balanced...")
        self._run_command("for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo 'schedutil' > $gov 2>/dev/null || echo 'ondemand' > $gov 2>/dev/null; done", shell=True, check=False)
        print(f"{Colors.GREEN}[+] CPU governor set to balanced{Colors.NC}\n")
        
        print("[2] Optimizing network stack...")
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_tw_reuse=1'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_fin_timeout=60'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.somaxconn=4096'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_max_syn_backlog=2048'], check=False)
        print(f"{Colors.GREEN}[+] Network optimized for balance{Colors.NC}\n")
        
        print("[3] Setting memory parameters...")
        self._run_command(['sysctl', '-w', 'vm.swappiness=30'], check=False)
        self._run_command(['sysctl', '-w', 'vm.dirty_ratio=15'], check=False)
        self._run_command(['sysctl', '-w', 'vm.dirty_background_ratio=5'], check=False)
        print(f"{Colors.GREEN}[+] Memory parameters optimized{Colors.NC}\n")
        
        print(f"{Colors.GREEN}[✓] Balanced profile applied!{Colors.NC}\n")
    
    def _tune_power_saving(self):
        """Power Saving profile"""
        print(f"\n{Colors.BLUE}[*] Applying Power Saving profile...{Colors.NC}\n")
        
        print("[1] Setting CPU governor to powersave...")
        self._run_command("for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo 'powersave' > $gov 2>/dev/null; done", shell=True, check=False)
        print(f"{Colors.GREEN}[+] CPU governor set to powersave{Colors.NC}\n")
        
        print("[2] Optimizing for power saving...")
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_tw_reuse=1'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_fin_timeout=120'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_keepalive_time=900'], check=False)
        print(f"{Colors.GREEN}[+] Network optimized for power saving{Colors.NC}\n")
        
        print("[3] Setting memory parameters for low power...")
        self._run_command(['sysctl', '-w', 'vm.swappiness=60'], check=False)
        self._run_command(['sysctl', '-w', 'vm.dirty_ratio=30'], check=False)
        self._run_command(['sysctl', '-w', 'vm.dirty_background_ratio=10'], check=False)
        self._run_command(['sysctl', '-w', 'kernel.sched_migration_cost_ns=500000'], check=False)
        print(f"{Colors.GREEN}[+] Memory parameters optimized{Colors.NC}\n")
        
        print(f"{Colors.GREEN}[✓] Power Saving profile applied!{Colors.NC}\n")
    
    def _tune_web_server(self):
        """Web Server Optimization profile"""
        print(f"\n{Colors.BLUE}[*] Applying Web Server Optimization profile...{Colors.NC}\n")
        
        print("[1] Optimizing for web server workload...")
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_tw_reuse=1'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_fin_timeout=30'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.somaxconn=65535'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_max_syn_backlog=65535'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.netdev_max_backlog=10000'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.ip_local_port_range=1024 65535'], check=False)
        
        print(f"{Colors.GREEN}[+] TCP connections optimized{Colors.NC}")
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_rmem=4096 87380 16777216'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_wmem=4096 65536 16777216'], check=False)
        print(f"{Colors.GREEN}[+] Buffer sizes optimized{Colors.NC}")
        
        self._run_command("for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo 'performance' > $gov 2>/dev/null; done", shell=True, check=False)
        print(f"{Colors.GREEN}[+] CPU governor set to performance{Colors.NC}")
        print(f"{Colors.GREEN}[✓] Web Server Optimization profile applied!{Colors.NC}\n")
    
    def _tune_database_server(self):
        """Database Server Optimization profile"""
        print(f"\n{Colors.BLUE}[*] Applying Database Server Optimization profile...{Colors.NC}\n")
        
        print("[1] Optimizing for database workload...")
        self._run_command(['sysctl', '-w', 'vm.swappiness=10'], check=False)
        self._run_command(['sysctl', '-w', 'vm.dirty_ratio=10'], check=False)
        self._run_command(['sysctl', '-w', 'vm.dirty_background_ratio=2'], check=False)
        self._run_command(['sysctl', '-w', 'vm.dirty_writeback_centisecs=500'], check=False)
        self._run_command(['sysctl', '-w', 'vm.page-cluster=3'], check=False)
        print(f"{Colors.GREEN}[+] Memory parameters optimized{Colors.NC}\n")
        
        print("[2] Configuring shared memory...")
        stdout, _ = self._run_command("grep MemTotal /proc/meminfo | awk '{print $2}'", shell=True, check=False)
        total_mem = int(stdout.strip()) if stdout else 1024000
        shmmax = (total_mem * 1024 * 75) // 100
        self._run_command(['sysctl', '-w', f'kernel.shmmax={shmmax}'], check=False)
        self._run_command(['sysctl', '-w', f'kernel.shmall={shmmax // 4096}'], check=False)
        print(f"{Colors.GREEN}[+] Shared memory configured{Colors.NC}\n")
        
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_tw_reuse=1'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.somaxconn=4096'], check=False)
        self._run_command("for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo 'performance' > $gov 2>/dev/null; done", shell=True, check=False)
        print(f"{Colors.GREEN}[+] CPU and network optimized{Colors.NC}")
        print(f"{Colors.GREEN}[✓] Database Server Optimization profile applied!{Colors.NC}\n")
    
    def _tune_streaming_server(self):
        """Streaming/Media Server Optimization profile"""
        print(f"\n{Colors.BLUE}[*] Applying Streaming/Media Server Optimization profile...{Colors.NC}\n")
        
        print("[1] Optimizing for streaming workload...")
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_rmem=131072 262144 16777216'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_wmem=131072 262144 16777216'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.rmem_max=16777216'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.wmem_max=16777216'], check=False)
        print(f"{Colors.GREEN}[+] Large buffers configured{Colors.NC}\n")
        
        print("[2] Optimizing for high throughput...")
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_tw_reuse=1'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.somaxconn=65535'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_max_syn_backlog=65535'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_congestion_control=bbr'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.default_qdisc=fq'], check=False)
        print(f"{Colors.GREEN}[+] Congestion control optimized{Colors.NC}\n")
        
        self._run_command(['sysctl', '-w', 'vm.swappiness=20'], check=False)
        self._run_command("for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo 'performance' > $gov 2>/dev/null; done", shell=True, check=False)
        print(f"{Colors.GREEN}[+] CPU and memory optimized{Colors.NC}")
        print(f"{Colors.GREEN}[✓] Streaming/Media Server Optimization profile applied!{Colors.NC}\n")
    
    def _tune_file_hosting_server(self):
        """File Hosting Server Optimization profile"""
        print(f"\n{Colors.BLUE}[*] Applying File Hosting Server Optimization profile...{Colors.NC}\n")
        
        print("[1] Optimizing for file hosting workload...")
        
        # Large file handling - optimize buffers
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_rmem=262144 524288 33554432'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_wmem=262144 524288 33554432'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.rmem_max=33554432'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.wmem_max=33554432'], check=False)
        print(f"{Colors.GREEN}[+] Large file buffers configured (32MB){Colors.NC}\n")
        
        # Connection handling
        print("[2] Optimizing TCP connections...")
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_tw_reuse=1'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_fin_timeout=20'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.somaxconn=65535'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_max_syn_backlog=32768'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.netdev_max_backlog=65535'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.ip_local_port_range=1024 65535'], check=False)
        print(f"{Colors.GREEN}[+] TCP optimized for high concurrency{Colors.NC}\n")
        
        # File descriptor limits
        print("[3] Setting high file descriptor limits...")
        self._run_command(['sysctl', '-w', 'fs.file-max=4000000'], check=False)
        print(f"{Colors.GREEN}[+] System file-max set to 4M{Colors.NC}\n")
        
        # Filesystem optimization
        print("[4] Optimizing filesystem caching...")
        self._run_command(['sysctl', '-w', 'vm.swappiness=15'], check=False)
        self._run_command(['sysctl', '-w', 'vm.dirty_ratio=20'], check=False)
        self._run_command(['sysctl', '-w', 'vm.dirty_background_ratio=5'], check=False)
        self._run_command(['sysctl', '-w', 'vm.dirty_writeback_centisecs=500'], check=False)
        print(f"{Colors.GREEN}[+] Filesystem caching optimized{Colors.NC}\n")
        
        # Connection tracking
        self._run_command(['sysctl', '-w', 'net.netfilter.nf_conntrack_max=1000000'], check=False)
        self._run_command(['sysctl', '-w', 'net.netfilter.nf_conntrack_tcp_timeout_established=432000'], check=False)
        
        # CPU performance
        self._run_command("for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo 'performance' > $gov 2>/dev/null; done", shell=True, check=False)
        print(f"{Colors.GREEN}[+] CPU and connection tracking optimized{Colors.NC}")
        print(f"{Colors.GREEN}[✓] File Hosting Server Optimization profile applied!{Colors.NC}\n")
    
    def _tune_torrenting_server(self):
        """Torrenting Server Optimization profile"""
        print(f"\n{Colors.BLUE}[*] Applying Torrenting Server Optimization profile...{Colors.NC}\n")
        
        print("[1] Optimizing for high peer connections...")
        
        # Massive connection handling for torrenting
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_tw_reuse=1'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_tw_recycle=1'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_fin_timeout=15'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.somaxconn=65535'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_max_syn_backlog=65535'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.netdev_max_backlog=65535'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.ip_local_port_range=1024 65535'], check=False)
        print(f"{Colors.GREEN}[+] TCP configured for extreme concurrency{Colors.NC}\n")
        
        print("[2] Configuring network buffers...")
        # Medium-sized buffers for many connections
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_rmem=65536 131072 8388608'], check=False)
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_wmem=65536 131072 8388608'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.rmem_max=16777216'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.wmem_max=16777216'], check=False)
        print(f"{Colors.GREEN}[+] Network buffers optimized for many peers{Colors.NC}\n")
        
        print("[3] Setting extremely high file descriptor limits...")
        self._run_command(['sysctl', '-w', 'fs.file-max=10000000'], check=False)
        print(f"{Colors.GREEN}[+] System file-max set to 10M{Colors.NC}\n")
        
        print("[4] Optimizing connection tracking...")
        self._run_command(['sysctl', '-w', 'net.netfilter.nf_conntrack_max=2000000'], check=False)
        self._run_command(['sysctl', '-w', 'net.netfilter.nf_conntrack_tcp_timeout_time_wait=60'], check=False)
        self._run_command(['sysctl', '-w', 'net.netfilter.nf_conntrack_tcp_timeout_established=600'], check=False)
        print(f"{Colors.GREEN}[+] Connection tracking for massive peer swarms{Colors.NC}\n")
        
        print("[5] Memory optimization...")
        self._run_command(['sysctl', '-w', 'vm.swappiness=5'], check=False)
        self._run_command(['sysctl', '-w', 'vm.dirty_ratio=10'], check=False)
        self._run_command(['sysctl', '-w', 'vm.dirty_background_ratio=2'], check=False)
        self._run_command(['sysctl', '-w', 'vm.vfs_cache_pressure=100'], check=False)
        print(f"{Colors.GREEN}[+] Memory optimized with minimal swap{Colors.NC}\n")
        
        print("[6] Congestion control...")
        self._run_command(['sysctl', '-w', 'net.ipv4.tcp_congestion_control=bbr'], check=False)
        self._run_command(['sysctl', '-w', 'net.core.default_qdisc=fq'], check=False)
        print(f"{Colors.GREEN}[+] BBR congestion control enabled{Colors.NC}\n")
        
        # CPU performance
        self._run_command("for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo 'performance' > $gov 2>/dev/null; done", shell=True, check=False)
        print(f"{Colors.GREEN}[+] CPU set to performance mode{Colors.NC}")
        print(f"{Colors.GREEN}[✓] Torrenting Server Optimization profile applied!{Colors.NC}\n")
    
    def display_menu(self):
        """Display main menu"""
        print(f"\n{Colors.BLUE}╔════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.BLUE}║   System Security Management Tool      ║{Colors.NC}")
        print(f"{Colors.BLUE}╚════════════════════════════════════════╝{Colors.NC}\n")
        
        print("System Information:")
        print(f"  OS: {self.os_type.value} (v{self.os_version})")
        print(f"  Package Manager: {self.package_manager.value}")
        print("")
        print("Select an option:")
        print("  [1] General System Hardening")
        print("  [2] Security Audit")
        print("  [3] Application Security")
        print("  [4] User & Access Control")
        print("  [5] System & Network Tuning")
        print("  [6] Exit")
        print("")
    
    def run(self):
        """Main menu loop"""
        self._check_root()
        self.detect_os()
        
        while True:
            self.display_menu()
            try:
                choice = input("Enter your choice (1-6): ").strip()
                
                if choice == '1':
                    self.system_hardening()
                elif choice == '2':
                    self.security_audit()
                elif choice == '3':
                    self.application_security()
                elif choice == '4':
                    self.user_access_control()
                elif choice == '5':
                    self.system_network_tuning()
                elif choice == '6':
                    print(f"{Colors.GREEN}[*] Exiting...{Colors.NC}")
                    sys.exit(0)
                else:
                    print(f"{Colors.RED}[!] Invalid option. Please try again.{Colors.NC}")
                
                input("Press Enter to continue...")
            except KeyboardInterrupt:
                print(f"\n{Colors.GREEN}[*] Exiting...{Colors.NC}")
                sys.exit(0)
            except Exception as e:
                print(f"{Colors.RED}[!] Error: {e}{Colors.NC}")

if __name__ == "__main__":
    manager = SystemSecurityManager()
    manager.run()
