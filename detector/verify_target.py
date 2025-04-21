import socket
import subprocess
import sys
import os
import requests
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP

class TargetVerifier:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.results = {
            'dos_ready': False,
            'brute_force_ready': False,
            'sql_injection_ready': False,
            'web_enum_ready': False,
            'port_scan_ready': False
        }
        
    def verify_all(self):
        """Run all verification checks"""
        print("\n🔍 Starting target verification...\n")
        
        self.verify_network_access()
        self.verify_ports()
        self.verify_services()
        self.verify_web_server()
        self.print_results()
        
    def verify_network_access(self):
        """Verify basic network connectivity"""
        print("📡 Checking network connectivity...")
        try:
            # Try ICMP ping
            response = sr1(IP(dst=self.target_ip)/ICMP(), timeout=2, verbose=0)
            if response:
                print("✅ ICMP ping successful")
                self.results['dos_ready'] = True
            else:
                print("❌ ICMP ping failed")
                
            # Try TCP ping
            response = sr1(IP(dst=self.target_ip)/TCP(dport=80, flags="S"), timeout=2, verbose=0)
            if response:
                print("✅ TCP ping successful")
                self.results['port_scan_ready'] = True
            else:
                print("❌ TCP ping failed")
                
        except Exception as e:
            print(f"❌ Network connectivity check failed: {e}")
    
    def verify_ports(self):
        """Verify required ports are accessible"""
        print("\n🔌 Checking required ports...")
        ports_to_check = {
            22: "SSH",
            21: "FTP",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL"
        }
        
        for port, service in ports_to_check.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target_ip, port))
            if result == 0:
                print(f"✅ Port {port} ({service}) is open")
                if port in [22, 21]:
                    self.results['brute_force_ready'] = True
                elif port in [80, 443]:
                    self.results['web_enum_ready'] = True
                elif port == 3306:
                    self.results['sql_injection_ready'] = True
            else:
                print(f"❌ Port {port} ({service}) is closed")
            sock.close()
    
    def verify_services(self):
        """Verify required services are running"""
        print("\n🔧 Checking required services...")
        
        # Check SSH service
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.target_ip, 22))
            banner = sock.recv(1024)
            if b'SSH' in banner:
                print("✅ SSH service is running")
                self.results['brute_force_ready'] = True
            sock.close()
        except:
            print("❌ SSH service check failed")
            
        # Check FTP service
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.target_ip, 21))
            banner = sock.recv(1024)
            if b'FTP' in banner:
                print("✅ FTP service is running")
                self.results['brute_force_ready'] = True
            sock.close()
        except:
            print("❌ FTP service check failed")
    
    def verify_web_server(self):
        """Verify web server configuration"""
        print("\n🌐 Checking web server...")
        
        # Check HTTP
        try:
            response = requests.get(f"http://{self.target_ip}", timeout=2)
            print(f"✅ HTTP server is running (Status: {response.status_code})")
            self.results['web_enum_ready'] = True
            self.results['sql_injection_ready'] = True
            
            # Check for common web paths
            test_paths = ['/login', '/admin', '/wp-admin']
            for path in test_paths:
                try:
                    response = requests.get(f"http://{self.target_ip}{path}", timeout=1)
                    if response.status_code != 404:
                        print(f"✅ Found web path: {path}")
                except:
                    pass
                    
        except requests.exceptions.RequestException:
            print("❌ HTTP server check failed")
            
        # Check HTTPS
        try:
            response = requests.get(f"https://{self.target_ip}", verify=False, timeout=2)
            print(f"✅ HTTPS server is running (Status: {response.status_code})")
        except requests.exceptions.RequestException:
            print("❌ HTTPS server check failed")
    
    def print_results(self):
        """Print verification results"""
        print("\n📊 Verification Results:")
        print("=" * 50)
        
        total_ready = 0
        for attack_type, is_ready in self.results.items():
            status = "✅ Ready" if is_ready else "❌ Not Ready"
            print(f"{attack_type.replace('_', ' ').title()}: {status}")
            if is_ready:
                total_ready += 1
        
        print("\n📝 Summary:")
        print(f"Total Features Ready: {total_ready}/{len(self.results)}")
        
        if total_ready == len(self.results):
            print("\n✅ Target is fully ready for all attacks!")
        else:
            print("\n⚠️ Some features are not ready. Please check the requirements.")
            self.print_requirements()
    
    def print_requirements(self):
        """Print requirements for features that are not ready"""
        print("\n📋 Requirements for Missing Features:")
        
        if not self.results['dos_ready']:
            print("\nDoS/DDoS Requirements:")
            print("- ICMP traffic allowed")
            print("- No rate limiting on ICMP/TCP/UDP")
            
        if not self.results['brute_force_ready']:
            print("\nBrute Force Requirements:")
            print("- SSH service running (port 22)")
            print("- FTP service running (port 21)")
            print("- Web login page accessible")
            
        if not self.results['sql_injection_ready']:
            print("\nSQL Injection Requirements:")
            print("- Web server running")
            print("- Login or form page accessible")
            print("- MySQL/Database service running")
            
        if not self.results['web_enum_ready']:
            print("\nWeb Enumeration Requirements:")
            print("- Web server running")
            print("- Directory listing enabled")
            print("- Common web paths accessible")
            
        if not self.results['port_scan_ready']:
            print("\nPort Scan Requirements:")
            print("- Multiple ports open")
            print("- TCP traffic allowed")
            print("- No firewall blocking port scans")

def main():
    if len(sys.argv) != 2:
        print("Usage: python verify_target.py <target_ip>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    verifier = TargetVerifier(target_ip)
    verifier.verify_all()

if __name__ == "__main__":
    main() 