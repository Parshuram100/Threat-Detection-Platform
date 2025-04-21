from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime, timedelta
from collections import defaultdict
import json
import threading
import time
from .signatures import SIGNATURES, WHITELIST, is_whitelisted, validate_signature

class PacketAnalyzer:
    def __init__(self):
        self.packet_buffer = defaultdict(list)
        self.attack_log = []
        self.last_cleanup = datetime.now()
        self.connection_tracker = defaultdict(lambda: {
            'syn_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'ports': set(),
            'last_seen': datetime.now(),
            'failed_logins': 0
        })
        
    def start_capture(self, interface=None):
        """Start packet capture on specified interface"""
        try:
            if interface is None:
                # Get default interface for Windows
                interface = conf.iface
                
            # Start packet capture in a separate thread
            self.capture_thread = threading.Thread(
                target=lambda: sniff(
                    iface=interface,
                    prn=self.process_packet,
                    store=0
                )
            )
            self.capture_thread.daemon = True
            self.capture_thread.start()
            print(f"Started packet capture on interface {interface}")
        except Exception as e:
            print(f"Error starting capture: {e}")
    
    def process_packet(self, packet):
        """Process each captured packet"""
        try:
            if IP not in packet:
                return

            # Extract basic packet info
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            timestamp = datetime.now()
            
            # Skip whitelisted traffic
            if is_whitelisted(src_ip, str(packet)):
                return
            
            # Create packet info dictionary
            packet_info = {
                'timestamp': timestamp,
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'protocol': self._get_protocol(packet),
                'payload': str(packet.payload),
                'size': len(packet)
            }

            # Add protocol-specific information
            if TCP in packet:
                packet_info.update({
                    'source_port': packet[TCP].sport,
                    'destination_port': packet[TCP].dport,
                    'flags': packet[TCP].flags,
                    'window': packet[TCP].window
                })
                self._analyze_tcp_packet(packet, packet_info)
                
            elif UDP in packet:
                packet_info.update({
                    'source_port': packet[UDP].sport,
                    'destination_port': packet[UDP].dport
                })
                self._analyze_udp_packet(packet, packet_info)
                
            elif ICMP in packet:
                packet_info.update({
                    'icmp_type': packet[ICMP].type,
                    'icmp_code': packet[ICMP].code
                })
                self._analyze_icmp_packet(packet, packet_info)

            # Add to buffer and check for attacks
            self.packet_buffer[src_ip].append(packet_info)
            self._check_for_attacks(src_ip)
            
            # Cleanup old data periodically
            self._cleanup_old_data()
            
        except Exception as e:
            print(f"Error processing packet: {e}")

    def _get_protocol(self, packet):
        """Determine packet protocol"""
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        return 'OTHER'

    def _analyze_tcp_packet(self, packet, packet_info):
        """Analyze TCP packets for attacks"""
        src_ip = packet_info['source_ip']
        tracker = self.connection_tracker[src_ip]
        
        # Track SYN packets for DoS detection
        if packet[TCP].flags & 0x02:  # SYN flag
            tracker['syn_count'] += 1
            
        # Track ports for scan detection
        tracker['ports'].add(packet_info['destination_port'])
        
        # Track potential brute force attempts
        if packet_info['destination_port'] in [22, 21, 23, 3389]:
            if packet[TCP].flags & 0x18:  # PSH+ACK flags
                tracker['failed_logins'] += 1

    def _analyze_udp_packet(self, packet, packet_info):
        """Analyze UDP packets for attacks"""
        src_ip = packet_info['source_ip']
        self.connection_tracker[src_ip]['udp_count'] += 1
        self.connection_tracker[src_ip]['ports'].add(packet_info['destination_port'])

    def _analyze_icmp_packet(self, packet, packet_info):
        """Analyze ICMP packets for attacks"""
        src_ip = packet_info['source_ip']
        self.connection_tracker[src_ip]['icmp_count'] += 1
    
    def _check_for_attacks(self, src_ip):
        """Check for various types of attacks"""
        try:
            tracker = self.connection_tracker[src_ip]
            current_time = datetime.now()
            time_window = 1  # 1 second window for rate-based detection
            
            # Check for DoS attacks
            if tracker['syn_count'] >= 50:  # SYN flood
                self._log_attack(src_ip, 'DOS_SYN_FLOOD', confidence=0.95)
                tracker['syn_count'] = 0
                
            if tracker['udp_count'] >= 100:  # UDP flood
                self._log_attack(src_ip, 'DOS_UDP_FLOOD', confidence=0.95)
                tracker['udp_count'] = 0
                
            if tracker['icmp_count'] >= 50:  # ICMP flood
                self._log_attack(src_ip, 'DOS_ICMP_FLOOD', confidence=0.95)
                tracker['icmp_count'] = 0
            
            # Check for port scanning
            if len(tracker['ports']) >= 10:  # More than 10 different ports
                self._log_attack(src_ip, 'PORT_SCAN', confidence=0.90)
                tracker['ports'].clear()
            
            # Check for brute force attempts
            if tracker['failed_logins'] >= 3:  # 3 failed attempts
                self._log_attack(src_ip, 'BRUTE_FORCE_SSH', confidence=0.95)
                tracker['failed_logins'] = 0
            
            # Check pattern-based attacks using signatures
            for name, signature in SIGNATURES.items():
                if validate_signature(signature, self.packet_buffer[src_ip]):
                    self._log_attack(src_ip, name, confidence=signature.confidence)
                    self.packet_buffer[src_ip].clear()

        except Exception as e:
            print(f"Error checking for attacks: {e}")

    def _log_attack(self, src_ip, attack_type, confidence=0.95):
        """Log detected attacks"""
        attack = {
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': src_ip,
            'attack_type': attack_type,
            'confidence': confidence,
            'details': self._get_attack_details(src_ip, attack_type)
                }
        print(f"Attack detected: {attack}")  # Debug logging
        self.attack_log.append(attack)
    
    def _get_attack_details(self, src_ip, attack_type):
        """Get detailed information about the attack"""
        tracker = self.connection_tracker[src_ip]
        details = {
            'packets_count': len(self.packet_buffer[src_ip]),
            'unique_ports': len(tracker['ports']),
            'syn_count': tracker['syn_count'],
            'udp_count': tracker['udp_count'],
            'icmp_count': tracker['icmp_count'],
            'failed_logins': tracker['failed_logins']
        }
        return details
    
    def _cleanup_old_data(self):
        """Clean up old data periodically"""
        current_time = datetime.now()
        if (current_time - self.last_cleanup).total_seconds() > 60:
            # Remove old packet buffer entries
            for ip in list(self.packet_buffer.keys()):
                self.packet_buffer[ip] = [
                    p for p in self.packet_buffer[ip]
                    if (current_time - p['timestamp']).total_seconds() < 60
                ]
                if not self.packet_buffer[ip]:
                    del self.packet_buffer[ip]
            
            # Remove old connection tracker entries
            for ip in list(self.connection_tracker.keys()):
                if (current_time - self.connection_tracker[ip]['last_seen']).total_seconds() > 60:
                    del self.connection_tracker[ip]
            
            self.last_cleanup = current_time
    
    def get_attack_log(self):
        """Get the attack log in JSON format"""
        return json.dumps(self.attack_log)

# Initialize global analyzer
analyzer = PacketAnalyzer() 