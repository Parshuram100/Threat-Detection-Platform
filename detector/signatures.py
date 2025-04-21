from typing import Dict, List, Pattern
import re

class AttackSignature:
    def __init__(self, name: str, pattern: Pattern, protocol: str, ports: List[int], 
                 min_packets: int = 1, max_packets: int = None, 
                 time_window: int = 60, confidence: float = 0.95):
        self.name = name
        self.pattern = pattern
        self.protocol = protocol
        self.ports = ports
        self.min_packets = min_packets
        self.max_packets = max_packets
        self.time_window = time_window
        self.confidence = confidence

# Define attack signatures with enhanced detection rules
SIGNATURES = {
    'DOS_SYN_FLOOD': AttackSignature(
        name='DOS_SYN_FLOOD',
        pattern=re.compile(r'^SYN$'),
        protocol='TCP',
        ports=[80, 443, 22, 21, 3389, 3306],  # Added more common ports
        min_packets=50,  # Reduced threshold for faster detection
        time_window=1,    # 1 second window
        confidence=0.98
    ),
    
    'DOS_UDP_FLOOD': AttackSignature(
        name='DOS_UDP_FLOOD',
        pattern=re.compile(r'^UDP$'),
        protocol='UDP',
        ports=list(range(1, 65536)),  # All ports for UDP flood
        min_packets=100,  # UDP packets per second
        time_window=1,
        confidence=0.95
    ),
    
    'DOS_ICMP_FLOOD': AttackSignature(
        name='DOS_ICMP_FLOOD',
        pattern=re.compile(r'^ICMP$'),
        protocol='ICMP',
        ports=[0],  # ICMP type 0 (echo reply)
        min_packets=50,  # ICMP packets per second
        time_window=1,
        confidence=0.95
    ),
    
    'BRUTE_FORCE_SSH': AttackSignature(
        name='BRUTE_FORCE_SSH',
        pattern=re.compile(r'^SSH-2\.0-OpenSSH.*$|^SSH-1\.99-OpenSSH.*$'),
        protocol='TCP',
        ports=[22],
        min_packets=3,    # Reduced threshold for faster detection
        time_window=30,   # 30 second window
        confidence=0.95
    ),
    
    'BRUTE_FORCE_FTP': AttackSignature(
        name='BRUTE_FORCE_FTP',
        pattern=re.compile(r'^USER\s+\w+\r\nPASS\s+\w+\r\n$|^USER\s+\w+\r\nPASS\s+\*\*\*\*\r\n$'),
        protocol='TCP',
        ports=[21],
        min_packets=3,    # Reduced threshold for faster detection
        time_window=30,   # 30 second window
        confidence=0.95
    ),
    
    'BRUTE_FORCE_LOGIN': AttackSignature(
        name='BRUTE_FORCE_LOGIN',
        pattern=re.compile(r'(?i)(?:login|auth|signin|authenticate|password|passwd|pwd)'),
        protocol='TCP',
        ports=[80, 443, 8080, 8443],
        min_packets=3,    # Reduced threshold for faster detection
        time_window=30,   # 30 second window
        confidence=0.95
    ),
    
    'SQL_INJECTION': AttackSignature(
        name='SQL_INJECTION',
        pattern=re.compile(r'(?i)(?:union\s+select|select\s+.*from|insert\s+into|update\s+.*set|delete\s+from|drop\s+table|exec\s*\(|xp_cmdshell|\' OR \'1\'=\'1|\' OR \'1\'=\'1\'--|\' OR \'1\'=\'1\'#|\' OR \'1\'=\'1\'/*)'),
        protocol='TCP',
        ports=[80, 443, 8080, 8443, 3306],
        min_packets=1,
        confidence=0.99
    ),
    
    'PORT_SCAN': AttackSignature(
        name='PORT_SCAN',
        pattern=re.compile(r'^SYN$'),
        protocol='TCP',
        ports=list(range(1, 65536)),
        min_packets=5,   # Reduced threshold for faster detection
        time_window=30,   # 30 second window
        confidence=0.90
    ),
    
    'WEB_ENUM': AttackSignature(
        name='WEB_ENUM',
        pattern=re.compile(r'(?i)(?:\.php|\.asp|\.aspx|\.jsp|\.html|\.htm|\.xml|\.json|\.txt|\.bak|\.old|\.zip|\.tar|\.gz|\.git|\.env|\.htaccess|wp-admin|wp-content|admin|administrator|\.\./|\.\.\\|\.\.%2f|\.\.%5c)'),
        protocol='TCP',
        ports=[80, 443, 8080, 8443],
        min_packets=10,   # Reduced threshold for faster detection
        time_window=30,   # 30 second window
        confidence=0.85
    )
}

# Whitelist of known good IPs and patterns
WHITELIST = {
    'ips': [
        r'^192\.168\.1\.\d+$',  # Local network
        r'^10\.0\.0\.\d+$',     # Local network
        r'^127\.0\.0\.1$'       # Localhost
    ],
    'patterns': [
        r'^GET /favicon\.ico',  # Browser favicon requests
        r'^GET /robots\.txt',   # Robots.txt requests
        r'^GET /sitemap\.xml'   # Sitemap requests
    ]
}

def is_whitelisted(ip: str, payload: str) -> bool:
    """Check if an IP or payload is whitelisted"""
    # Check IP against whitelist
    for pattern in WHITELIST['ips']:
        if re.match(pattern, ip):
            return True
    
    # Check payload against whitelist
    for pattern in WHITELIST['patterns']:
        if re.search(pattern, payload):
            return True
    
    return False

def validate_signature(signature: AttackSignature, packets: List[Dict]) -> bool:
    """Validate if a signature matches the packet pattern"""
    if not packets:
        return False
    
    # Check protocol
    if not any(p['protocol'] == signature.protocol for p in packets):
        return False
    
    # Check ports
    if not any(p['port'] in signature.ports for p in packets):
        return False
    
    # Check pattern
    matching_packets = [
        p for p in packets 
        if signature.pattern.search(p.get('payload', ''))
    ]
    
    # Check minimum packets requirement
    if len(matching_packets) < signature.min_packets:
        return False
    
    # Check maximum packets if specified
    if signature.max_packets and len(matching_packets) > signature.max_packets:
        return False
    
    # Check time window if specified
    if signature.time_window:
        first_packet = min(p['timestamp'] for p in matching_packets)
        last_packet = max(p['timestamp'] for p in matching_packets)
        if (last_packet - first_packet).total_seconds() > signature.time_window:
            return False
    
    return True 