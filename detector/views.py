import os
import json
import platform
import subprocess
import threading
import time
from pathlib import Path
import win32api
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.core.files.storage import FileSystemStorage
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import NetworkTraffic, DetectedThreat, SecurityScan, SecurityReport
from scapy.all import sniff, IP, TCP, UDP, ARP, Raw, ICMP, DNS
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
from datetime import datetime
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

# Global variables for process management
suricata_process = None
detection_thread = None
is_detecting = False

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.threshold = 0.75
        self.feature_names = [
            'packet_length',
            'has_ip',
            'has_tcp',
            'has_udp',
            'has_arp',
            'ip_version',
            'ip_length',
            'ip_ttl',
            'tcp_sport',
            'tcp_dport',
            'tcp_ack',
            'tcp_syn',
            'tcp_fin',
            'tcp_rst',
            'tcp_psh'
        ]
        self.attack_types = {
            'DOS': 'Denial of Service Attack',
            'PROBE': 'Network Probe/Port Scan',
            'R2L': 'Remote to Local Attack',
            'U2R': 'User to Root Attack',
            'BOTNET': 'Botnet Activity',
            'INJECTION': 'SQL/Command Injection',
            'XSS': 'Cross-Site Scripting',
            'BACKDOOR': 'Backdoor Activity'
        }
        
    def load_model(self):
        try:
            model_path = os.path.join(settings.BASE_DIR, 'ml_models', 'model.pkl')
            
            if not os.path.exists(model_path):
                # Try to find any existing model
                model_dir = os.path.join(settings.BASE_DIR, 'ml_models')
                model_files = [f for f in os.listdir(model_dir) if f.endswith('.pkl')]
                
                if model_files:
                    # Use the first available model
                    model_path = os.path.join(model_dir, model_files[0])
                    print(f"Using existing model: {model_files[0]}")
                else:
                    # Create a new default model
                    print("Creating default Isolation Forest model...")
                    self.model = IsolationForest(
                        n_estimators=100,
                        contamination=0.1,
                        random_state=42
                    )
                    # Train the model with some normal data
                    normal_data = np.random.normal(size=(1000, len(self.feature_names)))
                    self.model.fit(normal_data)
                    # Save the model
                    joblib.dump(self.model, model_path)
                    return {
                        "status": True,
                        "model_type": type(self.model).__name__,
                        "message": "Created and trained new default model"
                    }
            
            # Load the model
            print(f"Loading model from {model_path}")
            self.model = joblib.load(model_path)
            
            # Validate model type
            if not isinstance(self.model, (IsolationForest, type(None))):
                raise ValueError("Invalid model type: must be IsolationForest")
                
            return {
                "status": True,
                "model_type": type(self.model).__name__
            }
        except Exception as e:
            print(f"Error loading model: {e}")
            return {"status": False, "error": str(e)}
            
    def preprocess_packet(self, packet):
        try:
            features = {}
            
            # Basic packet features
            features['packet_length'] = len(packet)
            features['has_ip'] = int(IP in packet)
            features['has_tcp'] = int(TCP in packet)
            features['has_udp'] = int(UDP in packet)
            features['has_arp'] = int(ARP in packet)
            
            # IP features
            if IP in packet:
                features['ip_version'] = int(packet[IP].version)
                features['ip_length'] = packet[IP].len
                features['ip_ttl'] = packet[IP].ttl
            else:
                features['ip_version'] = 0
                features['ip_length'] = 0
                features['ip_ttl'] = 0
                
            # TCP features
            if TCP in packet:
                features['tcp_sport'] = packet[TCP].sport
                features['tcp_dport'] = packet[TCP].dport
                features['tcp_ack'] = int(packet[TCP].flags.A)
                features['tcp_syn'] = int(packet[TCP].flags.S)
                features['tcp_fin'] = int(packet[TCP].flags.F)
                features['tcp_rst'] = int(packet[TCP].flags.R)
                features['tcp_psh'] = int(packet[TCP].flags.P)
            else:
                features['tcp_sport'] = 0
                features['tcp_dport'] = 0
                features['tcp_ack'] = 0
                features['tcp_syn'] = 0
                features['tcp_fin'] = 0
                features['tcp_rst'] = 0
                features['tcp_psh'] = 0
                
            # Convert to array in correct order
            feature_array = np.array([features[name] for name in self.feature_names])
            return feature_array.reshape(1, -1), features
            
        except Exception as e:
            print(f"Error preprocessing packet: {e}")
            return None, None
        
    def detect_anomaly(self, packet):
        try:
            features, feature_dict = self.preprocess_packet(packet)
            if features is None:
                return False, 0.0, None, None
                
            # For Isolation Forest, we don't need scaling since it's based on tree structure
            score = self.model.score_samples(features)[0]
            
            # Convert score to probability-like value between 0 and 1
            probability = 1 / (1 + np.exp(-score))  # Sigmoid transformation
            is_anomaly = probability < self.threshold
            
            # Determine attack type based on features
            attack_type = self._classify_attack_type(feature_dict) if is_anomaly else None
            
            return is_anomaly, probability, attack_type, feature_dict
            
        except Exception as e:
            print(f"Error in anomaly detection: {e}")
            return False, 0.0, None, None
            
    def _classify_attack_type(self, features):
        """Classify the type of attack based on packet features"""
        if features['tcp_syn'] and not features['tcp_ack']:
            return 'PROBE'  # Potential port scan
        elif features['tcp_syn'] and features['tcp_rst']:
            return 'DOS'    # Potential SYN flood
        elif features['tcp_fin'] and features['tcp_rst']:
            return 'DOS'    # Potential FIN/RST flood
        elif features['tcp_psh'] and features['tcp_ack']:
            if features['tcp_dport'] in [80, 443, 8080]:
                return 'INJECTION'  # Potential web attack
        elif features['tcp_dport'] in [22, 23, 3389]:
            return 'R2L'    # Potential remote access attempt
            
        return 'UNKNOWN'

# Initialize anomaly detector
anomaly_detector = AnomalyDetector()

@login_required
def dashboard(request):
    """Dashboard view for real-time network monitoring"""
    recent_traffic = NetworkTraffic.objects.all()[:100]
    recent_threats = DetectedThreat.objects.filter(is_resolved=False)[:10]
    context = {
        'recent_traffic': recent_traffic,
        'recent_threats': recent_threats,
    }
    return render(request, 'detector/dashboard.html', context)

@login_required
def anomaly_detection(request):
    """Anomaly detection view"""
    threats = DetectedThreat.objects.all().order_by('-timestamp')[:50]
    context = {
        'threats': threats,
    }
    return render(request, 'detector/anomaly_detection.html', context)

@login_required
def security_tools(request):
    """Security tools view"""
    recent_scans = SecurityScan.objects.filter(initiated_by=request.user)[:10]
    context = {
        'recent_scans': recent_scans,
    }
    return render(request, 'detector/security_tools.html', context)

def get_suricata_config():
    """Get Suricata configuration based on OS"""
    system = platform.system()
    config = {}
    
    if system == "Windows":
        # Check common Windows installation paths
        possible_paths = [
            r"C:\Program Files\Suricata\suricata.exe",
            r"C:\Program Files (x86)\Suricata\suricata.exe",
            r"C:\Suricata\suricata.exe"
        ]
        
        # Find first existing Suricata installation
        suricata_path = None
        for path in possible_paths:
            if os.path.exists(path):
                suricata_path = path
                base_path = os.path.dirname(path)
                break
                
        if not suricata_path:
            # Default to Program Files if not found
            base_path = r"C:\Program Files\Suricata"
            suricata_path = os.path.join(base_path, "suricata.exe")
            
        config.update({
            'suricata_path': suricata_path,
            'config_path': os.path.join(base_path, "suricata.yaml"),
            'rules_path': os.path.join(base_path, "rules"),
            'log_path': os.path.join(base_path, "log"),
            'is_windows': True
        })
    else:  # Linux
        config.update({
            'suricata_path': "/usr/bin/suricata",
            'config_path': "/etc/suricata/suricata.yaml",
            'rules_path': "/etc/suricata/rules",
            'log_path': "/var/log/suricata",
            'is_windows': False
        })
    
    return config

def validate_suricata_installation():
    """Validate Suricata installation and create necessary directories"""
    config = get_suricata_config()
    
    # Check if Suricata is installed
    if not os.path.exists(config['suricata_path']):
        # Try to create base directory structure on Windows
        if config.get('is_windows'):
            base_path = os.path.dirname(config['suricata_path'])
            try:
                os.makedirs(base_path, exist_ok=True)
            except Exception as e:
                print(f"Error creating Suricata directory: {e}")
        raise FileNotFoundError(f"Suricata not found at {config['suricata_path']}")
    
    # Create directories if they don't exist
    for path in [config['rules_path'], config['log_path']]:
        try:
            os.makedirs(path, exist_ok=True)
        except Exception as e:
            print(f"Error creating directory {path}: {e}")
    
    # Create default config if it doesn't exist
    if not os.path.exists(config['config_path']):
        try:
            default_config = """
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"

default-rule-path: {rules_path}
rule-files:
  - emerging-threats.rules
  - custom.rules

af-packet:
  - interface: any
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: {log_path}/eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - ssh
        - flow
""".format(
    rules_path=config['rules_path'].replace('\\', '/'),
    log_path=config['log_path'].replace('\\', '/')
)
            os.makedirs(os.path.dirname(config['config_path']), exist_ok=True)
            with open(config['config_path'], 'w') as f:
                f.write(default_config)
        except Exception as e:
            print(f"Error creating default config: {e}")
            
    return config

@login_required
@require_http_methods(["POST"])
def start_suricata(request):
    """Start Suricata IDS with proper configuration"""
    try:
        data = json.loads(request.body)
        config = validate_suricata_installation()
        
        # Kill any existing Suricata process
        global suricata_process
        if suricata_process:
            try:
                suricata_process.terminate()
                suricata_process.wait(timeout=5)
            except Exception as e:
                print(f"Error terminating existing Suricata process: {e}")
            suricata_process = None
        
        # Build command based on OS
        cmd = [
            config['suricata_path'],
            "-c", config['config_path'],
            "--af-packet",
            "-v"  # Verbose output
        ]
        
        # Add interface if specified
        interface = data.get('interface')
        if interface:
            cmd.extend(["-i", interface])
        
        # Add rule files based on user selection
        if data.get('emerging_threats', True):
            et_rules = os.path.join(config['rules_path'], "emerging-threats.rules")
            if os.path.exists(et_rules):
                cmd.extend(["-S", et_rules])
                
        if data.get('custom_rules', True):
            custom_rules = os.path.join(config['rules_path'], "custom.rules")
            if os.path.exists(custom_rules):
                cmd.extend(["-S", custom_rules])
        
        # Ensure log directory exists
        os.makedirs(config['log_path'], exist_ok=True)
        
        # Start Suricata process
        print(f"Starting Suricata with command: {' '.join(cmd)}")
        suricata_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if config.get('is_windows') else 0
        )
        
        # Start log monitoring thread
        threading.Thread(
            target=monitor_suricata_logs,
            args=(config['log_path'],),
            daemon=True
        ).start()
        
        # Wait briefly and check if process is still running
        time.sleep(2)
        if suricata_process.poll() is not None:
            # Process terminated early
            stdout, stderr = suricata_process.communicate()
            error_msg = stderr or stdout
            raise Exception(f"Suricata failed to start: {error_msg}")
        
        return JsonResponse({
            "status": "success",
            "message": "Suricata started successfully",
            "details": {
                "pid": suricata_process.pid,
                "command": " ".join(cmd),
                "config": config
            }
        })
        
    except Exception as e:
        if suricata_process:
            try:
                suricata_process.terminate()
            except:
                pass
            suricata_process = None
            
        return JsonResponse({
            "status": "error",
            "message": str(e),
            "details": {
                "config": config if 'config' in locals() else None,
                "error": str(e)
            }
        }, status=500)

def monitor_suricata_logs(log_path):
    """Monitor Suricata log files for alerts"""
    eve_log = os.path.join(log_path, "eve.json")
    
    while suricata_process and suricata_process.poll() is None:
        try:
            if os.path.exists(eve_log):
                with open(eve_log, 'r') as f:
                    f.seek(0, 2)  # Go to end of file
                    while suricata_process and suricata_process.poll() is None:
                        line = f.readline()
                        if line:
                            try:
                                alert = json.loads(line)
                                if alert.get('event_type') == 'alert':
                                    process_suricata_alert(alert)
                            except json.JSONDecodeError:
                                continue
                        else:
                            time.sleep(0.1)
            else:
                time.sleep(1)  # Wait for log file to be created
        except Exception as e:
            print(f"Error monitoring logs: {e}")
            time.sleep(1)
    
    print("Suricata process terminated, stopping log monitor")

def process_suricata_alert(alert):
    """Process Suricata alerts and send through WebSocket"""
    try:
        # Extract relevant information
        alert_data = {
            "timestamp": alert.get('timestamp'),
            "source_ip": alert.get('src_ip'),
            "destination_ip": alert.get('dest_ip'),
            "source_port": alert.get('src_port'),
            "destination_port": alert.get('dest_port'),
            "protocol": alert.get('proto'),
            "alert_type": "Suricata Alert",
            "signature_id": alert.get('alert', {}).get('signature_id'),
            "signature": alert.get('alert', {}).get('signature'),
            "category": alert.get('alert', {}).get('category'),
            "severity": alert.get('alert', {}).get('severity'),
            "risk_level": "HIGH" if alert.get('alert', {}).get('severity') >= 2 else "MEDIUM"
        }
        
        # Send alert through WebSocket
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            "anomaly_detection",
            {
                "type": "anomaly_detected",
                "alert": alert_data
            }
        )
        
        # Save to database
        DetectedThreat.objects.create(
            source_ip=alert_data['source_ip'],
            destination_ip=alert_data['destination_ip'],
            alert_type=alert_data['alert_type'],
            signature=alert_data['signature'],
            risk_level=alert_data['risk_level']
        )
        
    except Exception as e:
        print(f"Error processing Suricata alert: {e}")

def get_packet_protocol(packet):
    if TCP in packet:
        return 'TCP'
    elif UDP in packet:
        return 'UDP'
    elif ARP in packet:
        return 'ARP'
    elif ICMP in packet:
        return 'ICMP'
    else:
        return 'Other'

def get_packet_source(packet):
    if IP in packet:
        source = packet[IP].src
        if TCP in packet:
            source += f":{packet[TCP].sport}"
        elif UDP in packet:
            source += f":{packet[UDP].sport}"
        return source
    elif ARP in packet:
        return packet[ARP].psrc
    return "Unknown"

def get_packet_destination(packet):
    if IP in packet:
        dest = packet[IP].dst
        if TCP in packet:
            dest += f":{packet[TCP].dport}"
        elif UDP in packet:
            dest += f":{packet[UDP].dport}"
        return dest
    elif ARP in packet:
        return packet[ARP].pdst
    return "Unknown"

def packet_callback(packet):
    if not is_detecting:
        return
        
    try:
        # Process packet for anomaly detection
        is_anomaly, probability, attack_type, features = anomaly_detector.detect_anomaly(packet)
        
        # Prepare packet data
        packet_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'protocol': get_packet_protocol(packet),
            'source': get_packet_source(packet),
            'destination': get_packet_destination(packet),
            'length': len(packet),
            'is_anomaly': is_anomaly,
            'probability': float(probability) if probability else 0.0,
            'attack_type': attack_type if attack_type else 'Normal',
            'features': features
        }
        
        # Send to network traffic channel
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            'network_traffic',
            {
                'type': 'traffic_update',
                'message': packet_data
            }
        )
        
        # If anomaly detected, send to anomaly detection channel
        if is_anomaly:
            async_to_sync(channel_layer.group_send)(
                'anomaly_detection',
                {
                    'type': 'anomaly_alert',
                    'message': {
                        'timestamp': packet_data['timestamp'],
                        'attack_type': attack_type,
                        'probability': probability,
                        'source': packet_data['source'],
                        'destination': packet_data['destination']
                    }
                }
            )
            
    except Exception as e:
        print(f"Error in packet callback: {e}")

def detection_loop():
    sniff(prn=packet_callback, store=False, stop_filter=lambda x: not is_detecting)

@login_required
def anomaly_detection_view(request):
    return render(request, 'detector/anomaly_detection.html')

@login_required
@require_http_methods(["POST"])
def load_model(request):
    try:
        result = anomaly_detector.load_model()
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def start_detection(request):
    global is_detecting, detection_thread
    
    try:
        data = json.loads(request.body)
        threshold = data.get('threshold', 0.75)
        anomaly_detector.threshold = threshold
        
        # Load the model before starting detection
        model_status = anomaly_detector.load_model()
        if not model_status["status"]:
            return JsonResponse({
                "status": "error",
                "message": f"Failed to load model: {model_status['error']}"
            }, status=500)
            
        if not is_detecting:
            is_detecting = True
            detection_thread = threading.Thread(target=detection_loop)
            detection_thread.daemon = True
            detection_thread.start()
            
        return JsonResponse({
            "status": "success",
            "message": "Detection started successfully",
            "model_info": {
                "type": model_status["model_type"],
                "features": len(anomaly_detector.feature_names),
                "attack_types": list(anomaly_detector.attack_types.keys())
            }
        })
    except Exception as e:
        return JsonResponse({
            "status": "error",
            "message": f"Error starting detection: {str(e)}"
        }, status=500)

@login_required
@require_http_methods(["POST"])
def stop_detection(request):
    global is_detecting, detection_thread
    
    try:
        is_detecting = False
        if detection_thread:
            detection_thread.join(timeout=1.0)
            
        return JsonResponse({"status": "success"})
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def stop_suricata(request):
    """Stop Suricata IDS"""
    try:
        global suricata_process
        if suricata_process:
            suricata_process.terminate()
            suricata_process = None
            
        return JsonResponse({"status": "success"})
        
    except Exception as e:
        return JsonResponse({
            "status": "error",
            "message": str(e)
        }, status=500)

@login_required
@require_http_methods(["GET"])
def export_results(request):
    try:
        # Implementation for exporting results
        pass
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)

@require_http_methods(["POST"])
def run_security_scan(request):
    """API endpoint to run security scans"""
    scan_type = request.POST.get('scan_type')
    target = request.POST.get('target')
    
    scan = SecurityScan.objects.create(
        scan_type=scan_type,
        target=target,
        initiated_by=request.user
    )
    
    # Implement scan logic here
    # This is a placeholder for actual scanning functionality
    
    return JsonResponse({
        "status": "success",
        "scan_id": scan.id
    })

@require_http_methods(["POST"])
def upload_pcap(request):
    """API endpoint to upload and analyze PCAP files"""
    if 'pcap_file' not in request.FILES:
        return JsonResponse({"status": "error", "message": "No file uploaded"})
    
    pcap_file = request.FILES['pcap_file']
    scan = SecurityScan.objects.create(
        scan_type='PCAP',
        target=pcap_file.name,
        initiated_by=request.user,
        pcap_file=pcap_file
    )
    
    # Implement PCAP analysis logic here
    # This is a placeholder for actual PCAP analysis
    
    return JsonResponse({
        "status": "success",
        "scan_id": scan.id
    })

@login_required
def download_log(request):
    """Download detection or Suricata log file"""
    try:
        log_type = request.GET.get('type', 'detection')  # 'detection' or 'suricata'
        config = get_suricata_config()
        
        if log_type == 'suricata':
            log_path = os.path.join(config['log_path'], 'suricata.log')
            filename = 'suricata.log'
        else:
            log_path = os.path.join(config['log_path'], 'detection.log')
            filename = 'detection.log'
            
        if not os.path.exists(log_path):
            return JsonResponse({
                'status': 'error',
                'message': f'Log file not found: {log_path}'
            }, status=404)
            
        with open(log_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
            
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': f'Error downloading log: {str(e)}'
        }, status=500)

@login_required
@require_http_methods(["POST"])
def start_capture(request):
    """Start packet capture"""
    global is_detecting, detection_thread
    
    try:
        if not is_detecting:
            is_detecting = True
            detection_thread = threading.Thread(target=detection_loop)
            detection_thread.daemon = True
            detection_thread.start()
            
        return JsonResponse({
            "status": "success",
            "message": "Packet capture started successfully"
        })
    except Exception as e:
        return JsonResponse({
            "status": "error",
            "message": str(e)
        }, status=500)

@login_required
@require_http_methods(["POST"])
def stop_capture(request):
    """Stop packet capture"""
    global is_detecting, detection_thread
    
    try:
        is_detecting = False
        if detection_thread:
            detection_thread.join(timeout=1.0)
            detection_thread = None
            
        return JsonResponse({
            "status": "success",
            "message": "Packet capture stopped successfully"
        })
    except Exception as e:
        return JsonResponse({
            "status": "error",
            "message": str(e)
        }, status=500)

@login_required
@require_http_methods(["POST"])
def test_suricata(request):
    """Test Suricata configuration and validate rules"""
    try:
        # Get default config based on OS
        config = get_suricata_config()
        
        # Try to parse request body, but don't fail if empty
        try:
            if request.body:
                data = json.loads(request.body)
                if data.get('suricata_path'):
                    config['suricata_path'] = data['suricata_path']
                if data.get('rules_path'):
                    config['rules_path'] = data['rules_path']
        except json.JSONDecodeError:
            # Continue with default config if request body is invalid
            pass
            
        # Create necessary directories
        try:
            os.makedirs(config['rules_path'], exist_ok=True)
            os.makedirs(config['log_path'], exist_ok=True)
        except Exception as e:
            return JsonResponse({
                "status": "error",
                "message": f"Failed to create directories: {str(e)}",
                "details": {
                    "config": config,
                    "error": str(e)
                }
            }, status=500)
        
        # Create default rules if they don't exist
        rule_files = {
            'emerging-threats.rules': """
# Emerging Threats Rules
alert tcp any any -> $HOME_NET any (msg:"ET SCAN Potential SSH Scan"; flow:to_server; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:2003068; rev:4;)
alert tcp any any -> $HOME_NET 3389 (msg:"ET SCAN RDP Scan"; flow:to_server; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:2003069; rev:4;)
""",
            'custom.rules': """
# Custom Rules
alert tcp any any -> $HOME_NET any (msg:"CUSTOM SCAN High Port TCP Scan"; flow:to_server; flags:S,12; threshold: type both, track by_src, count 10, seconds 60; classtype:attempted-recon; sid:10000001; rev:1;)
alert icmp any any -> $HOME_NET any (msg:"CUSTOM PING Large ICMP Packet"; itype:8; dsize:>800; classtype:bad-unknown; sid:10000002; rev:1;)
"""
        }
        
        rules_status = {}
        for rule_file, content in rule_files.items():
            rule_path = os.path.join(config['rules_path'], rule_file)
            try:
                if not os.path.exists(rule_path):
                    with open(rule_path, 'w') as f:
                        f.write(content.strip())
                rules_status[rule_file] = {
                    'status': 'initialized',
                    'path': rule_path,
                    'rule_count': sum(1 for line in open(rule_path) if line.strip() and not line.startswith('#'))
                }
            except Exception as e:
                rules_status[rule_file] = {
                    'status': 'error',
                    'path': rule_path,
                    'error': str(e)
                }
                    
        # Test Suricata version
        try:
            version_result = subprocess.run(
                [config['suricata_path'], "--build-info"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if version_result.returncode != 0:
                return JsonResponse({
                    "status": "error",
                    "message": "Suricata not found or invalid installation",
                    "details": {
                        "windows_default": r"C:\Program Files\Suricata\suricata.exe",
                        "linux_default": "/usr/bin/suricata",
                        "current_path": config['suricata_path'],
                        "error": version_result.stderr
                    }
                }, status=400)
        except FileNotFoundError:
            return JsonResponse({
                "status": "error",
                "message": "Suricata executable not found",
                "details": {
                    "windows_default": r"C:\Program Files\Suricata\suricata.exe",
                    "linux_default": "/usr/bin/suricata",
                    "current_path": config['suricata_path']
                }
            }, status=400)
        except Exception as e:
            return JsonResponse({
                "status": "error",
                "message": f"Error running Suricata: {str(e)}",
                "details": {
                    "config": config,
                    "error": str(e)
                }
            }, status=500)
            
        # Test configuration
        test_cmd = [config['suricata_path'], "-T", "-c", config['config_path']]
        try:
            test_result = subprocess.run(
                test_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            if test_result.returncode != 0:
                return JsonResponse({
                    "status": "error",
                    "message": "Configuration test failed",
                    "details": {
                        "command": " ".join(test_cmd),
                        "error": test_result.stderr,
                        "config": config
                    }
                }, status=400)
        except Exception as e:
            return JsonResponse({
                "status": "error",
                "message": f"Error testing configuration: {str(e)}",
                "details": {
                    "command": " ".join(test_cmd),
                    "config": config,
                    "error": str(e)
                }
            }, status=500)
            
        return JsonResponse({
            "status": "success",
            "message": "Suricata configuration test passed",
            "details": {
                "version": version_result.stdout,
                "config": config,
                "rules_status": rules_status
            }
        })
            
    except Exception as e:
        return JsonResponse({
            "status": "error",
            "message": f"Unexpected error: {str(e)}",
            "details": {
                "config": config if 'config' in locals() else None,
                "error": str(e)
            }
        }, status=500)

@login_required
@require_http_methods(["POST"])
def upload_model(request):
    """Handle model file upload"""
    try:
        if 'model_file' not in request.FILES:
            return JsonResponse({
                "status": "error",
                "message": "Model file is required"
            }, status=400)

        model_file = request.FILES['model_file']

        # Validate file extension
        if not model_file.name.endswith('.pkl'):
            return JsonResponse({
                "status": "error",
                "message": "File must be in .pkl format"
            }, status=400)

        # Save file
        fs = FileSystemStorage(location=os.path.join(settings.BASE_DIR, 'ml_models'))
        fs.save('model.pkl', model_file)

        # Validate model
        try:
            model = joblib.load(os.path.join(settings.BASE_DIR, 'ml_models', 'model.pkl'))
            
            # Validate model type and required methods
            if not isinstance(model, IsolationForest):
                raise ValueError("Invalid model type: must be IsolationForest")

            if not hasattr(model, 'fit') or not hasattr(model, 'predict'):
                raise ValueError("Invalid model: missing required methods")

            return JsonResponse({
                "status": "success",
                "message": "Model file uploaded and validated successfully"
            })
        except Exception as e:
            # Clean up file if validation fails
            fs.delete('model.pkl')
            raise ValueError(f"Model validation failed: {str(e)}")

    except Exception as e:
        return JsonResponse({
            "status": "error",
            "message": str(e)
        }, status=500)

@login_required
@require_http_methods(["POST"])
def analyze_model(request):
    """Analyze model features and characteristics"""
    try:
        model_path = os.path.join(settings.BASE_DIR, 'ml_models', 'model.pkl')
        if not os.path.exists(model_path):
            return JsonResponse({
                "status": "error",
                "message": "Model file not found"
            }, status=404)

        model = joblib.load(model_path)
        
        # Validate model type
        if not isinstance(model, IsolationForest):
            raise ValueError("Invalid model type: must be IsolationForest")

        # Get feature names from global anomaly_detector instance
        feature_names = anomaly_detector.feature_names

        # Calculate feature importance scores
        features = []
        # Create a sample dataset with zeros
        X_sample = np.zeros((100, len(feature_names)))
        base_score = model.score_samples(X_sample).mean()

        # Calculate importance for each feature
        for i, name in enumerate(feature_names):
            # Create a perturbation in the feature
            X_perturbed = X_sample.copy()
            X_perturbed[:, i] = 1
            # Calculate importance as the change in anomaly score
            perturbed_score = model.score_samples(X_perturbed).mean()
            importance = abs(base_score - perturbed_score)
            
            features.append({
                "name": name,
                "importance": float(importance)
            })

        # Normalize importance scores
        max_importance = max(f["importance"] for f in features)
        if max_importance > 0:
            for feature in features:
                feature["importance"] = feature["importance"] / max_importance

        # Sort features by importance
        features.sort(key=lambda x: x["importance"], reverse=True)

        return JsonResponse({
            "status": "success",
            "features": features,
            "model_type": type(model).__name__,
            "parameters": model.get_params()
        })

    except Exception as e:
        return JsonResponse({
            "status": "error",
            "message": str(e)
        }, status=500)

@login_required
@require_http_methods(["GET"])
def browse_directories(request):
    """Browse system directories for Suricata installation"""
    try:
        path = request.GET.get('path', None)
        is_windows = platform.system() == "Windows"
        
        if not path:
            # Return root directories
            if is_windows:
                try:
                    drives = win32api.GetLogicalDriveStrings()
                    drives = [d for d in drives.split('\000') if d]  # Filter empty strings
                    print(f"Found drives: {drives}")  # Debug log
                    dirs = [{'name': d.rstrip('\\'), 'path': d, 'type': 'drive'} for d in drives]
                except Exception as e:
                    print(f"Error getting drives: {e}")
                    # Fallback to C: drive
                    dirs = [{'name': 'C:', 'path': 'C:\\', 'type': 'drive'}]
            else:
                dirs = [{'name': '/', 'path': '/', 'type': 'dir'}]
            
            return JsonResponse({
                "status": "success",
                "current_path": '',
                "is_windows": is_windows,
                "items": dirs
            })
        
        try:
            # Normalize path for Windows
            if is_windows:
                path = path.replace('/', '\\')
                if path.endswith('\\'):
                    path = path[:-1]
            
            print(f"Scanning directory: {path}")  # Debug log
            
            # List contents of specified directory
            dirs = []
            files = []
            
            with os.scandir(path) as entries:
                for entry in entries:
                    try:
                        item = {
                            'name': entry.name,
                            'path': entry.path,
                            'type': 'dir' if entry.is_dir() else 'file'
                        }
                        
                        if entry.is_dir():
                            dirs.append(item)
                        elif entry.is_file():
                            # Filter for relevant files
                            if entry.name.lower() in ['suricata.exe', 'suricata', 'suricata.yaml'] or \
                               entry.name.lower().endswith('.rules'):
                                files.append(item)
                    except PermissionError:
                        print(f"Permission denied for: {entry.path}")  # Debug log
                        continue
                    except Exception as e:
                        print(f"Error processing entry {entry.path}: {e}")  # Debug log
                        continue
            
            # Sort directories and files
            dirs.sort(key=lambda x: x['name'].lower())
            files.sort(key=lambda x: x['name'].lower())
            
            # Combine sorted lists
            items = dirs + files
            
            return JsonResponse({
                "status": "success",
                "current_path": path,
                "is_windows": is_windows,
                "items": items
            })
            
        except PermissionError as e:
            print(f"Permission error accessing {path}: {e}")  # Debug log
            return JsonResponse({
                "status": "error",
                "message": f"Permission denied accessing {path}"
            }, status=403)
        except FileNotFoundError as e:
            print(f"Directory not found {path}: {e}")  # Debug log
            return JsonResponse({
                "status": "error",
                "message": f"Directory not found: {path}"
            }, status=404)
        except Exception as e:
            print(f"Error accessing directory {path}: {e}")  # Debug log
            return JsonResponse({
                "status": "error",
                "message": f"Error accessing directory: {str(e)}"
            }, status=500)
            
    except Exception as e:
        print(f"Unexpected error in browse_directories: {e}")  # Debug log
        return JsonResponse({
            "status": "error",
            "message": f"Unexpected error: {str(e)}"
        }, status=500)
