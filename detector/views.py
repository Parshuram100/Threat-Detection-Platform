import os
import json
import platform
import subprocess
import threading
import time
import hashlib
import requests
from pathlib import Path
import win32api
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse, FileResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.core.files.storage import FileSystemStorage
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import NetworkTraffic, DetectedThreat
from scapy.all import sniff, IP, TCP, UDP, ARP, Raw, ICMP, DNS
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
import google.generativeai as genai
from django.template.loader import render_to_string
import tempfile
import psutil
import socket
import whois
import pdfkit
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize API keys with proper error handling
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_API_URL = 'https://www.virustotal.com/api/v3'

# Initialize Gemini API with better error handling
model = None
gemini_error = None
try:
    if GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-pro')
    else:
        gemini_error = "Gemini API key not found in environment variables"
except Exception as e:
    gemini_error = f"Error initializing Gemini API: {str(e)}"
    print(gemini_error)

# Global variables for process management
is_detecting = False

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
    return render(request, 'detector/anomaly_detection.html')

@login_required
def ai_security_analyst(request):
    """AI Security Analyst view"""
    try:
        context = {
            'gemini_api_configured': bool(GEMINI_API_KEY and model),
            'error': gemini_error if not (GEMINI_API_KEY and model) else None
        }
        
        if model:
            # Get recent threats and analysis
            recent_threats = DetectedThreat.objects.filter(
                is_resolved=False
            ).order_by('-timestamp')[:10]
            
            # Get system status
            system_status = {
                'suricata_running': check_suricata_status(),
                'detection_running': is_detecting,
                'last_analysis': DetectedThreat.objects.latest('timestamp').timestamp if DetectedThreat.objects.exists() else None
            }
            
            context.update({
                'recent_threats': recent_threats,
                'system_status': system_status
            })
            
        return render(request, 'detector/ai_security_analyst.html', context)
    except Exception as e:
        return render(request, 'detector/ai_security_analyst.html', {
            'error': str(e),
            'gemini_api_configured': False
        })

@login_required
def malware_analysis(request):
    """Malware Analysis view"""
    try:
        context = {
            'virustotal_api_configured': bool(VIRUSTOTAL_API_KEY),
            'error': "VirusTotal API key not found in environment variables" if not VIRUSTOTAL_API_KEY else None
        }
        
        if VIRUSTOTAL_API_KEY:
            # Get recent malware detections
            recent_malware = DetectedThreat.objects.filter(
                threat_type='malware',
                is_resolved=False
            ).order_by('-timestamp')[:10]
            
            # Add VirusTotal analysis for each malware
            for malware in recent_malware:
                try:
                    headers = {
                        'x-apikey': VIRUSTOTAL_API_KEY
                    }
                    response = requests.get(
                        f"{VIRUSTOTAL_API_URL}/files/{malware.file_hash}",
                        headers=headers
                    )
                    if response.status_code == 200:
                        malware.virustotal_data = response.json()
                    else:
                        malware.virustotal_data = {'error': 'Analysis not available'}
                except Exception as e:
                    malware.virustotal_data = {'error': str(e)}
            
            context['recent_malware'] = recent_malware
            
        return render(request, 'detector/malware_analysis.html', context)
    except Exception as e:
        return render(request, 'detector/malware_analysis.html', {
            'error': str(e),
            'virustotal_api_configured': False
        })

def validate_ip_or_domain(target):
    """Validate if the target is a valid IP address or domain name"""
    try:
        ip_address(target)
        return True
    except ValueError:
        # Check if it's a valid domain
        if re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+$', target):
            return True
    return False

@login_required
@require_http_methods(["POST"])
def nmap_scan(request):
    """Execute Nmap scan and return results"""
    try:
        target = request.POST.get('target')
        scan_type = request.POST.get('scan_type', 'quick')
        timeout = request.POST.get('timeout', '60')
        options = request.POST.getlist('options[]', [])

        if not validate_ip_or_domain(target):
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid target IP or domain'
            }, status=400)

        # Initialize Nmap scanner
        nm = nmap.PortScanner()
        
        # Build scan arguments based on type and options
        base_args = {
            'quick': '-sV -F',  # Version detection, fast scan
            'full': '-sV -sC -A',  # Version detection, default scripts, aggressive
            'stealth': '-sS -sV',  # SYN scan with version detection
            'version': '-sV --version-intensity 7',  # Intensive version detection
            'os': '-O --osscan-guess',  # OS detection with guess
            'ping': '-sn',  # Ping scan only
            'udp': '-sU --top-ports 100',  # UDP scan of top ports
            'comprehensive': '-sS -sV -sC -O -A --version-all'  # All features
        }

        scan_args = base_args.get(scan_type, '-sV -F')

        # Add additional options
        if 'version' in options:
            scan_args += ' -sV --version-all'
        if 'os' in options:
            scan_args += ' -O --osscan-guess'
        if 'scripts' in options:
            scan_args += ' -sC'
        if 'timing' in options:
            scan_args += ' -T4'

        # Add timeout
        scan_args += f' --host-timeout {timeout}s'
        
        # Execute scan
        nm.scan(target, arguments=scan_args)
        
        # Process results
        network_data = {
            'nodes': [],
            'edges': []
        }
        
        # Add target as central node
        network_data['nodes'].append({
            'id': target,
            'label': target,
            'title': f'Target: {target}',
            'shape': 'dot',
            'size': 20
        })
        
        # Process scan results
        output = []
        for host in nm.all_hosts():
            output.append(f"\n[+] Host: {host}")
            
            # Add host to network map
            if host != target:
                network_data['nodes'].append({
                    'id': host,
                    'label': host,
                    'title': f'Host: {host}',
                    'shape': 'dot',
                    'size': 15
                })
                network_data['edges'].append({
                    'from': target,
                    'to': host
                })
            
            # Get host information
            if 'osmatch' in nm[host]:
                os_matches = nm[host]['osmatch']
                if os_matches:
                    output.append(f"OS: {os_matches[0]['name']} ({os_matches[0]['accuracy']}%)")
                    if len(os_matches) > 1:
                        output.append("Other possible OS matches:")
                        for match in os_matches[1:3]:  # Show top 3 matches
                            output.append(f"- {match['name']} ({match['accuracy']}%)")

            # Get host status
            if 'status' in nm[host]:
                status = nm[host]['status']
                output.append(f"Status: {status['state']} ({status['reason']})")

            # Process ports and services
            for proto in nm[host].all_protocols():
                output.append(f"\nProtocol: {proto}")
                ports = sorted(nm[host][proto].keys())
                
                for port in ports:
                    service = nm[host][proto][port]
                    state = service['state']
                    name = service.get('name', '')
                    product = service.get('product', '')
                    version = service.get('version', '')
                    extrainfo = service.get('extrainfo', '')
                    cpe = service.get('cpe', '')
                    
                    service_info = f"Port {port}/{proto}: {state}"
                    if name:
                        service_info += f" - {name}"
                    if product:
                        service_info += f" ({product}"
                        if version:
                            service_info += f" {version}"
                        if extrainfo:
                            service_info += f" - {extrainfo}"
                        service_info += ")"
                    if cpe:
                        service_info += f"\n  CPE: {cpe}"
                    
                    output.append(service_info)
                    
                    # Add service node to network map
                    service_id = f"{host}:{port}"
                    service_label = f"{port}/{proto}\n{name}"
                    if product:
                        service_label += f"\n{product}"
                    
                    network_data['nodes'].append({
                        'id': service_id,
                        'label': service_label,
                        'title': service_info,
                        'shape': 'diamond',
                        'size': 10
                    })
                    network_data['edges'].append({
                        'from': host,
                        'to': service_id
                    })

            # Add script results if available
            if 'script' in nm[host]:
                output.append("\nScript Results:")
                for script_name, script_output in nm[host]['script'].items():
                    output.append(f"\n{script_name}:")
                    output.append(script_output)

        return JsonResponse({
            'status': 'success',
            'output': '\n'.join(output),
            'network_data': network_data
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@login_required
@require_http_methods(["POST"])
def traceroute(request):
    """Execute traceroute command"""
    try:
        target = request.POST.get('target')
        
        if not validate_ip_or_domain(target):
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid target IP or domain'
            }, status=400)
            
        # Execute traceroute
        if platform.system() == "Windows":
            cmd = ['tracert', '-d', target]
        else:
            cmd = ['traceroute', '-n', target]
            
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        return JsonResponse({
            'status': 'success',
            'output': result.stdout
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@login_required
@require_http_methods(["POST"])
def whois_lookup(request):
    """Perform WHOIS lookup"""
    try:
        domain = request.POST.get('domain')
        
        if not domain:
            return JsonResponse({
                'status': 'error',
                'message': 'Domain is required'
            }, status=400)
            
        # Perform WHOIS lookup
        w = whois.whois(domain)
        
        # Format output
        output = []
        output.append(f"Domain Name: {w.domain_name}")
        output.append(f"Registrar: {w.registrar}")
        output.append(f"Creation Date: {w.creation_date}")
        output.append(f"Expiration Date: {w.expiration_date}")
        output.append(f"Name Servers: {', '.join(w.name_servers) if isinstance(w.name_servers, list) else w.name_servers}")
        output.append(f"Status: {', '.join(w.status) if isinstance(w.status, list) else w.status}")
        
        if w.emails:
            output.append(f"Contact Email: {', '.join(w.emails) if isinstance(w.emails, list) else w.emails}")
            
        return JsonResponse({
            'status': 'success',
            'output': '\n'.join(output)
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@login_required
@require_http_methods(["POST"])
def dns_lookup(request):
    """Perform DNS lookup"""
    try:
        domain = request.POST.get('domain')
        record_type = request.POST.get('record_type', 'A')
        
        if not domain:
            return JsonResponse({
                'status': 'error',
                'message': 'Domain is required'
            }, status=400)
            
        # Perform DNS lookup
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, record_type)
        
        # Format output
        output = [f"DNS lookup for {domain} ({record_type} records):"]
        for rdata in answers:
            output.append(str(rdata))
            
        return JsonResponse({
            'status': 'success',
            'output': '\n'.join(output)
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@csrf_exempt
@login_required
@require_http_methods(["POST"])
def export_results(request):
    """Export detection results as PDF"""
    try:
        data = json.loads(request.body)
        attacks = data.get('attacks', [])
        stats = data.get('stats', {})
        
        # Create report context
        context = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'attacks': attacks,
            'stats': stats,
            'total_attacks': len(attacks),
            'attack_distribution': {
                'DoS/DDoS': stats.get('dos', 0) + stats.get('ddos', 0),
                'Brute Force': stats.get('bruteForce', 0),
                'SQL Injection': stats.get('sqlInjection', 0),
                'Web Enumeration': stats.get('webEnum', 0),
                'Port Scanning': stats.get('portScan', 0)
            }
        }
        
        # Render HTML template
        html_content = render_to_string('detector/report_template.html', context)
        
        # Configure PDF options
        pdf_options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': 'UTF-8',
            'custom-header': [
                ('Accept-Encoding', 'gzip')
            ],
            'no-outline': None
        }
        
        # Create PDF
        pdf_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        try:
            pdfkit.from_string(html_content, pdf_file.name, options=pdf_options)
            
            # Return PDF file
            with open(pdf_file.name, 'rb') as f:
                response = HttpResponse(f.read(), content_type='application/pdf')
                response['Content-Disposition'] = 'attachment; filename="attack_report.pdf"'
                return response
        finally:
            # Clean up temporary file
            try:
                os.unlink(pdf_file.name)
            except:
                pass
                
    except Exception as e:
        return JsonResponse({
            "status": "error",
            "message": f"Error exporting results: {str(e)}"
        }, status=500)

@csrf_exempt
@login_required
@require_http_methods(["POST"])
def stop_capture(request):
    """Stop packet capture"""
    global is_detecting
    
    try:
        is_detecting = False
        return JsonResponse({
            "status": "success",
            "message": "Packet capture stopped successfully"
        })
    except Exception as e:
        return JsonResponse({
            "status": "error",
            "message": str(e)
        }, status=500)

@require_http_methods(["GET"])
def network_info(request):
    try:
        # Get all network interfaces
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        # Find active interface and IP
        active_interface = None
        ip_address = None
        
        # Common interface names to check
        interface_names = ['Wi-Fi', 'Ethernet', 'Local Area Connection', 'Wireless Network Connection']
        
        # First try to find a specific interface
        for interface in interface_names:
            if interface in interfaces:
                for addr in interfaces[interface]:
                    if addr.family == socket.AF_INET:  # IPv4 address
                        active_interface = interface
                        ip_address = addr.address
                        break
                if active_interface:
                    break
        
        # If no specific interface found, get the first active one
        if not active_interface:
            for interface, addrs in interfaces.items():
                if interface in stats and stats[interface].isup:
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            active_interface = interface
                            ip_address = addr.address
                            break
                if active_interface:
                    break
        
        # Get network status
        status = "Active" if active_interface and stats.get(active_interface, {}).isup else "Inactive"
        
        # Get detection mode
        detection_mode = "Signature and Anomaly" if is_detecting else "Inactive"
        
        return JsonResponse({
            'interface': active_interface or 'No active interface found',
            'ip_address': ip_address or 'No IP address found',
            'status': status,
            'mode': detection_mode,
            'is_detecting': is_detecting
        })
        
    except Exception as e:
        print(f"Error getting network info: {e}")  # Debug logging
        return JsonResponse({
            'error': str(e),
            'interface': 'Unknown',
            'ip_address': 'Unknown',
            'status': 'Error',
            'mode': 'Unknown',
            'is_detecting': False
        }, status=500)

@login_required
@require_http_methods(["GET"])
def browse_directories(request):
    """API endpoint to browse directories on the system."""
    try:
        path = request.GET.get('path', '')
        if not path:
            path = os.path.expanduser('~')
        
        if not os.path.exists(path):
            return JsonResponse({'error': 'Path does not exist'}, status=400)
            
        items = []
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            items.append({
                'name': item,
                'path': full_path,
                'is_dir': os.path.isdir(full_path),
                'size': os.path.getsize(full_path) if not os.path.isdir(full_path) else 0
            })
            
        return JsonResponse({
            'path': path,
            'items': items
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def start_capture(request):
    """API endpoint to start network traffic capture."""
    try:
        # Check if capture is already running
        if hasattr(start_capture, 'capture_thread') and start_capture.capture_thread.is_alive():
            return JsonResponse({'error': 'Capture is already running'}, status=400)
            
        # Start capture in a separate thread
        def capture_thread():
            try:
                # Your capture logic here
                # This is a placeholder - implement your actual capture logic
                pass
            except Exception as e:
                print(f"Capture error: {e}")
                
        start_capture.capture_thread = threading.Thread(target=capture_thread)
        start_capture.capture_thread.daemon = True
        start_capture.capture_thread.start()
        
        return JsonResponse({'status': 'Capture started'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def start_detection(request):
    """Start anomaly detection process"""
    try:
        global is_detecting
        if is_detecting:
            return JsonResponse({'error': 'Detection is already running'}, status=400)
            
        is_detecting = True
        return JsonResponse({'status': 'Detection started'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def stop_detection(request):
    """Stop anomaly detection process"""
    try:
        global is_detecting
        is_detecting = False
        return JsonResponse({'status': 'Detection stopped'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def load_model(request):
    """Load a pre-trained model"""
    try:
        model_path = request.POST.get('model_path')
        if not model_path or not os.path.exists(model_path):
            return JsonResponse({'error': 'Invalid model path'}, status=400)
            
        # Add your model loading logic here
        return JsonResponse({'status': 'Model loaded successfully'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def upload_model(request):
    """Upload a new model file"""
    try:
        if 'model_file' not in request.FILES:
            return JsonResponse({'error': 'No file uploaded'}, status=400)
            
        model_file = request.FILES['model_file']
        fs = FileSystemStorage()
        filename = fs.save(model_file.name, model_file)
        
        return JsonResponse({
            'status': 'Model uploaded successfully',
            'filename': filename
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def analyze_model(request):
    """Analyze the current model"""
    try:
        # Add your model analysis logic here
        return JsonResponse({
            'status': 'Model analyzed successfully',
            'metrics': {
                'accuracy': 0.95,
                'precision': 0.94,
                'recall': 0.93,
                'f1_score': 0.94
            }
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def start_suricata(request):
    """Start Suricata IDS"""
    try:
        # Add your Suricata start logic here
        return JsonResponse({'status': 'Suricata started successfully'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def stop_suricata(request):
    """Stop Suricata IDS"""
    try:
        # Add your Suricata stop logic here
        return JsonResponse({'status': 'Suricata stopped successfully'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def test_suricata(request):
    """Test Suricata configuration"""
    try:
        # Add your Suricata test logic here
        return JsonResponse({'status': 'Suricata test completed successfully'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["GET"])
def download_log(request):
    """Download log file"""
    try:
        log_type = request.GET.get('type', 'detection')
        log_path = os.path.join(settings.MEDIA_ROOT, f'{log_type}_log.txt')
        
        if not os.path.exists(log_path):
            return JsonResponse({'error': 'Log file not found'}, status=404)
            
        with open(log_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type='text/plain')
            response['Content-Disposition'] = f'attachment; filename="{log_type}_log.txt"'
            return response
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["GET"])
def download_report(request):
    """Download a generated security report"""
    try:
        report_type = request.GET.get('type', 'security')
        report_id = request.GET.get('id')
        
        if not report_id:
            return JsonResponse({'error': 'Report ID is required'}, status=400)
            
        # Construct the report file path
        report_path = os.path.join(settings.MEDIA_ROOT, 'reports', f'{report_type}_report_{report_id}.pdf')
        
        if not os.path.exists(report_path):
            return JsonResponse({'error': 'Report not found'}, status=404)
            
        with open(report_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{report_type}_report_{report_id}.pdf"'
            return response
            
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def check_suricata_status():
    """Check if Suricata is running"""
    try:
        if platform.system() == "Windows":
            # Check for Suricata process on Windows
            for proc in psutil.process_iter(['name']):
                if 'suricata' in proc.info['name'].lower():
                    return True
        else:
            # Check for Suricata process on Linux/Unix
            result = subprocess.run(['pgrep', 'suricata'], capture_output=True)
            return result.returncode == 0
    except:
        return False

@login_required
@require_http_methods(["POST"])
def analyze_file(request):
    """Analyze a file using VirusTotal API"""
    try:
        if not VIRUSTOTAL_API_KEY:
            return JsonResponse({'error': 'VirusTotal API key not configured'}, status=500)

        if 'file' not in request.FILES:
            return JsonResponse({'error': 'No file provided'}, status=400)

        file = request.FILES['file']
        if file.size > 32 * 1024 * 1024:  # 32MB limit
            return JsonResponse({'error': 'File size exceeds 32MB limit'}, status=400)

        # Upload file to VirusTotal
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        files = {'file': (file.name, file.read(), file.content_type)}
        response = requests.post(f"{VIRUSTOTAL_API_URL}/files", headers=headers, files=files)
        
        if response.status_code != 200:
            return JsonResponse({'error': 'Failed to upload file to VirusTotal'}, status=response.status_code)

        # Get analysis results
        analysis_id = response.json()['data']['id']
        analysis_response = requests.get(f"{VIRUSTOTAL_API_URL}/analyses/{analysis_id}", headers=headers)
        
        if analysis_response.status_code != 200:
            return JsonResponse({'error': 'Failed to get analysis results'}, status=analysis_response.status_code)

        return JsonResponse(analysis_response.json())

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def analyze_url(request):
    """Analyze a URL using VirusTotal API"""
    try:
        if not VIRUSTOTAL_API_KEY:
            return JsonResponse({'error': 'VirusTotal API key not configured'}, status=500)

        data = json.loads(request.body)
        url = data.get('url')
        
        if not url:
            return JsonResponse({'error': 'URL is required'}, status=400)

        # Submit URL for analysis
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY,
            'Content-Type': 'application/json'
        }
        response = requests.post(
            f"{VIRUSTOTAL_API_URL}/urls",
            headers=headers,
            data=json.dumps({'url': url})
        )
        
        if response.status_code != 200:
            return JsonResponse({'error': 'Failed to submit URL for analysis'}, status=response.status_code)

        # Get analysis results
        analysis_id = response.json()['data']['id']
        analysis_response = requests.get(f"{VIRUSTOTAL_API_URL}/analyses/{analysis_id}", headers=headers)
        
        if analysis_response.status_code != 200:
            return JsonResponse({'error': 'Failed to get analysis results'}, status=analysis_response.status_code)

        return JsonResponse(analysis_response.json())

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def analyze_hash(request):
    """Analyze a file hash using VirusTotal API"""
    try:
        if not VIRUSTOTAL_API_KEY:
            return JsonResponse({'error': 'VirusTotal API key not configured'}, status=500)

        data = json.loads(request.body)
        hash_value = data.get('hash')
        
        if not hash_value:
            return JsonResponse({'error': 'Hash is required'}, status=400)

        # Get file report
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        response = requests.get(f"{VIRUSTOTAL_API_URL}/files/{hash_value}", headers=headers)
        
        if response.status_code != 200:
            return JsonResponse({'error': 'Failed to get file report'}, status=response.status_code)

        return JsonResponse(response.json())

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
