import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import NetworkTraffic, DetectedThreat
import numpy as np
from datetime import datetime, timedelta
import asyncio

# Custom JSON encoder to handle NumPy types
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, np.bool_):
            return bool(obj)
        return super().default(obj)

class NetworkTrafficConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add(
            "network_traffic",
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            "network_traffic",
            self.channel_name
        )

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']

        await self.channel_layer.group_send(
            "network_traffic",
            {
                'type': 'traffic_update',
                'message': message
            }
        )

    async def traffic_update(self, event):
        message = event['message']
        await self.send(text_data=json.dumps({
            'type': 'traffic_update',
            'data': message
        }, cls=NumpyEncoder))

class AnomalyDetectionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        await self.channel_layer.group_add("anomaly_detection", self.channel_name)
        
    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("anomaly_detection", self.channel_name)
        
    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            if data.get('type') == 'config':
                # Handle configuration updates
                self.sensitivity = data.get('sensitivity', 0.75)
                self.mode = data.get('mode', 'signature')
                self.realtime = data.get('realtime', True)
                
                # Send acknowledgment
                await self.send(text_data=json.dumps({
                    'type': 'config_ack',
                    'status': 'success',
                    'message': 'Configuration updated'
                }))
                
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': str(e)
            }))
    
    async def anomaly_alert(self, event):
        """Handle anomaly detection alerts"""
        try:
            alert = event['message']
            
            # Analyze the attack
            analysis = await self.analyze_attack(alert)
            
            # Prepare visualization data
            visualization = {
                'attack_type': alert['attack_type'],
                'source_ip': alert['source_ip'],
                'destination_ip': alert['destination_ip'],
                'timestamp': alert['timestamp'],
                'confidence': alert.get('confidence', 0.95),
                'pattern': analysis['pattern'],
                'risk_level': analysis['risk_level'],
                'recommendations': analysis['recommendations']
            }
            
            # Send to client
            await self.send(text_data=json.dumps({
                'type': 'attack_alert',
                'message': visualization
            }))
            
        except Exception as e:
            print(f"Error processing alert: {e}")
    
    async def analyze_attack(self, alert):
        """Analyze an attack alert and add additional information"""
        analysis = {
            'pattern': self._get_attack_pattern(alert),
            'risk_level': self._calculate_risk_level(alert),
            'recommendations': self._get_recommendations(alert)
        }
        return analysis
        
    def _get_attack_pattern(self, alert):
        """Get the attack pattern based on the alert type"""
        patterns = {
            'DOS_SYN_FLOOD': {
                'description': 'High frequency of SYN packets with small window size',
                'indicators': ['SYN flag', 'Small TCP window', 'Multiple connections'],
                'visualization': {
                    'type': 'line',
                    'data': {
                        'labels': ['Time'],
                        'datasets': [{
                            'label': 'SYN Packets',
                            'data': [],
                            'borderColor': '#dc3545',
                            'fill': False
                        }]
                    }
                }
            },
            'DOS_UDP_FLOOD': {
                'description': 'High frequency of UDP packets',
                'indicators': ['UDP protocol', 'High packet rate', 'Multiple ports'],
                'visualization': {
                    'type': 'line',
                    'data': {
                        'labels': ['Time'],
                        'datasets': [{
                            'label': 'UDP Packets',
                            'data': [],
                            'borderColor': '#dc3545',
                            'fill': False
                        }]
                    }
                }
            },
            'DOS_ICMP_FLOOD': {
                'description': 'High frequency of ICMP packets',
                'indicators': ['ICMP protocol', 'High packet rate', 'Echo requests'],
                'visualization': {
                    'type': 'line',
                    'data': {
                        'labels': ['Time'],
                        'datasets': [{
                            'label': 'ICMP Packets',
                            'data': [],
                            'borderColor': '#dc3545',
                            'fill': False
                        }]
                    }
                }
            },
            'BRUTE_FORCE_SSH': {
                'description': 'Multiple failed SSH login attempts',
                'indicators': ['Port 22', 'Multiple attempts', 'Short intervals'],
                'visualization': {
                    'type': 'bar',
                    'data': {
                        'labels': ['Time'],
                        'datasets': [{
                            'label': 'Failed Attempts',
                            'data': [],
                            'backgroundColor': '#ffc107'
                        }]
                    }
                }
            },
            'BRUTE_FORCE_FTP': {
                'description': 'Multiple failed FTP login attempts',
                'indicators': ['Port 21', 'Multiple attempts', 'FTP commands'],
                'visualization': {
                    'type': 'bar',
                    'data': {
                        'labels': ['Time'],
                        'datasets': [{
                            'label': 'Failed Attempts',
                            'data': [],
                            'backgroundColor': '#ffc107'
                        }]
                    }
                }
            },
            'BRUTE_FORCE_LOGIN': {
                'description': 'Multiple failed web login attempts',
                'indicators': ['HTTP/HTTPS', 'POST requests', 'Login endpoints'],
                'visualization': {
                    'type': 'bar',
                    'data': {
                        'labels': ['Time'],
                        'datasets': [{
                            'label': 'Failed Attempts',
                            'data': [],
                            'backgroundColor': '#ffc107'
                        }]
                    }
                }
            },
            'SQL_INJECTION': {
                'description': 'SQL injection attempt detected',
                'indicators': ['SQL keywords', 'High entropy', 'Web endpoints'],
                'visualization': {
                    'type': 'pie',
                    'data': {
                        'labels': ['SQL Keywords', 'Other'],
                        'datasets': [{
                            'data': [],
                            'backgroundColor': ['#17a2b8', '#6c757d']
                        }]
                    }
                }
            },
            'WEB_ENUM': {
                'description': 'Web enumeration activity detected',
                'indicators': ['Directory scanning', 'Multiple endpoints', 'GET requests'],
                'visualization': {
                    'type': 'line',
                    'data': {
                        'labels': ['Time'],
                        'datasets': [{
                            'label': 'Requests',
                            'data': [],
                            'borderColor': '#6c757d',
                            'fill': False
                        }]
                    }
                }
            },
            'PORT_SCAN': {
                'description': 'Port scanning activity detected',
                'indicators': ['Multiple ports', 'SYN packets', 'No established connections'],
                'visualization': {
                    'type': 'line',
                    'data': {
                        'labels': ['Time'],
                        'datasets': [{
                            'label': 'Ports Scanned',
                            'data': [],
                            'borderColor': '#6c757d',
                            'fill': False
                        }]
                    }
                }
            }
        }
        return patterns.get(alert['attack_type'], {
            'description': 'Unknown attack pattern',
            'indicators': [],
            'visualization': None
        })
        
    def _calculate_risk_level(self, alert):
        """Calculate the risk level of an attack"""
        # Base risk level on attack type and probability
        risk_levels = {
            'DOS_SYN_FLOOD': 3,
            'DOS_UDP_FLOOD': 3,
            'DOS_ICMP_FLOOD': 3,
            'BRUTE_FORCE_SSH': 2,
            'BRUTE_FORCE_FTP': 2,
            'BRUTE_FORCE_LOGIN': 2,
            'SQL_INJECTION': 3,
            'WEB_ENUM': 1,
            'PORT_SCAN': 1
        }
        
        base_risk = risk_levels.get(alert['attack_type'], 1)
        probability = alert.get('confidence', 0)
        
        # Adjust risk based on probability
        if probability > 0.9:
            base_risk += 1
        elif probability < 0.5:
            base_risk -= 1
            
        return min(max(base_risk, 1), 3)  # Ensure risk is between 1 and 3
        
    def _get_recommendations(self, alert):
        """Get recommendations based on attack type"""
        recommendations = {
            'DOS_SYN_FLOOD': [
                'Implement SYN cookies',
                'Configure rate limiting',
                'Update firewall rules',
                'Consider DDoS protection service'
            ],
            'DOS_UDP_FLOOD': [
                'Configure UDP flood protection',
                'Implement rate limiting',
                'Update firewall rules',
                'Consider DDoS protection service'
            ],
            'DOS_ICMP_FLOOD': [
                'Configure ICMP flood protection',
                'Implement rate limiting',
                'Update firewall rules',
                'Consider DDoS protection service'
            ],
            'BRUTE_FORCE_SSH': [
                'Implement SSH key authentication',
                'Configure fail2ban',
                'Update SSH configuration',
                'Consider VPN access instead'
            ],
            'BRUTE_FORCE_FTP': [
                'Disable anonymous FTP',
                'Implement strong password policy',
                'Configure fail2ban',
                'Consider SFTP instead'
            ],
            'BRUTE_FORCE_LOGIN': [
                'Implement CAPTCHA',
                'Configure account lockout',
                'Enable 2FA',
                'Monitor login attempts'
            ],
            'SQL_INJECTION': [
                'Implement parameterized queries',
                'Update web application',
                'Configure WAF rules',
                'Review database permissions'
            ],
            'WEB_ENUM': [
                'Configure robots.txt',
                'Implement rate limiting',
                'Update web server configuration',
                'Monitor suspicious requests'
            ],
            'PORT_SCAN': [
                'Update firewall rules',
                'Configure port scan detection',
                'Implement network segmentation',
                'Monitor network traffic'
            ]
        }
        return recommendations.get(alert['attack_type'], [
            'Monitor the situation',
            'Review logs',
            'Update security measures'
        ])