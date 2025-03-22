from django.db import models
from django.contrib.auth.models import User

class NetworkTraffic(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    source_port = models.IntegerField()
    destination_port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    packet_size = models.IntegerField()
    flags = models.CharField(max_length=50, blank=True)
    payload = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']

class DetectedThreat(models.Model):
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True)
    threat_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    description = models.TextField()
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    related_traffic = models.ForeignKey(NetworkTraffic, on_delete=models.CASCADE, null=True)
    is_resolved = models.BooleanField(default=False)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    resolution_notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']

class SecurityScan(models.Model):
    SCAN_TYPE_CHOICES = [
        ('PORT', 'Port Scan'),
        ('VULN', 'Vulnerability Scan'),
        ('PCAP', 'PCAP Analysis'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True)
    scan_type = models.CharField(max_length=10, choices=SCAN_TYPE_CHOICES)
    target = models.CharField(max_length=255)
    initiated_by = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, default='pending')
    results = models.JSONField(null=True, blank=True)
    pcap_file = models.FileField(upload_to='pcaps/', null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']

class SecurityReport(models.Model):
    title = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    report_type = models.CharField(max_length=50)
    content = models.JSONField()
    is_archived = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']
