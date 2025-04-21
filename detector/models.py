from django.db import models
from django.contrib.auth.models import User

class NetworkTraffic(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    protocol = models.CharField(max_length=10)
    port = models.IntegerField()
    packet_size = models.IntegerField()
    payload = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-timestamp']

class DetectedThreat(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    threat_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    description = models.TextField()
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
