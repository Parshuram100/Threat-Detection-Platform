from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/network_traffic/$', consumers.NetworkTrafficConsumer.as_asgi()),
    re_path(r'ws/anomaly_detection/$', consumers.AnomalyDetectionConsumer.as_asgi()),
]