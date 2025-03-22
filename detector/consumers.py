import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import NetworkTraffic, DetectedThreat

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
        }))

class AnomalyDetectionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add(
            "anomaly_detection",
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            "anomaly_detection",
            self.channel_name
        )

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']

        await self.channel_layer.group_send(
            "anomaly_detection",
            {
                'type': 'anomaly_alert',
                'message': message
            }
        )

    async def anomaly_alert(self, event):
        message = event['message']
        await self.send(text_data=json.dumps({
            'type': 'anomaly_detected',
            'alert': message
        }))