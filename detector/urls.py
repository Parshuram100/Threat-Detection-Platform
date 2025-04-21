from django.urls import path
from . import views

app_name = 'detector'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('anomaly-detection/', views.anomaly_detection, name='anomaly_detection'),
    path('api/start-capture/', views.start_capture, name='start_capture'),
    path('api/stop-capture/', views.stop_capture, name='stop_capture'),
    path('api/start-detection/', views.start_detection, name='start_detection'),
    path('api/stop-detection/', views.stop_detection, name='stop_detection'),
    path('api/load-model/', views.load_model, name='load_model'),
    path('api/upload-model/', views.upload_model, name='upload_model'),
    path('api/analyze-model/', views.analyze_model, name='analyze_model'),
    path('api/start-suricata/', views.start_suricata, name='start_suricata'),
    path('api/stop-suricata/', views.stop_suricata, name='stop_suricata'),
    path('api/test-suricata/', views.test_suricata, name='test_suricata'),
    path('api/export-results/', views.export_results, name='export_results'),
    path('api/download-log/', views.download_log, name='download_log'),
    path('ai-security-analyst/', views.ai_security_analyst, name='ai_security_analyst'),
    path('malware-analysis/', views.malware_analysis, name='malware_analysis'),
    path('download-report/', views.download_report, name='download_report'),
    path('api/analyze-file/', views.analyze_file, name='analyze_file'),
    path('api/analyze-url/', views.analyze_url, name='analyze_url'),
    path('api/analyze-hash/', views.analyze_hash, name='analyze_hash'),
] 