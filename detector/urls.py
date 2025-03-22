from django.urls import path
from . import views

app_name = 'detector'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('anomaly-detection/', views.anomaly_detection, name='anomaly_detection'),
    path('security-tools/', views.security_tools, name='security_tools'),
    path('api/browse-directories/', views.browse_directories, name='browse_directories'),
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
] 