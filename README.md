# Threat Detection Platform

A comprehensive network security platform built with Django that provides real-time network monitoring, anomaly detection, and security tools.

## Features

1. **Real-Time Network Monitoring**
   - Live packet capture and analysis
   - WebSocket-based real-time updates
   - Interactive traffic visualization
   - Source/destination IP tracking
   - Protocol and port monitoring

2. **Anomaly Detection**
   - AI-driven threat detection
   - Real-time anomaly analysis
   - Severity-based threat classification
   - Threat visualization and statistics
   - Threat resolution tracking

3. **Security Tools**
   - Port scanning capabilities
   - PCAP file analysis
   - Network traffic analysis
   - Security report generation
   - Scan history tracking

## Tech Stack

- Backend: Django, Django Channels
- Frontend: HTML, CSS, JavaScript, Chart.js
- Networking: Scapy
- AI/ML: scikit-learn
- Database: SQLite (default), PostgreSQL (recommended)
- WebSocket: Django Channels

## Prerequisites

- Python 3.8+
- pip (Python package manager)
- Virtual environment (recommended)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd threat-detection-platform
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up the database:
```bash
python manage.py makemigrations
python manage.py migrate
```

5. Create a superuser:
```bash
python manage.py createsuperuser
```

6. Run the development server:
```bash
python manage.py runserver
```

## Usage

1. Access the web interface at `http://localhost:8000`
2. Log in with your superuser credentials
3. Navigate through the three main sections:
   - Dashboard: Real-time network monitoring
   - Anomaly Detection: Threat detection and analysis
   - Security Tools: Network scanning and analysis tools

## Security Considerations

- The platform requires administrative privileges for packet capture
- Ensure proper firewall rules are in place
- Use HTTPS in production
- Regularly update dependencies
- Follow security best practices for deployment

## Development

### Project Structure

```
threat_detection_platform/
├── detector/                 # Main application
│   ├── models.py            # Database models
│   ├── views.py             # View functions
│   ├── consumers.py         # WebSocket consumers
│   └── routing.py           # WebSocket routing
├── templates/               # HTML templates
│   ├── base.html           # Base template
│   └── detector/           # App-specific templates
├── static/                 # Static files
├── manage.py              # Django management script
└── requirements.txt       # Project dependencies
```

### Adding New Features

1. Create new models in `models.py`
2. Add view functions in `views.py`
3. Create templates in `templates/detector/`
4. Update URL patterns in `urls.py`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Django framework and community
- Scapy for network packet manipulation
- Chart.js for data visualization
- All contributors and maintainers 