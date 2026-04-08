# Security Scanner

A professional, full-featured web-based security scanner built with FastAPI. Performs network vulnerability scanning, web security assessments, and AI-powered analysis to identify potential security risks.

## Features

- **Network Scanning**: Nmap-based network reconnaissance with multiple scan profiles
  - Fast Recon: Quick port discovery
  - Basic: Standard port scanning
  - Top Ports: Scan most common ports
  - Service: Identify services and versions
  - Full: Comprehensive network analysis

- **Web Security Checks**: Automated web application security testing
  - HTTP security headers validation
  - SSL/TLS certificate analysis
  - Common vulnerability detection
  - Web service enumeration

- **OWASP Mapping**: Intelligent mapping of findings to OWASP categories
  - Categorized vulnerability classification
  - Risk level assessment (Low, Medium, High)
  - Actionable remediation guidance

- **AI-Powered Analysis**: Leverages custom LLMs for intelligent vulnerability analysis
  - Context-aware security assessment
  - Custom model support (via OpenAI API)
  - Detailed technical insights

- **User Authentication**: Secure login and registration system
  - Password hashing with Werkzeug
  - Session-based authentication
  - User profiles with preferences

- **Scan History**: Complete audit trail of all scans
  - Database persistence with SQLite + SQLAlchemy ORM
  - Scan duration tracking
  - Historical analysis and comparison

- **Professional UI**: Modern, responsive web interface
  - Dark and light color themes
  - Real-time scan status
  - Collapsible result sections
  - Professional enterprise design

## Tech Stack

- **Backend**: FastAPI 0.110.1 + Uvicorn
- **Frontend**: Jinja2 templates + HTML5/CSS3
- **Database**: SQLite with SQLAlchemy ORM
- **Security Tools**: Nmap for network scanning
- **AI Integration**: OpenAI API v1.0+
- **Authentication**: Werkzeug password hashing
- **Containerization**: Docker & Docker Compose
- **Python**: 3.12-slim

## Quick Start

### Prerequisites
- Docker and Docker Compose
- (Optional) Modern web browser

### Installation & Running

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd lukasproject
   ```

2. **Configure environment variables**
   
   Create a `.env` file in the project root:
   ```bash
   OPENAI_API_KEY=your-api-key-here
   OPENAI_BASE_URL=https://api.openai.com/v1
   MODEL=gpt-4
   ```
   
   For custom endpoints (like Ollama):
   ```bash
   OPENAI_API_KEY=any-key
   OPENAI_BASE_URL=http://localhost:11434/v1
   MODEL=gemma3:27b
   ```

3. **Start with Docker Compose**
   ```bash
   docker compose -f compose.yml up --build
   ```

4. **Access the application**
   - Navigate to `http://localhost:8000`
   - Default credentials: `admin` / `nimda123`

5. **Stop the application**
   ```bash
   docker compose -f compose.yml down
   ```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | API key for AI model access | Required |
| `OPENAI_BASE_URL` | Base URL for OpenAI-compatible API | `https://api.openai.com/v1` |
| `MODEL` | LLM model identifier | `gpt-4` |
| `AI_TOKEN` | Alternative token field | - |
| `AI_URL` | Alternative API URL | - |

### Scan Profiles

**Fast Recon** (Fastest)
- Quick port discovery
- Ideal for initial reconnaissance
- ~30 seconds typical runtime

**Basic** (Recommended)
- Standard port scanning (1000 common ports)
- Service version detection
- ~1-2 minutes typical runtime

**Top Ports** (Balanced)
- Scans top 100-500 ports
- Balanced speed vs coverage
- ~30-60 seconds typical runtime

**Service** (Detailed)
- Service detection and version enumeration
- OS fingerprinting
- ~2-5 minutes typical runtime

**Full** (Comprehensive)
- Complete network analysis
- All ports, aggressive scanning
- 5+ minutes typical runtime

## API Documentation

### Authentication

The web UI uses cookie-based authentication. For API access, use the `/api/scan` endpoint.

### Endpoints

#### Health Check
```
GET /ping
```
Returns application health status.

**Response:**
```json
{
  "ok": true,
  "service": "app"
}
```

#### Submit Security Scan (API)
```
POST /api/scan
Content-Type: application/json

{
  "target": "example.com",
  "profile": "basic",
  "web_scan": true
}
```

**Request Parameters:**
- `target` (required): Domain name or IP address to scan
- `profile` (optional): One of `basic`, `fast_recon`, `top_ports`, `service`, `full`. Default: `basic`
- `web_scan` (optional): Run web security checks. Default: `true`

**Response:**
```json
{
  "target": "example.com",
  "network_scan": {
    "status": "up",
    "ports": [
      {
        "port": 80,
        "state": "open",
        "protocol": "tcp",
        "service": "http",
        "version": "Apache 2.4.41"
      },
      {
        "port": 443,
        "state": "open",
        "protocol": "tcp",
        "service": "https",
        "version": "Apache 2.4.41"
      }
    ]
  },
  "web_checks": {
    "performed": true,
    "findings": [
      {
        "url": "http://example.com",
        "headers": [...],
        "vulnerabilities": [...]
      }
    ],
    "urls": ["http://example.com", "https://example.com"]
  },
  "owasp_mapping": [
    {
      "owasp_category": "A01:2021 - Broken Access Control",
      "findings": [...],
      "risk_level": "Medium"
    }
  ],
  "ai_analysis": "Detailed security assessment from AI model..."
}
```

### Web UI Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Home/dashboard (requires auth) |
| `/login` | GET, POST | User login |
| `/register` | GET, POST | User registration |
| `/logout` | GET | User logout |
| `/scan` | GET, POST | Security scan interface |
| `/profile` | GET, POST | User profile management |
| `/history` | GET | View all scans |
| `/history/{scan_id}` | GET | View detailed scan results |
| `/about` | GET | Application information |

## Authentication & Users

### Default Account

The application comes with a pre-configured admin account:
- **Username**: `admin`
- **Password**: `nimda123`

> ⚠️ **Important**: Change this password in production!

### Creating New Users

1. Navigate to `/register`
2. Provide a username and password
3. Optionally add email and display name
4. Account is active immediately

## Project Structure

```
lukasproject/
├── app/
│   ├── main.py              # FastAPI application & routes
│   ├── models.py            # SQLAlchemy ORM models
│   ├── scanner.py           # Nmap integration
│   ├── web_checks.py        # Web security checks
│   ├── ai_client.py         # OpenAI API integration
│   └── templates/           # Jinja2 HTML templates
│       ├── base.html        # Base template with styling
│       ├── login.html       # Login form
│       ├── register.html    # Registration form
│       ├── scan.html        # Scan interface
│       ├── profile.html     # User profile
│       ├── history.html     # Scan history list
│       └── ...
├── Dockerfile               # Container configuration
├── compose.yml              # Docker Compose configuration
├── requirements.txt         # Python dependencies
├── .env                     # Environment configuration
└── README.md               # This file
```

## Development

### Local Setup (without Docker)

1. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

4. **Run the application**
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

The application will be available at `http://localhost:8000`

### Running Tests

**Verify syntax**
```bash
python -m py_compile app/main.py app/models.py
```

**Test Nmap integration**
```bash
docker compose run --rm app nmap -Pn -oX - -sV example.com
```

## API Usage Examples

### Using cURL

```bash
# Submit a scan
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "scanme.nmap.org",
    "profile": "basic",
    "web_scan": true
  }'

# Health check
curl http://localhost:8000/ping
```

### Using Python

```python
import requests
import json

response = requests.post(
    'http://localhost:8000/api/scan',
    json={
        'target': 'scanme.nmap.org',
        'profile': 'basic',
        'web_scan': True
    }
)

scan_results = response.json()
print(json.dumps(scan_results, indent=2))
```

### Using JavaScript

```javascript
async function runScan(target) {
  const response = await fetch('/api/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      target: target,
      profile: 'basic',
      web_scan: true
    })
  });
  
  const results = await response.json();
  return results;
}

// Usage
runScan('example.com').then(results => {
  console.log('Scan complete:', results);
});
```

## Security Considerations

- **Authentication**: Use strong passwords in production
- **API Keys**: Never commit `.env` files with real API keys
- **Network Access**: Restrict access to the application in production
- **Nmap Permissions**: May require elevated privileges for certain scans
- **Rate Limiting**: Consider implementing rate limiting in production
- **HTTPS**: Deploy behind a reverse proxy with TLS in production

## Troubleshooting

### Container won't start
```bash
# Check logs
docker compose logs app

# Rebuild container
docker compose down
docker compose up --build
```

### Nmap not found
Ensure the Dockerfile is building correctly and includes nmap:
```bash
docker compose run --rm app nmap --version
```

### AI Analysis not working
1. Verify `OPENAI_API_KEY` is set in `.env`
2. Test connectivity: `curl $OPENAI_BASE_URL/models`
3. Check API key validity with OpenAI console

### Database errors
The database is created automatically. If issues persist:
```bash
docker compose down
docker volume prune  # Warning: removes all volumes
docker compose up --build
```

## License

[Specify your license here]

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## Support

For issues, questions, or suggestions, please [open an issue on GitHub](https://github.com/yourusername/lukasproject/issues).

## Changelog

### v1.0.0
- Initial release
- Network scanning with Nmap
- Web security checks
- OWASP vulnerability mapping
- AI-powered analysis
- User authentication & profiles
- Scan history with duration tracking
- Professional web UI with dark/light themes
