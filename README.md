# InsightAI

InsightAI is a web-based security scanning platform built with FastAPI, Nmap, and AI-assisted analysis. The app supports authenticated users running network scans, optional web checks, OWASP mapping, and AI-powered risk summaries.

## Features

- **Nmap-based network scanning** with multiple profiles
- **Web security checks** for discovered web targets
- **OWASP vulnerability mapping** for findings
- **AI-driven risk analysis** using OpenAI-compatible APIs
- **User authentication** and profile management
- **Persistent scan history** with duration and risk metadata
- **Modern responsive UI** with dark/light theme support

## Technology

- FastAPI
- Uvicorn
- Jinja2 templates
- SQLite + SQLAlchemy
- Nmap
- OpenAI-compatible API integration
- Docker + Docker Compose
- Python 3.12

## Quick Start

### Prerequisites

- Docker
- Docker Compose
- A modern browser

### Setup

1. Clone the repository:

```bash
git clone <repository-url>
cd InsightAI
```

2. Create or update `.env`:

```bash
PORT=8000
OPENAI_API_KEY=your-api-key
OPENAI_BASE_URL=https://api.openai.com/v1
MODEL=gemma3:27b
```

3. Start the app:

```bash
docker compose -f compose.yml up --build
```

4. Open InsightAI in your browser:

- `http://localhost:8000`

If `PORT` is changed in `.env`, the app will use that value and fall back to `8000` when unset.

### Stop the app

```bash
docker compose -f compose.yml down
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | HTTP port for the app | `8000` |
| `OPENAI_API_KEY` | AI API key | Required |
| `OPENAI_BASE_URL` | OpenAI-compatible base URL | `https://api.openai.com/v1` |
| `MODEL` | AI model identifier | `gemma3:27b` |
| `AI_TOKEN` | Alternate API key env var | - |
| `AI_URL` | Alternate API URL env var | - |

## Scan Profiles

- `fast_recon` — fast reconnaissance
- `basic` — standard port scan
- `top_ports` — top ports scan
- `service` — service detection with version info
- `full` — broader comprehensive scan

## User Experience

InsightAI users can:

- run scans from `/scan`
- choose profile, web checks, and AI analysis
- view collapsible scan results
- see AI risk level and recommendations
- store history and review past scans
- update profile settings and default scan behavior

## API Reference

### Health Check

```http
GET /ping
```

Response:

```json
{
  "ok": true,
  "service": "app"
}
```

### Scan API

```http
POST /api/scan
Content-Type: application/json
```

Example request:

```json
{
  "target": "scanme.nmap.org",
  "profile": "basic",
  "web_scan": true
}
```

Response includes:

- `target`
- `network_scan`
- `web_checks`
- `owasp_mapping`
- `ai_analysis`

## Web Routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Redirects to login or dashboard |
| `/login` | GET, POST | Login page |
| `/register` | GET, POST | User registration |
| `/logout` | GET | Logout |
| `/scan` | GET, POST | Scan interface |
| `/profile` | GET, POST | Update preferences |
| `/history` | GET | View scan history |
| `/history/{scan_id}` | GET | Scan detail page |
| `/about` | GET | About page |

## Project Structure

```
InsightAI/
├── app/
│   ├── ai_client.py        # AI analysis and env loader
│   ├── main.py             # FastAPI routes and logic
│   ├── models.py           # SQLAlchemy ORM models
│   ├── scanner.py          # Nmap scan execution
│   ├── web_checks.py       # Web discovery and checks
│   └── templates/          # Jinja2 frontend templates
├── compose.yml             # Docker Compose setup
├── Dockerfile              # Container build config
├── .env                    # Local environment variables
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```

## Development

### Run without Docker

1. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the application:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port ${PORT:-8000}
```

4. Open `http://localhost:${PORT:-8000}`.

## Usage Examples

### cURL

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "scanme.nmap.org",
    "profile": "basic",
    "web_scan": true
  }'
```

### Python

```python
import requests

response = requests.post(
    'http://localhost:8000/api/scan',
    json={
        'target': 'scanme.nmap.org',
        'profile': 'basic',
        'web_scan': True,
    }
)
print(response.json())
```

## Notes

- AI analysis works when `OPENAI_API_KEY` and `OPENAI_BASE_URL` are configured.
- `PORT` in `.env` or system environment is used by Docker and Uvicorn.
- Update passwords and API keys before production use.

## License

Add license information here.

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## Support

For issues, questions, or suggestions, please open an issue on GitHub.

## Changelog

### v1.0.0
- Initial release
- Network scanning with Nmap
- Web security checks
