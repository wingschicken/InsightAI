# InsightAI

InsightAI is a secure vulnerability scanning web application built with FastAPI, Nmap, and AI-driven tooling. It integrates safe, non-privileged scan profiles, web asset discovery, OWASP-aligned vulnerability mapping, AI-assisted analysis, retrieval-augmented generation (RAG) chat, and system health monitoring.

The platform demonstrates how AI can process and interpret security tool outputs to produce structured, actionable insights. Additionally, the RAG system showcases how curated knowledge—such as vulnerability examples—can be incorporated as contextual input to improve analysis quality and relevance.

Note:
This project is intended for demonstration purposes only. In a real-world security environment, a more comprehensive toolkit would be required, incorporating multiple specialized scanning and analysis tools beyond Nmap to achieve broader coverage and deeper insight.

## Features

- **Safe Nmap scanning** using non-admin-friendly profiles
- **Web security checks** for discovered HTTP(S) targets
- **OWASP-style findings mapping**
- **AI-powered scan summaries and recommendations**
- **Persistent scan history for authenticated users**
- **Chat interface with optional RAG mode**
- **System and RAG status visibility**
- **Dark/light themes and responsive UI**

## Technology

- FastAPI
- Uvicorn
- Jinja2 templates
- SQLite + SQLAlchemy
- Nmap
- OpenAI-compatible API integration
- ChromaDB-backed RAG service
- Docker + Docker Compose

## Quick Start

### Prerequisites

- Docker
- Docker Compose
- A modern browser

### Run with Docker

```bash
git clone https://github.com/wingschicken/InsightAI.git
cd InsightAI
docker compose -f compose.yml up --build
```

Open the app at `http://localhost:8000`.

Default credentials:
- Username: `admin`
- Password: `nimda123`

### Stop the app

```bash
docker compose -f compose.yml down
```

## Configuration

Create a `.env` file with the following values:

```bash
PORT=8000
OPENAI_API_KEY=your-api-key
OPENAI_BASE_URL=https://api.openai.com/v1
MODEL=gemma3:27b
```

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | HTTP port for the app | `8000` |
| `OPENAI_API_KEY` | AI API key for assistant and RAG | Required |
| `OPENAI_BASE_URL` | OpenAI-compatible base URL | `https://api.openai.com/v1` |
| `MODEL` | AI model identifier | `gemma3:27b` |

## Scan Profiles

All supported scan profiles use non-admin-safe Nmap options when possible:

- `fast_recon` — fast reconnaissance
- `basic` — standard port and service scan
- `top_ports` — top ports scan
- `service` — service detection
- `full` — full port scan
- `nonadmin` — safest TCP connect scan

## Chat and RAG

InsightAI includes an AI chat interface with an optional RAG mode. When RAG mode is enabled, messages are forwarded to the RAG backend with a payload like:

```json
{ "query": "your question", "top_k": 4 }
```

This enables responses grounded in ingested knowledge.

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

## RAG Endpoints

- `POST /api/rag/ingest` — update the RAG knowledge database
- `POST /api/rag_chat/{chat_id}` — send a chat prompt through RAG and persist the result
- RAG backend direct endpoints: `GET /ping`, `POST /ingest-file`, `POST /chat`

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
| `/chat` | GET | AI chat and RAG interface |
| `/status` | GET | Health dashboard |
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
