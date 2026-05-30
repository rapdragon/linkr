# Linkr

DNS & Proxy Manager — a single web UI to manage FQDNs across Pi-hole (DNS) and Nginx Proxy Manager (reverse proxy).

## Features

- **Unified view** — see all FQDNs with their DNS and proxy status in one table
- **One-click creation** — creates both Pi-hole DNS entry + NPM proxy host together
- **Edit existing entries** — change forward target, DNS IP, SSL settings
- **Mismatch detection** — flags entries that exist in one system but not the other
- **Split DNS** — external domains can optionally resolve locally via Pi-hole
- **Let's Encrypt** — auto-requests SSL certs for external domains with public DNS validation
- **Custom cert support** — detects and displays internal CA certs vs Let's Encrypt
- **Rate limit tracking** — tracks LE cert requests to avoid hitting the 50/week limit
- **Duplicate prevention** — validates domain doesn't already exist before creating
- **User auth** — login required, admin/viewer roles
- **REST API** — authenticated API for programmatic access

## Quick Start

```bash
docker run -d \
  --name linkr \
  --restart unless-stopped \
  -p 5000:5000 \
  -v linkr-data:/data \
  rapdragon/linkr:latest
```

Open http://localhost:5000 — the setup wizard will guide you through creating an admin account and configuring Pi-hole/NPM connections.

## Configuration

### Pi-hole Requirements
- Pi-hole v6+ with `app_sudo = true` in `pihole.toml` (under `[webserver.api]`)
- This allows the API to modify DNS host records

### NPM Requirements
- Nginx Proxy Manager with API access (default port 81 or custom)
- Admin credentials for token-based auth

## REST API

All API endpoints require authentication via `X-API-Key` header.

Generate an API key: Config → Users → Generate API Key

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/fqdns` | List all FQDNs with status |
| POST | `/api/fqdns` | Create new FQDN |
| DELETE | `/api/fqdns/<domain>` | Delete FQDN from both systems |
| GET | `/api/health` | Health check |

### Create FQDN

```bash
curl -X POST http://localhost:5000/api/fqdns \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "service.example.com",
    "forward_host": "10.0.0.5",
    "forward_port": 8080,
    "type": "internal",
    "dns_ip": "10.0.0.1"
  }'
```

For external (SSL) domains, add `"type": "external"` and optionally `"force_ssl": true`.

### Delete FQDN

```bash
curl -X DELETE http://localhost:5000/api/fqdns/service.example.com \
  -H "X-API-Key: your-key"
```

### List FQDNs

```bash
curl http://localhost:5000/api/fqdns \
  -H "X-API-Key: your-key"
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | random | Flask session secret |
| `DB_PATH` | `/data/dns_proxy_manager.db` | SQLite database path |
| `DEBUG` | `false` | Enable debug mode |

## Tech Stack

- Python 3.12 + Flask
- SQLite
- Docker (Alpine-based)

## License

MIT
