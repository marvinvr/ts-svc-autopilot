# ts-svc-autopilot

Automatically expose Docker containers as Tailscale Services using label-based configuration - zero-config service mesh for your homelab.

## Quick Start

### Admin Console Setup

Before installing the autopilot, configure your Tailscale admin console at https://login.tailscale.com/admin/services:

1. **Create service definitions** (Services → Add service):
   - Create a service for each application you want to expose
   - Example: Service name `web`, `api`, `db`, etc.
   - Note: The autopilot will automatically configure and advertise these services

2. **(Optional) Configure service tags**:
   - Navigate to Access Controls
   - Add tags for service identification (e.g., `tag:homelab-service`)
   - Tag your Docker host (e.g., `tag:homelab`)

3. **(Recommended) Enable auto-approval**:
   - Navigate to Access Controls and edit your ACL policy
   - Add auto-approvers to skip manual approval for service advertisements:
   ```json
   {
     "autoApprovers": {
       "services": {
         "tag:homelab-service": ["tag:homelab"]
       }
     }
   }
   ```
   - This allows devices tagged `tag:homelab` to automatically advertise services tagged `tag:homelab-service`

See [Tailscale Services documentation](https://tailscale.com/kb/1552/tailscale-services) for detailed setup instructions.

### Prerequisites

1. Tailscale installed and authenticated on your Docker host
2. Host must have a tag-based identity (not user-based)
3. Docker daemon running with API socket exposed
4. Services created in Tailscale admin console (see above)

### Installation

#### Option 1: Docker Compose

Create a `docker-compose.yaml`:

```yaml
version: '3.8'

services:
  ts-svc-autopilot:
    image: ghcr.io/marvinvr/ts-svc-autopilot:latest
    container_name: ts-svc-autopilot
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /var/run/tailscale/tailscaled.sock:/var/run/tailscale/tailscaled.sock
    environment:
      - LOG_LEVEL=info
      - RECONCILE_INTERVAL=60s
```

Start the service:
```bash
docker compose up -d
```

#### Option 2: Docker Run

```bash
docker run -d \
  --name ts-svc-autopilot \
  --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /var/run/tailscale/tailscaled.sock:/var/run/tailscale/tailscaled.sock \
  -e LOG_LEVEL=info \
  -e RECONCILE_INTERVAL=60s \
  ghcr.io/marvinvr/ts-svc-autopilot:latest
```

#### Verify Installation

Check the logs:
```bash
docker logs -f ts-svc-autopilot
```

Verify services are advertised:
```bash
tailscale serve status --json
```

### Usage

**🚨 CRITICAL:** Container ports MUST be published to host. Tailscale serve only supports `localhost` proxies. This is a technical limitation of Tailscale.

```yaml
services:
  myapp:
    image: nginx:latest
    ports:
      - "9080:80"  # REQUIRED! HOST:CONTAINER format
    labels:
      - "ts-svc.enable=true"
      - "ts-svc.service=myapp"
#     - "ts-svc.port=443"                  # Port on Tailscale (default: 80)
      - "ts-svc.target=80"                 # CONTAINER port (RIGHT side of "9080:80")
#     - "ts-svc.target-protocol=http"     # Protocol (default: http)
```

**Port Mapping Rules:**
- `ports:` = `"HOST:CONTAINER"` (e.g., `"9080:80"` = host 9080 → container 80)
- `ts-svc.target` = CONTAINER port (always the RIGHT side)
- Result: Tailscale:443 → localhost:9080 → Container:80

Access from any device in your tailnet:
```bash
curl http://myapp.your-tailnet.ts.net
```

### Available Labels

| Label | Required | Default | Description | Example |
|-------|----------|---------|-------------|---------|
| `ts-svc.enable` | Yes | - | Enable autopilot for container | `true` |
| `ts-svc.service` | Yes | - | Service name | `web`, `api-v2` |
| `ts-svc.target` | Yes | - | **CONTAINER** port (RIGHT side of `ports:`) | `80`, `3000` |
| `ts-svc.port` | No | `80` | Port exposed on Tailscale | `443`, `8080` |
| `ts-svc.target-protocol` | No | `http` | Protocol type | `http`, `https`, `tcp` |

**Critical:** If `ports: "9080:80"`, then `ts-svc.target=80` (container port, NOT 9080)

### Supported Protocols

- `http`: Layer 7 HTTP forwarding
- `https`: Layer 7 HTTPS forwarding (auto TLS cert)
- `tcp`: Layer 4 TCP forwarding
- `tls-terminated-tcp`: Layer 4 with TLS termination

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Logging level (debug, info, warn, error) |
| `RECONCILE_INTERVAL` | `60s` | State reconciliation interval |
| `DOCKER_HOST` | `unix:///var/run/docker.sock` | Docker daemon socket |
| `TAILSCALE_SOCKET` | `/var/run/tailscale/tailscaled.sock` | Tailscale daemon socket |

## How It Works

1. **Container Discovery**: Monitors Docker events API for container lifecycle events (start, stop, die, restart)
2. **Label Parsing**: Extracts Tailscale service configuration from container labels
3. **Port Detection**: Queries Docker API for published host ports
4. **Configuration Generation**: Creates Tailscale service configuration proxying to `localhost:HOST_PORT`
5. **Configuration Application**: Executes Tailscale CLI commands to apply config and advertise services
6. **Stateless Operation**: Periodically reconciles state by querying Docker and Tailscale APIs

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                     Docker Host                        │
│                                                        │
│  ┌──────────────────┐         ┌──────────────────┐     │
│  │  ts-svc-autopilot│────────▶│ Tailscale Daemon │     │
│  │   (Container)    │  CLI    │   (Host Process) │     │
│  └────────┬─────────┘         └────────┬─────────┘     │
│           │                            │               │
│           │ Docker Socket              │ Proxies to    │
│           │ Monitoring                 │ localhost     │
│           ▼                            ▼               │
│  ┌──────────────────┐         ┌──────────────────┐     │
│  │   App Container  │◀────────│  localhost:9080  │     │
│  │   Port 80        │  Mapped │  localhost:9081  │     │
│  │  ports: 9080:80  │◀────────│                  │     │
│  └──────────────────┘         └──────────────────┘     │
│                                                        │
└────────────────────────────────────────────────────────┘
                         │
                         │ Tailscale Network
                         ▼
              ┌─────────────────────┐
              │  Tailnet Clients    │
              │  Access services:   │
              │  web.tailnet.ts.net │
              └─────────────────────┘

Flow: Tailscale → localhost:9080 → Container:80
```

## Examples

### Web Application

```yaml
services:
  nginx:
    image: nginx:latest
    ports:
      - "8080:80"  # HOST:CONTAINER
    labels:
      - "ts-svc.enable=true"
      - "ts-svc.service=web"
      - "ts-svc.target=80"             # CONTAINER port (right side)
```

### Database

```yaml
services:
  postgres:
    image: postgres:16
    ports:
      - "5432:5432"  # HOST:CONTAINER (same on both sides)
    environment:
      POSTGRES_PASSWORD: secret
    labels:
      - "ts-svc.enable=true"
      - "ts-svc.service=db"
      - "ts-svc.port=5432"           # Tailscale port (default: 80)
      - "ts-svc.target=5432"         # CONTAINER port
      - "ts-svc.target-protocol=tcp" # Protocol (default: http)
```

### API (Different Host and Container Ports)

```yaml
services:
  api:
    image: myapi:latest
    ports:
      - "8080:3000"  # HOST:CONTAINER - Host 8080 → Container 3000
    labels:
      - "ts-svc.enable=true"
      - "ts-svc.service=api"
      - "ts-svc.port=443"              # Tailscale port (default: 80)
      - "ts-svc.target=3000"           # CONTAINER port (right side: "8080:3000")
      - "ts-svc.target-protocol=http"  # Protocol (default: http)
```

## Building from Source

```bash
# Build binary
go build -o ts-svc-autopilot .

# Build Docker image
docker build -t ts-svc-autopilot:latest .

# Run locally
./ts-svc-autopilot
```

## Links

- [Tailscale Services Documentation](https://tailscale.com/kb/1552/tailscale-services)
- [Tailscale Service Configuration Reference](https://tailscale.com/kb/1589/tailscale-services-configuration-file)
- [Docker SDK for Go](https://docs.docker.com/engine/api/sdk/)

## License

MIT
