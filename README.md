# SentinelFlow

**Real-time network traffic anomaly detection dashboard** using continuous packet capture, ML classification, and web-based visualization.

SentinelFlow monitors client-to-server traffic on a Docker network bridge, analyzes it in two-second windows, classifies each non-empty window using a trained decision-tree model, and displays results in a web dashboard with color-coded traffic status (green = NORMAL, red = ANOMALY, amber = NO TRAFFIC).

## Architecture

```
┌─────────────────────────────────────────────────────┐
│         Docker Compose (Local/Prod)                 │
├─────────────────────┬───────────────────────────────┤
│ Backend (Port 8000) │ Frontend (Port 8080)           │
│                     │                               │
│ FastAPI            │ Angular + Nginx                │
│ + Scapy Capture    │ + Dashboard UI                 │
│ + Model (2-class)  │ + Status Display               │
│ + CORS enabled     │ + Feature Vector               │
│ + 2sec windows     │ + Auto-refresh 2sec            │
└─────────────────────┴───────────────────────────────┘
      ↕ /api/detection (HTTP GET with CORS)
```

## Quick Start

### Using Docker (Recommended)

```bash
docker compose build
docker compose up -d
```

Open dashboard: **http://localhost:8080**

Dashboard shows:
- ✓ **GREEN**: NORMAL traffic (prediction=0)
- ! **RED**: ANOMALY detected (prediction=1)
- · **AMBER**: NO TRAFFIC (empty window)

**Generate test traffic:**
```bash
docker exec sentinel-client python -c "import urllib.request; urllib.request.urlopen('http://172.20.0.3:8000').read(1)"
```

**Check API directly:**
```bash
curl http://localhost:8080/api/detection
```

**Stop:**
```bash
docker compose down
```

### Using Direct Python

**Install and start backend:**
```bash
pip install -r requirements.txt
sudo python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

**Query API:**
```bash
curl http://localhost:8000/api/detection
```

**Or run terminal monitor:**
```bash
sudo python3 detector/traffic_detector.py
```

## Model & Features

**Input Vector (8 features):**
- `packets_per_sec`, `bytes_per_sec`, `connections_per_sec`
- `http_requests_per_sec`, `avg_packet_size`, `min_packet_size`
- `max_packet_size`, `packet_size_std`

**Model:** DecisionTreeClassifier | Classes: 0=NORMAL, 1=ANOMALY | File: `sentinelflow_v2_model.joblib`

**Dashboard Updates:** Every 2 seconds from `/api/detection` endpoint

## GitHub Deployment

### Automated CI/CD with GitHub Actions

Create `.github/workflows/deploy.yml`:

```yaml
name: Build & Deploy SentinelFlow
on:
  push:
    branches: [main, feature/sentinelflow-v2-features]
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build & push backend
        uses: docker/build-push-action@v5
        with:
          context: .
          file: ./backend/Dockerfile
          push: true
          tags: ghcr.io/${{ github.repository_owner }}/sentinelflow-backend:latest

      - name: Build & push frontend
        uses: docker/build-push-action@v5
        with:
          context: ./frontend
          file: ./frontend/Dockerfile
          push: true
          tags: ghcr.io/${{ github.repository_owner }}/sentinelflow-frontend:latest
```

### Deploy to Production

**1. Pull images on server:**
```bash
docker pull ghcr.io/YOUR_USERNAME/sentinelflow-backend:latest
docker pull ghcr.io/YOUR_USERNAME/sentinelflow-frontend:latest
```

**2. Use production Compose:**

Create `docker-compose.prod.yml`:
```yaml
services:
  backend:
    image: ghcr.io/YOUR_USERNAME/sentinelflow-backend:latest
    network_mode: host
    privileged: true
    restart: always
  frontend:
    image: ghcr.io/YOUR_USERNAME/sentinelflow-frontend:latest
    ports: ["8080:80"]
    extra_hosts: ["host.docker.internal:host-gateway"]
    depends_on: [backend]
    restart: always
```

**3. Deploy:**
```bash
docker compose -f docker-compose.prod.yml up -d
```

### Alternative Deployments
- **Kubernetes**: Helm charts with container images from `ghcr.io`
- **AWS**: ECS/Fargate with ECR
- **Self-hosted**: Systemd service wrapping Docker Compose

## File Structure

```
SentinelFlow/
├── backend/
│   ├── main.py                  # FastAPI + CORS
│   └── Dockerfile
├── detector/
│   ├── __init__.py
│   └── traffic_detector.py      # Core detector
├── frontend/
│   ├── src/app/
│   │   ├── app.component.ts     # Angular logic
│   │   ├── app.component.html   # Dashboard
│   │   └── app.component.css    # Styling
│   ├── Dockerfile
│   ├── nginx.conf               # Proxy config
│   └── package.json
├── docker-compose.yml           # Local dev
├── docker-compose.prod.yml      # Production
├── requirements.txt
└── README.md
```

## Legacy Files

- `predict_traffic.py`, `predict_traffic_continuous.py` – Old monitors (removable)
- `collect_normal.py`, `packet_test.py` – Old v1 collectors (removable)
- Keep: `collect_dataset.py`, `train_model_v2.py` (for retraining)
