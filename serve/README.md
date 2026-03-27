# WAF++ PASS — Web UI (Internal Serve)

A CISO-friendly web dashboard for WAF++ PASS. Browse, filter, and manage all security controls through a visual interface — no YAML required.

## Features

| Section | Description |
|---------|-------------|
| **Dashboard** | Executive overview with WAF++ score, pillar breakdown, severity charts |
| **Controls Library** | Browse all 70+ controls, filter by pillar/severity, search, manage waivers |
| **Findings** | Detailed results from the latest scan with per-check breakdown |
| **Compliance Matrix** | Which controls map to GDPR, ISO 27001:2022, BSI C5:2020, EUCS, CSRD |
| **Waivers Manager** | Add/edit/remove risk acceptances, export as `.wafpass-skip.yml` |
| **Run Scan** | Trigger a scan against any IaC directory from the browser |

## Quick Start

### 1. Install dependencies

```bash
# From the pass/ directory
pip install fastapi uvicorn

# Or add to your project
pip install "wafpass[web]"
```

### 2. Start the server

```bash
# From the pass/ directory
uvicorn serve.app:app --reload --port 8080

# Or run directly
python -m serve.app
```

### 3. Open the dashboard

```
http://localhost:8080
```

## How It Works

The serve package is a **FastAPI** application that:

1. Reads all WAF++ control YAML files from `../controls/` at startup
2. Injects them as server-side JSON into the Jinja2 HTML template
3. Serves a single-page application using **Alpine.js** for interactivity and **Chart.js** for visualisations
4. Exposes a REST API for scan execution, waiver management, and YAML export

No build step, no Node.js, no bundler — just Python and CDN-loaded JavaScript.

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Main dashboard (HTML) |
| `GET` | `/api/controls` | List all controls as JSON |
| `GET` | `/api/controls/{id}` | Full raw YAML for one control |
| `GET` | `/api/waivers` | Current waivers |
| `PUT` | `/api/waivers` | Save waivers |
| `DELETE` | `/api/waivers/{id}` | Remove a waiver |
| `GET` | `/api/waivers/export` | Download `.wafpass-skip.yml` |
| `POST` | `/api/scan` | Run a scan (body: `{path, iac, pillar}`) |
| `GET` | `/api/results` | Latest scan results |
| `GET` | `/api/docs` | OpenAPI documentation |

## Waiver Workflow

1. Open **Controls Library**
2. Find the control you want to waive (filter by pillar, severity, or search)
3. Click **Add Waiver** or click **Details → Waiver tab**
4. Enter a reason (required), owner, and optional expiry date
5. Click **Save Waiver**
6. Go to **Waivers Manager → Export .wafpass-skip.yml**
7. Copy the downloaded file to your IaC root as `.wafpass-skip.yml`

The waiver file follows the standard WAF++ PASS waiver format and can be used directly with `wafpass check --skip-file .wafpass-skip.yml`.

## File Structure

```
serve/
├── __init__.py        # Package marker
├── app.py             # FastAPI application (routes, scan engine, waiver persistence)
├── waivers.yml        # Auto-created: persisted waivers (gitignore this in production)
├── last_results.json  # Auto-created: cached last scan results
├── templates/
│   └── index.html     # Single-page application (Alpine.js + Chart.js + Tailwind CSS)
└── README.md          # This file
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CONTROLS_DIR` | `../controls/` | Path to WAF++ YAML control files |
| `WAIVERS_FILE` | `./waivers.yml` | Where waivers are persisted |
| `LAST_RESULTS_FILE` | `./last_results.json` | Cached scan results |

To change the controls directory, edit the `CONTROLS_DIR` constant in `app.py`.

## Production Deployment

For production use, consider:

```bash
# Run with multiple workers
uvicorn serve.app:app --host 0.0.0.0 --port 8080 --workers 4

# Or with gunicorn
pip install gunicorn
gunicorn serve.app:app -w 4 -k uvicorn.workers.UvicornWorker
```

Add authentication (e.g., HTTP Basic Auth middleware or a reverse proxy with SSO) before exposing to your network.

## Dependencies

- **fastapi** >= 0.100 — REST API framework
- **uvicorn** — ASGI server
- **pyyaml** — YAML parsing (already a wafpass dependency)

Frontend libraries loaded from CDN (no install needed):
- **Tailwind CSS** 3.x — utility CSS
- **Alpine.js** 3.x — reactive state management
- **Chart.js** 4.x — charts and visualisations
