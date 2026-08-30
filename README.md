# Nutanix Storage Sniffer

Nutanix Storage Sniffer is a FastAPI + static web UI tool to analyze Nutanix storage Pool data and visualize VDisk usage, chain relationships, and shared storage reference.

## Features

- Live CVM collection and offline log analysis modes
- Treemap-style storage visualization by container/entity
- Chain-v2 shared storage model with chain-tree selection
- VDisk lineage/family navigation (parent/children)
- VM/VG mapping and inspector drill-down panels
- Legend filters and customizable color palette

## Project Structure

- `app/main.py` - API server and storage processing pipelines
- `app/parser.py` - parsers for `ncli`, curator, and vdisk logs
- `app/cvm_collector.py` - live CVM command collection workflow
- `app/static/index.html` - main UI (treemap + inspector)
- `app/model_chain.py` - chain-v2 dataclasses/models
- `collect_offline_log.py` - offline data collection helper script

## Requirements

- Python 3.11+
- Docker + Docker Compose (recommended runtime)

## Run with Docker

```bash
docker compose up -d --build vdisk-sniffer
docker compose logs -f vdisk-sniffer
```

The app runs on `http://localhost:8000` unless overridden by your compose configuration.

## Local Run (without Docker)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## Usage

1. Open the web UI http://ipaddress:8000.
2. Choose **Live CVM** or **Offline Mode**.
3. Run analysis to load the storage tree.
4. Use treemap selection, inspector, search, and legend filters to investigate usage and shared storage behavior.

## Notes

- Shared storage estimates depend on available curator and chain logs.
- For large environments, offline mode is useful for reproducible debugging and comparisons.
