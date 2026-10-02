# TRACE — AI Incident Investigator

Hackathon MVP for defensive cybersecurity incident reconstruction.

## What it does

1. Upload JSON, JSONL, CSV, or simple key=value security logs.
2. Normalize events.
3. Detect suspicious patterns with deterministic rules.
4. Correlate nearby events by user, IP, and resource.
5. Build a timeline and attack path.
6. Optionally send the correlated evidence to Kimi K3 for an evidence-grounded investigation.

## Run locally

```bash
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS/Linux
# source .venv/bin/activate

pip install -r requirements.txt
uvicorn app:app --reload
```

Open http://127.0.0.1:8000

## Kimi K3

Set:

```text
KIMI_API_KEY=...
KIMI_BASE_URL=https://api.kimi.ai/coding/v1
KIMI_MODEL=k3
```

The backend keeps the API key server-side. Never put it in frontend JavaScript or commit it to GitHub.

## Demo

Click "Load demo incident", then "Investigate Incident".

## Safe-use note

Use only synthetic logs or logs from systems you are authorized to investigate.
TRACE is an incident-analysis prototype, not an automated authorization to take disruptive action.
