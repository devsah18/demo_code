import csv
import io
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from openai import OpenAI

BASE_DIR = Path(__file__).resolve().parent
app = FastAPI(title="TRACE - AI Incident Investigator", version="0.1.0")

KIMI_API_KEY = os.getenv("KIMI_API_KEY", "").strip()
KIMI_BASE_URL = os.getenv("KIMI_BASE_URL", "https://api.kimi.ai/coding/v1").strip()
KIMI_MODEL = os.getenv("KIMI_MODEL", "k3").strip()

def parse_time(value: Any):
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None

def first(d: dict, keys, default=None):
    lower = {str(k).lower(): v for k, v in d.items()}
    for key in keys:
        if key in d:
            return d[key]
        if key.lower() in lower:
            return lower[key.lower()]
    return default

def normalize_event(raw: dict, idx: int, source: str):
    timestamp = first(raw, ["timestamp", "time", "datetime", "date"])
    event_type = first(raw, ["event", "event_type", "type", "action", "activity"], "unknown")
    user = first(raw, ["user", "username", "account", "user_id", "actor"], "unknown")
    ip = first(raw, ["ip", "source_ip", "src_ip", "client_ip"], "unknown")
    resource = first(raw, ["resource", "endpoint", "path", "asset", "target"], "unknown")
    status = first(raw, ["status", "result", "outcome"], "unknown")
    size = first(raw, ["bytes", "size", "download_bytes", "export_size"], 0)

    try:
        size_num = float(re.sub(r"[^0-9.]", "", str(size))) if size not in (None, "") else 0
    except ValueError:
        size_num = 0

    text = json.dumps(raw, ensure_ascii=False).lower()
    event_low = str(event_type).lower()

    if "login" in event_low or "auth" in event_low:
        kind = "login"
    elif any(x in event_low for x in ["api", "request", "http"]):
        kind = "api"
    elif any(x in event_low for x in ["database", "db", "query", "sql"]):
        kind = "database"
    elif any(x in event_low for x in ["export", "download", "exfil", "transfer"]):
        kind = "export"
    elif any(x in event_low for x in ["privilege", "role", "admin", "permission"]):
        kind = "privilege"
    else:
        kind = event_low

    suspicious_hints = []
    if any(x in text for x in ["suspicious", "anomalous", "unusual", "impossible travel"]):
        suspicious_hints.append("explicit_anomaly")
    if "failed" in text and "login" in text:
        suspicious_hints.append("failed_login")
    if size_num >= 5_000_000_000:
        suspicious_hints.append("large_export")

    return {
        "id": idx,
        "timestamp": str(timestamp or ""),
        "dt": parse_time(timestamp).isoformat() if parse_time(timestamp) else None,
        "event": str(event_type),
        "kind": kind,
        "user": str(user),
        "ip": str(ip),
        "resource": str(resource),
        "status": str(status),
        "size": size_num,
        "source": source,
        "raw": raw,
        "hints": suspicious_hints,
    }

def parse_file(content: bytes, filename: str):
    name = filename.lower()
    text = content.decode("utf-8", errors="replace").strip()

    if not text:
        return []

    if name.endswith(".csv"):
        rows = list(csv.DictReader(io.StringIO(text)))
        return rows

    # JSON array or single object
    if name.endswith(".json"):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [x for x in data if isinstance(x, dict)]
            if isinstance(data, dict):
                # Accept {"events": [...]}
                if isinstance(data.get("events"), list):
                    return [x for x in data["events"] if isinstance(x, dict)]
                return [data]
        except json.JSONDecodeError:
            pass

    # JSONL fallback
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                rows.append(obj)
                continue
        except json.JSONDecodeError:
            pass

        # Basic key=value log support
        pairs = dict(re.findall(r'([A-Za-z_]+)=(".*?"|\S+)', line))
        if pairs:
            rows.append({k: v.strip('"') for k, v in pairs.items()})

    return rows

def correlate(events):
    events.sort(key=lambda e: e["dt"] or "")
    by_user = defaultdict(list)
    for e in events:
        by_user[e["user"]].append(e)

    suspicious = []
    correlated = []

    for e in events:
        score = 0
        reasons = []

        if "explicit_anomaly" in e["hints"]:
            score += 3
            reasons.append("explicit anomaly marker")
        if "failed_login" in e["hints"]:
            score += 2
            reasons.append("failed authentication activity")
        if e["kind"] == "export" and e["size"] >= 5_000_000_000:
            score += 4
            reasons.append("large data export")
        if e["kind"] in {"database", "privilege"}:
            score += 2
            reasons.append("sensitive or privileged activity")

        user_events = by_user.get(e["user"], [])
        if e["kind"] == "login":
            recent = user_events[max(0, user_events.index(e) - 5): user_events.index(e)]
            distinct_ips = {x["ip"] for x in recent if x["ip"] != "unknown"}
            if distinct_ips and e["ip"] != "unknown" and e["ip"] not in distinct_ips:
                score += 3
                reasons.append("new source IP for account")

        if score >= 2:
            suspicious.append({
                "event_id": e["id"],
                "score": score,
                "reasons": reasons,
            })

    suspicious_ids = {x["event_id"] for x in suspicious}

    # Correlate nearby events sharing user, IP, or resource.
    for i, e in enumerate(events):
        if e["id"] in suspicious_ids:
            correlated.append(e)
            continue
        nearby = events[max(0, i - 3): i + 4]
        linked = any(
            x["id"] in suspicious_ids and (
                (e["user"] != "unknown" and e["user"] == x["user"]) or
                (e["ip"] != "unknown" and e["ip"] == x["ip"]) or
                (e["resource"] != "unknown" and e["resource"] == x["resource"])
            )
            for x in nearby if x["id"] != e["id"]
        )
        if linked:
            correlated.append(e)

    correlated = sorted({e["id"]: e for e in correlated}.values(), key=lambda e: e["dt"] or "")
    return suspicious, correlated

def build_deterministic_report(events, suspicious, correlated):
    users = [e["user"] for e in correlated if e["user"] != "unknown"]
    resources = [e["resource"] for e in correlated if e["resource"] != "unknown"]

    compromised_user = max(set(users), key=users.count) if users else "unknown"
    affected_resource = next(
        (e["resource"] for e in reversed(correlated)
         if e["kind"] in {"database", "export"} and e["resource"] != "unknown"),
        (resources[-1] if resources else "unknown")
    )

    has_login = any(e["kind"] == "login" for e in correlated)
    has_db = any(e["kind"] == "database" for e in correlated)
    has_export = any(e["kind"] == "export" and e["size"] >= 5_000_000_000 for e in correlated)
    has_priv = any(e["kind"] == "privilege" for e in correlated)

    if has_export and has_db and has_login:
        incident = "Possible account compromise with data exfiltration"
        severity = "HIGH"
        actions = [
            "Revoke active sessions for the affected account",
            "Rotate credentials and review MFA events",
            "Investigate accessed and exported records",
            "Review activity from the same IP/session"
        ]
    elif has_priv and has_login:
        incident = "Possible account compromise with privilege escalation"
        severity = "HIGH"
        actions = [
            "Revoke the affected session",
            "Rotate credentials",
            "Review privilege changes and admin activity",
            "Audit resources accessed after escalation"
        ]
    elif has_login and len(suspicious) >= 2:
        incident = "Suspicious authentication activity"
        severity = "MEDIUM"
        actions = [
            "Review authentication history",
            "Challenge or revoke the suspicious session",
            "Enable or verify MFA",
            "Monitor follow-on resource access"
        ]
    elif suspicious:
        incident = "Suspicious activity requiring investigation"
        severity = "MEDIUM"
        actions = [
            "Review the flagged events",
            "Verify the account and source IP",
            "Monitor subsequent activity"
        ]
    else:
        incident = "No clear incident detected"
        severity = "LOW"
        actions = ["Continue monitoring and retain logs for investigation"]

    evidence = []
    for e in correlated[:12]:
        evidence.append({
            "time": e["timestamp"],
            "event": e["event"],
            "user": e["user"],
            "ip": e["ip"],
            "resource": e["resource"],
            "reason": next(
                (", ".join(x["reasons"]) for x in suspicious if x["event_id"] == e["id"]),
                "correlated with nearby suspicious activity"
            ),
        })

    nodes = []
    seen = set()
    for e in correlated:
        for label, value, kind in [
            ("IP", e["ip"], "ip"),
            ("Account", e["user"], "user"),
            ("Resource", e["resource"], "resource"),
            ("Event", e["event"], "event"),
        ]:
            if value == "unknown" or not value:
                continue
            key = (kind, value)
            if key not in seen:
                seen.add(key)
                nodes.append({"kind": kind, "label": label, "value": value})

    # Build a simple graph path based on the most relevant event chain.
    graph = {
        "nodes": nodes[:30],
        "edges": []
    }

    previous = None
    for e in correlated:
        current = None
        if e["kind"] == "login":
            current = ("user", e["user"])
        elif e["kind"] == "api":
            current = ("event", e["event"])
        elif e["kind"] == "privilege":
            current = ("event", e["event"])
        elif e["kind"] == "database":
            current = ("resource", e["resource"])
        elif e["kind"] == "export":
            current = ("event", e["event"])

        if current and previous:
            graph["edges"].append({
                "from": {"kind": previous[0], "value": previous[1]},
                "to": {"kind": current[0], "value": current[1]},
            })
        if current:
            previous = current

    return {
        "incident": incident,
        "initial_event": correlated[0]["event"] if correlated else "None",
        "compromised_account": compromised_user,
        "affected_resource": affected_resource,
        "severity": severity,
        "confidence": min(98, 55 + len(suspicious) * 4 + (15 if has_export else 0) + (8 if has_db else 0)),
        "evidence_count": len(correlated),
        "recommended_actions": actions,
        "evidence": evidence,
        "graph": graph,
    }

def kimi_investigate(report, correlated):
    if not KIMI_API_KEY:
        return report

    evidence_payload = []
    for e in correlated[:40]:
        evidence_payload.append({
            "timestamp": e["timestamp"],
            "event": e["event"],
            "kind": e["kind"],
            "user": e["user"],
            "ip": e["ip"],
            "resource": e["resource"],
            "status": e["status"],
            "size": e["size"],
        })

    prompt = f"""
You are TRACE, a defensive cybersecurity incident investigator.
Analyze the correlated evidence below. Do not provide attack instructions.
Return ONLY valid JSON with exactly these keys:
incident, initial_event, compromised_account, affected_resource,
severity, confidence, recommended_actions, evidence

severity must be LOW, MEDIUM, HIGH, or CRITICAL.
confidence must be an integer from 0 to 100 and should be described as model confidence,
not a calibrated probability.
recommended_actions must be an array of short defensive actions.
evidence must be an array of objects with keys: time, event, reason.

Be conservative: distinguish suspicious activity from confirmed compromise.
Do not invent facts not present in the evidence.

Deterministic preliminary report:
{json.dumps(report, ensure_ascii=False)}

Correlated evidence:
{json.dumps(evidence_payload, ensure_ascii=False)}
"""

    try:
        client = OpenAI(api_key=KIMI_API_KEY, base_url=KIMI_BASE_URL)
        response = client.chat.completions.create(
            model=KIMI_MODEL,
            temperature=0.1,
            messages=[
                {"role": "system", "content": "You produce concise, evidence-grounded defensive incident investigations."},
                {"role": "user", "content": prompt},
            ],
        )
        content = response.choices[0].message.content or ""
        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"^```(?:json)?\s*", "", content)
            content = re.sub(r"\s*```$", "", content)
        ai = json.loads(content)

        for key in ["incident", "initial_event", "compromised_account", "affected_resource",
                    "severity", "confidence", "recommended_actions", "evidence"]:
            if key not in ai:
                raise ValueError(f"Missing key: {key}")

        ai["graph"] = report["graph"]
        ai["evidence_count"] = report["evidence_count"]
        return ai
    except Exception as exc:
        report["ai_error"] = f"Kimi investigation unavailable; deterministic report shown. ({type(exc).__name__})"
        return report

@app.get("/")
def home():
    return FileResponse(BASE_DIR / "static" / "index.html")

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "kimi_configured": bool(KIMI_API_KEY),
        "model": KIMI_MODEL,
        "base_url": KIMI_BASE_URL,
    }

@app.post("/api/investigate")
async def investigate(files: list[UploadFile] = File(...)):
    all_events = []
    raw_count = 0

    for upload in files:
        content = await upload.read()
        rows = parse_file(content, upload.filename or "upload.log")
        raw_count += len(rows)
        for idx, row in enumerate(rows):
            if isinstance(row, dict):
                all_events.append(normalize_event(row, len(all_events) + 1, upload.filename or "upload"))

    if not all_events:
        return JSONResponse({"error": "No readable events found in the uploaded files."}, status_code=400)

    suspicious, correlated = correlate(all_events)
    report = build_deterministic_report(all_events, suspicious, correlated)
    report = kimi_investigate(report, correlated)

    return {
        "stats": {
            "events_analyzed": raw_count,
            "events_normalized": len(all_events),
            "anomalies": len(suspicious),
            "correlated_events": len(correlated),
        },
        "report": report,
        "timeline": [
            {
                "time": e["timestamp"],
                "event": e["event"],
                "kind": e["kind"],
                "user": e["user"],
                "resource": e["resource"],
                "ip": e["ip"],
            }
            for e in correlated
        ],
    }
