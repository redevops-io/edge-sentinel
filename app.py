"""edge-sentinel — agentic SOC module wrapping the running CrowdSec core.

Sibling of agents/billing (the reference vertical slice). Same pattern, new core:
wraps the self-hosted **CrowdSec** instance (the OSS detection/decision engine) with

  * an agent layer that reads REAL CrowdSec data (live decisions over the LAPI bouncer
    API + alerts via `cscli ... -o json`), and
  * an MD3 SOC dashboard (same design tokens as deploy/module_service.py) rendered from
    that live data — no mock data.

Pattern, mapped from billing → edge-sentinel:
  1. point CORE at the running CrowdSec LAPI + a bouncer API key,
  2. `fetch_activity` pulls real decisions + alerts + a `compute_kpis`,
  3. reuse BASE_CSS + the SOC render helpers below,
  4. add agentic actions in /agent/run that are deterministic core calls, with a
     human-approval gate on anything that BLOCKS traffic (block_ip → approve_block).

Endpoints:
  GET  /health        -> {"status","core":"crowdsec","connected": <bool>}
  GET  /api/activity  -> live KPIs + decisions + alerts derived from CrowdSec
  GET  /              -> MD3 SOC dashboard rendered from the live data
  POST /agent/run     -> agentic action:
                           {"action":"block_ip","ip":...}      -> pending_approval
                           {"action":"approve_block","ip":...}  -> real cscli ban
                           {"action":"triage"}                  -> summarize alerts

Config (env; seed.py writes agents/edge-sentinel/.env automatically):
  CROWDSEC_LAPI_URL   LAPI base, default http://localhost:8086
  CROWDSEC_BOUNCER_KEY  X-Api-Key for GET /v1/decisions (from `cscli bouncers add`)
  CROWDSEC_CONTAINER  docker container name, default agentic-cores-crowdsec-1
  CROWDSEC_FRONT_URL  link for the "Open CrowdSec metrics" button
  PORT                uvicorn port, default 8203
  ANTHROPIC_API_KEY   OPTIONAL — if set, `triage` adds an LLM reasoning blurb;
                      the endpoint works fully without it.
"""
from __future__ import annotations

import html
import json
import os
import subprocess
import time
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

# --- config ------------------------------------------------------------------
# Load agents/edge-sentinel/.env (written by seed.py) without a python-dotenv dep.
_ENV_FILE = Path(__file__).resolve().parent / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

CROWDSEC_LAPI_URL = os.environ.get("CROWDSEC_LAPI_URL", "http://localhost:8086").rstrip("/")
CROWDSEC_BOUNCER_KEY = os.environ.get("CROWDSEC_BOUNCER_KEY", "")
CROWDSEC_CONTAINER = os.environ.get("CROWDSEC_CONTAINER", "agentic-cores-crowdsec-1")
CROWDSEC_FRONT_URL = os.environ.get("CROWDSEC_FRONT_URL", "http://192.168.40.8:8086").rstrip("/")
# How to invoke docker for `cscli` (alerts/bans). On the host this needs `sudo docker`;
# inside the integrated container we run as root with the docker socket mounted, so
# DOCKER_CMD="docker" (no sudo). Override via env.
DOCKER_CMD = os.environ.get("DOCKER_CMD", "sudo docker").split()
PORT = int(os.environ.get("PORT", "8203"))

TENANT = "Summit Roofing Co."
SUBTITLE = "Network security & systems, triaged and explained by an agent — on a real CrowdSec core, with a human in the loop before any block."

app = FastAPI(title="edge-sentinel (Summit Roofing Co. · core: CrowdSec)")


# --- CrowdSec clients --------------------------------------------------------
# Two read paths, same as the prompt prescribes:
#   * decisions: GET /v1/decisions on the LAPI using the bouncer X-Api-Key.
#   * alerts:    `cscli alerts list -o json` shelled out via docker exec (LAPI alert
#                auth needs a machine login; cscli is the simplest reliable path).
def _cscli(args: list[str]) -> tuple[int, str, str]:
    """Run `cscli <args>` inside the CrowdSec container. `sudo` for the docker socket."""
    cmd = [*DOCKER_CMD, "exec", CROWDSEC_CONTAINER, "cscli", *args]
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=20)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def crowdsec_connected() -> bool:
    """True iff the LAPI answers (any HTTP status means the service is up)."""
    try:
        r = httpx.get(f"{CROWDSEC_LAPI_URL}/health", timeout=3.0)
        # CrowdSec LAPI has no public /health; a TCP+HTTP response (even 404) is "up".
        return r.status_code < 500
    except Exception:
        try:
            r = httpx.get(f"{CROWDSEC_LAPI_URL}/", timeout=3.0)
            return r.status_code < 500
        except Exception:
            return False


def fetch_decisions() -> list[dict]:
    """Live active decisions via the LAPI bouncer endpoint (GET /v1/decisions)."""
    if not CROWDSEC_BOUNCER_KEY:
        return []
    try:
        r = httpx.get(
            f"{CROWDSEC_LAPI_URL}/v1/decisions",
            headers={"X-Api-Key": CROWDSEC_BOUNCER_KEY},
            timeout=8.0,
        )
        r.raise_for_status()
        return r.json() or []
    except Exception:
        return []


def fetch_alerts() -> list[dict]:
    """Recent alerts via `cscli alerts list -o json` (docker exec)."""
    rc, out, _err = _cscli(["alerts", "list", "-o", "json"])
    if rc != 0 or not out.strip():
        return []
    try:
        return json.loads(out) or []
    except Exception:
        return []


# --- live data + KPIs (cached briefly) ---------------------------------------
_CACHE: dict = {"ts": 0.0, "data": None}
_CACHE_TTL = 10.0  # seconds — keep the dashboard snappy without hammering CrowdSec


# Map a scenario / reason string to a SOC severity bucket + display pill class.
def _severity(scenario: str) -> str:
    s = (scenario or "").lower()
    if any(k in s for k in ("bruteforce", "brute", "-bf", "credential", "exploit", "rce", "malware", "c2")):
        return "critical"
    if any(k in s for k in ("probing", "probe", "traversal", "injection", "http-", "web")):
        return "high"
    if any(k in s for k in ("scan", "nmap", "port")):
        return "medium"
    return "low"


def _short_scenario(scenario: str) -> str:
    """Pull the crowdsecurity/<name> token when present, else the raw text."""
    if not scenario:
        return "—"
    for tok in scenario.replace("(", " ").replace(")", " ").split():
        if "/" in tok:
            return tok
    return scenario


def _ago(iso: str) -> str:
    if not iso:
        return "—"
    try:
        from datetime import datetime, timezone

        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        secs = (datetime.now(timezone.utc) - t).total_seconds()
        if secs < 60:
            return f"{int(secs)}s ago"
        if secs < 3600:
            return f"{int(secs // 60)}m ago"
        if secs < 86400:
            return f"{int(secs // 3600)}h ago"
        return f"{int(secs // 86400)}d ago"
    except Exception:
        return iso[:16].replace("T", " ")


def fetch_activity(force: bool = False) -> dict:
    """Pull REAL CrowdSec data and compute the SOC KPIs the dashboard renders."""
    now = time.time()
    if not force and _CACHE["data"] is not None and now - _CACHE["ts"] < _CACHE_TTL:
        return _CACHE["data"]

    connected = crowdsec_connected()
    decisions = fetch_decisions() if connected else []
    alerts = fetch_alerts() if connected else []

    # --- decisions table (active bans) ---
    decision_rows = []
    for d in decisions:
        scenario = d.get("scenario", "")
        decision_rows.append({
            "value": d.get("value", "—"),
            "scope": d.get("scope", "Ip"),
            "scenario": _short_scenario(scenario),
            "scenario_full": scenario,
            "type": (d.get("type") or "ban").upper(),
            "duration": (d.get("duration") or "").split(".")[0],
            "origin": d.get("origin", "—"),
            "severity": _severity(scenario),
        })
    decision_rows.sort(key=lambda r: {"critical": 0, "high": 1, "medium": 2, "low": 3}[r["severity"]])

    # --- alert feed (newest first) ---
    alert_rows = []
    for a in alerts:
        scenario = a.get("scenario", "")
        src = a.get("source") or {}
        alert_rows.append({
            "scenario": _short_scenario(scenario),
            "scenario_full": scenario,
            "source": src.get("value") or src.get("ip") or "—",
            "scope": src.get("scope", "Ip"),
            "events": a.get("events_count", 0),
            "created_at": a.get("created_at", ""),
            "ago": _ago(a.get("created_at", "")),
            "severity": _severity(scenario),
        })
    alert_rows.sort(key=lambda r: r["created_at"], reverse=True)

    # --- KPIs straight from the live data ---
    active_bans = len([d for d in decisions if (d.get("type") or "ban") == "ban"])

    from datetime import datetime, timezone, timedelta

    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    def _within_24h(iso: str) -> bool:
        try:
            return datetime.fromisoformat(iso.replace("Z", "+00:00")) >= cutoff
        except Exception:
            return True  # if unparseable, count it rather than hide it

    alerts_24h = len([a for a in alerts if _within_24h(a.get("created_at", ""))])

    # top scenarios by count across alerts
    scenario_counts: dict[str, int] = {}
    for a in alerts:
        key = _short_scenario(a.get("scenario", ""))
        scenario_counts[key] = scenario_counts.get(key, 0) + 1
    top_scenarios = sorted(scenario_counts.items(), key=lambda kv: kv[1], reverse=True)

    unique_sources = len({(d.get("value") or "") for d in decisions if d.get("value")})

    last_event = alert_rows[0]["ago"] if alert_rows else "—"

    # threat banner state: any active blocking decision = active threat handled
    has_threat = active_bans > 0

    # scenario bars (% of total alerts) for the SOC "blocked by category" meter
    total_alerts = max(sum(scenario_counts.values()), 1)
    bar_items = [
        {"label": k, "pct": int(round(100 * v / total_alerts)), "count": v}
        for k, v in top_scenarios[:5]
    ]

    data = {
        "tenant": TENANT,
        "core": "crowdsec",
        "connected": connected,
        "front_url": CROWDSEC_FRONT_URL,
        "has_threat": has_threat,
        "kpis": [
            {"label": "Threats blocked", "value": str(active_bans), "note": "active decisions enforced"},
            {"label": "Alerts (24h)", "value": str(alerts_24h), "note": f"{len(alerts)} total in store"},
            {"label": "Source IPs", "value": str(unique_sources), "note": "unique blocked sources"},
            {"label": "Last event", "value": last_event, "note": top_scenarios[0][0] if top_scenarios else "—"},
        ],
        "decisions": decision_rows,
        "alerts": alert_rows,
        "top_scenarios": [{"scenario": k, "count": v} for k, v in top_scenarios],
        "bars": bar_items,
        "counts": {"decisions": len(decisions), "alerts": len(alerts), "sources": unique_sources},
    }
    _CACHE.update(ts=now, data=data)
    return data


# --- MD3 styling (BASE_CSS reused verbatim from deploy/module_service.py) -----
BASE_CSS = """
:root{
  --surface-dim:#0e0e11; --surface:#131316; --surface-bright:#393a3d;
  --surface-container-lowest:#0d0e10; --surface-container-low:#1b1b1f;
  --surface-container:#1f1f23; --surface-container-high:#2a2a2e; --surface-container-highest:#353539;
  --on-surface:#e4e2e6; --on-surface-variant:#c7c5ca; --on-surface-muted:#918f96;
  --outline:#938f99; --outline-variant:#2f2f33;
  --primary:#4fd1c5; --on-primary:#00201c; --primary-container:#00504a; --on-primary-container:#a8f0e6;
  --secondary:#f5b544; --on-secondary:#3d2e00; --secondary-container:#5c4500;
  --success:#5bd98a; --success-container:#0f3d22; --warning:#f5b544; --warning-container:#4a3500;
  --danger:#f2544f; --danger-container:#5c1512; --info:#5aa9f0; --info-container:#103a5c;
  --sp-1:4px;--sp-2:8px;--sp-3:12px;--sp-4:16px;--sp-5:24px;--sp-6:32px;--sp-7:40px;--sp-8:48px;
  --radius-sm:8px;--radius-md:12px;--radius-lg:16px;--radius-xl:28px;--radius-pill:999px;
  --shadow-1:0 1px 2px rgba(0,0,0,.45);--shadow-2:0 2px 6px rgba(0,0,0,.5);
  --font-sans:"Roboto",system-ui,-apple-system,"Segoe UI",sans-serif;
  --font-mono:"Roboto Mono",ui-monospace,"SF Mono",monospace;
}
*{box-sizing:border-box}
.display-l{font:400 57px/64px var(--font-sans);letter-spacing:-.25px}
.headline-m{font:400 28px/36px var(--font-sans)} .headline-s{font:400 24px/32px var(--font-sans)}
.title-l{font:400 22px/28px var(--font-sans)} .title-m{font:500 16px/24px var(--font-sans);letter-spacing:.15px}
.title-s{font:500 14px/20px var(--font-sans)} .body-m{font:400 14px/20px var(--font-sans)}
.body-s{font:400 12px/16px var(--font-sans)} .label-m{font:500 12px/16px var(--font-sans);letter-spacing:.5px}
.page{background:var(--surface);color:var(--on-surface);font-family:var(--font-sans);padding:var(--sp-5);margin:0}
.shell{max-width:1440px;margin-inline:auto;display:flex;flex-direction:column;gap:var(--sp-5)}
.grid{display:grid;gap:var(--sp-4);grid-template-columns:repeat(12,1fr)}
.kpi-row{display:grid;gap:var(--sp-4);grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
.col-3{grid-column:span 3}.col-4{grid-column:span 4}.col-6{grid-column:span 6}.col-8{grid-column:span 8}.col-12{grid-column:span 12}
@media(max-width:839px){[class^="col-"]{grid-column:span 12}}
.card{background:var(--surface-container);border:1px solid var(--outline-variant);border-radius:var(--radius-lg);padding:var(--sp-5);display:flex;flex-direction:column;gap:var(--sp-4)}
.card__head{display:flex;align-items:center;justify-content:space-between;gap:var(--sp-3)}
.card__title{font:500 16px/24px var(--font-sans);letter-spacing:.15px;color:var(--on-surface);margin:0}
.tile{background:var(--surface-container);border:1px solid var(--outline-variant);border-radius:var(--radius-lg);padding:var(--sp-4) var(--sp-5);display:flex;flex-direction:column;gap:var(--sp-1)}
.tile__label{font:500 12px/16px var(--font-sans);letter-spacing:.5px;text-transform:uppercase;color:var(--on-surface-muted)}
.tile__value{font:500 32px/40px var(--font-mono);color:var(--on-surface);font-feature-settings:"tnum"}
.tile__delta{font:500 12px/16px var(--font-sans);color:var(--on-surface-variant)} .tile__delta--up{color:var(--success)} .tile__delta--down{color:var(--danger)}
.pill{display:inline-flex;align-items:center;gap:6px;height:24px;padding:0 10px;border-radius:var(--radius-pill);font:500 12px/1 var(--font-sans)}
.pill--success{background:var(--success-container);color:var(--success)}.pill--warn{background:var(--warning-container);color:var(--warning)}
.pill--danger{background:var(--danger-container);color:var(--danger)}.pill--info{background:var(--info-container);color:var(--info)}
.pill--neutral{background:var(--surface-container-highest);color:var(--on-surface-variant)}
.pill__dot{width:6px;height:6px;border-radius:50%;background:currentColor}
.table{width:100%;border-collapse:collapse;font-size:14px}
.table th{text-align:left;color:var(--on-surface-muted);font:500 12px/16px var(--font-sans);letter-spacing:.5px;text-transform:uppercase;padding:var(--sp-3) var(--sp-4);border-bottom:1px solid var(--outline-variant)}
.table td{padding:var(--sp-3) var(--sp-4);color:var(--on-surface);border-bottom:1px solid var(--outline-variant)}
.table td.num{text-align:right;font-family:var(--font-mono);font-feature-settings:"tnum"}
.table tbody tr:last-child td{border-bottom:none}
.table tbody tr:hover{background:rgba(228,226,230,.08)}
.banner{display:flex;align-items:center;gap:var(--sp-4);padding:var(--sp-4) var(--sp-5);border-radius:var(--radius-md);border-left:4px solid var(--warning);background:var(--warning-container);color:var(--on-surface)}
.bar{height:8px;border-radius:var(--radius-pill);background:var(--surface-container-highest);overflow:hidden}
.bar>span{display:block;height:100%;background:var(--primary)}
"""

PAGE_CSS = """
a{color:var(--primary);text-decoration:none}
.appbar{background:var(--surface-container-low);border:1px solid var(--outline-variant);border-radius:var(--radius-lg);padding:var(--sp-5) var(--sp-5)}
.appbar__row{display:flex;align-items:center;gap:var(--sp-3);flex-wrap:wrap}
.appbar h1{margin:0;font:400 28px/36px var(--font-sans);color:var(--on-surface)}
.appbar__tenant{margin-top:var(--sp-3);color:var(--on-surface-variant);font:400 14px/20px var(--font-sans)}
.appbar__tenant b{color:var(--on-surface)}
.appbar__sub{margin-top:var(--sp-2);color:var(--on-surface-muted);font:400 14px/20px var(--font-sans);max-width:820px}
.spacer{flex:1}
.btn{display:inline-flex;align-items:center;gap:6px;height:36px;padding:0 16px;border-radius:var(--radius-pill);background:var(--primary-container);color:var(--on-primary-container);font:500 14px/1 var(--font-sans);border:1px solid var(--primary-container)}
.btn:hover{filter:brightness(1.1)}
.section-label{font:500 12px/16px var(--font-sans);letter-spacing:.5px;text-transform:uppercase;color:var(--primary);display:flex;align-items:center;gap:var(--sp-3);margin:0}
.section-label::after{content:"";flex:1;height:1px;background:var(--outline-variant)}
.barlist{display:flex;flex-direction:column;gap:var(--sp-4)}
.barlist__row{display:grid;grid-template-columns:200px 1fr 56px;align-items:center;gap:var(--sp-4)}
.barlist__label{color:var(--on-surface-variant);font:400 13px/18px var(--font-mono)}
.barlist__pct{text-align:right;font-family:var(--font-mono);font-feature-settings:"tnum";font-size:13px;color:var(--on-surface-variant)}
.footer{color:var(--on-surface-muted);font:400 12px/16px var(--font-sans);text-align:center;padding-top:var(--sp-2)}
.status-banner{display:flex;align-items:center;gap:var(--sp-4);padding:var(--sp-4) var(--sp-5);border-radius:var(--radius-md);border-left:4px solid var(--success);background:var(--success-container);color:var(--on-surface)}
.status-banner--threat{border-left-color:var(--danger);background:var(--danger-container)}
.status-banner__icon{font-size:20px;line-height:1}
.feed{display:flex;flex-direction:column}
.feed__row{display:flex;align-items:center;gap:var(--sp-4);padding:var(--sp-3) 0;border-bottom:1px solid var(--outline-variant)}
.feed__row:last-child{border-bottom:none}
.feed__sev{flex:0 0 auto}
.feed__main{flex:1;min-width:0}
.feed__scenario{font:500 14px/20px var(--font-mono);color:var(--on-surface)}
.feed__meta{font:400 12px/16px var(--font-sans);color:var(--on-surface-muted)}
.feed__src{font-family:var(--font-mono);color:var(--on-surface-variant)}
.feed__time{flex:0 0 auto;font:400 12px/16px var(--font-mono);color:var(--on-surface-muted)}
.mono{font-family:var(--font-mono);font-feature-settings:"tnum"}
"""

FONT_LINK = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
    'family=Roboto:wght@400;500&family=Roboto+Mono:wght@400;500&display=swap">'
)


def _esc(v) -> str:
    return html.escape(str(v))


_SEV_PILL = {
    "critical": "pill--danger",
    "high": "pill--warn",
    "medium": "pill--info",
    "low": "pill--neutral",
}


def _sev_pill(sev: str, label: str | None = None) -> str:
    cls = _SEV_PILL.get(sev, "pill--neutral")
    return f"<span class='pill {cls}'><span class='pill__dot'></span>{_esc(label or sev.upper())}</span>"


def _kpi_tiles(kpis: list[dict]) -> str:
    cells = ""
    for k in kpis:
        cells += (
            "<div class='tile'>"
            f"<div class='tile__label'>{_esc(k['label'])}</div>"
            f"<div class='tile__value'>{_esc(k['value'])}</div>"
            f"<div class='tile__delta'>{_esc(k['note'])}</div>"
            "</div>"
        )
    return f"<section class='kpi-row'>{cells}</section>"


def _status_banner(data: dict) -> str:
    """Green 'All systems normal' / red when there's an active threat being handled."""
    if not data["connected"]:
        return (
            "<div class='status-banner status-banner--threat'>"
            "<span class='status-banner__icon'>!</span>"
            "<span class='pill pill--danger'><span class='pill__dot'></span>CORE UNREACHABLE</span>"
            "<span class='body-m'>CrowdSec LAPI is not responding — detections cannot be read.</span>"
            "</div>"
        )
    if data["has_threat"]:
        crit = [a for a in data["alerts"] if a["severity"] == "critical"]
        n = len(data["decisions"])
        top = data["alerts"][0]["scenario"] if data["alerts"] else "—"
        return (
            "<div class='status-banner status-banner--threat'>"
            "<span class='status-banner__icon'>&#9888;</span>"
            f"<span class='pill pill--danger'><span class='pill__dot'></span>ACTIVE THREATS · {n} blocked</span>"
            f"<span class='body-m'>{len(crit)} critical · agent is enforcing {n} block decision(s) at the edge. "
            f"Latest: <span class='mono'>{_esc(top)}</span>. Sensitive blocks are human-approved.</span>"
            "</div>"
        )
    return (
        "<div class='status-banner'>"
        "<span class='status-banner__icon'>&#10003;</span>"
        "<span class='pill pill--success'><span class='pill__dot'></span>All systems normal</span>"
        "<span class='body-m'>No active block decisions. CrowdSec is monitoring; the agent is on watch.</span>"
        "</div>"
    )


def _alert_feed(data: dict) -> str:
    """Alert feed grouped by severity with color pills."""
    order = ["critical", "high", "medium", "low"]
    by_sev: dict[str, list[dict]] = {s: [] for s in order}
    for a in data["alerts"]:
        by_sev.setdefault(a["severity"], []).append(a)

    rows = ""
    for sev in order:
        for a in by_sev.get(sev, []):
            rows += (
                "<div class='feed__row'>"
                f"<div class='feed__sev'>{_sev_pill(sev)}</div>"
                "<div class='feed__main'>"
                f"<div class='feed__scenario'>{_esc(a['scenario'])}</div>"
                f"<div class='feed__meta'>from <span class='feed__src'>{_esc(a['source'])}</span> "
                f"· {_esc(a['scope'])} · {_esc(a['events'])} event(s)</div>"
                "</div>"
                f"<div class='feed__time'>{_esc(a['ago'])}</div>"
                "</div>"
            )
    if not rows:
        rows = "<div class='feed__row'><div class='feed__meta'>No alerts in the CrowdSec store.</div></div>"
    return (
        "<div class='card'>"
        "<div class='card__head'><h2 class='card__title'>Alert feed · by severity</h2>"
        "<span class='pill pill--info'><span class='pill__dot'></span>data: live from CrowdSec</span></div>"
        f"<div class='feed'>{rows}</div>"
        "</div>"
    )


def _scenario_bars(data: dict) -> str:
    body = ""
    for item in data["bars"]:
        body += (
            "<div class='barlist__row'>"
            f"<div class='barlist__label'>{_esc(item['label'])}</div>"
            f"<div class='bar'><span style='width:{int(item['pct'])}%'></span></div>"
            f"<div class='barlist__pct'>{_esc(item['count'])}</div>"
            "</div>"
        )
    if not body:
        body = "<div class='barlist__label'>No scenarios recorded.</div>"
    return (
        "<div class='card'>"
        "<div class='card__head'><h2 class='card__title'>Detections by scenario (live)</h2></div>"
        f"<div class='barlist'>{body}</div>"
        "</div>"
    )


def _decisions_table(data: dict) -> str:
    rows = ""
    for d in data["decisions"]:
        rows += (
            "<tr>"
            f"<td class='mono'>{_esc(d['value'])}</td>"
            f"<td>{_esc(d['scope'])}</td>"
            f"<td class='mono'>{_esc(d['scenario'])}</td>"
            f"<td>{_sev_pill(d['severity'])}</td>"
            f"<td class='mono'>{_esc(d['duration'])}</td>"
            f"<td><span class='pill pill--danger'>{_esc(d['type'])}</span></td>"
            "</tr>"
        )
    if not rows:
        rows = "<tr><td colspan='6'>No active decisions.</td></tr>"
    return (
        "<div class='card'>"
        "<div class='card__head'><h2 class='card__title'>Attack sources · active decisions</h2>"
        "<span class='pill pill--info'><span class='pill__dot'></span>GET /v1/decisions</span></div>"
        "<table class='table'><thead><tr>"
        "<th>Source</th><th>Scope</th><th>Scenario</th><th>Severity</th><th>Expires in</th><th>Action</th>"
        "</tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "</div>"
    )


def render(data: dict) -> str:
    connected = data["connected"]
    conn_txt = "core: CrowdSec connected" if connected else "core: CrowdSec UNREACHABLE"
    conn_cls = "pill--success" if connected else "pill--danger"
    status_pill = (
        f"<span class='pill {conn_cls}'><span class='pill__dot'></span>agent active · {_esc(conn_txt)}</span>"
    )
    live_badge = "<span class='pill pill--info'><span class='pill__dot'></span>data: live from CrowdSec</span>"
    open_btn = (
        f"<a class='btn' href='{_esc(data['front_url'])}' target='_blank' rel='noopener' "
        "title='CrowdSec has no rich UI — this is the LAPI endpoint; CrowdSec is CLI-managed via cscli'>"
        "Open CrowdSec metrics &#8599;</a>"
    )

    body = (
        _status_banner(data)
        + _kpi_tiles(data["kpis"])
        + "<section class='shell' style='gap:var(--sp-4)'>"
        "<div class='section-label'>Threat activity</div>"
        "<div class='grid'>"
        f"<div class='col-6'>{_alert_feed(data)}</div>"
        f"<div class='col-6'>{_scenario_bars(data)}</div>"
        "</div></section>"
        + "<section class='shell' style='gap:var(--sp-4)'>"
        "<div class='section-label'>Attack sources &amp; decisions</div>"
        "<div class='grid'>"
        f"<div class='col-12'>{_decisions_table(data)}</div>"
        "</div></section>"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Edge Sentinel — {_esc(TENANT)}</title>
{FONT_LINK}
<style>{BASE_CSS}{PAGE_CSS}</style>
</head>
<body class="page">
<div class="shell">
  <header class="appbar">
    <div class="appbar__row">
      <h1>Edge Sentinel</h1>
      {status_pill}
      {live_badge}
      <span class="spacer"></span>
      {open_btn}
    </div>
    <div class="appbar__tenant"><b>{_esc(TENANT)}</b> · core: CrowdSec (open-source detection &amp; response, CLI-managed)</div>
    <div class="appbar__sub">{_esc(SUBTITLE)}</div>
  </header>
  {body}
  <footer class="footer">edge-sentinel · live activity for {_esc(TENANT)} ·
    <a href="/api/activity">/api/activity</a> · agent + human, on a real CrowdSec core · redevops.io Agentic Business OS</footer>
</div>
</body>
</html>"""


# --- optional LLM reasoning blurb (guarded: works without any API key) -------
def _llm_blurb(prompt: str) -> str | None:
    """Return a one-line reasoning blurb from Claude, or None if no key / any error.

    Optional by design — the agentic actions are deterministic CrowdSec/cscli work;
    the LLM only narrates. Absence of ANTHROPIC_API_KEY must never break the endpoint.
    """
    base = os.environ.get("REDEVOPS_LLM_BASE_URL")
    if base:
        try:
            r = httpx.post(
                base.rstrip("/") + "/chat/completions",
                json={"model": os.environ.get("REDEVOPS_LLM_MODEL", "DeepSeek-V4-Flash"),
                      "messages": [{"role": "user", "content": prompt}],
                      "max_tokens": 220, "temperature": 0.3},
                timeout=90.0,   # DeepSeek runs on CPU (~15 tok/s) — be patient
            )
            if r.status_code == 200:
                txt = (r.json().get("choices") or [{}])[0].get("message", {}).get("content", "").strip()
                if txt:
                    return txt
        except Exception:
            pass
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    try:
        r = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                # claude-opus-4-8 is Anthropic's current Opus-tier model id.
                "model": "claude-opus-4-8",
                "max_tokens": 220,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=15.0,
        )
        r.raise_for_status()
        return "".join(
            b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text"
        ).strip() or None
    except Exception:
        return None


# --- agentic actions ---------------------------------------------------------
def _block_ip(body: dict) -> dict:
    """Blocking traffic is the SENSITIVE action — never auto-executed.

    Mirrors the module's `approval_required:[remediation]`: stage the block and return
    pending_approval. The actual ban only happens via the `approve_block` action.
    """
    ip = (body.get("ip") or "").strip()
    if not ip:
        return {"status": "error", "action": "block_ip", "error": "missing 'ip'"}
    return {
        "status": "pending_approval",
        "action": "block_ip",
        "ip": ip,
        "requires": "human approval",
        "summary": f"block {ip}",
        "detail": (
            f"Edge block of {ip} is staged and awaiting human approval. "
            "Blocks are never auto-enforced by the agent — call approve_block to enforce."
        ),
    }


def _approve_block(body: dict) -> dict:
    """The approved path: actually add the ban decision via cscli (real enforcement)."""
    ip = (body.get("ip") or "").strip()
    if not ip:
        return {"status": "error", "action": "approve_block", "error": "missing 'ip'"}
    duration = body.get("duration", "4h")
    reason = body.get("reason", "blocked via edge-sentinel agent (human-approved)")
    rc, out, err = _cscli(
        ["decisions", "add", "--ip", ip, "--duration", duration, "--reason", reason, "--type", "ban"]
    )
    ok = rc == 0
    fetch_activity(force=True)  # refresh the cache so the dashboard shows it immediately
    return {
        "status": "done" if ok else "error",
        "action": "approve_block",
        "ip": ip,
        "duration": duration,
        "enforced": ok,
        "summary": f"Banned {ip} for {duration} via CrowdSec (cscli decisions add)." if ok
                   else f"Failed to ban {ip}.",
        "cscli_output": (out or err).strip(),
    }


def _triage(body: dict) -> dict:
    """Summarize the current alerts/decisions (deterministic; LLM blurb optional)."""
    data = fetch_activity(force=True)
    decisions = data["decisions"]
    alerts = data["alerts"]
    by_sev: dict[str, int] = {}
    for a in alerts:
        by_sev[a["severity"]] = by_sev.get(a["severity"], 0) + 1
    top = data["top_scenarios"][:3]

    detail = "; ".join(f"{d['value']} ({d['scenario']}, {d['severity']})" for d in decisions[:6]) or "none"
    summary = (
        f"{len(decisions)} active block(s), {len(alerts)} alert(s) in store. "
        f"Severity mix: " + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items())) + ". "
        f"Top scenarios: " + ", ".join(f"{s['scenario']}({s['count']})" for s in top) + "."
    )
    out = {
        "status": "done",
        "action": "triage",
        "active_decisions": len(decisions),
        "alerts": len(alerts),
        "severity_breakdown": by_sev,
        "top_scenarios": top,
        "summary": summary,
    }
    blurb = _llm_blurb(
        "You are a SOC analyst agent for a small roofing contractor's network. In ONE sentence, "
        f"triage these active CrowdSec block decisions and recommend a next step: {detail}. "
        "Be concrete and professional. Final answer only, no preamble."
    )
    if blurb:
        out["reasoning"] = blurb
    return out


# --- routes ------------------------------------------------------------------
@app.get("/health")
def health() -> dict:
    return {"status": "ok", "core": "crowdsec", "connected": crowdsec_connected()}


@app.get("/api/activity")
def activity() -> JSONResponse:
    return JSONResponse(fetch_activity())


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return render(fetch_activity())


@app.post("/agent/run")
async def agent_run(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        body = {}
    action = (body or {}).get("action", "")

    if action == "block_ip":
        return JSONResponse(_block_ip(body or {}))
    if action == "approve_block":
        return JSONResponse(_approve_block(body or {}))
    if action == "triage":
        return JSONResponse(_triage(body or {}))
    return JSONResponse(
        {"status": "error", "error": f"unknown action '{action}'",
         "supported": ["block_ip", "approve_block", "triage"]},
        status_code=400,
    )


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT)
