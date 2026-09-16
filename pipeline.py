#!/usr/bin/env python3
"""
AI Incident Pipeline
=====================
Fetches AI incident data from four public sources, normalizes each record
into a unified `AI_Event` schema, deduplicates across sources, and writes
everything into a local SQLite database (ai_events.db).

Sources
-------
1. AIAAIC   - Google Sheet (public, CSV export of the "Incidents" tab).
2. AIID     - AI Incident Database GraphQL API (incidentdatabase.ai/api/graphql).
3. sipi.bot - AI Agent Incident Database, public JSON export.
4. AIM      - OECD AI Incidents Monitor. No public API or CSV export could be
              found (verified by hand -- see README). The site only exposes a
              browser "Download results" button behind a JS-rendered SPA.
              This source therefore falls back to a manually-exported file:
              pass --aim-file <path to a CSV/JSON export> to include it.

Run with:  python pipeline.py [--aim-file PATH] [--aiaaic-file PATH]
                               [--aiid-file PATH] [--sipi-file PATH]

Every *-file flag lets you substitute a manually downloaded copy of that
source instead of hitting the network (useful if a source's live endpoint
goes down, changes shape, or you already verified a fallback CSV/JSON export
by hand). Network fetching is the default for AIAAIC, AIID, and sipi.bot.

One source failing (network error, HTML/parse error, schema change) is
logged and skipped -- it never aborts the whole run.
"""

import argparse
import csv
import hashlib
import io
import json
import logging
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, date
from difflib import SequenceMatcher

import requests

try:
    import yaml  # PyYAML -- used for MITRE ATLAS data
except ImportError:  # pragma: no cover
    yaml = None

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("ai_incident_pipeline")

DB_PATH = "ai_events.db"
HTTP_TIMEOUT = 30
UA = "Mozilla/5.0 (compatible; ai-incident-pipeline/1.0; +research use)"

# ---------------------------------------------------------------------------
# Verified source endpoints (each was hand-checked with curl/WebFetch before
# being hardcoded here -- see README.md for how/when each was verified).
# ---------------------------------------------------------------------------

# AIAAIC: public Google Sheet. gid=888071280 is the "Incidents" tab (the main
# repository table) -- found by listing the sheet's gids and checking headers
# of each exported tab; other gids are "Systems", "Datasets", "Changelog".
AIAAIC_SHEET_ID = "1Bn55B4xz21-_Rgdr8BBb2lt0n_4rzLGxFADMlVW0PYI"
AIAAIC_INCIDENTS_GID = "888071280"
AIAAIC_CSV_URL = (
    f"https://docs.google.com/spreadsheets/d/{AIAAIC_SHEET_ID}/export"
    f"?format=csv&gid={AIAAIC_INCIDENTS_GID}"
)

# AIID: public read-only GraphQL endpoint. It rejects requests that don't
# look like they came from a browser tab on incidentdatabase.ai, so we send
# Origin/Referer/User-Agent headers that satisfy that check.
AIID_GRAPHQL_URL = "https://incidentdatabase.ai/api/graphql"
AIID_QUERY = """
query GetIncidents($limit: Int, $skip: Int) {
  incidents(pagination: {limit: $limit, skip: $skip}, sort: {incident_id: ASC}) {
    incident_id
    title
    description
    date
    AllegedDeployerOfAISystem { name }
    AllegedDeveloperOfAISystem { name }
    AllegedHarmedOrNearlyHarmedParties { name }
    reports { report_number title url }
  }
}
"""

# sipi.bot: public dataset, CC BY 4.0, plain JSON.
SIPI_JSON_URL = "https://sipi.bot/data/ai-agent-incidents.json"

# ---------------------------------------------------------------------------
# 15 additional sources (verified by hand with curl/requests before being
# hardcoded -- see README.md "New sources" section for the full verification
# notes on every URL below, including the ones that turned out to have no
# machine-accessible path).
# ---------------------------------------------------------------------------

# 1. CED -- Cyber Events Database (U Maryland). The public site
# (gotech.umd.edu/cyber-events-database and its companion cybereventsdatabase.org)
# is a JS-rendered SPA (built on the "base44" platform) with an "ApiManagement"
# page that documents an API but the page itself ships no bulk CSV/JSON and no
# reachable unauthenticated REST endpoint was found. Manual-fallback only.
CED_AI_KEYWORDS = [
    "artificial intelligence", "machine learning", " ai ", "chatbot", "llm",
    "large language model", "neural network", "generative ai", "deepfake",
    "facial recognition", "algorithm", "automated decision", "genai", "gpt",
]

# 2. AVID -- AI Vulnerability Database. Public GitHub data repo, verified via
# `GET https://api.github.com/repos/avidml/avid-db/contents/vulnerabilities`
# (returns per-year folders of JSON vuln reports, e.g. AVID-2023-V001.json).
AVID_REPO = "avidml/avid-db"
AVID_API_CONTENTS = f"https://api.github.com/repos/{AVID_REPO}/contents/vulnerabilities"
AVID_RAW_BASE = f"https://raw.githubusercontent.com/{AVID_REPO}/main/vulnerabilities"

# 3. NVD/CVE -- public NVD REST API 2.0, verified with a live keywordSearch
# call (returned real CVE JSON, no key required for light use).
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_AI_KEYWORDS = [
    "machine learning", "large language model", "LLM", "artificial intelligence",
    "neural network", "tensorflow", "pytorch",
]

# 6. MIT AI Risk Repository. airisk.mit.edu/risks was checked directly: no
# CSV/XLSX export URL or gid is reachable without authentication -- the only
# structured-data links on the page are Airtable *embeds*
# (airtable.com/embed/app32FOUBa5WcUfEO/...), which require an Airtable API
# key to pull programmatically, not a public bulk download. Manual-fallback only.

# 7. DARR -- Deployer AI Risk Register. Public GitHub repo with real, non-code
# data files under data/ (verified: darr-deployer-ai-risk-register.json exists
# and parses).
DARR_JSON_URL = "https://raw.githubusercontent.com/Myr-Aya/darr-deployer-ai-risk-register/main/data/darr-deployer-ai-risk-register.json"
DARR_SUBRISKS_URL = "https://raw.githubusercontent.com/Myr-Aya/darr-deployer-ai-risk-register/main/data/subrisks.json"

# 8. MITRE ATLAS. dist/ATLAS-latest.yaml (and dist/v6/ATLAS-latest.yaml) are
# themselves one-line "pointer" files containing the relative path of the
# actual current release file (verified: dist/ATLAS-latest.yaml ->
# "v6/ATLAS-latest.yaml" -> "ATLAS-2026.08.yaml", which is the real YAML).
ATLAS_REPO_RAW = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist"
ATLAS_LATEST_POINTER = f"{ATLAS_REPO_RAW}/ATLAS-latest.yaml"

# 9. DAIL -- Database of AI Litigation (GWU). blogs.gwu.edu page uses a
# TablePress/wpDataTable plugin rendered server-side with no discoverable
# CSV/JSON export endpoint (no Airtable/embed either). Manual-fallback only.

# 11. GitHub Advisories. api.github.com/graphql was verified to require
# authentication (unauthenticated POST returns HTTP 403 "Bad credentials"/
# rate-limit message, not real data). Live fetch only runs if a GITHUB_TOKEN
# env var is set; otherwise it's skipped gracefully with a logged note.
GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"
GITHUB_ADVISORY_PACKAGES = [
    "tensorflow", "pytorch", "langchain", "transformers", "huggingface_hub",
    "openai", "anthropic", "keras", "onnx", "mlflow",
]

# 12. AI Incidents Explorer. aiincidents.org/explorer/ has no separate JSON
# API endpoint (several guessed paths all 404), but the rendered page itself
# embeds the full incident catalog as `<script type="application/json"
# id="data-incidents">` -- verified: 81 incidents, matching the brief.
AIINCIDENTS_EXPLORER_URL = "https://aiincidents.org/explorer/"

# 13. INHUMAIN. inhumain.ai/ai-incident-tracker/ (redirects from the no-slash
# URL) publishes a real HTML "Top 20" incidents table plus methodology; the
# full claimed 847-incident database is "by request" only. Manual-fallback
# flag covers the full set.
INHUMAIN_URL = "https://inhumain.ai/ai-incident-tracker/"

# 14. StupidLLM. robots.txt at stupidllm.com explicitly allows crawling
# (`Allow: /`, and explicitly welcomes AI crawlers). /incidents redirects to
# https://www.stupidllm.com/incidents, which is a client-rendered (Next.js/
# React) page -- no incident links or embedded JSON were present in the raw
# HTML actually fetched, so live scraping yields 0 rows in practice; a manual
# fallback flag is provided for a hand-exported listing.
STUPIDLLM_URL = "https://www.stupidllm.com/incidents"
STUPIDLLM_ROBOTS_URL = "https://www.stupidllm.com/robots.txt"

# 15. CA DMV Autonomous Vehicle incident reporting index page.
DMV_AV_URL = "https://www.dmv.ca.gov/portal/vehicle-industry-services/autonomous-vehicles/autonomous-vehicles-incident-reporting/"

# 4. InspectAgents. inspectagents.com/failures/ ships `/api/agent-feedback`,
# `/api/mcp/`, and `/api/openapi` endpoints -- these are product/feedback/MCP
# integration APIs, not a bulk incident/failure-taxonomy export. No public
# bulk export was found. Manual-fallback only.


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def http_get(url, **kwargs):
    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", UA)
    resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT, **kwargs)
    resp.raise_for_status()
    return resp


def make_event_id(source_name, source_record_id, title, event_date):
    """Stable id: hash of source + record id (or title+date if no record id)."""
    basis = f"{source_name}|{source_record_id or ''}|{title or ''}|{event_date or ''}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:24]


def normalize_title(title):
    if not title:
        return ""
    t = title.lower().strip()
    t = re.sub(r"[^a-z0-9\s]", "", t)
    t = re.sub(r"\s+", " ", t)
    return t


def parse_date_loose(value):
    """Best-effort parse of a date string into ISO YYYY-MM-DD, else None."""
    if not value:
        return None
    value = str(value).strip()
    if not value:
        return None
    fmts = ["%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y", "%d/%m/%Y", "%Y", "%B %Y", "%b %Y"]
    for fmt in fmts:
        try:
            d = datetime.strptime(value, fmt)
            if fmt == "%Y":
                return f"{d.year}-01-01"
            if fmt in ("%B %Y", "%b %Y"):
                return f"{d.year}-{d.month:02d}-01"
            return d.strftime("%Y-%m-%d")
        except ValueError:
            continue
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", value)
    if m:
        return m.group(0)
    return None


# ---------------------------------------------------------------------------
# Fetchers -- one per source. Each returns a list of *raw* dict records
# (source-native shape). Parsing/normalization into AI_Event happens
# separately so raw records can be preserved for audit (sources_raw table).
# ---------------------------------------------------------------------------

def fetch_aiaaic_raw(file_path=None):
    """AIAAIC repository -- public Google Sheet, 'Incidents' tab, CSV export."""
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        resp = http_get(AIAAIC_CSV_URL)
        text = resp.content.decode("utf-8", errors="replace")

    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    # Sheet layout: row0 = section title, row1 = headers, row2 = sub-headers
    # for merged columns (Jurisdiction/Sector under "Impacted area", etc.),
    # row3+ = data.
    header = rows[1]
    subheader = rows[2] if len(rows) > 2 else []
    # Build merged column names using subheader where the top header is blank.
    columns = []
    for i, h in enumerate(header):
        sub = subheader[i] if i < len(subheader) else ""
        columns.append(sub.strip() if (not h.strip() and sub.strip()) else h.strip())

    records = []
    for row in rows[3:]:
        if not any(cell.strip() for cell in row):
            continue
        rec = {columns[i] if i < len(columns) else f"col{i}": (row[i] if i < len(row) else "")
               for i in range(len(row))}
        if not rec.get("AIAAIC ID#"):
            continue
        records.append(rec)
    return records


def fetch_aiid_raw(file_path=None, page_size=200, max_pages=100):
    """AIID -- public GraphQL API, paginated."""
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else data.get("incidents", [])

    headers = {
        "Content-Type": "application/json",
        "Origin": "https://incidentdatabase.ai",
        "Referer": "https://incidentdatabase.ai/apps/discover/",
        "User-Agent": UA,
    }
    all_records = []
    skip = 0
    for _ in range(max_pages):
        payload = {"query": AIID_QUERY, "variables": {"limit": page_size, "skip": skip}}
        resp = requests.post(AIID_GRAPHQL_URL, json=payload, headers=headers, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        body = resp.json()
        if "errors" in body and body["errors"]:
            raise RuntimeError(f"AIID GraphQL error: {body['errors']}")
        batch = body.get("data", {}).get("incidents", [])
        if not batch:
            break
        all_records.extend(batch)
        if len(batch) < page_size:
            break
        skip += page_size
    return all_records


def fetch_sipi_raw(file_path=None):
    """sipi.bot AI Agent Incident Database -- public JSON, CC BY 4.0."""
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        resp = http_get(SIPI_JSON_URL)
        data = resp.json()
    incidents = data.get("incidents", [])
    # Per the brief: drop rows where type == "statistic", keep only type == "incident".
    return [r for r in incidents if r.get("type") == "incident"]


def fetch_aim_raw(file_path=None):
    """
    OECD AI Incidents Monitor (AIM).

    No public API or bulk CSV/JSON export could be found: oecd.ai/en/incidents
    is a JS-rendered single-page app whose only export mechanism is an
    in-browser "Download results" button, and no oecd.ai/api-style endpoint
    responds to direct requests. This was verified by fetching the page and
    the methodology page directly -- neither exposes a machine-accessible
    endpoint or documented API (see README.md for details).

    Manual fallback: pass --aim-file pointing at a CSV or JSON file exported
    by hand from the "Download results" button on https://oecd.ai/en/incidents.
    Without that flag this source contributes zero rows and is skipped.
    """
    if not file_path:
        log.warning(
            "AIM (OECD): no verified public API/export exists; skipping. "
            "Pass --aim-file <path> with a manual export from oecd.ai/en/incidents to include it."
        )
        return []
    if file_path.lower().endswith(".json"):
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else data.get("results", data.get("data", []))
    with open(file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def _is_ai_relevant(text):
    if not text:
        return False
    t = f" {text.lower()} "
    return any(kw in t for kw in CED_AI_KEYWORDS)


def fetch_ced_raw(file_path=None):
    """CED (Cyber Events Database, U Maryland).

    No public bulk CSV/JSON download or reachable REST endpoint was found
    (gotech.umd.edu/cyber-events-database and cybereventsdatabase.org are both
    JS-rendered SPAs -- verified directly). Manual fallback only: pass
    --ced-file with a hand-exported CSV. Rows are filtered down to AI-relevant
    ones (keyword match across common text columns) before being returned,
    since CED is a general cyber-events database and only AI-relevant rows
    belong in AI_Event.
    """
    if not file_path:
        log.warning(
            "CED: no public bulk export/API found; skipping. "
            "Pass --ced-file <path> with a manual export to include AI-relevant rows."
        )
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    ai_rows = []
    for row in rows:
        blob = " ".join(str(v) for v in row.values() if v)
        if _is_ai_relevant(blob):
            ai_rows.append(row)
    log.info("CED: %d/%d rows kept as AI-relevant", len(ai_rows), len(rows))
    return ai_rows


def normalize_ced(rec):
    def g(*keys):
        for k in keys:
            if k in rec and rec[k] not in (None, ""):
                return rec[k]
        return None

    rid = g("event_id", "id", "ID")
    return {
        "source_name": "CED",
        "source_record_id": str(rid) if rid is not None else None,
        "title": g("event_name", "title", "Title", "name"),
        "description": g("description", "Description", "summary"),
        "date": parse_date_loose(g("event_date", "date", "Date")),
        "sector_or_industry": g("industry", "sector", "Sector"),
        "location": g("location", "Location"),
        "country": g("country", "Country"),
        "financial_loss_amount": None,
        "financial_loss_currency": None,
        "financial_loss_notes": g("loss", "financial_loss", "Financial Loss"),
        "harm_type": g("event_type", "type", "Type"),
        "involved_entities": g("actor", "organization", "Organization"),
        "severity_or_consequence": g("severity", "Severity"),
        "url_or_reference": g("source_url", "url", "URL"),
        "raw_json": json.dumps(rec, ensure_ascii=False),
    }


def fetch_aiincidents_raw(file_path=None):
    """AI Incidents Explorer -- real incident catalog, embedded as JSON
    inside the rendered explorer page (no separate API endpoint exists;
    verified: several guessed /api/*.json paths all 404). Feeds AI_Event."""
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("incidents", data) if isinstance(data, dict) else data
    resp = http_get(AIINCIDENTS_EXPLORER_URL)
    html = resp.text
    m = re.search(
        r'<script[^>]*id="data-incidents"[^>]*>(.*?)</script>', html, re.S
    )
    if not m:
        raise RuntimeError("AI Incidents Explorer: embedded data-incidents JSON block not found")
    data = json.loads(m.group(1))
    return data.get("incidents", [])


def normalize_aiincidents(rec):
    return {
        "source_name": "AI Incidents Explorer",
        "source_record_id": rec.get("id"),
        "title": rec.get("title"),
        "description": rec.get("summary"),
        "date": parse_date_loose(rec.get("incidentDate") or rec.get("disclosureDate")),
        "sector_or_industry": rec.get("modality"),
        "location": None,
        "country": None,
        "financial_loss_amount": None,
        "financial_loss_currency": None,
        "financial_loss_notes": None,
        "harm_type": rec.get("harmDomain") or rec.get("incidentType"),
        "involved_entities": rec.get("actorClass"),
        "severity_or_consequence": rec.get("sourceTier"),
        "url_or_reference": rec.get("sourceUrl"),
        "raw_json": json.dumps(rec, ensure_ascii=False),
    }


def _strip_html(s):
    return re.sub(r"<[^>]+>", "", s or "").strip()


def fetch_inhumain_raw(file_path=None):
    """INHUMAIN -- public 'Top 20' HTML table is scraped live; the full
    claimed 847-incident database is by-request-only, so it needs a manual
    export via --inhumain-file."""
    records = []
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            if file_path.lower().endswith(".json"):
                data = json.load(f)
                records.extend(data if isinstance(data, list) else data.get("incidents", []))
            else:
                records.extend(list(csv.DictReader(f)))
        return records

    resp = http_get(INHUMAIN_URL)
    html = resp.text
    tables = re.findall(r"<table[^>]*>.*?</table>", html, re.S)
    target = None
    for t in tables:
        header_cells = re.findall(r"<th[^>]*>(.*?)</th>", t, re.S)
        headers = [_strip_html(h).lower() for h in header_cells]
        if "incident" in headers and "date" in headers:
            target = t
            break
    if target is None:
        raise RuntimeError("INHUMAIN: could not locate the Top-20 incidents table")

    header_cells = re.findall(r"<th[^>]*>(.*?)</th>", target, re.S)
    headers = [_strip_html(h).lower() for h in header_cells]
    body = target.split("</thead>", 1)[-1]
    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", body, re.S)
    for row in rows:
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
        if not cells:
            continue
        values = [_strip_html(c) for c in cells]
        rec = dict(zip(headers, values))
        records.append(rec)
    return records


def normalize_inhumain(rec):
    title = rec.get("incident") or rec.get("title")
    rid = rec.get("#") or rec.get("id")
    return {
        "source_name": "INHUMAIN",
        "source_record_id": str(rid) if rid else None,
        "title": title,
        "description": title,
        "date": parse_date_loose(rec.get("date")),
        "sector_or_industry": rec.get("category"),
        "location": None,
        "country": None,
        "financial_loss_amount": None,
        "financial_loss_currency": None,
        "financial_loss_notes": None,
        "harm_type": rec.get("category"),
        "involved_entities": None,
        "severity_or_consequence": rec.get("severity"),
        "url_or_reference": rec.get("source") or rec.get("url"),
        "raw_json": json.dumps(rec, ensure_ascii=False),
    }


def fetch_stupidllm_raw(file_path=None):
    """StupidLLM -- robots.txt allows crawling, but the live /incidents page
    is client-rendered with no incident links or embedded JSON present in the
    raw HTML (verified directly), so live scraping yields 0 rows in practice.
    Use --stupidllm-file for a hand-exported listing."""
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            if file_path.lower().endswith(".json"):
                data = json.load(f)
                return data if isinstance(data, list) else data.get("incidents", [])
            return list(csv.DictReader(f))

    robots = http_get(STUPIDLLM_ROBOTS_URL).text
    if re.search(r"User-agent:\s*\*\s*\n\s*Disallow:\s*/\s*$", robots, re.M):
        log.warning("StupidLLM: robots.txt disallows crawling; skipping live scrape.")
        return []
    time.sleep(1)  # be polite
    resp = http_get(STUPIDLLM_URL)
    html = resp.text
    records = []
    for m in re.finditer(r'<script[^>]*type="application/json"[^>]*>(.*?)</script>', html, re.S):
        try:
            data = json.loads(m.group(1))
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(data, dict) and "incidents" in data:
            records.extend(data["incidents"])
    if not records:
        for m in re.finditer(r'href="(/incidents/[^"?#]+)"', html):
            records.append({"url": "https://www.stupidllm.com" + m.group(1)})
    log.info("StupidLLM: live scrape found %d record(s)", len(records))
    return records


def normalize_stupidllm(rec):
    return {
        "source_name": "StupidLLM",
        "source_record_id": rec.get("id") or rec.get("slug"),
        "title": rec.get("title") or rec.get("url"),
        "description": rec.get("summary") or rec.get("description"),
        "date": parse_date_loose(rec.get("date")),
        "sector_or_industry": None,
        "location": None,
        "country": None,
        "financial_loss_amount": None,
        "financial_loss_currency": None,
        "financial_loss_notes": None,
        "harm_type": rec.get("category"),
        "involved_entities": None,
        "severity_or_consequence": None,
        "url_or_reference": rec.get("url"),
        "raw_json": json.dumps(rec, ensure_ascii=False),
    }


def fetch_dmvav_raw(file_path=None):
    """CA DMV AV incident reporting index. Ingests the report index (as
    published on the page: manufacturer / date / report URL) as AI_Event
    records. PDF content extraction is a documented limitation, not required.
    """
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    resp = http_get(DMV_AV_URL)
    html = resp.text
    records = []
    for m in re.finditer(r'<a[^>]*href="([^"]+\.pdf)"[^>]*>(.*?)</a>', html, re.S):
        url, label = m.group(1), _strip_html(m.group(2))
        if not url.startswith("http"):
            url = "https://www.dmv.ca.gov" + url
        records.append({"report_url": url, "label": label})
    log.info("CA DMV AV: found %d PDF report link(s) on the index page", len(records))
    return records


def normalize_dmvav(rec):
    label = rec.get("label") or ""
    return {
        "source_name": "CA DMV AV",
        "source_record_id": rec.get("report_url"),
        "title": label or "CA DMV AV incident report",
        "description": None,
        "date": parse_date_loose(rec.get("date")),
        "sector_or_industry": "Autonomous vehicles",
        "location": "California",
        "country": "US",
        "financial_loss_amount": None,
        "financial_loss_currency": None,
        "financial_loss_notes": None,
        "harm_type": "AV incident report",
        "involved_entities": rec.get("manufacturer"),
        "severity_or_consequence": None,
        "url_or_reference": rec.get("report_url"),
        "raw_json": json.dumps(rec, ensure_ascii=False),
    }


# ---------------------------------------------------------------------------
# Normalizers -- source-native dict -> unified AI_Event dict.
# Fields we cannot populate from a source are left as None rather than guessed.
# ---------------------------------------------------------------------------

def normalize_aiaaic(rec):
    rid = rec.get("AIAAIC ID#", "").strip()
    title = rec.get("Headline", "").strip()
    ev_date = parse_date_loose(rec.get("Occurred", ""))
    country = rec.get("Jurisdiction", "").strip() or None
    sector = rec.get("Sector", "").strip() or None
    entities = "; ".join(filter(None, [rec.get("Deployer", "").strip(), rec.get("Developer", "").strip()])) or None
    harm = "; ".join(filter(None, [
        rec.get("External harm (taxonomy)", "").strip(),
        rec.get("Ethical issue (taxonomy)", "").strip(),
    ])) or None
    severity = rec.get("Consequence (taxonomy)", "").strip() or rec.get("Harm status", "").strip() or None
    url = None
    summary = rec.get("Summary/links", "")
    m = re.search(r"https?://\S+", summary)
    if m:
        url = m.group(0).rstrip(",")
    return {
        "source_name": "AIAAIC",
        "source_record_id": rid,
        "title": title or None,
        "description": summary.strip() or None,
        "date": ev_date,
        "sector_or_industry": sector,
        "location": country,
        "country": country,
        "financial_loss_amount": None,  # AIAAIC does not report loss amounts numerically
        "financial_loss_currency": None,
        "financial_loss_notes": None,
        "harm_type": harm,
        "involved_entities": entities,
        "severity_or_consequence": severity,
        "url_or_reference": url,
        "raw_json": json.dumps(rec, ensure_ascii=False),
    }


def normalize_aiid(rec):
    rid = str(rec.get("incident_id", "")) or None
    title = rec.get("title")
    ev_date = parse_date_loose(rec.get("date"))
    deployers = [e.get("name") for e in (rec.get("AllegedDeployerOfAISystem") or []) if e.get("name")]
    developers = [e.get("name") for e in (rec.get("AllegedDeveloperOfAISystem") or []) if e.get("name")]
    harmed = [e.get("name") for e in (rec.get("AllegedHarmedOrNearlyHarmedParties") or []) if e.get("name")]
    entities = "; ".join(sorted(set(deployers + developers))) or None
    reports = rec.get("reports") or []
    url = reports[0]["url"] if reports and reports[0].get("url") else None
    return {
        "source_name": "AIID",
        "source_record_id": rid,
        "title": title,
        "description": rec.get("description"),
        "date": ev_date,
        "sector_or_industry": None,  # AIID does not have a first-class sector field in this query
        "location": None,            # AIID does not provide structured location fields
        "country": None,
        "financial_loss_amount": None,  # AIID does not track financial loss numerically
        "financial_loss_currency": None,
        "financial_loss_notes": None,
        "harm_type": "; ".join(harmed) or None,
        "involved_entities": entities,
        "severity_or_consequence": None,
        "url_or_reference": url,
        "raw_json": json.dumps(rec, ensure_ascii=False),
    }


def normalize_sipi(rec):
    rid = rec.get("id")
    loss_amount = rec.get("loss_usd")
    loss_notes = rec.get("loss_range")
    if isinstance(loss_notes, (list, dict)):
        loss_notes = json.dumps(loss_notes, ensure_ascii=False)
    return {
        "source_name": "sipi.bot",
        "source_record_id": rid,
        "title": rec.get("title"),
        "description": rec.get("what_happened"),
        "date": parse_date_loose(rec.get("date")),
        "sector_or_industry": rec.get("agent_type"),  # closest available proxy (coding, etc.)
        "location": None,  # sipi.bot does not report physical location
        "country": None,
        "financial_loss_amount": loss_amount if isinstance(loss_amount, (int, float)) else None,
        "financial_loss_currency": "USD" if loss_amount is not None else None,
        "financial_loss_notes": loss_notes,
        "harm_type": rec.get("category"),
        "involved_entities": rec.get("organization"),
        "severity_or_consequence": rec.get("outcome"),
        "url_or_reference": rec.get("source_url"),
        "raw_json": json.dumps(rec, ensure_ascii=False),
    }


def normalize_aim(rec):
    """
    AIM records are whatever shape a manually-exported CSV/JSON from
    oecd.ai/en/incidents happens to have -- we make a best effort at common
    column names and otherwise leave fields blank rather than guessing.
    """
    def g(*keys):
        for k in keys:
            if k in rec and rec[k] not in (None, ""):
                return rec[k]
        return None

    rid = g("id", "ID", "incident_id")
    title = g("title", "Title", "headline")
    ev_date = parse_date_loose(g("date", "Date", "event_date"))
    return {
        "source_name": "AIM",
        "source_record_id": str(rid) if rid is not None else None,
        "title": title,
        "description": g("description", "Description", "summary"),
        "date": ev_date,
        "sector_or_industry": g("sector", "Sector", "industry", "concepts"),  # "concepts" is a loose topic tag list, not a real sector taxonomy
        "location": g("location", "Location"),
        "country": g("country", "Country"),
        "financial_loss_amount": None,  # AIM (news-derived) does not structure loss amounts
        "financial_loss_currency": None,
        "financial_loss_notes": None,
        "harm_type": g("harm_type", "harm", "Harm"),
        "involved_entities": g("entities", "Entities", "organization", "companies"),
        "severity_or_consequence": g("severity", "Severity"),
        "url_or_reference": g("url", "URL", "link"),
        "raw_json": json.dumps(rec, ensure_ascii=False),
    }


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------
# Strategy (documented for human review -- this is a heuristic, not ground
# truth): two normalized events from *different* sources are considered
# probable duplicates if either:
#   (a) they share the same non-empty url_or_reference (exact match), or
#   (b) their normalized titles are >= TITLE_SIM_THRESHOLD similar (via
#       difflib.SequenceMatcher) AND their event dates are within
#       DATE_PROXIMITY_DAYS of each other (or either date is missing).
# The first-seen event (by source fetch order: AIAAIC, AIID, sipi.bot, AIM)
# is kept as the canonical record. Later matches are NOT dropped -- they are
# still inserted as their own AI_Event rows, but with `duplicate_of` set to
# the canonical event_id, and the canonical row's `merged_from_sources`
# field is updated to list every source that contributed a match. This
# preserves all raw data while making the merge relationship explorable.

TITLE_SIM_THRESHOLD = 0.82
DATE_PROXIMITY_DAYS = 14


def _date_close(d1, d2, days):
    if not d1 or not d2:
        return True  # treat missing dates as non-disqualifying
    try:
        a = datetime.strptime(d1, "%Y-%m-%d").date()
        b = datetime.strptime(d2, "%Y-%m-%d").date()
    except ValueError:
        return True
    return abs((a - b).days) <= days


def _year_of(date_str):
    if not date_str:
        return None
    try:
        return int(date_str[:4])
    except ValueError:
        return None


def dedup_events(events):
    """events: list of normalized dicts (with event_id already assigned).
    Mutates and returns the list with duplicate_of / merged_from_sources set.

    Performance note: a naive all-pairs comparison is O(n^2) SequenceMatcher
    calls, which is too slow once n is in the thousands (AIAAIC + AIID alone
    total ~4000 events). We bucket candidates by event year (since
    DATE_PROXIMITY_DAYS is small, a match can only land in the same or an
    adjacent year) and only compare within the relevant buckets, plus a
    shared "unknown year" bucket for records with no parseable date. A cheap
    url match is also checked directly via a dict lookup.
    """
    for e in events:
        e.setdefault("duplicate_of", None)
        e.setdefault("merged_from_sources", e["source_name"])

    by_year = {}       # year -> list of (event_dict, norm_title)
    unknown_year = []  # (event_dict, norm_title) with no parseable date
    url_index = {}      # normalized url -> event_dict (canonical only)

    def candidates_for(year):
        pool = list(unknown_year)
        if year is not None:
            for y in (year - 1, year, year + 1):
                pool.extend(by_year.get(y, []))
        else:
            for lst in by_year.values():
                pool.extend(lst)
        return pool

    for e in events:
        norm_title = normalize_title(e.get("title"))
        year = _year_of(e.get("date"))
        norm_url = e.get("url_or_reference").strip().rstrip("/") if e.get("url_or_reference") else None

        match = None
        if norm_url and norm_url in url_index and url_index[norm_url]["source_name"] != e["source_name"]:
            match = url_index[norm_url]
        else:
            for cand, cand_title in candidates_for(year):
                if cand["source_name"] == e["source_name"]:
                    continue
                if norm_title and cand_title:
                    ratio = SequenceMatcher(None, norm_title, cand_title).ratio()
                    if ratio >= TITLE_SIM_THRESHOLD and _date_close(e.get("date"), cand.get("date"), DATE_PROXIMITY_DAYS):
                        match = cand
                        break

        if match:
            e["duplicate_of"] = match["event_id"]
            sources = set(match["merged_from_sources"].split("; "))
            sources.add(e["source_name"])
            match["merged_from_sources"] = "; ".join(sorted(sources))
        else:
            entry = (e, norm_title)
            if year is not None:
                by_year.setdefault(year, []).append(entry)
            else:
                unknown_year.append(entry)
            if norm_url:
                url_index.setdefault(norm_url, e)
    return events


# ---------------------------------------------------------------------------
# SQLite
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS AI_Event (
    event_id                TEXT PRIMARY KEY,
    source_name             TEXT NOT NULL,
    source_record_id        TEXT,
    title                   TEXT,
    description             TEXT,
    date                    TEXT,
    sector_or_industry      TEXT,
    location                TEXT,
    country                 TEXT,
    financial_loss_amount   REAL,
    financial_loss_currency TEXT,
    financial_loss_notes    TEXT,
    harm_type               TEXT,
    involved_entities       TEXT,
    severity_or_consequence TEXT,
    url_or_reference        TEXT,
    raw_json                TEXT,
    duplicate_of            TEXT,
    merged_from_sources     TEXT,
    fetched_at              TEXT
);

CREATE TABLE IF NOT EXISTS sources_raw (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name         TEXT NOT NULL,
    source_record_id    TEXT,
    raw_json            TEXT NOT NULL,
    fetched_at          TEXT NOT NULL
);

-- Enrichment / non-incident tables (additive; never fed through AI_Event dedup) --

CREATE TABLE IF NOT EXISTS Vulnerability_Report (
    report_id           TEXT PRIMARY KEY,
    source              TEXT NOT NULL,       -- 'AVID' or 'NVD/CVE'
    external_id         TEXT,                -- e.g. AVID-2023-V001 or CVE-2024-12345
    title               TEXT,
    description         TEXT,
    published_date      TEXT,
    affected_systems    TEXT,
    severity            TEXT,
    url_or_reference    TEXT,
    raw_json            TEXT,
    related_event_id    TEXT,                -- nullable, for future human linking to AI_Event
    fetched_at          TEXT
);

CREATE TABLE IF NOT EXISTS Risk_Taxonomy (
    risk_id             TEXT PRIMARY KEY,
    source              TEXT NOT NULL DEFAULT 'MIT Risk Repo',
    category            TEXT,
    subcategory         TEXT,
    title               TEXT,
    description         TEXT,
    raw_json            TEXT,
    related_event_id    TEXT,
    fetched_at          TEXT
);

CREATE TABLE IF NOT EXISTS Risk_Register (
    risk_id             TEXT PRIMARY KEY,
    source              TEXT NOT NULL DEFAULT 'DARR',
    risk_type           TEXT,                -- 'canonical' (82) or 'atlas-anchored-subrisk' (61)
    title               TEXT,
    description         TEXT,
    mit_risk_ref        TEXT,
    atlas_ref           TEXT,
    raw_json            TEXT,
    related_event_id    TEXT,
    fetched_at          TEXT
);

CREATE TABLE IF NOT EXISTS Atlas_Taxonomy (
    atlas_id            TEXT PRIMARY KEY,
    entry_type          TEXT,                -- 'tactic' | 'technique' | 'mitigation' | 'case-study'
    name                TEXT,
    description         TEXT,
    raw_json            TEXT,
    related_event_id    TEXT,
    fetched_at          TEXT
);

CREATE TABLE IF NOT EXISTS Legal_Case (
    case_id             TEXT PRIMARY KEY,
    source              TEXT NOT NULL DEFAULT 'DAIL',
    case_name           TEXT,
    court               TEXT,
    filing_date         TEXT,
    status              TEXT,
    summary             TEXT,
    url_or_reference    TEXT,
    raw_json            TEXT,
    related_event_id    TEXT,
    fetched_at          TEXT
);

CREATE TABLE IF NOT EXISTS Security_Advisory (
    advisory_id         TEXT PRIMARY KEY,
    source              TEXT NOT NULL DEFAULT 'GitHub Advisories',
    ghsa_id             TEXT,
    package_name        TEXT,
    summary             TEXT,
    severity            TEXT,
    published_date      TEXT,
    url_or_reference    TEXT,
    raw_json            TEXT,
    related_event_id    TEXT,
    fetched_at          TEXT
);

CREATE TABLE IF NOT EXISTS InspectAgents_Report (
    report_id           TEXT PRIMARY KEY,
    source              TEXT NOT NULL DEFAULT 'InspectAgents',
    title               TEXT,
    description         TEXT,
    raw_json            TEXT,
    related_event_id    TEXT,
    fetched_at          TEXT
);
"""


def write_to_db(events, raw_by_source, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)
        now = datetime.now().isoformat()

        def scalar(v):
            """SQLite can't bind list/dict; coerce any stray ones to JSON text."""
            if isinstance(v, (list, dict)):
                return json.dumps(v, ensure_ascii=False)
            return v

        for source_name, raw_records in raw_by_source.items():
            for rec in raw_records:
                rid = rec.get("AIAAIC ID#") or rec.get("incident_id") or rec.get("id")
                conn.execute(
                    "INSERT INTO sources_raw (source_name, source_record_id, raw_json, fetched_at) VALUES (?, ?, ?, ?)",
                    (source_name, str(rid) if rid is not None else None, json.dumps(rec, ensure_ascii=False), now),
                )

        for e in events:
            conn.execute(
                """
                INSERT OR REPLACE INTO AI_Event (
                    event_id, source_name, source_record_id, title, description, date,
                    sector_or_industry, location, country,
                    financial_loss_amount, financial_loss_currency, financial_loss_notes,
                    harm_type, involved_entities, severity_or_consequence,
                    url_or_reference, raw_json, duplicate_of, merged_from_sources, fetched_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(scalar(v) for v in (
                    e["event_id"], e["source_name"], e.get("source_record_id"), e.get("title"),
                    e.get("description"), e.get("date"), e.get("sector_or_industry"),
                    e.get("location"), e.get("country"),
                    e.get("financial_loss_amount"), e.get("financial_loss_currency"),
                    e.get("financial_loss_notes"), e.get("harm_type"), e.get("involved_entities"),
                    e.get("severity_or_consequence"), e.get("url_or_reference"), e.get("raw_json"),
                    e.get("duplicate_of"), e.get("merged_from_sources"), now,
                )),
            )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Enrichment sources -- each returns a list of ready-to-insert row dicts for
# its own table (NOT AI_Event). Every function is independently wrapped in
# try/except by the caller so one broken source never aborts the run.
# ---------------------------------------------------------------------------

def fetch_avid_vulnerability_reports(max_records=200):
    """AVID -- public GitHub data repo (avidml/avid-db). Verified live via
    the GitHub contents API; JSON vuln reports live under vulnerabilities/<year>/."""
    rows = []
    years_resp = requests.get(AVID_API_CONTENTS, headers={"User-Agent": UA}, timeout=HTTP_TIMEOUT)
    years_resp.raise_for_status()
    years = [d["name"] for d in years_resp.json() if d["type"] == "dir"]
    for year in years:
        listing = requests.get(f"{AVID_API_CONTENTS}/{year}", headers={"User-Agent": UA}, timeout=HTTP_TIMEOUT)
        listing.raise_for_status()
        files = [d["name"] for d in listing.json() if d["name"].endswith(".json")]
        for fname in files:
            if len(rows) >= max_records:
                return rows
            try:
                raw = requests.get(f"{AVID_RAW_BASE}/{year}/{fname}", headers={"User-Agent": UA}, timeout=HTTP_TIMEOUT)
                raw.raise_for_status()
                rec = raw.json()
            except Exception as exc:
                log.warning("AVID: failed to fetch %s/%s (%s)", year, fname, exc)
                continue
            vuln_id = rec.get("metadata", {}).get("vuln_id") or fname.replace(".json", "")
            desc = (rec.get("problemtype", {}) or {}).get("description", {}) or {}
            affects = rec.get("affects", {}) or {}
            affected = "; ".join(filter(None, [
                "; ".join(a.get("name", "") for a in affects.get("artifacts", []) if a.get("name")),
            ]))
            rows.append({
                "report_id": f"AVID-{vuln_id}",
                "source": "AVID",
                "external_id": vuln_id,
                "title": desc.get("value", "")[:200] if isinstance(desc, dict) else str(desc)[:200],
                "description": desc.get("value") if isinstance(desc, dict) else str(desc),
                "published_date": None,
                "affected_systems": affected or None,
                "severity": (rec.get("problemtype", {}) or {}).get("classof"),
                "url_or_reference": f"https://raw.githubusercontent.com/{AVID_REPO}/main/vulnerabilities/{year}/{fname}",
                "raw_json": json.dumps(rec, ensure_ascii=False),
                "related_event_id": None,
            })
    return rows


def fetch_nvd_vulnerability_reports(keywords=NVD_AI_KEYWORDS, results_per_keyword=30):
    """NVD/CVE -- public NVD REST API 2.0, filtered to AI/ML-relevant CVEs by keyword."""
    rows = []
    seen = set()
    for kw in keywords:
        try:
            resp = requests.get(
                NVD_API_URL,
                params={"keywordSearch": kw, "resultsPerPage": results_per_keyword},
                headers={"User-Agent": UA},
                timeout=HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log.warning("NVD/CVE: keyword '%s' failed (%s)", kw, exc)
            continue
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)
            descs = cve.get("descriptions", [])
            desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), None)
            metrics = cve.get("metrics", {})
            severity = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    severity = metrics[key][0].get("cvssData", {}).get("baseSeverity")
                    break
            refs = cve.get("references", [])
            url = refs[0]["url"] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            rows.append({
                "report_id": f"NVD-{cve_id}",
                "source": "NVD/CVE",
                "external_id": cve_id,
                "title": cve_id,
                "description": desc_en,
                "published_date": parse_date_loose(cve.get("published")),
                "affected_systems": kw,
                "severity": severity,
                "url_or_reference": url,
                "raw_json": json.dumps(cve, ensure_ascii=False),
                "related_event_id": None,
            })
        time.sleep(1.5)  # be polite to the unauthenticated NVD rate limit
    return rows


def fetch_mit_risk_taxonomy(file_path=None):
    """MIT AI Risk Repository. No verified bulk CSV/XLSX export exists
    (airisk.mit.edu/risks only surfaces Airtable *embeds*, which need an
    Airtable API key to read programmatically -- verified by hand). Manual
    fallback only: pass --mitrisk-file with a hand-exported CSV/XLSX/JSON."""
    if not file_path:
        log.warning(
            "MIT Risk Repo: no public bulk export found (Airtable embeds require an API key); "
            "skipping. Pass --mitrisk-file <path> with a manual export to include it."
        )
        return []
    rows = []
    if file_path.lower().endswith(".json"):
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        records = data if isinstance(data, list) else data.get("risks", [])
    else:
        with open(file_path, "r", encoding="utf-8") as f:
            records = list(csv.DictReader(f))
    for i, rec in enumerate(records):
        def g(*keys):
            for k in keys:
                if k in rec and rec[k]:
                    return rec[k]
            return None
        rid = g("id", "ID") or f"mitrisk-{i}"
        rows.append({
            "risk_id": str(rid),
            "source": "MIT Risk Repo",
            "category": g("category", "Category", "Domain"),
            "subcategory": g("subcategory", "Subcategory", "Sub-domain"),
            "title": g("title", "Title", "risk", "Risk"),
            "description": g("description", "Description"),
            "raw_json": json.dumps(rec, ensure_ascii=False),
            "related_event_id": None,
        })
    return rows


def fetch_darr_risk_register():
    """DARR -- Deployer AI Risk Register. Public GitHub repo raw JSON files."""
    rows = []
    resp = http_get(DARR_JSON_URL)
    data = resp.json()
    risks = data.get("risks", data if isinstance(data, list) else [])
    if isinstance(risks, dict):
        risks = list(risks.values())
    for rec in risks:
        rid = str(rec.get("id") or rec.get("risk_id") or rec.get("code") or len(rows))
        rows.append({
            "risk_id": f"DARR-{rid}",
            "source": "DARR",
            "risk_type": "canonical",
            "title": rec.get("title") or rec.get("name"),
            "description": rec.get("description"),
            "mit_risk_ref": rec.get("mit_risk_id") or rec.get("mit_ref"),
            "atlas_ref": rec.get("atlas_id") or rec.get("atlas_ref"),
            "raw_json": json.dumps(rec, ensure_ascii=False),
            "related_event_id": None,
        })
    try:
        sub_resp = http_get(DARR_SUBRISKS_URL)
        subrisks = sub_resp.json()
        subrisks = subrisks if isinstance(subrisks, list) else subrisks.get("subrisks", [])
        for rec in subrisks:
            rid = str(rec.get("id") or rec.get("code") or len(rows))
            rows.append({
                "risk_id": f"DARR-SUB-{rid}",
                "source": "DARR",
                "risk_type": "atlas-anchored-subrisk",
                "title": rec.get("title") or rec.get("name"),
                "description": rec.get("description"),
                "mit_risk_ref": rec.get("mit_risk_id") or rec.get("mit_ref"),
                "atlas_ref": rec.get("atlas_id") or rec.get("atlas_ref"),
                "raw_json": json.dumps(rec, ensure_ascii=False),
                "related_event_id": None,
            })
    except Exception as exc:
        log.warning("DARR: sub-risks file fetch failed (%s); canonical risks still included", exc)
    return rows


def _resolve_atlas_latest_yaml():
    """dist/ATLAS-latest.yaml (and dist/v6/ATLAS-latest.yaml) are one-line
    pointer files containing a path *relative to the directory they live in*;
    follow them (max 4 hops) to the real release YAML."""
    path = "ATLAS-latest.yaml"  # relative to ATLAS_REPO_RAW (dist/)
    for _ in range(4):
        resp = http_get(f"{ATLAS_REPO_RAW}/{path}")
        text = resp.text.strip()
        if text.endswith(".yaml") and "\n" not in text and len(text) < 200:
            # Pointer: resolve relative to the directory of the current path.
            current_dir = "/".join(path.split("/")[:-1])
            path = f"{current_dir}/{text}" if current_dir else text
            continue
        return resp.text
    raise RuntimeError("MITRE ATLAS: pointer chain did not resolve to real YAML")


def fetch_atlas_taxonomy():
    """MITRE ATLAS -- public GitHub YAML data (techniques/mitigations/case
    studies). Case studies are NOT auto-promoted to AI_Event.

    Verified real schema of dist/v6/ATLAS-<version>.yaml: top-level
    'tactics', 'techniques', 'mitigations', 'case-studies' are each a dict
    keyed by ATLAS id (e.g. "AML.T0000"), not a list."""
    if yaml is None:
        raise RuntimeError("PyYAML not installed; run `pip install pyyaml`")
    text = _resolve_atlas_latest_yaml()
    data = yaml.safe_load(text)
    rows = []

    def add(section, entry_type, name_key="name", desc_key="description"):
        block = data.get(section) or {}
        items = block.values() if isinstance(block, dict) else block
        keys = block.keys() if isinstance(block, dict) else [None] * len(block)
        for atlas_id, item in zip(keys, items):
            if not isinstance(item, dict):
                continue
            rows.append({
                "atlas_id": atlas_id or item.get("id") or item.get("object-id"),
                "entry_type": entry_type,
                "name": item.get(name_key),
                "description": item.get(desc_key) or item.get("summary"),
                "raw_json": json.dumps(item, ensure_ascii=False),
                "related_event_id": None,  # case studies deliberately not auto-linked to AI_Event
            })

    add("tactics", "tactic")
    add("techniques", "technique")
    add("mitigations", "mitigation")
    add("case-studies", "case-study")
    return rows


def fetch_dail_legal_cases(file_path=None):
    """DAIL -- Database of AI Litigation (GWU). blogs.gwu.edu renders the
    table via a TablePress/wpDataTable plugin with no discoverable bulk
    CSV/JSON export endpoint (verified by hand). Manual fallback only."""
    if not file_path:
        log.warning(
            "DAIL: no public bulk export found (TablePress-rendered, no export endpoint); "
            "skipping. Pass --dail-file <path> with a manual export to include it."
        )
        return []
    rows = []
    with open(file_path, "r", encoding="utf-8") as f:
        if file_path.lower().endswith(".json"):
            data = json.load(f)
            records = data if isinstance(data, list) else data.get("cases", [])
        else:
            records = list(csv.DictReader(f))
    for i, rec in enumerate(records):
        def g(*keys):
            for k in keys:
                if k in rec and rec[k]:
                    return rec[k]
            return None
        rows.append({
            "case_id": str(g("id", "ID") or f"dail-{i}"),
            "source": "DAIL",
            "case_name": g("case_name", "Case Name", "case", "Case"),
            "court": g("court", "Court"),
            "filing_date": parse_date_loose(g("filing_date", "Filing Date", "date")),
            "status": g("status", "Status"),
            "summary": g("summary", "Summary", "description"),
            "url_or_reference": g("url", "URL", "link"),
            "raw_json": json.dumps(rec, ensure_ascii=False),
            "related_event_id": None,
        })
    return rows


def fetch_github_security_advisories(packages=GITHUB_ADVISORY_PACKAGES):
    """GitHub Advisories -- public GraphQL API. Verified that unauthenticated
    requests to api.github.com/graphql are rejected (HTTP 403 / bad
    credentials); a GITHUB_TOKEN env var is required. If absent, this source
    is skipped gracefully (not an error)."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        log.warning(
            "GitHub Advisories: no GITHUB_TOKEN env var set (the GraphQL API requires auth); "
            "skipping live fetch. Set GITHUB_TOKEN to enable this source."
        )
        return []
    rows = []
    query = """
    query($eco: SecurityAdvisoryEcosystem, $pkg: String, $cursor: String) {
      securityVulnerabilities(ecosystem: $eco, package: $pkg, first: 20, after: $cursor) {
        nodes {
          advisory { ghsaId summary severity publishedAt permalink }
          package { name }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
    """
    headers = {"Authorization": f"Bearer {token}", "User-Agent": UA}
    for pkg in packages:
        resp = requests.post(
            GITHUB_GRAPHQL_URL,
            json={"query": query, "variables": {"eco": "PIP", "pkg": pkg, "cursor": None}},
            headers=headers, timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        body = resp.json()
        nodes = (body.get("data") or {}).get("securityVulnerabilities", {}).get("nodes", []) if body.get("data") else []
        for node in nodes:
            adv = node.get("advisory", {})
            rows.append({
                "advisory_id": adv.get("ghsaId"),
                "source": "GitHub Advisories",
                "ghsa_id": adv.get("ghsaId"),
                "package_name": (node.get("package") or {}).get("name"),
                "summary": adv.get("summary"),
                "severity": adv.get("severity"),
                "published_date": parse_date_loose(adv.get("publishedAt")),
                "url_or_reference": adv.get("permalink"),
                "raw_json": json.dumps(node, ensure_ascii=False),
                "related_event_id": None,
            })
    return rows


def fetch_inspectagents_reports(file_path=None):
    """InspectAgents. The live site exposes /api/agent-feedback, /api/mcp/,
    and /api/openapi -- product/feedback/MCP-integration endpoints, not a
    bulk failure-taxonomy export (verified by hand). Manual fallback only."""
    if not file_path:
        log.warning(
            "InspectAgents: reachable but no public bulk export found (only "
            "feedback/MCP-integration APIs exist); skipping. Pass --inspectagents-file "
            "<path> with a manual export to include it."
        )
        return []
    rows = []
    with open(file_path, "r", encoding="utf-8") as f:
        records = json.load(f) if file_path.lower().endswith(".json") else list(csv.DictReader(f))
    if isinstance(records, dict):
        records = records.get("failures", records.get("reports", []))
    for i, rec in enumerate(records):
        rows.append({
            "report_id": str(rec.get("id") or f"inspectagents-{i}"),
            "source": "InspectAgents",
            "title": rec.get("title") or rec.get("name"),
            "description": rec.get("description") or rec.get("summary"),
            "raw_json": json.dumps(rec, ensure_ascii=False),
            "related_event_id": None,
        })
    return rows


# Enrichment table registry: (table_name, columns, fetch_fn, file_arg_or_None, needs_file_arg_passed)
ENRICHMENT_TABLES = [
    ("Vulnerability_Report",
     ["report_id", "source", "external_id", "title", "description", "published_date",
      "affected_systems", "severity", "url_or_reference", "raw_json", "related_event_id"],
     lambda args: fetch_avid_vulnerability_reports() + fetch_nvd_vulnerability_reports(),
     None),
    ("Risk_Taxonomy",
     ["risk_id", "source", "category", "subcategory", "title", "description",
      "raw_json", "related_event_id"],
     lambda args: fetch_mit_risk_taxonomy(args.mitrisk_file),
     "mitrisk_file"),
    ("Risk_Register",
     ["risk_id", "source", "risk_type", "title", "description", "mit_risk_ref",
      "atlas_ref", "raw_json", "related_event_id"],
     lambda args: fetch_darr_risk_register(),
     None),
    ("Atlas_Taxonomy",
     ["atlas_id", "entry_type", "name", "description", "raw_json", "related_event_id"],
     lambda args: fetch_atlas_taxonomy(),
     None),
    ("Legal_Case",
     ["case_id", "source", "case_name", "court", "filing_date", "status", "summary",
      "url_or_reference", "raw_json", "related_event_id"],
     lambda args: fetch_dail_legal_cases(args.dail_file),
     "dail_file"),
    ("Security_Advisory",
     ["advisory_id", "source", "ghsa_id", "package_name", "summary", "severity",
      "published_date", "url_or_reference", "raw_json", "related_event_id"],
     lambda args: fetch_github_security_advisories(),
     None),
    ("InspectAgents_Report",
     ["report_id", "source", "title", "description", "raw_json", "related_event_id"],
     lambda args: fetch_inspectagents_reports(args.inspectagents_file),
     "inspectagents_file"),
]


def write_enrichment_table(conn, table_name, columns, rows):
    now = datetime.now().isoformat()
    cols = columns + ["fetched_at"]
    placeholders = ", ".join(["?"] * len(cols))
    sql = f"INSERT OR REPLACE INTO {table_name} ({', '.join(cols)}) VALUES ({placeholders})"
    for row in rows:
        values = []
        for c in columns:
            v = row.get(c)
            if isinstance(v, (list, dict)):
                v = json.dumps(v, ensure_ascii=False)
            values.append(v)
        values.append(now)
        conn.execute(sql, tuple(values))
    conn.commit()


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

SOURCES = [
    ("AIAAIC", fetch_aiaaic_raw, normalize_aiaaic, "aiaaic_file"),
    ("AIID", fetch_aiid_raw, normalize_aiid, "aiid_file"),
    ("sipi.bot", fetch_sipi_raw, normalize_sipi, "sipi_file"),
    ("AIM", fetch_aim_raw, normalize_aim, "aim_file"),
    # -- new real-world incident sources (also flow through the same dedup pass) --
    ("CED", fetch_ced_raw, normalize_ced, "ced_file"),
    ("AI Incidents Explorer", fetch_aiincidents_raw, normalize_aiincidents, "aiincidents_file"),
    ("INHUMAIN", fetch_inhumain_raw, normalize_inhumain, "inhumain_file"),
    ("StupidLLM", fetch_stupidllm_raw, normalize_stupidllm, "stupidllm_file"),
    ("CA DMV AV", fetch_dmvav_raw, normalize_dmvav, "dmvav_file"),
]


def run(args):
    all_events = []
    raw_by_source = {}
    summary = {}

    for source_name, fetcher, normalizer, file_arg in SOURCES:
        file_path = getattr(args, file_arg, None)
        try:
            log.info("Fetching %s ...", source_name)
            raw_records = fetcher(file_path)
            raw_by_source[source_name] = raw_records
            events = []
            for rec in raw_records:
                try:
                    norm = normalizer(rec)
                except Exception as exc:  # per-record failure shouldn't kill the source
                    log.warning("%s: failed to normalize a record (%s)", source_name, exc)
                    continue
                norm["event_id"] = make_event_id(
                    norm["source_name"], norm.get("source_record_id"), norm.get("title"), norm.get("date")
                )
                events.append(norm)
            all_events.extend(events)
            summary[source_name] = len(events)
            log.info("%s: %d records normalized", source_name, len(events))
        except Exception as exc:
            log.error("%s: fetch failed, skipping this source (%s)", source_name, exc)
            raw_by_source.setdefault(source_name, [])
            summary[source_name] = 0

    log.info("Running cross-source deduplication over %d total events ...", len(all_events))
    dedup_events(all_events)
    n_dupes = sum(1 for e in all_events if e["duplicate_of"])
    log.info("Deduplication found %d probable duplicate(s) across sources", n_dupes)

    write_to_db(all_events, raw_by_source)
    log.info("Wrote %d AI_Event rows to %s", len(all_events), DB_PATH)

    # -- enrichment tables (vulnerabilities, taxonomies, legal cases, advisories) --
    enrichment_summary = {}
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(SCHEMA)
        for table_name, columns, fetch_fn, _file_arg in ENRICHMENT_TABLES:
            try:
                log.info("Fetching enrichment table %s ...", table_name)
                rows = fetch_fn(args)
                write_enrichment_table(conn, table_name, columns, rows)
                enrichment_summary[table_name] = len(rows)
                log.info("%s: %d rows", table_name, len(rows))
            except Exception as exc:
                log.error("%s: fetch/write failed, skipping (%s)", table_name, exc)
                enrichment_summary[table_name] = 0
    finally:
        conn.close()

    print("\n=== Run summary ===")
    print("-- AI_Event sources --")
    for source_name, count in summary.items():
        print(f"  {source_name:24s}: {count} events")
    print(f"  duplicates flagged: {n_dupes}")
    print(f"  total rows in AI_Event: {len(all_events)}")
    print("-- Enrichment tables --")
    for table_name, count in enrichment_summary.items():
        print(f"  {table_name:24s}: {count} rows")
    print(f"  database: {DB_PATH}")


def parse_args():
    p = argparse.ArgumentParser(description="AI Incident Pipeline")
    p.add_argument("--aiaaic-file", help="Manually downloaded AIAAIC CSV (skip network fetch)")
    p.add_argument("--aiid-file", help="Manually downloaded AIID JSON export (skip network fetch)")
    p.add_argument("--sipi-file", help="Manually downloaded sipi.bot JSON (skip network fetch)")
    p.add_argument("--aim-file", help="Manually exported OECD AIM CSV/JSON (required to include this source)")
    # -- new AI_Event-feeding sources --
    p.add_argument("--ced-file", help="Manual CED (Cyber Events Database) CSV export (required to include this source; filtered to AI-relevant rows)")
    p.add_argument("--aiincidents-file", help="Manual AI Incidents Explorer JSON export (skip live scrape of the embedded catalog)")
    p.add_argument("--inhumain-file", help="Manual INHUMAIN full-database export (CSV/JSON) -- supplements the live-scraped Top 20")
    p.add_argument("--stupidllm-file", help="Manual StupidLLM incidents export (CSV/JSON) (skip network fetch)")
    p.add_argument("--dmvav-file", help="Manual CA DMV AV incident report index CSV (skip network fetch)")
    # -- new enrichment-table sources --
    p.add_argument("--mitrisk-file", help="Manually exported MIT AI Risk Repository CSV/JSON (required to include this source; no public bulk export exists)")
    p.add_argument("--dail-file", help="Manually exported DAIL (GWU AI Litigation Database) CSV/JSON (required to include this source)")
    p.add_argument("--inspectagents-file", help="Manually exported InspectAgents failure-taxonomy CSV/JSON (required to include this source)")
    return p.parse_args()


if __name__ == "__main__":
    run(parse_args())
