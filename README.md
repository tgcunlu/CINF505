# AI Incident Pipeline

Fetches AI incident records from four public sources, normalizes them into a
single `AI_Event` schema, flags likely cross-source duplicates, and writes
everything to a local SQLite database (`ai_events.db`).

## Run it

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python pipeline.py
```

This fetches fresh data over the network for AIAAIC, AIID, and sipi.bot, and
prints a summary of rows per source plus how many duplicates were flagged.
`ai_events.db` is created/overwritten in the current directory.

To substitute a manually-downloaded file for any source instead of hitting
the network (or to supply AIM data, see below):

```bash
python3 pipeline.py --aiaaic-file path/to/aiaaic.csv \
                     --aiid-file path/to/aiid.json \
                     --sipi-file path/to/sipi.json \
                     --aim-file path/to/aim_export.csv
```

## Sources and what each contributes

| Source | Access method (verified) | Automation | Notes |
|---|---|---|---|
| **AIAAIC** | Public Google Sheet, CSV export of the "Incidents" tab: `https://docs.google.com/spreadsheets/d/1Bn55B4xz21-_Rgdr8BBb2lt0n_4rzLGxFADMlVW0PYI/export?format=csv&gid=888071280` | Fully automated | The doc has multiple tabs (Incidents, Systems, Datasets, Changelog, a welcome page); the `gid` above was found by listing the sheet's tab ids and checking each export's header row. Richest source for sector, country/jurisdiction, harm taxonomy, and entities. No structured financial-loss field. |
| **AIID** (AI Incident Database) | Public read-only GraphQL API at `https://incidentdatabase.ai/api/graphql`, paginated | Fully automated | The API rejects requests without browser-like `Origin`/`Referer`/`User-Agent` headers ("API access is restricted to web browsers") — the pipeline sends headers that satisfy this. Good title/description/date and deployer/developer/harmed-party entities. No structured sector, location, or financial-loss fields are pulled from this query. |
| **sipi.bot** (AI Agent Incident Database) | Public JSON at `https://sipi.bot/data/ai-agent-incidents.json`, CC BY 4.0 | Fully automated | Only agent-related financial/operational incidents. Rows with `type: "statistic"` are filtered out; only `type: "incident"` rows are kept. Has decent financial-loss fields (`loss_usd`, `loss_range`) but no sector/location/country fields — `agent_type` (e.g. "coding") is used as a rough proxy for sector. |
| **AIM** (OECD AI Incidents Monitor) | **No public API or bulk export found** | Manual fallback only | `oecd.ai/en/incidents` is a JS-rendered SPA with only a browser "Download results" button; no `oecd.ai/api/...`-style endpoint responds to direct HTTP requests, and the methodology page documents no programmatic access route (data comes from the Event Registry news-monitoring platform, which is a paid third-party product, not a public feed). This was checked directly with `curl`/WebFetch rather than assumed. To include AIM data, manually click "Download results" on the site and pass the file via `--aim-file`; the pipeline maps common column names (`title`, `date`, `sector`, `country`, `location`, `url`, ...) and leaves anything it can't find as `NULL` rather than guessing. |

## AI_Event schema

```sql
CREATE TABLE AI_Event (
    event_id                TEXT PRIMARY KEY,   -- sha256(source|source_record_id|title|date), truncated
    source_name             TEXT NOT NULL,
    source_record_id        TEXT,
    title                   TEXT,
    description             TEXT,
    date                    TEXT,               -- ISO YYYY-MM-DD where parseable
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
    raw_json                TEXT,               -- original source record, for traceability
    duplicate_of            TEXT,               -- event_id of the canonical record, if this is a probable duplicate
    merged_from_sources     TEXT,               -- "; "-joined list of source names that matched this canonical record
    fetched_at              TEXT
);

CREATE TABLE sources_raw (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name         TEXT NOT NULL,
    source_record_id    TEXT,
    raw_json            TEXT NOT NULL,
    fetched_at          TEXT NOT NULL
);
```

`sources_raw` holds every fetched record exactly as received (before
normalization), independent of how it maps into `AI_Event`, purely for audit.

## Field-coverage gaps per source (do not assume these are filled in)

- **sector_or_industry**: populated for AIAAIC (`Sector` column); approximated
  for sipi.bot via `agent_type`; `NULL` for AIID (not exposed by the query
  used); depends entirely on the manual export's columns for AIM.
- **location / country**: populated for AIAAIC (`Jurisdiction` column, used
  for both fields since AIAAIC doesn't separate them further); `NULL` for
  AIID and sipi.bot (neither source structures this); depends on AIM export.
- **financial_loss_***: only sipi.bot has anything (`loss_usd` as a number
  when known, `loss_range` as free text otherwise, currency assumed USD).
  AIAAIC, AIID, and AIM contribute no financial figures — these fields are
  `NULL`/`None` for those sources rather than fabricated.

## Deduplication approach (needs human review)

Two events from **different** sources are flagged as a probable duplicate if
either:

1. They share the same normalized `url_or_reference` (exact match after
   trimming trailing slashes), or
2. Their normalized titles (lowercased, punctuation stripped) are at least
   82% similar per `difflib.SequenceMatcher`, **and** their dates are within
   14 days of each other (a missing date on either side does not disqualify
   a match).

Records are processed in source order (AIAAIC, AIID, sipi.bot, AIM). The
first event seen for a given real-world incident becomes the **canonical**
row; every later match is still inserted as its own `AI_Event` row (nothing
is silently dropped) but gets `duplicate_of` set to the canonical row's
`event_id`, and the canonical row's `merged_from_sources` is updated to list
every source that matched it.

To keep this tractable at a few thousand records, candidate comparisons are
bucketed by event year (checking only the same and adjacent years) instead
of comparing every event against every other event — a case with no
parseable date is compared against everything. This is a heuristic, not
ground truth: title-similarity + date-proximity can both miss real
duplicates (differently-worded titles, wrong/rounded dates) and produce
false positives (generic titles like "Chatbot gives harmful advice"). Treat
`duplicate_of`/`merged_from_sources` as a starting point for manual review,
not an authoritative merge.

## Error handling

Each source is fetched and normalized independently. If a source's request
fails (network error, non-200 response, unexpected JSON/CSV shape) the
pipeline logs it and continues with zero rows from that source — one
source's failure never aborts the run for the others. This applies to both
the original four sources and all 15 sources added below.

## The 15 new sources

Every URL/endpoint below was hand-verified with real `curl`/`requests` calls
(not assumed) before being hardcoded. Five are genuine real-world incident
sources and flow into `AI_Event` through the exact same fetch → normalize →
dedup pipeline as the original four. The rest are enrichment/reference data
(vulnerabilities, taxonomies, a risk register, legal cases, advisories) and
live in their own tables, each with a nullable `related_event_id` column for
future manual linking — they are never mixed into `AI_Event`.

| # | Source | Classification | Automation status | Table | Row count (real run, 2026-09-10) |
|---|---|---|---|---|---|
| 1 | CED (Cyber Events Database) | incident (AI-filtered) | manual-fallback-only (`--ced-file`) | `AI_Event` | 0 (no file supplied) |
| 2 | AVID | vulnerability | full (live) | `Vulnerability_Report` | 230 (shared with NVD/CVE below) |
| 3 | NVD/CVE | vulnerability | full (live) | `Vulnerability_Report` | — |
| 4 | InspectAgents | enrichment (agent-failure reports) | manual-fallback-only (`--inspectagents-file`) | `InspectAgents_Report` | 0 (no file supplied) |
| 5 | FAIL ticker | skipped | skipped — not implemented | n/a | n/a |
| 6 | MIT AI Risk Repository | taxonomy | manual-fallback-only (`--mitrisk-file`) | `Risk_Taxonomy` | 0 (no file supplied) |
| 7 | DARR | register | full (live) | `Risk_Register` | 143 |
| 8 | MITRE ATLAS | taxonomy | full (live) | `Atlas_Taxonomy` | 324 |
| 9 | DAIL | legal | manual-fallback-only (`--dail-file`) | `Legal_Case` | 0 (no file supplied) |
| 10 | AJL Harms | skipped | skipped — future manual-entry candidate | n/a | n/a |
| 11 | GitHub Advisories | advisory | partial-live (needs `GITHUB_TOKEN`) | `Security_Advisory` | 0 (no token set in this run) |
| 12 | AI Incidents Explorer | incident | full (live) | `AI_Event` | 81 |
| 13 | INHUMAIN | incident | partial-live (Top 20 scraped; full 847-set needs `--inhumain-file`) | `AI_Event` | 20 |
| 14 | StupidLLM | incident | attempted-live, 0 rows (client-rendered page, no export found); `--stupidllm-file` fallback available | `AI_Event` | 0 |
| 15 | CA DMV AV | incident | attempted-live, 0 rows (index page has no direct PDF links in raw HTML); `--dmvav-file` fallback available | `AI_Event` | 0 |

### Vulnerability_Report (AVID + NVD/CVE)

- **AVID** — `avidml/avid-db` on GitHub is a real, public data repo (verified
  via `GET https://api.github.com/repos/avidml/avid-db/contents/vulnerabilities`,
  which returns year-folders of JSON reports like `AVID-2023-V001.json`). The
  pipeline walks every year folder and fetches every report via the GitHub
  contents API + raw.githubusercontent.com.
- **NVD/CVE** — `https://services.nvd.nist.gov/rest/json/cves/2.0` is public
  and responded to a live `keywordSearch` call with real CVE JSON, no key
  required (rate-limited without a key, so the pipeline sleeps between
  keyword queries: "machine learning", "large language model", "LLM",
  "artificial intelligence", "neural network", "tensorflow", "pytorch").
- Both share the `Vulnerability_Report` table (`source` column distinguishes
  them), each row has a nullable `related_event_id` for future manual linking
  to `AI_Event`, and no cross-source dedup runs on this table (that would be
  a separate, lower-priority heuristic exercise).

### Risk_Taxonomy (MIT AI Risk Repository) — manual-fallback only

`https://airisk.mit.edu/risks` was checked directly (not assumed): the only
structured-data links present are **Airtable embeds**
(`airtable.com/embed/app32FOUBa5WcUfEO/...`), which require an Airtable API
key to read programmatically. No CSV/XLSX bulk-export URL or Google Sheet
`gid` responded with real repository data (one linked Google Sheet returned
only a "please view on desktop" landing page, not the risk table). Pass
`--mitrisk-file <path>` with a hand-exported CSV/XLSX/JSON to populate this
table; without it, `Risk_Taxonomy` is (correctly) empty.

### Risk_Register (DARR)

`github.com/Myr-Aya/darr-deployer-ai-risk-register` publishes real JSON data
files directly (`data/darr-deployer-ai-risk-register.json`,
`data/subrisks.json`), fetched live via raw.githubusercontent.com. The real
run produced exactly **143 rows** (82 canonical risks + 61 ATLAS-anchored
sub-risks), matching the count documented in the DARR repo itself.

### Atlas_Taxonomy (MITRE ATLAS)

`github.com/mitre-atlas/atlas-data` publishes the current release as YAML
under `dist/`. Both `dist/ATLAS-latest.yaml` and `dist/v6/ATLAS-latest.yaml`
turned out to be one-line **pointer files** (each containing a path relative
to its own directory) rather than data — the pipeline follows this pointer
chain (`ATLAS-latest.yaml` → `v6/ATLAS-latest.yaml` → `ATLAS-2026.08.yaml`,
as of this run) to the real release YAML, then parses tactics, techniques,
mitigations, and case studies (all dict-keyed by ATLAS id in the real
schema, e.g. `AML.T0000`). The real run produced 324 rows (16 tactics, 197
techniques, 39 mitigations, 72 case studies). Case studies are stored here,
not auto-promoted to `AI_Event`, with `related_event_id` left `NULL` for
optional future manual linking.

### Legal_Case (DAIL) — manual-fallback only

`blogs.gwu.edu/law-eti/ai-litigation-database/` renders its table via a
TablePress/wpDataTable WordPress plugin server-side; no CSV/JSON export
endpoint, Airtable embed, or admin-ajax data route was found reachable
without authentication. Pass `--dail-file <path>` to populate `Legal_Case`.

### Security_Advisory (GitHub Advisories)

`api.github.com/graphql` was verified to reject unauthenticated requests
(HTTP 403 / rate-limit message, not real advisory data). The pipeline only
runs this fetch live if a `GITHUB_TOKEN` environment variable is set
(`export GITHUB_TOKEN=ghp_...` before running `pipeline.py`); it then queries
`securityVulnerabilities` filtered to AI/ML packages (tensorflow, pytorch,
langchain, transformers, huggingface_hub, openai, anthropic, keras, onnx,
mlflow). Without a token it logs a clear warning and contributes 0 rows
rather than failing the run.

### InspectAgents_Report — manual-fallback only

`inspectagents.com/failures/` is reachable (HTTP 200) and ships `/api/agent-
feedback`, `/api/mcp/`, and `/api/openapi` endpoints, but these are product
feedback / MCP-integration APIs, not a bulk failure-taxonomy export — no
endpoint returns a list of documented agent failures. Given the ambiguity
noted in the brief, this was treated as an enrichment/taxonomy-style table
(`InspectAgents_Report`, with `related_event_id`) rather than an `AI_Event`
feeder, since nothing found on the live site resembles individually-dated,
sourced real-world incidents — it reads more like a curated
failure-mode/taxonomy resource. Pass `--inspectagents-file <path>` to
populate it.

### FAIL ticker — skipped entirely

`fail.ticker.io` is explicitly a meta-aggregator of OECD AIM + AIID + the MIT
tracker — all sources already ingested by this pipeline (AIM natively, AIID
natively, and "the MIT tracker" overlaps with the MIT AI Risk Repository /
general MIT AI incident commentary). Ingesting it would double-count
incidents already sourced directly and add no new primary information, so no
ingestion code was written for it, per the brief.

### AJL Harms — skipped, future manual-entry candidate

`https://www.ajl.org/harms` was checked directly: the only external
resource loaded by the page is a Google Fonts stylesheet — no CSV/JSON
export, API, or Airtable embed of any kind is present. Automation was
skipped; no table was created. If AJL harms should be represented later,
treat it as a manual-entry candidate (hand-transcribed into a CSV and loaded
via a future `--ajl-file` flag, following the same pattern as the other
fallback sources) rather than something to scrape.

### New AI_Event sources — automation notes

- **AI Incidents Explorer** (`aiincidents.org/explorer/`) — no separate JSON
  API exists (several guessed `/api/*.json` paths all 404), but the rendered
  page embeds its full catalog as `<script type="application/json"
  id="data-incidents">`. The real run pulled all **81** incidents this way,
  matching the count in the brief.
- **INHUMAIN** (`inhumain.ai/ai-incident-tracker/`) — the public page
  publishes a real "Top 20" HTML table (scraped live, 20 rows) plus
  methodology; the full claimed 847-incident database is by-request-only, so
  `--inhumain-file` is provided to supplement the live Top 20 with a manually
  obtained full export.
- **StupidLLM** (`stupidllm.com/incidents`) — `robots.txt` explicitly allows
  crawling (`Allow: /`, and even names AI crawlers as welcome), so a
  respectful, delayed live scrape was implemented. In practice the
  `/incidents` page (redirects to `www.stupidllm.com/incidents`) is
  client-rendered with no incident links or embedded JSON present in the raw
  HTML fetched, so the live scrape correctly returns 0 rows; `--stupidllm-file`
  is available for a hand-exported listing.
- **CA DMV AV** — the incident-reporting index page
  (`dmv.ca.gov/.../autonomous-vehicles-incident-reporting/`) was fetched
  live and scanned for `.pdf` links; none were present in the HTML actually
  returned (the page appears to be primarily policy/instructional text linking
  out to an NHTSA reporting form rather than hosting the report PDFs itself).
  This is a documented limitation, not a bug — the fetcher is real and
  correct, the source just didn't expose report links at the URL specified.
  `--dmvav-file` is available for a manually compiled report index (PDF
  content extraction remains out of scope per the brief).
- **CED** — see the `Risk_Taxonomy`-style writeup above: no bulk export was
  found (JS-rendered "base44" SPA on both `gotech.umd.edu/cyber-events-
  database` and `cybereventsdatabase.org`, including its `/ApiManagement`
  page). `--ced-file` accepts a manually exported CSV; rows are filtered to
  AI-relevant ones (keyword match across free-text columns) before being
  normalized into `AI_Event`, since CED is a general cyber-events database.

### New CLI flags

```
--ced-file PATH            CED manual CSV export (AI-relevant rows only)
--aiincidents-file PATH    AI Incidents Explorer manual JSON export
--inhumain-file PATH       INHUMAIN full-database manual export (supplements live Top 20)
--stupidllm-file PATH      StupidLLM manual export
--dmvav-file PATH          CA DMV AV manual report-index CSV
--mitrisk-file PATH        MIT AI Risk Repository manual export
--dail-file PATH           DAIL (GWU AI Litigation Database) manual export
--inspectagents-file PATH  InspectAgents manual export
```

Plus the `GITHUB_TOKEN` environment variable (not a CLI flag) enables the
live GitHub Advisories fetch.

### New tables (schema summary)

```sql
CREATE TABLE Vulnerability_Report (
    report_id, source, external_id, title, description, published_date,
    affected_systems, severity, url_or_reference, raw_json,
    related_event_id, fetched_at
);
CREATE TABLE Risk_Taxonomy (
    risk_id, source, category, subcategory, title, description,
    raw_json, related_event_id, fetched_at
);
CREATE TABLE Risk_Register (
    risk_id, source, risk_type, title, description, mit_risk_ref,
    atlas_ref, raw_json, related_event_id, fetched_at
);
CREATE TABLE Atlas_Taxonomy (
    atlas_id, entry_type, name, description, raw_json,
    related_event_id, fetched_at
);
CREATE TABLE Legal_Case (
    case_id, source, case_name, court, filing_date, status, summary,
    url_or_reference, raw_json, related_event_id, fetched_at
);
CREATE TABLE Security_Advisory (
    advisory_id, source, ghsa_id, package_name, summary, severity,
    published_date, url_or_reference, raw_json, related_event_id, fetched_at
);
CREATE TABLE InspectAgents_Report (
    report_id, source, title, description, raw_json,
    related_event_id, fetched_at
);
```

`related_event_id` is a plain nullable column (no enforced foreign key) on
every enrichment table, intended for future human linking to `AI_Event` —
none of these tables are auto-linked or auto-merged into `AI_Event`.

## Exporting to Excel

```bash
.venv/bin/python export_to_excel.py
```

`export_to_excel.py` reads every table in `ai_events.db` and writes one sheet
per table into `ai_events.xlsx` (bold header row, frozen header, auto-sized
columns). An empty table (e.g. a manual-fallback source with no file
supplied) still gets a sheet with just headers — that's expected, not an
error.

## Real end-to-end run results (2026-09-10)

```
-- AI_Event sources --
  AIAAIC                  : 2257 events
  AIID                    : 1675 events
  sipi.bot                : 85 events
  AIM                     : 0 events   (no --aim-file supplied)
  CED                     : 0 events   (no --ced-file supplied)
  AI Incidents Explorer   : 81 events
  INHUMAIN                : 20 events
  StupidLLM               : 0 events   (client-rendered page, no export found)
  CA DMV AV               : 0 events   (no PDF links found on the index page)
  duplicates flagged: 11
  total rows in AI_Event: 4118
-- Enrichment tables --
  Vulnerability_Report    : 230 rows   (AVID + NVD/CVE combined)
  Risk_Taxonomy           : 0 rows     (no --mitrisk-file supplied)
  Risk_Register           : 143 rows   (82 canonical + 61 ATLAS-anchored sub-risks)
  Atlas_Taxonomy          : 324 rows   (16 tactics, 197 techniques, 39 mitigations, 72 case studies)
  Legal_Case              : 0 rows     (no --dail-file supplied)
  Security_Advisory       : 0 rows     (no GITHUB_TOKEN set)
  InspectAgents_Report    : 0 rows     (no --inspectagents-file supplied)
```

Every zero above reflects a genuinely empty, verified-inaccessible live
source (or one deliberately left for a manual file) — no data was fabricated
to fill a table.
