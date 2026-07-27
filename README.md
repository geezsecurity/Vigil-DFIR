# Log-Triage (Vigil)

**Fast, self-hosted Windows Event Log (.evtx) triage for DFIR.** Load a case, and in
seconds get rule + heuristic + YARA detections, MITRE ATT&CK coverage, reconstructed
attack chains, risk-ranked entities, a merged super-timeline, mined forensic evidence,
and a one-click incident-response report — all in the browser, with parsing and detection
running server-side so multi-hundred-MB logs never choke your tab.

> Parsing and rule scanning happen on the server; the browser only renders. A 335k-event
> case loads as one continuous scroll (fetch-on-scroll), and search/filter is instant.

---

## Highlights

**Detection engine** (`engine.cjs`, also runs in-browser for offline use)
- **3 layers:** behavioral heuristics (always on) + a Sigma subset (with Windows field
  mapping, modifiers, and boolean conditions) + a YARA-lite string/regex/hex engine.
- **Aho-Corasick prescreen** so thousands of Sigma rules scan huge logs quickly.
- **Sigma pipe-aggregations** (`count` / distinct `count(field)` / `sum` / `min` / `max` /
  `avg`, `by <field>`, sliding `timeframe`) run as a windowed correlation pass — brute
  force, password spray, user guessing, Kerberoasting-style thresholds.
- Heuristics for log clearing, brute force / password spray, encoded PowerShell, new
  services, external RDP, account & privileged-group changes, Kerberoasting, **DCSync,
  LSASS dumping, PsExec, overpass-the-hash, and malicious scheduled tasks**.

**Investigation surface**
- **MITRE ATT&CK** — coverage matrix (tactics × techniques), click a technique to filter
  the grid, and one-click **ATT&CK Navigator layer** export.
- **Attack-chain correlation** — groups detections per host into time-bounded bursts and
  names them by kill-chain progression (`Execution → Persistence → Defense Evasion → …`).
- **Entity risk scoring** — ranks users / hosts / IPs by severity + technique diversity
  (with noise dampening), each opening a full **profile dossier** (related entities you
  can walk, logon stats, techniques, timeline).
- **Process-tree reconstruction** — rebuilds process ancestry from Sysmon `ProcessGuid` /
  `ParentProcessGuid` (EID 1, end times from EID 5) into an interactive collapsible tree with
  expand/collapse-all, live image/command/PID search, a *detections-only* filter, per-process
  run-time and PID, and uncaptured-parent hints; branches with a detection are highlighted and
  each node opens its event.
- **Logon-session reconstruction** — pairs 4624 logons with their 4634/4647 logoff by
  `LogonId` into a sortable, filterable session table (decoded logon type, source IP /
  workstation, duration, RDP + external-source flags, still-active sessions).
- **Lateral-movement graph** — an interactive, draggable node-link map of host↔host / IP→host
  movement derived from remote logons (4624 type 3/10), explicit credentials (4648), NTLM
  (4776), RDP (1149) and share access (5140/5145); edges are colored by technique, detection
  paths are highlighted, and clicking a node pivots the grid.
- **Watchlist** — two modes. **Observed in case** auto-carves every **IP / hash / domain**
  present in the logs (IPs from address fields, hashes from Sysmon `Hashes`, domains from DNS
  queries), filterable by type with counts, hosts and first/last seen. **My indicators** lets
  you paste or upload known-bad IOCs (reused across cases) and scan the case for matches —
  IPs/hashes/domains match on exact tokens (no substring false positives), files/users via an
  Aho-Corasick pass.
- **Threat-intel enrichment** — with an API key configured in **⚙ Settings**, check any
  observed or matched IP/hash against **AbuseIPDB** (abuse score, ISP, Tor) and **VirusTotal**
  (malicious-engine ratio, file name/type) — one click per row, or "Check all shown" (throttled
  for free tiers). A malicious/suspicious/clean verdict is shown inline. Keys live server-side
  (git-ignored); results cache for 24h. Fully opt-in.
- **Rarity & stacking** — long-tail frequency analysis to surface what rules miss: distinct
  **processes**, **parent → child** pairs (abnormal ancestry like Office/web-server → shell is
  flagged), **logon origins** (user × host × type × source) and **services**, each sorted
  rarest-first with a *rare only* filter, hosts, first/last seen, and grid pivot.
- **Super-timeline** — full-log activity histogram + a merged, filterable notable-event
  feed (detections, logons, RDP, lateral movement …) with click-to-zoom time windows.
- **Evidence** — mined forensic artifacts (accounts, services, tasks, LSASS access, share
  access, Defender hits, **paired logon sessions**, **auto-decoded PowerShell `-enc`**, IOCs).
- **Casework** — turn triage into a case file: tag any event with a **verdict** (True /
  False Positive, Suspicious, Benign, Reviewed) plus **tags** and a **note** (a colored edge
  marks annotated rows in the grid), and keep a **case narrative** + **findings** list in the
  📝 Case Notes tab. All persisted per-case and folded into the IR report.
- **One-click IR report** — export a full triage summary — now including the **analyst
  assessment** (narrative, findings, and True-Positive / Suspicious verdicts) — as **HTML,
  PDF, or DOCX**.
- **✦ AI Support** — bring your own model (**Claude**, **ChatGPT**, or **Gemini** — pick one in
  ⚙ Settings and paste its key). A context-aware **AI Support** button in every section explains
  what it's looking at; on the **Dashboard** it narrates *what happened* across the case, in
  **Case Notes** it drafts a concise incident summary straight into the report, and in the event
  modal it explains a single record. Calls run **server-side** (keys stay server-side, never in
  the browser).

**Performance & UX**
- Constant-memory streaming `.evtx` parser (handles multi-GB files).
- **Disk-backed SQLite event index (FTS5)** → search / filter / sort + true `LIMIT/OFFSET`
  pagination that scales past RAM to 10M+ events (built on Node's built-in `node:sqlite`,
  so there's still no native build step). Free-text is token/prefix via FTS5, with an exact
  substring fallback for IPs / paths / hash fragments.
- Fetch-on-scroll grid: the browser holds only the visible rows.
- **Multi-case workspace** — each case is its own directory + index; create, switch, and
  delete cases from the toolbar without losing the others.
- **Chain of custody** — every ingested file is SHA-256 hashed on upload and recorded with
  its size, type and ingest time.
- Dedicated Firewall and VPN sections; multi-file case management; flagging; session
  persistence across refreshes.

---

## Quick start

### npm
```bash
cd server
npm install
npm start
# → EVTX Triage server on http://localhost:8742
```
> Requires **Node.js 22.5+** (the case index uses the built-in `node:sqlite`). The server
> checks your version on startup and tells you if it's too old.

### Docker
```bash
cd server
docker compose up -d --build
# → http://localhost:8742      (cases persist in the evtx-data volume)
docker compose down
```

Open `http://localhost:8742/`, drop in `.evtx` / JSONL files (or **Load sample**), and the
UI switches to server mode automatically.

> **Offline mode:** opening `server/public/index.html` directly as a file also works —
> parsing and detection then run entirely in the browser (best for small logs).

---

## Configuration

| Env var            | Default     | Meaning                                            |
|--------------------|-------------|----------------------------------------------------|
| `PORT`             | `8742`      | Port to listen on                                  |
| `EVTX_DATA`        | `./data`    | Where logs / rules / detections are stored         |
| `EVTX_BROWSE_CAP`  | `1000000`   | Events streamed to the grid before fetch-on-scroll |
| `EVTX_DETECT_CAP`  | `2000000`   | Max events scanned per detection pass (RAM bound)  |

In Docker, set these under `environment:` in `docker-compose.yml`.

---

## Tests

A dependency-free regression harness covers the detection engine (heuristics, Sigma field
modifiers + conditions, YARA-lite, Aho-Corasick index parity, ATT&CK mapping, entity
scoring, attack-chain correlation):

```bash
cd server
npm test
```

---

## Architecture

```
server/
  server.mjs        Express backend: streaming .evtx parser, /api/* endpoints,
                    multi-case management, server-side detection + analytics
  store.mjs         SQLite layer (node:sqlite): case catalog, chain of custody,
                    per-case event index + FTS5 search
  engine.cjs        Detection engine (heuristics + Sigma + YARA + ATT&CK + correlation)
  public/index.html Single-file UI ("Vigil") — engine is inlined for offline use
  test/             engine regression harness  (npm test)
  Dockerfile        Alpine image (node:22, pure-JS, no native build)
  docker-compose.yml

data/
  catalog.db        cases list + SHA-256 chain of custody
  cases/<id>/       events.jsonl (bodies) · events.idx · index.db (SQLite+FTS) · meta/dets/flags
```

Key endpoints: `/api/upload`, `/api/search` (SQLite/FTS, paginated), `/api/bodies`
(fetch-on-scroll), `/api/detect`, `/api/detections`, `/api/dashboard`, `/api/evidence`,
`/api/entity`, `/api/timeline`, `/api/cat` (Firewall/VPN), and case management
(`/api/cases`, `POST /api/cases`, `POST /api/cases/:id/activate`, `DELETE /api/cases/:id`).

---

## Security notes

- The server has **no authentication** — run it on a trusted host / network only, and
  never expose it directly to the internet.
- The optional **AI Support** feature sends a summary of the selected data (an event, the
  detections, or a case overview) to the AI provider you configured (**Claude / ChatGPT /
  Gemini**). Keys live server-side in the git-ignored `data/settings.json` (or `ANTHROPIC_API_KEY`
  / `OPENAI_API_KEY` / `GEMINI_API_KEY`) and are never returned to the browser. Don't use it on
  data you can't share externally.
- **Threat-intel enrichment** is opt-in and only runs when you click an indicator. It sends
  that single IP/hash to **AbuseIPDB / VirusTotal**. API keys are stored server-side in the
  git-ignored `data/settings.json` (or the `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` env
  vars) and are never returned to the browser.
- **Case data, watchlists and API keys are never committed** — `data/` is git-ignored. Keep
  real incident data out of version control.

---

## Status

Actively developed. Detection engine, ATT&CK, correlation, entity profiles, super-timeline,
evidence, and reporting are implemented and covered by the test harness. Firewall/VPN
analytics are on the roadmap.
