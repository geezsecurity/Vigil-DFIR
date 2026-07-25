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
- **Super-timeline** — full-log activity histogram + a merged, filterable notable-event
  feed (detections, logons, RDP, lateral movement …) with click-to-zoom time windows.
- **Evidence** — mined forensic artifacts (accounts, services, tasks, LSASS access, share
  access, Defender hits, **paired logon sessions**, **auto-decoded PowerShell `-enc`**, IOCs).
- **One-click IR report** — export a full triage summary as **HTML, PDF, or DOCX**.

**Performance & UX**
- Constant-memory streaming `.evtx` parser (handles multi-GB files).
- Server-side in-memory case index → sub-50 ms search/filter/sort across the whole log.
- Fetch-on-scroll grid: the browser holds only the visible rows.
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
                    in-memory case index, server-side detection + analytics
  engine.cjs        Detection engine (heuristics + Sigma + YARA + ATT&CK + correlation)
  public/index.html Single-file UI ("Vigil") — engine is inlined for offline use
  test/             engine regression harness  (npm test)
  Dockerfile        Alpine image (pure-JS, no native build)
  docker-compose.yml
```

Key endpoints: `/api/upload`, `/api/search`, `/api/bodies` (fetch-on-scroll),
`/api/detect`, `/api/detections`, `/api/dashboard`, `/api/evidence`, `/api/entity`,
`/api/timeline`, `/api/cat` (Firewall/VPN).

---

## Security notes

- The server has **no authentication** — run it on a trusted host / network only, and
  never expose it directly to the internet.
- The optional **AI** feature sends selected event JSON to an external API — don't use it
  on data you can't share externally.
- **Case data is never committed** — `data/` is git-ignored. Keep real incident data out
  of version control.

---

## Status

Actively developed. Detection engine, ATT&CK, correlation, entity profiles, super-timeline,
evidence, and reporting are implemented and covered by the test harness. Firewall/VPN
analytics, IOC watchlists, and analyst notes are on the roadmap.
