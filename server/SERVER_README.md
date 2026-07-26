# EVTX Triage — Server Edition

Run the analyzer as a small web service on a Linux box. **Parsing and rule scanning
happen on the server**, the current log + rules + detections are **persisted on disk**,
and the browser just renders. Refreshing the page restores your session; **Remove Current
Log** wipes it and starts fresh (your loaded rules are kept).

## What moved to the server
- `.evtx` / JSONL parsing (no longer uses browser memory/CPU).
- Sigma + YARA + heuristic detection scanning.
- Rule storage — rules pulled from the internet **or** uploaded from your machine are
  saved under `data/rules/` and survive restarts.
- Session persistence — the parsed log and its detections are stored under `data/`, so a
  browser refresh re-loads them instead of starting empty.

## Requirements
- Node.js **22.5+** — the case index uses Node's built-in `node:sqlite` (SQLite + FTS5),
  which is still pure-JS (no native build / toolchain). The server checks your version on
  startup and tells you if it's too old.

If `npm start` prints that Node is too old, install a current one (e.g. `nvm install 22`)
and retry.

## Install & run
```bash
cd server
npm install
npm start
# -> EVTX Triage server on http://localhost:8742  (data: ./server/data)
```
Open `http://<server-ip>:8742/` in your browser. The page detects the backend
automatically and switches to server mode (title shows "EVTX Triage (server)").

### Run with Docker (one command)
```bash
cd server
docker compose up -d --build      # builds the image and starts it
# -> http://localhost:8742
docker compose logs -f            # follow logs
docker compose down               # stop (cases persist in the evtx-data volume)
```
Cases, rules and detections live in the **`evtx-data`** named volume, so they survive
restarts and rebuilds. To keep them in a host folder instead, edit `docker-compose.yml`
and change the volume line to `- ./data:/data`. Configuration is via the same env vars
below (set them under `environment:` in the compose file). The image is pure-JS (Alpine
base, no native build) and includes a `/api/meta` healthcheck.

Run tests before building an image:
```bash
npm test          # engine regression harness (fast, no dependencies)
```

### Configuration (optional)
| Env var             | Default        | Meaning                                            |
|---------------------|----------------|----------------------------------------------------|
| `PORT`              | `8742`         | Port to listen on                                  |
| `EVTX_DATA`         | `./data`       | Where logs/rules/detections live                   |
| `EVTX_BROWSE_CAP`   | `1000000`       | Max events streamed to the grid (UI window)        |
| `EVTX_DETECT_CAP`   | `2000000`      | Max events scanned per detection pass (RAM bound)  |

Large logs (multi-GB `.evtx`) are parsed in **constant memory** by streaming 64 KB chunks
straight to disk, so the server won't OOM. The browser then loads the first
`EVTX_BROWSE_CAP` events for the interactive grid (a banner shows the window), while
**detections are computed server-side across up to `EVTX_DETECT_CAP` events** and shown in
the ⚑ Detections tab. Raise `EVTX_DETECT_CAP` if you have the RAM and want the whole log
scanned in one pass.

```bash
PORT=9000 EVTX_DATA=/var/lib/evtx-triage EVTX_DETECT_CAP=5000000 npm start
```

### Run as a service (systemd)
```ini
# /etc/systemd/system/evtx-triage.service
[Unit]
Description=EVTX Triage
After=network.target

[Service]
WorkingDirectory=/opt/evtx-triage/server
ExecStart=/usr/bin/node server.mjs
Environment=PORT=8742
Environment=EVTX_DATA=/var/lib/evtx-triage
Restart=on-failure
User=evtx

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl enable --now evtx-triage
```

## Usage
1. **Open file** → pick one or more `.evtx` / JSONL files (multi-select works). They upload;
   the server parses and stores them as a **case**.
2. **+ Add logs** → append more Windows event logs (Security + System + Sysmon +
   PowerShell …) to the current case without losing what's loaded. A progress bar shows
   upload %, then server-side parsing. ★ flags are kept and detections re-run across
   everything. The **case bar** above the grid shows a chip per source log (empty logs
   hidden) with its count — click one to filter the grid to that log.

### Firewall & VPN sections
There are dedicated **🔥 Firewall** and **🔒 VPN** tabs, each with its own
**+ Add Firewall/VPN log** button. Logs added there (pfSense, FortiGate, Palo Alto,
iptables, Cisco ASA, OpenVPN, AnyConnect, WireGuard, GlobalProtect, IPsec, syslog, etc.)
are parsed, tagged by category, and shown **only in their own section** — they are kept out
of the main Events grid and the case bar so they don't drown out the Windows event flow.
Each tab shows a live count, and rows are clickable for full detail. Raw text log lines are
mapped to events tagged by source with the original line preserved as the message.
3. **Load sample** → generates a small **synthetic** incident across three fake source logs
   using `example.com` domains and TEST-NET IPs (no real data). Good for a quick demo; it
   lights up detections and evidence (brute force, external RDP, rogue account + priv-esc,
   Kerberoasting, malicious PowerShell, LSASS access, persistence, log clearing).
4. Default well-known SigmaHQ rules are fetched **by the server** on first load. Add more
   via **⚑ Rules** — paste, URL, or **Choose rules folder…** (uploads your local Hayabusa
   `rules/` to the server, where they're saved).
5. Detections, Evidence, and Dashboard populate from the server's scan across the case.
6. **Refresh anytime** — your case, detections, and **flagged events (★)** all come back.
   Flags are saved two ways — instantly in the browser (localStorage) **and** on the server —
   and merged on reload, so they survive a refresh reliably. **Remove Current Log** clears the
   case (keeps saved rules).
7. **Light / dark theme** — toggle with the 🌙 / ☀ button in the top-right corner.

> Tip: after deploying a new build, do one hard refresh (Ctrl/Cmd+Shift+R). Open the browser
> console — it logs the build stamp (e.g. `Vigil build 2026-06-25 · flags+localStorage`) so
> you can confirm you're running the latest code rather than a cached page.

## API (for scripting)
| Method | Path                  | Purpose                                   |
|--------|-----------------------|-------------------------------------------|
| POST   | `/api/upload`         | multipart `file` → parse + store (new case)|
| POST   | `/api/upload?mode=append` | parse + **append** files to current case |
| GET    | `/api/events`         | stored events as NDJSON                    |
| GET    | `/api/meta`           | current session + rule counts             |
| POST   | `/api/rules/default`  | server fetches curated SigmaHQ set        |
| POST   | `/api/rules/fetch`    | `{url}` → fetch+save one rule             |
| POST   | `/api/rules/upload`   | multipart rule files → save               |
| POST   | `/api/rules/clear`    | delete all saved rules                    |
| GET    | `/api/rules`          | rule file counts                          |
| POST   | `/api/detect`         | scan stored log with stored rules         |
| GET    | `/api/detections`     | stored detection results                  |
| POST   | `/api/reset`          | remove current log + detections           |
| GET    | `/api/suppressions`   | list suppressed rule IDs                  |
| POST   | `/api/suppressions`   | `{ruleId,suppress}` toggle (or `{suppressed:[]}`) — re-filters detections |
| GET    | `/api/cases`          | list cases (id, name, count, active)      |
| POST   | `/api/cases`          | `{name}` → create + activate a new case   |
| POST   | `/api/cases/:id/activate` | switch the active case                |
| DELETE | `/api/cases/:id`      | delete a case (logs + index + custody)    |

`/api/search` accepts `{ q, eid, provider, src, excluded[], det, ruleId, technique,
flagged, timeRange, sort, limit, offset }` and runs against the per-case SQLite index
(FTS5 free-text + `LIMIT/OFFSET` pagination). `/api/meta` now also returns `activeCase`,
`cases[]` and the current case's `custody[]` (SHA-256 per ingested file).

## Security notes (read before exposing it)
- There is **no authentication**. Anyone who can reach the port can upload logs, read
  stored events, and trigger outbound rule fetches. Bind it to localhost and reach it over
  an SSH tunnel, or put it behind a reverse proxy with auth / IP allow-listing.
- It makes **outbound HTTPS** to `raw.githubusercontent.com` only when you load rules.
- Single-session design: one "current log" at a time (a new upload replaces the old).
- `data/` holds your event data in clear JSON — protect that directory.

## Very large logs (millions of events)
Parsing and detection run **server-side with constant memory**, so multi-GB `.evtx` files and
cases with millions of events are handled on the server. Because a browser tab can't hold
millions of rows at once, the **Events grid shows one window at a time** (a few hundred
thousand events) with **‹ Prev / Next ›** buttons in the banner to page through the whole log.
Flags keep their true positions across windows. Detections, Firewall and VPN are computed over
the **entire** log, and the **Dashboard** shows a server-computed **full-log overview** (totals,
failed logons, notable events, time span, top providers / Event IDs / computers / usernames, and
an activity timeline), so you get the whole picture even while the grid is windowed. Evidence
reflects the currently loaded window. Raise `EVTX_BROWSE_CAP` to fetch more per window on a
large server (very large windows will stress the browser).

## Notes & limits (same engine as the single-file build)
- The Events grid is windowed for big cases (see above); detections and the dashboard cover
  the full log. True on-demand row virtualization across 10M+ rows with server-side search is
  a possible future step.
- YARA support is a lightweight subset (strings/regex/hex/counts), not full libyara.
- Sigma **pipe-aggregations** are supported — `count() / count(field) / sum / min / max /
  avg`, optional `by <field>`, with a sliding `timeframe` window (brute force, password
  spray, user guessing, Kerberoasting…). `near` and Sigma v2 reference-based correlation
  rules are not yet evaluated.
- Sigma field mapping uses a synonym map, not the full Sigma pipeline config.

## Offline / static fallback
The same UI still works as a standalone file (`evtx-analyzer.html`) with no server — open
it directly and parsing/detection run in the browser. When served by this backend, it
automatically uses the server instead.
