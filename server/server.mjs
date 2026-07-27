// EVTX Triage — server backend
// Moves .evtx parsing and rule scanning off the browser and onto this Linux host,
// persists the current log + rules + detections on disk, and serves the UI.
import express from "express";
import multer from "multer";
import yaml from "js-yaml";
import { parseEvtxFile, parseEvtxFileAsync } from "winevtx";
import { Buffer as NodeBuffer } from "node:buffer";
import fs from "node:fs";
import { open as fsopen } from "node:fs/promises";
import readline from "node:readline";
import path from "node:path";
import https from "node:https";
import http from "node:http";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import crypto from "node:crypto";
import { Catalog, CaseIndex } from "./store.mjs";

const require = createRequire(import.meta.url);
const Engine = require("./engine.cjs");

// Minimal HTTPS/HTTP GET (so the server works on Node versions without a global fetch)
function httpGetText(url, redirects = 5){
  return new Promise((resolve, reject)=>{
    let lib;
    try { lib = new URL(url).protocol === "http:" ? http : https; } catch(e){ return reject(e); }
    lib.get(url, { headers: { "User-Agent": "evtx-triage" } }, (res)=>{
      const code = res.statusCode || 0;
      if (code >= 300 && code < 400 && res.headers.location && redirects > 0){
        res.resume();
        const next = new URL(res.headers.location, url).toString();
        return resolve(httpGetText(next, redirects - 1));
      }
      if (code < 200 || code >= 300){ res.resume(); return reject(new Error("HTTP " + code)); }
      let data = ""; res.setEncoding("utf8");
      res.on("data", c => data += c);
      res.on("end", () => resolve(data));
    }).on("error", reject);
  });
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA = process.env.EVTX_DATA || path.join(__dirname, "data");
const RULES_DIR = path.join(DATA, "rules");        // rules are shared across all cases
const SIGMA_DIR = path.join(RULES_DIR, "sigma");
const YARA_DIR = path.join(RULES_DIR, "yara");
const TMP = path.join(DATA, "tmp");
const CASES_DIR = path.join(DATA, "cases");         // one sub-dir per case
for (const d of [DATA, RULES_DIR, SIGMA_DIR, YARA_DIR, TMP, CASES_DIR]) fs.mkdirSync(d, { recursive: true });

/* ---------- multi-case state ------------------------------------------------------
   Each case is a directory under data/cases/<caseId>/ holding events.jsonl (bodies),
   events.idx (byte offsets), meta.json, detections.json, flags.json and index.db (the
   SQLite event index + FTS). One case is "active" at a time; the per-case file paths
   below are re-pointed by setActiveCase().  catalog.db lists cases + chain of custody. */
const catalog = new Catalog(DATA);
let ACTIVE = null, CASE_DIR = null;
let EVENTS, META, DETS, FLAGS, EVENTS_IDX, CASE_DB;
let _caseIndex = null;   // CaseIndex instance bound to ACTIVE
let _evCache = null, _idxCache = null;   // per-case caches (declared here so setActiveCase can clear them)
function caseDir(id){ return path.join(CASES_DIR, id); }
function newCaseId(){ return "c" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
function setActiveCase(id){
  if (_caseIndex){ _caseIndex.close(); _caseIndex = null; }
  _evCache = null; _idxCache = null;                 // drop caches keyed to the old case's files
  ACTIVE = id || null;
  if (ACTIVE){
    CASE_DIR = caseDir(ACTIVE); fs.mkdirSync(CASE_DIR, { recursive: true });
    EVENTS = path.join(CASE_DIR, "events.jsonl"); META = path.join(CASE_DIR, "meta.json");
    DETS = path.join(CASE_DIR, "detections.json"); FLAGS = path.join(CASE_DIR, "flags.json");
    EVENTS_IDX = path.join(CASE_DIR, "events.idx"); CASE_DB = path.join(CASE_DIR, "index.db");
    catalog.setActive(ACTIVE);
  } else {
    CASE_DIR = EVENTS = META = DETS = FLAGS = EVENTS_IDX = CASE_DB = null;
  }
}
// Move a pre-multicase case (files sitting in data/ root) into data/cases/<id>/ and register it.
function migrateLegacy(){
  const legacy = path.join(DATA, "events.jsonl");
  if (!fs.existsSync(legacy)) return;
  let meta = {}; try{ meta = JSON.parse(fs.readFileSync(path.join(DATA, "meta.json"), "utf8")); }catch{}
  const id = meta.caseId || newCaseId();
  const dir = caseDir(id); fs.mkdirSync(dir, { recursive: true });
  for (const f of ["events.jsonl", "meta.json", "detections.json", "flags.json", "events.idx"]){
    const s = path.join(DATA, f); if (fs.existsSync(s)) { try{ fs.renameSync(s, path.join(dir, f)); }catch{} }
  }
  catalog.upsertCase({ id, name: (meta.files && meta.files[0]) || ("Case " + new Date().toISOString().slice(0,10)),
    createdAt: meta.uploadedAt || new Date().toISOString(), count: meta.count||0, tsMin: meta.tsMin, tsMax: meta.tsMax });
  for (const s of (meta.sources||[])) catalog.addCustody(id, { name: s.name, sha256: null, bytes: 0, type: s.type, count: s.count });
  if (!catalog.getActive()) catalog.setActive(id);
}
migrateLegacy();
// pick up the last-active case (verify its dir still exists), else newest, else none
(function initActive(){
  let id = catalog.getActive();
  if (id && !fs.existsSync(caseDir(id))) id = null;
  if (!id){ const cs = catalog.listCases().filter(c => fs.existsSync(caseDir(c.id))); id = cs[0] ? cs[0].id : null; }
  setActiveCase(id);
})();

const PORT = process.env.PORT || 8742;
const SIGMA_REPO = "SigmaHQ/sigma", SIGMA_BRANCH = "master";
const SIGMA_RAW = `https://raw.githubusercontent.com/${SIGMA_REPO}/${SIGMA_BRANCH}/`;
const BROWSE_CAP = parseInt(process.env.EVTX_BROWSE_CAP || "1000000", 10); // max events sent to the grid
const TIMELINE_CAP = 8000;     // detection-timeline rows returned to the client

const app = express();
app.use(express.json({ limit: "8mb" }));
// stream uploads to disk (handles multi-GB files without buffering them in RAM)
const upload = multer({ storage: multer.diskStorage({ destination: TMP }), limits: { fileSize: 64 * 1024 * 1024 * 1024 } });

/* ---------- event extraction (mirrors the client exactly so indices align) ---------- */
function getProvider(ev){ const s=(ev&&ev.Event&&ev.Event.System)||(ev&&ev.System)||{};
  const p=s.Provider_attributes||s.Provider;
  if(p){ if(typeof p==="string")return p; if(p.Name)return p.Name; if(p["#attributes"]&&p["#attributes"].Name)return p["#attributes"].Name; }
  return (ev&&ev.Provider)||"Unknown"; }
function getEventId(s){ let e=s&&s.EventID;
  if(e&&typeof e==="object")e=e["#text"]!=null?e["#text"]:(e.Value!=null?e.Value:e["@Value"]);
  return e==null?"":e; }
function getTime(ev){ const s=(ev.Event&&ev.Event.System)||ev.System||{}; const tc=s.TimeCreated;
  return ev.SystemTime||(tc&&(tc.SystemTime||(tc["#attributes"]&&tc["#attributes"].SystemTime)))
    ||(s.TimeCreated_attributes&&s.TimeCreated_attributes.SystemTime)||""; }
function scalarize(v){ if(v&&typeof v==="object"&&!Array.isArray(v)){ if(v["#text"]!=null)return v["#text"]; if(v.Value!=null)return v.Value; if(v["#attributes"]!=null&&Object.keys(v).length===1)return ""; } return v; }
function getData(ev){ const E=ev.Event||ev;
  let d=E.EventData!=null?E.EventData:ev.EventData;
  if(d==null && E.UserData){ const u=E.UserData; const ks=(u&&typeof u==="object")?Object.keys(u):[]; d=(ks.length===1&&u[ks[0]]&&typeof u[ks[0]]==="object")?u[ks[0]]:u; }   // UserData wraps a single child element
  if(d==null) d={};
  let o;
  if(d&&Array.isArray(d.Data)){ o={}; let i=0;
    for(const it of d.Data){ if(it&&typeof it==="object"&&it.Name!==undefined) o[it.Name]=it["#text"]!=null?it["#text"]:(it.Value!=null?it.Value:"");
      else o["Data"+(++i)]=it; }
    for(const k in d) if(k!=="Data") o[k]=d[k]; }
  else if(d&&typeof d==="object") o=d;
  else return {value:d};
  // flatten nested {#text}/{Value} field values (only copies when needed)
  let nested=false; for(const k in o){ const v=o[k]; if(v&&typeof v==="object"&&!Array.isArray(v)&&(v["#text"]!=null||v.Value!=null)){ nested=true; break; } }
  if(!nested) return o;
  const out={}; for(const k in o) out[k]=scalarize(o[k]); return out; }
function getComputer(ev){ const s=(ev.Event&&ev.Event.System)||ev.System||{}; return s.Computer||ev.Computer||""; }
function getChannel(ev){ const s=(ev.Event&&ev.Event.System)||ev.System||{}; return s.Channel||ev.Channel||""; }
function recordOf(ev){ const sys=(ev.Event&&ev.Event.System)||ev.System||{};
  const ts=getTime(ev); return { ts, tms:ts?Date.parse(ts):NaN, provider:getProvider(ev),
    eventId:getEventId(sys), computer:getComputer(ev), channel:getChannel(ev), data:getData(ev), raw:ev._raw||"" }; }

/* ---------- parsing ---------- */
function normEvtxRec(rec){ const ev=rec.event||{}; const sys=ev.Event&&ev.Event.System;
  if(sys){ const iso=isFinite(rec.timestamp)?new Date(rec.timestamp*1000).toISOString():"";
    if(!sys.TimeCreated||typeof sys.TimeCreated!=="object")sys.TimeCreated={}; sys.TimeCreated.SystemTime=iso; }
  return ev; }
function sniffTime(line){
  const res=[/\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/,
    /\b(\d{1,2}\/\d{1,2}\/\d{4}[ ,]+\d{1,2}:\d{2}:\d{2})/, /\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/];
  for(const re of res){ const m=re.exec(line); if(m){ let d=new Date(m[1]);
    if(isNaN(d)&&/^[A-Z][a-z]{2}\s/.test(m[1]))d=new Date(m[1]+" "+new Date().getUTCFullYear());
    if(!isNaN(d))return d.toISOString(); } }
  return ""; }

// backpressure-aware write
function wput(ws,s){ return ws.write(s) ? Promise.resolve() : new Promise(r=>ws.once("drain",r)); }
// file-backed DataSource: reads only the requested slice, so winevtx streams huge files in ~64KB of RAM
function fileDataSource(fh, size){ return { size,
  async readAt(offset, len){ const buf=NodeBuffer.allocUnsafe(len);
    const { bytesRead }=await fh.read(buf, 0, len, offset); return buf.subarray(0, bytesRead); } }; }

// Stream-parse one uploaded file straight to the events writer. onMeta(ts) is called per event.
// Each event is tagged with srcLabel so the UI can group/filter by source log.
async function streamParseToFile(srcPath, name, ws, onMeta, srcLabel, cat){
  const tag = srcLabel || name;
  const C = cat ? (e)=>{ e._cat=cat; return e; } : (e)=>e;   // tag firewall/vpn events for their own section
  const fh = await fsopen(srcPath, "r");
  try{
    const head = NodeBuffer.allocUnsafe(8); await fh.read(head, 0, 8, 0);
    const magic = head.slice(0,7).toString("latin1");
    if (magic === "ElfFile") {            // authoritative EVTX signature (not just the extension)
      const st = await fh.stat();
      const src = fileDataSource(fh, st.size);
      for await (const rec of parseEvtxFileAsync(src)) { const ev = C(normEvtxRec(rec)); ev._src = tag;
        await wput(ws, JSON.stringify(ev)+"\n"); onMeta(getTime(ev)); }
      return;
    }
    // text: stream line-by-line (NDJSON / raw). Multi-line single JSON arrays aren't streamed.
    const rawProv = (cat==="firewall"?"Firewall":cat==="vpn"?"VPN":logType(tag)) || "(text log)";
    const rl = readline.createInterface({ input: fs.createReadStream(srcPath, { encoding:"utf8" }), crlfDelay: Infinity });
    for await (let line of rl){ const t = line && line.replace(/^\uFEFF/,"").trim(); if(!t) continue;
      if (t[0]==="{" || t[0]==="[") { try { const o = JSON.parse(t);
        if (Array.isArray(o)) { for(let e of o){ e=C(e); e._src=tag; await wput(ws, JSON.stringify(e)+"\n"); onMeta(getTime(e)); } }
        else { C(o); o._src=tag; await wput(ws, JSON.stringify(o)+"\n"); onMeta(getTime(o)); }
        continue; } catch {} }
      const ev = C({ Event:{ System:{ Provider:{Name:rawProv}, EventID:"", Computer:"", Channel:tag,
        TimeCreated:{ SystemTime: sniffTime(t) } }, EventData:{ Message:t } }, _raw:t, _src:tag });
      await wput(ws, JSON.stringify(ev)+"\n"); onMeta(getTime(ev));
    }
  } finally { await fh.close(); }
}

/* ---------- rules persistence ---------- */
function listRuleFiles(dir){ try { return fs.readdirSync(dir).map(f=>path.join(dir,f)); } catch { return []; } }
function loadSigmaRules(){ const rules=[], aggRules=[]; let skipped=0, errors=0;
  for(const f of listRuleFiles(SIGMA_DIR)){ try{ const res=Engine.parseSigmaDocs(fs.readFileSync(f,"utf8"), yaml.loadAll);
    rules.push(...res.rules); if(res.aggRules)aggRules.push(...res.aggRules); skipped+=res.skipped.length; errors+=res.errors.length; }catch{ errors++; } }
  return { rules, aggRules, skipped, errors }; }
function loadYaraRules(){ let txt=""; for(const f of listRuleFiles(YARA_DIR)){ try{ txt+="\n"+fs.readFileSync(f,"utf8"); }catch{} }
  if(!txt.trim())return { rules:[], errors:0 };
  try{ const r=Engine.compileYaraRules(txt); return { rules:r.rules, errors:r.errors.length }; }catch{ return { rules:[], errors:1 }; } }
function ruleCounts(){ return { sigmaFiles:listRuleFiles(SIGMA_DIR).length, yaraFiles:listRuleFiles(YARA_DIR).length }; }
function safeName(s){ return String(s||"rule").replace(/[^a-zA-Z0-9._-]/g,"_").slice(0,120); }

/* ---------- meta / events ---------- */
const DETECT_CAP = parseInt(process.env.EVTX_DETECT_CAP || "2000000", 10); // max events scanned in one pass
function readMeta(){ try{ return JSON.parse(fs.readFileSync(META,"utf8")); }catch{ return null; } }
// engine records for detection — reuses the shared parsed-event cache when available
async function eventRecords(cap){
  if(!fs.existsSync(EVENTS))return [];
  const evs=await getParsedEvents();
  if(evs){ const recs=evs.map(e=>recordOf(e.ev)); return (cap && recs.length>cap)?recs.slice(0,cap):recs; }
  const recs=[];   // fallback: log too big to cache -> stream
  const rl=readline.createInterface({ input: fs.createReadStream(EVENTS,{encoding:"utf8"}), crlfDelay:Infinity });
  for await (const ln of rl){ if(!ln.trim())continue;
    try{ recs.push(recordOf(JSON.parse(ln))); }catch{}
    if(cap && recs.length>=cap){ rl.close(); break; } }
  return recs; }

/* ---------- shared parsed-event cache -------------------------------------------
   The log is JSON-parsed ONCE into memory and reused by every analytics endpoint
   (evidence / timeline / dashboard) instead of each one re-streaming + re-parsing
   the whole file — the parse is the expensive part. Keyed by mtime+size; bounded so
   multi-GB logs fall back to streaming rather than exhausting RAM. Big servers can
   raise EVTX_RECORD_CACHE.                                                          */
const RECORD_CACHE_MAX = parseInt(process.env.EVTX_RECORD_CACHE || "3000000", 10);
// _evCache declared in the multi-case state block above  // { mtimeMs, size, evs:[{i, ev}] }
async function getParsedEvents(){
  if(!fs.existsSync(EVENTS)) return null;
  const st=fs.statSync(EVENTS);
  if(_evCache && _evCache.mtimeMs===st.mtimeMs && _evCache.size===st.size) return _evCache.evs;
  const evs=[]; let i=-1, over=false;
  const rl=readline.createInterface({ input: fs.createReadStream(EVENTS,{encoding:"utf8"}), crlfDelay:Infinity });
  for await (const ln of rl){ i++; if(!ln) continue; let ev; try{ ev=JSON.parse(ln); }catch{ continue; }
    evs.push({ i, ev });
    if(evs.length>RECORD_CACHE_MAX){ over=true; rl.close(); break; } }
  if(over){ _evCache=null; return null; }          // too large to hold — callers stream instead
  _evCache={ mtimeMs:st.mtimeMs, size:st.size, evs };
  return evs; }
// iterate every (parsed event, global index) — from the RAM cache when possible, else streaming
async function forEachEvent(fn){
  const evs=await getParsedEvents();
  if(evs){ for(const e of evs) fn(e.ev, e.i); return; }
  const rl=readline.createInterface({ input: fs.createReadStream(EVENTS,{encoding:"utf8"}), crlfDelay:Infinity });
  let i=-1;
  for await (const ln of rl){ i++; if(!ln) continue; let ev; try{ ev=JSON.parse(ln); }catch{ continue; } fn(ev, i); } }

/* ---------- byte-offset index (random access into events.jsonl) ----------------
   events.jsonl is one JSON event per line. events.idx holds the byte offset of each
   line start as consecutive little-endian Float64 (safe past 2^53 bytes). This lets
   any event be fetched by index with a single seek+read instead of scanning the file,
   powering fetch-on-scroll and server-side search without loading bodies into RAM.   */
// _idxCache declared in the multi-case state block above  // { mtimeMs, size, offsets: Float64Array }
function idxFresh(){
  try{ const a=fs.statSync(EVENTS), b=fs.statSync(EVENTS_IDX);
    return b.mtimeMs>=a.mtimeMs && b.size>0 && b.size%8===0; }catch{ return false; }
}
// Stream the file as raw bytes and record the start offset of every non-final line.
async function buildEventsIndex(){
  const fh=await fsopen(EVENTS,"r");
  const ws=fs.createWriteStream(EVENTS_IDX);
  const CHUNK=1<<20; const buf=NodeBuffer.allocUnsafe(CHUNK);
  const rec=NodeBuffer.allocUnsafe(8);
  let pos=0, started=false, pending=-1;
  const emit=(off)=>{ rec.writeDoubleLE(off,0); if(!ws.write(NodeBuffer.from(rec)) ) {} };
  try{
    while(true){
      const { bytesRead }=await fh.read(buf,0,CHUNK,pos);
      if(!bytesRead) break;
      for(let j=0;j<bytesRead;j++){
        const abs=pos+j;
        if(!started){ emit(0); started=true; }
        if(pending>=0){ emit(pending); pending=-1; }   // a later byte confirms this line start
        if(buf[j]===0x0A) pending=abs+1;               // next line begins after the newline
      }
      pos+=bytesRead;
    }
  } finally { await fh.close(); }
  await new Promise(r=>ws.end(r));   // a trailing newline leaves `pending` unconfirmed -> correctly dropped
}
async function getOffsets(){
  if(!fs.existsSync(EVENTS)) return null;
  const st=fs.statSync(EVENTS);
  if(_idxCache && _idxCache.mtimeMs===st.mtimeMs && _idxCache.size===st.size) return _idxCache;
  if(!idxFresh()) await buildEventsIndex();
  const raw=fs.readFileSync(EVENTS_IDX);
  const offsets=new Float64Array(raw.buffer, raw.byteOffset, Math.floor(raw.length/8));
  _idxCache={ mtimeMs:st.mtimeMs, size:st.size, offsets, fileSize:st.size };
  return _idxCache;
}
// Read raw JSON lines for the given event indices (in the order requested).
async function readBodies(ids){
  const idx=await getOffsets(); if(!idx) return [];
  const { offsets, fileSize }=idx; const n=offsets.length;
  const fh=await fsopen(EVENTS,"r"); const out=new Array(ids.length);
  try{
    for(let k=0;k<ids.length;k++){ const i=ids[k];
      if(i==null||i<0||i>=n){ out[k]=null; continue; }
      const start=offsets[i], end=(i+1<n?offsets[i+1]:fileSize);
      const len=end-start; if(len<=0){ out[k]=null; continue; }
      const b=NodeBuffer.allocUnsafe(len);
      const { bytesRead }=await fh.read(b,0,len,start);
      let s=b.toString("utf8",0,bytesRead); if(s.endsWith("\n"))s=s.slice(0,-1); if(s.endsWith("\r"))s=s.slice(0,-1);
      out[k]=s;
    }
  } finally { await fh.close(); }
  return out;
}

/* ---------- SQLite-backed case index (Phase 1) -----------------------------------
   The per-event metadata + a bounded fulltext blob live in cases/<id>/index.db (see
   store.mjs), so /api/search filters + paginates on disk instead of holding the whole
   log in RAM. The index is built incrementally: events.jsonl is append-only, so only
   the tail (new bytes) is parsed on refresh; a shrink/rewrite triggers a full rebuild. */
const IDX_BATCH = 20000;   // events per insert transaction (bounds memory on huge cases)
const SEVN_IDX = {critical:4,high:3,medium:2,low:1,informational:0,info:0};
const sevNumIdx = l => { const n = SEVN_IDX[String(l||"").toLowerCase()]; return n==null?2:n; };

// Build the lowercased fulltext blob for one event (mirrors the old in-memory `ft`).
function bodyText(ev){
  const sys=(ev.Event&&ev.Event.System)||ev.System||{};
  const prov=getProvider(ev), eidv=String(getEventId(sys)||""), comp=getComputer(ev), srcv=ev._src||ev._source||"";
  const data=getData(ev);
  let ft=prov+" "+eidv+" "+comp+" "+srcv;
  for(const k in data){ const v=data[k]; ft+=" "+(v==null?"":(typeof v==="object"?JSON.stringify(v):v)); if(ft.length>2000)break; }
  return ft.toLowerCase();
}
// Bring index.db up to date with the current events.jsonl (incremental tail-index).
async function refreshIndex(ci){
  const size = fs.existsSync(EVENTS) ? fs.statSync(EVENTS).size : 0;
  const have = ci.indexedBytes();
  if(size === have) return;
  if(size < have) ci.resetEvents();                 // file shrank/rewritten -> rebuild
  const startByte = ci.indexedBytes();
  let idx = ci.indexedCount(), bytepos = startByte, batch = [];
  const flush = ()=>{ if(batch.length){ ci.ingest(batch, bytepos, idx); batch=[]; } };
  const rl = readline.createInterface({ input: fs.createReadStream(EVENTS, { encoding:"utf8", start:startByte }), crlfDelay: Infinity });
  for await (const ln of rl){
    bytepos += Buffer.byteLength(ln, "utf8") + 1;    // events.jsonl is strictly \n-terminated
    if(!ln){ idx++; continue; }
    let ev; try{ ev = JSON.parse(ln); }catch{ idx++; continue; }
    const sys=(ev.Event&&ev.Event.System)||ev.System||{};
    const ts=getTime(ev), tms=ts?Date.parse(ts):NaN;
    batch.push({ idx, ts, tms:Number.isNaN(tms)?null:tms, provider:getProvider(ev), eid:String(getEventId(sys)||""),
      computer:getComputer(ev), channel:getChannel(ev), src:ev._src||ev._source||"", cat:ev._cat||"", body:bodyText(ev) });
    idx++;
    if(batch.length >= IDX_BATCH) flush();
  }
  flush();
}
// Sync detections.json + flags.json into the index (so their filters are one SQL query).
function syncDetFlags(ci){
  let detSig=""; try{ const st=fs.statSync(DETS); detSig=st.mtimeMs+":"+st.size; }catch{}
  if(detSig !== ci.detSig()){
    let hits={}; if(detSig){ try{ hits=JSON.parse(fs.readFileSync(DETS,"utf8")).hits||{}; }catch{} }
    ci.syncDetections(hits, sevNumIdx, Engine.techniqueFromTag, detSig);
  }
  let flagSig=""; try{ const st=fs.statSync(FLAGS); flagSig=st.mtimeMs+":"+st.size; }catch{}
  if(flagSig !== ci.flagSig()){
    let arr=[]; if(flagSig){ try{ arr=JSON.parse(fs.readFileSync(FLAGS,"utf8")); }catch{} }
    ci.syncFlags(arr, flagSig);
  }
}
// Get the active case's index, built/synced up to the current on-disk state.
async function caseIndex(){
  if(!ACTIVE || !fs.existsSync(EVENTS)) return null;
  if(!_caseIndex) _caseIndex = new CaseIndex(CASE_DB);
  await refreshIndex(_caseIndex);
  syncDetFlags(_caseIndex);
  return _caseIndex;
}
// Stream a file through SHA-256 (chain of custody) without buffering it in RAM.
function sha256File(p){
  return new Promise((resolve,reject)=>{ const h=crypto.createHash("sha256");
    const s=fs.createReadStream(p); s.on("error",reject); s.on("data",c=>h.update(c)); s.on("end",()=>resolve(h.digest("hex"))); });
}

/* =====================  ROUTES  ===================== */
app.get("/api/meta", (req,res)=> res.json({ ok:true, meta:readMeta(), rules:ruleCounts(),
  hasDetections: ACTIVE && fs.existsSync(DETS), browseCap: BROWSE_CAP,
  activeCase: ACTIVE, cases: listCasesView(), custody: ACTIVE ? catalog.getCustody(ACTIVE) : [] }));

/* ---------- multi-case management ---------- */
function listCasesView(){
  return catalog.listCases().filter(c=>fs.existsSync(caseDir(c.id)))
    .map(c=>({ id:c.id, name:c.name, count:c.count, tsMin:c.tsMin, tsMax:c.tsMax,
      createdAt:c.createdAt, active:c.id===ACTIVE }));
}
// A case is "empty" if it holds no events on disk (freshly created / abandoned).
function caseIsEmpty(id){ const p=path.join(caseDir(id),"events.jsonl"); try{ return !fs.existsSync(p) || fs.statSync(p).size===0; }catch{ return true; } }
// Remove abandoned empty cases (no events) so the switcher doesn't fill with 0-event entries.
function pruneEmptyCases(exceptId){
  for(const c of catalog.listCases()){
    if(c.id===exceptId || c.id===ACTIVE) continue;
    if(caseIsEmpty(c.id)){ try{ fs.rmSync(caseDir(c.id),{recursive:true,force:true}); }catch{} catalog.deleteCase(c.id); }
  }
}
app.get("/api/cases", (req,res)=> res.json({ ok:true, active:ACTIVE, cases:listCasesView() }));
// create a new empty case and make it active (the upload that follows populates it)
app.post("/api/cases", (req,res)=>{
  const name=(req.body&&String(req.body.name||"").trim())||("Case "+new Date().toISOString().slice(0,16).replace("T"," "));
  const id=newCaseId(); setActiveCase(id);
  catalog.upsertCase({ id, name, createdAt:new Date().toISOString(), count:0, tsMin:null, tsMax:null });
  pruneEmptyCases(id);                             // drop previously-abandoned empty cases
  res.json({ ok:true, active:ACTIVE, cases:listCasesView() });
});
// switch the active case
app.post("/api/cases/:id/activate", (req,res)=>{
  const id=req.params.id;
  if(!catalog.getCase(id) || !fs.existsSync(caseDir(id))) return res.status(404).json({error:"no such case"});
  setActiveCase(id);
  res.json({ ok:true, active:ACTIVE, meta:readMeta(), cases:listCasesView() });
});
// delete a case (files + catalog entry). If it was active, fall back to the newest remaining case.
app.delete("/api/cases/:id", (req,res)=>{
  const id=req.params.id;
  if(!catalog.getCase(id)) return res.status(404).json({error:"no such case"});
  if(id===ACTIVE && _caseIndex){ _caseIndex.close(); _caseIndex=null; }
  try{ fs.rmSync(caseDir(id), { recursive:true, force:true }); }catch{}
  catalog.deleteCase(id);
  if(id===ACTIVE){ const rest=catalog.listCases().filter(c=>fs.existsSync(caseDir(c.id))); setActiveCase(rest[0]?rest[0].id:null); }
  res.json({ ok:true, active:ACTIVE, cases:listCasesView() });
});

// classify a filename into a friendly log-type label
function logType(name){ const n=String(name||"").toLowerCase();
  if(/security/.test(n))return "Security"; if(/sysmon/.test(n))return "Sysmon";
  if(/powershell/.test(n))return "PowerShell"; if(/system/.test(n))return "System";
  if(/application/.test(n))return "Application"; if(/defender|windows defender/.test(n))return "Defender";
  if(/terminal|rdp|remoteconnection|localsessionmanager/.test(n))return "RDP/Terminal";
  if(/task\s*scheduler|taskscheduler/.test(n))return "TaskScheduler"; if(/setup/.test(n))return "Setup";
  if(/wmi/.test(n))return "WMI";
  if(/firewall|pfsense|fortigate|fortinet|palo\s*alto|paloalto|iptables|\bfw\b|netscreen|asa/.test(n))return "Firewall";
  if(/\bvpn\b|openvpn|anyconnect|wireguard|ipsec|globalprotect|pulse\s*secure/.test(n))return "VPN";
  if(/proxy|squid|bluecoat|zscaler/.test(n))return "Proxy"; if(/dns/.test(n))return "DNS";
  if(/iis|access\.log|w3c|httpd|nginx|apache/.test(n))return "Web/IIS";
  return name && name.replace(/\.(evtx|jsonl?|ndjson|log|txt|csv|tsv|syslog)$/i,"") || "Log"; }

app.post("/api/upload", upload.array("file"), async (req,res)=>{
  try{
    if(!req.files||!req.files.length) return res.status(400).json({error:"no file"});
    const cat = (req.query.cat==="firewall"||req.query.cat==="vpn") ? req.query.cat : null;
    const append = String(req.query.mode||"")==="append" && ACTIVE && fs.existsSync(EVENTS);
    if(!append){                                   // a plain upload populates a fresh case
      // reuse the active case if it's still empty (e.g. just created via "New case"),
      // otherwise start a new one — either way, drop other abandoned empty cases.
      if(!(ACTIVE && caseIsEmpty(ACTIVE))) setActiveCase(newCaseId());
      catalog.clearCustody(ACTIVE);
      pruneEmptyCases(ACTIVE);
    }
    const prev = append ? (readMeta()||{}) : {};
    const ws = fs.createWriteStream(EVENTS, append ? { flags:"a" } : {});
    let total = append ? (prev.count||0) : 0;
    let tsMin = append ? (prev.tsMin||null) : null, tsMax = append ? (prev.tsMax||null) : null;
    const sources = append ? (prev.sources||[]).slice() : [];
    for(const f of req.files){
      const label=f.originalname; let c=0, sMin=null, sMax=null;
      let sha=null, bytes=0; try{ bytes=fs.statSync(f.path).size; sha=await sha256File(f.path); }catch{} // chain of custody
      const onMeta=(ts)=>{ total++; c++;
        if(ts){ if(tsMin===null||ts<tsMin)tsMin=ts; if(tsMax===null||ts>tsMax)tsMax=ts;
          if(sMin===null||ts<sMin)sMin=ts; if(sMax===null||ts>sMax)sMax=ts; } };
      try{ await streamParseToFile(f.path, f.originalname, ws, onMeta, label, cat); }
      finally{ try{ fs.unlinkSync(f.path); }catch{} }
      const type=(cat==="firewall"?"Firewall":cat==="vpn"?"VPN":logType(label));
      sources.push({ name:label, type, count:c, tsMin:sMin, tsMax:sMax, cat:cat||undefined, sha256:sha, bytes });
      catalog.addCustody(ACTIVE, { name:label, sha256:sha, bytes, type, count:c, ingestedAt:new Date().toISOString() });
    }
    await new Promise(r=>ws.end(r));
    const meta={ caseId:ACTIVE, count:total, tsMin, tsMax, sources, files:sources.map(s=>s.name), uploadedAt:new Date().toISOString() };
    fs.writeFileSync(META, JSON.stringify(meta));
    const existing=catalog.getCase(ACTIVE);
    catalog.upsertCase({ id:ACTIVE, name:(existing&&existing.name)||(sources[0]&&sources[0].name)||("Case "+new Date().toISOString().slice(0,10)),
      createdAt:(existing&&existing.createdAt)||meta.uploadedAt, count:total, tsMin, tsMax });
    try{ fs.unlinkSync(DETS); }catch{}            // detections must be recomputed for the new case contents
    if(!append){ try{ fs.unlinkSync(FLAGS); }catch{} }  // keep flags when appending (indices stay valid)
    res.json({ ok:true, meta, appended:append });
  }catch(err){ console.error(err); try{ for(const f of (req.files||[])) fs.unlinkSync(f.path); }catch{}
    res.status(500).json({error:String(err.message||err)}); }
});

// serve events as NDJSON; supports ?offset=&limit= so the browser only loads a window of huge logs
app.get("/api/events", (req,res)=>{
  if(!fs.existsSync(EVENTS)) return res.status(404).end();
  const limit=Math.max(0, parseInt(req.query.limit||"0",10)||0);
  const offset=Math.max(0, parseInt(req.query.offset||"0",10)||0);
  res.type("application/x-ndjson");
  if(!limit && !offset){ fs.createReadStream(EVENTS).pipe(res); return; }
  const rl=readline.createInterface({ input: fs.createReadStream(EVENTS,{encoding:"utf8"}), crlfDelay:Infinity });
  let i=0;
  rl.on("line", l=>{ if(i>=offset && (!limit || i<offset+limit)) res.write(l+"\n");
    i++; if(limit && i>=offset+limit) rl.close(); });
  rl.on("close", ()=>res.end());
});

// fetch a rule from the internet (server-side) and save it
app.post("/api/rules/fetch", async (req,res)=>{
  try{ let url=(req.body&&req.body.url||"").trim(); if(!url)return res.status(400).json({error:"no url"});
    const m=/^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/blob\/(.+)$/.exec(url);
    if(m)url="https://raw.githubusercontent.com/"+m[1]+"/"+m[2]+"/"+m[3];
    let txt; try{ txt=await httpGetText(url); }catch(e){ return res.status(502).json({error:String(e.message||e)}); }
    const isYara=/\.ya?ra?$/i.test(url)&&!/\.ya?ml$/i.test(url);
    const dir=isYara?YARA_DIR:SIGMA_DIR; const base=safeName(url.split("/").pop());
    fs.writeFileSync(path.join(dir, base.replace(/\.(ya?ml|yara?)$/i,"")+(isYara?".yar":".yml")), txt);
    res.json({ ok:true, rules:ruleCounts() });
  }catch(err){ res.status(500).json({error:String(err.message||err)}); }
});

// save uploaded local rule files (from the user's machine) onto the server
app.post("/api/rules/upload", upload.array("file"), (req,res)=>{
  try{ let saved=0; for(const f of (req.files||[])){
      try{
        if(!/\.(ya?ml|yara?)$/i.test(f.originalname)) continue;
        const isYara=/\.yara?$/i.test(f.originalname)&&!/\.ya?ml$/i.test(f.originalname);
        const dir=isYara?YARA_DIR:SIGMA_DIR;
        const txt=fs.readFileSync(f.path,"utf8");            // disk storage -> read from temp path
        fs.writeFileSync(path.join(dir, Date.now()+"_"+saved+"_"+safeName(f.originalname)), txt); saved++;
      } finally { try{ fs.unlinkSync(f.path); }catch{} }
    }
    res.json({ ok:true, saved, rules:ruleCounts() });
  }catch(err){ res.status(500).json({error:String(err.message||err)}); }
});

// pull the curated well-known SigmaHQ set (server-side) and save it
app.post("/api/rules/default", async (req,res)=>{
  try{ const paths=JSON.parse(fs.readFileSync(path.join(__dirname,"curated-paths.json"),"utf8"));
    let saved=0; const CC=10; let i=0;
    async function worker(){ while(i<paths.length){ const p=paths[i++];
      try{ const txt=await httpGetText(SIGMA_RAW+p); fs.writeFileSync(path.join(SIGMA_DIR, safeName(p.split("/").pop())), txt); saved++; }catch{} } }
    await Promise.all(Array.from({length:CC},worker));
    res.json({ ok:true, saved, rules:ruleCounts() });
  }catch(err){ res.status(500).json({error:String(err.message||err)}); }
});

app.get("/api/rules", (req,res)=> res.json({ ok:true, rules:ruleCounts() }));
app.post("/api/rules/clear", (req,res)=>{
  for(const dir of [SIGMA_DIR,YARA_DIR]) for(const f of listRuleFiles(dir)){ try{ fs.unlinkSync(f); }catch{} }
  try{ fs.unlinkSync(DETS); }catch{}
  res.json({ ok:true, rules:ruleCounts() });
});

// run heuristics + sigma + yara on the server over the stored log; persist enriched results
/* ---------- rule suppression (global allowlist, survives restarts) --------------
   Suppressed rule IDs are stored once for the whole server (rules are shared across
   cases) and applied at detect time. Toggling suppression re-filters the stored
   detections in place — no full re-scan — so it feels instant on huge cases.        */
const SUPPRESS_FILE = path.join(DATA, "suppressions.json");
function loadSuppressed(){ try{ return new Set(JSON.parse(fs.readFileSync(SUPPRESS_FILE,"utf8")).suppressed||[]); }catch{ return new Set(); } }
function saveSuppressed(set){ try{ fs.writeFileSync(SUPPRESS_FILE, JSON.stringify({ suppressed:[...set] })); }catch(e){ console.error(e); } }

// ---- IOC watchlist (global, reusable across cases; matched against the active case) ----
const WATCHLIST_FILE = path.join(DATA, "watchlist.json");
const IOC_CAP = 20000;
function loadWatchlist(){ try{ const a=JSON.parse(fs.readFileSync(WATCHLIST_FILE,"utf8")).iocs; return Array.isArray(a)?a:[]; }catch{ return []; } }
function saveWatchlist(list){ try{ fs.writeFileSync(WATCHLIST_FILE, JSON.stringify({ iocs:list.slice(0,IOC_CAP) })); }catch(e){ console.error(e); } }
// Parse free-text IOC input into typed records. One indicator per line; blank lines and lines
// starting with # are ignored. Optional "type:value" or "value,label" (CSV) forms are accepted.
function parseIocInput(text){
  const out=[]; const TYPES=new Set(["ip","hash","domain","file","user","string"]);
  for(let line of String(text||"").split(/\r?\n/)){
    line=line.trim(); if(!line||line[0]==="#") continue;
    let label=""; const comma=line.indexOf(",");
    if(comma>=0){ label=line.slice(comma+1).trim(); line=line.slice(0,comma).trim(); }
    let type=""; const colon=line.indexOf(":");
    if(colon>0 && TYPES.has(line.slice(0,colon).toLowerCase())){ type=line.slice(0,colon).toLowerCase(); line=line.slice(colon+1).trim(); }
    if(!line) continue;
    out.push({ value:line, type:type||Engine.iocType(line), label });
  }
  return out;
}
function mergeIocs(existing, add){
  const byVal=new Map(existing.map(x=>[String(x.value).toLowerCase(), x]));
  for(const it of add){ const k=String(it.value).toLowerCase();
    if(byVal.has(k)){ const cur=byVal.get(k); if(it.label&&!cur.label)cur.label=it.label; if(it.type)cur.type=it.type; }
    else if(byVal.size<IOC_CAP){ byVal.set(k, { value:it.value, type:it.type, label:it.label||"", added:new Date().toISOString() }); } }
  return [...byVal.values()];
}

// ---- Settings (API keys, gitignored) + threat-intel enrichment (AbuseIPDB / VirusTotal) ----
const SETTINGS_FILE = path.join(DATA, "settings.json");
function loadSettings(){ try{ return JSON.parse(fs.readFileSync(SETTINGS_FILE,"utf8"))||{}; }catch{ return {}; } }
function saveSettings(s){ try{ fs.writeFileSync(SETTINGS_FILE, JSON.stringify(s), { mode:0o600 }); }catch(e){ console.error(e); } }
// key lookup: saved settings win, else environment. Never returned to the browser.
function getApiKey(provider){ const s=loadSettings();
  return String(s[provider+"ApiKey"] || process.env[provider.toUpperCase()+"_API_KEY"] || "").trim(); }
const ENRICH_CACHE_FILE = path.join(DATA, "enrich-cache.json");
const ENRICH_TTL_MS = 24*3600*1000;
function loadEnrichCache(){ try{ return JSON.parse(fs.readFileSync(ENRICH_CACHE_FILE,"utf8"))||{}; }catch{ return {}; } }
function saveEnrichCache(c){ try{ const keys=Object.keys(c); if(keys.length>5000){ for(const k of keys.slice(0,keys.length-5000)) delete c[k]; } fs.writeFileSync(ENRICH_CACHE_FILE, JSON.stringify(c)); }catch(e){ console.error(e); } }

function fetchWithTimeout(url, opt, ms){ const ac=new AbortController(); const t=setTimeout(()=>ac.abort(), ms||15000);
  return fetch(url, { ...opt, signal:ac.signal }).finally(()=>clearTimeout(t)); }
async function abuseipdbCheck(ip, key){
  const u=new URL("https://api.abuseipdb.com/api/v2/check");
  u.searchParams.set("ipAddress", ip); u.searchParams.set("maxAgeInDays", "90");
  const r=await fetchWithTimeout(u, { headers:{ Key:key, Accept:"application/json" } });
  if(!r.ok) throw new Error("HTTP "+r.status);
  const d=(await r.json()).data||{};
  return { provider:"abuseipdb", indicator:d.ipAddress||ip, type:"ip",
    score:d.abuseConfidenceScore, reports:d.totalReports, country:d.countryCode,
    isp:d.isp, domain:d.domain, usage:d.usageType, tor:d.isTor, lastReport:d.lastReportedAt,
    link:"https://www.abuseipdb.com/check/"+encodeURIComponent(ip) };
}
async function virustotalCheck(indicator, type, key){
  const p = type==="ip" ? "ip_addresses/"+encodeURIComponent(indicator) : "files/"+encodeURIComponent(indicator);
  const r=await fetchWithTimeout("https://www.virustotal.com/api/v3/"+p, { headers:{ "x-apikey":key } });
  if(r.status===404) return { provider:"virustotal", indicator, type, found:false, stats:{malicious:0,suspicious:0,harmless:0,undetected:0} };
  if(!r.ok) throw new Error("HTTP "+r.status);
  const attr=(((await r.json()).data)||{}).attributes||{}; const st=attr.last_analysis_stats||{};
  return { provider:"virustotal", indicator, type, found:true,
    stats:{ malicious:st.malicious||0, suspicious:st.suspicious||0, harmless:st.harmless||0, undetected:st.undetected||0 },
    reputation:attr.reputation, name:attr.meaningful_name, fileType:attr.type_description,
    asOwner:attr.as_owner, country:attr.country,
    link:"https://www.virustotal.com/gui/"+(type==="ip"?"ip-address/":"file/")+encodeURIComponent(indicator) };
}

// Assemble the full detection payload (timeline + ATT&CK + entities + chains + aggregates)
// from a per-event hit map. Shared by /api/detect (fresh scan) and suppression re-filtering.
function assembleDetections(byIdx, rows, meta, ruleStats){
  ruleStats=ruleStats||{}; meta=meta||{};
  const SEV={critical:4,high:3,medium:2,low:1,informational:0,info:0};
  const sevn=l=>{const n=SEV[String(l||"").toLowerCase()];return n==null?2:n;};
  const obj={}; let total=0; const timeline=[]; const byRule=new Map(); const byComp=new Map();
  const bySev={critical:0,high:0,medium:0,low:0,info:0}; const bySrc={sigma:0,yara:0,heuristic:0};
  const byTech=new Map(), byTac=new Map();   // ATT&CK technique/tactic coverage
  const scorer=Engine.makeEntityScorer();    // entity risk scoring
  const chainItems=[];                        // one item per detected event -> attack-chain correlation
  for(const [i,a] of byIdx){ if(!a||!a.length)continue; obj[i]=a; total+=a.length;
    const r=rows[i]||{computer:"",ts:"",tms:NaN,data:{},provider:"",channel:"",eventId:""};
    byComp.set(r.computer||"(none)",(byComp.get(r.computer||"(none)")||0)+1);
    let evLvl="info", evTags=[], evTitle=(a[0]&&(a[0].title||a[0].ruleId))||"";
    for(const h of a){ const key=h.source+"|"+(h.ruleId||h.title); scorer.feed(h, r);
      if(sevn(h.level)>sevn(evLvl)){ evLvl=h.level; evTitle=h.title||h.ruleId; }
      if(h.tags&&h.tags.length) evTags=evTags.concat(h.tags);
      let g=byRule.get(key); if(!g){g={ruleId:h.ruleId||h.title,title:h.title||h.ruleId,source:h.source,level:h.level,count:0};byRule.set(key,g);}
      g.count++; if(sevn(h.level)>sevn(g.level))g.level=h.level;
      bySev[String(h.level).toLowerCase()]=(bySev[String(h.level).toLowerCase()]||0)+1; bySrc[h.source]=(bySrc[h.source]||0)+1;
      if(timeline.length<TIMELINE_CAP) timeline.push({idx:i,ts:r.ts,tms:r.tms,computer:r.computer,channel:r.channel||r.provider,eid:r.eventId,level:h.level,title:h.title||h.ruleId,source:h.source});
      const pa=Engine.parseAttack(h.tags);
      for(const t of pa.techniques){ let g2=byTech.get(t.id);
        if(!g2){ g2={id:t.id,name:t.name,tactic:t.tactic,count:0,level:"info",rules:new Set()}; byTech.set(t.id,g2); }
        g2.count++; if(sevn(h.level)>sevn(g2.level))g2.level=h.level; g2.rules.add(h.ruleId||h.title); }
      for(const slug of new Set(pa.tactics)){ let g3=byTac.get(slug); if(!g3){ g3={tactic:slug,count:0,techniques:new Set()}; byTac.set(slug,g3);} g3.count++; }
    }
    chainItems.push({ idx:i, tms:r.tms, host:r.computer||"", user:(Engine.extractEntities(r.data,r.computer).users[0]||""),
      level:evLvl, title:evTitle, source:(a[0]&&a[0].source)||"", ruleId:(a[0]&&a[0].ruleId)||"", tags:evTags });
  }
  timeline.sort((a,b)=>(b.tms||0)-(a.tms||0));
  for(const t of byTech.values()){ if(t.tactic){ const g=byTac.get(t.tactic); if(g)g.techniques.add(t.id); } }
  const TAC_NAMES=Engine.attack.tactics, TAC_ORDER=Engine.attack.tacticOrder;
  const attack={
    techniques:[...byTech.values()].sort((a,b)=>sevn(b.level)-sevn(a.level)||b.count-a.count)
      .map(t=>({id:t.id,name:t.name,tactic:t.tactic,count:t.count,level:t.level,rules:[...t.rules]})),
    tactics:TAC_ORDER.filter(s=>byTac.has(s)).map(s=>({slug:s,name:TAC_NAMES[s],count:byTac.get(s).count,techniques:byTac.get(s).techniques.size})),
    techniqueCount:byTech.size, tacticCount:byTac.size };
  return { hits:obj, timeline, entities:scorer.result(60), chains:Engine.buildAttackChains(chainItems),
    byRule:[...byRule.values()].sort((a,b)=>sevn(b.level)-sevn(a.level)||b.count-a.count),
    byComputer:[...byComp.entries()].sort((a,b)=>b[1]-a[1]).slice(0,20).map(([c,n])=>({computer:c,count:n})),
    bySev, bySrc, attack,
    summary:{ events:rows.length, scanned:rows.length, fullCount:meta.count||rows.length,
      truncated:!!(meta.count&&meta.count>rows.length), withDetections:Object.keys(obj).length, total,
      sigma:ruleStats.sigma||0, correlation:ruleStats.correlation||0, yara:ruleStats.yara||0, skipped:ruleStats.skipped||0,
      suppressed:ruleStats.suppressed||0 } };
}

// Full detection scan of the active case's log -> stored detections.json. Returns the payload.
async function runFullDetect(){
  const rows=await eventRecords(DETECT_CAP);
  if(!rows.length) return null;
  const meta=readMeta()||{};
  const sig=loadSigmaRules(), yar=loadYaraRules();
  const suppressed=loadSuppressed();
  const byIdx=new Map();
  const add=(i,h)=>{ if(suppressed.has(h.ruleId)) return;   // skip allowlisted / disabled rules
    let a=byIdx.get(i); if(!a){a=[];byIdx.set(i,a);} if(!a.some(x=>x.ruleId===h.ruleId&&x.source===h.source))a.push(h); };
  for(const h of Engine.runHeuristics(rows)) add(h.idx,{ruleId:h.ruleId,title:h.title,level:h.level,source:"heuristic",why:h.why,tags:h.tags});
  if(sig.rules.length||yar.rules.length){ const index=Engine.buildIndex(sig.rules);
    const m=Engine.runRules(rows,sig.rules,yar.rules,{index}); for(const [i,hits] of m)for(const h of hits)add(i,h); }
  // windowed Sigma aggregations (brute force / spray / roasting) — a correlation pass over the log
  if(sig.aggRules&&sig.aggRules.length){ const mc=Engine.runCorrelations(rows,sig.aggRules); for(const [i,hits] of mc)for(const h of hits)add(i,h); }
  const out=assembleDetections(byIdx, rows, meta,
    { sigma:sig.rules.length, correlation:(sig.aggRules||[]).length, yara:yar.rules.length, skipped:sig.skipped, suppressed:suppressed.size });
  fs.writeFileSync(DETS, JSON.stringify(out));
  return out;
}

app.post("/api/detect", async (req,res)=>{
  try{
    const out=await runFullDetect();
    if(!out) return res.status(400).json({error:"no log loaded"});
    res.json({ ok:true, ...out });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

// list / update suppressed rules. POST { ruleId, suppress } toggles one; { suppressed:[...] }
// replaces the list. Adding a suppression re-filters the stored detections in place (fast);
// removing one (un-suppress) needs a full re-scan to recover the rule's hits.
app.get("/api/suppressions", (req,res)=> res.json({ ok:true, suppressed:[...loadSuppressed()] }));
app.post("/api/suppressions", async (req,res)=>{
  try{
    const b=req.body||{}; const before=loadSuppressed(); const set=new Set(before);
    if(Array.isArray(b.suppressed)){ set.clear(); for(const r of b.suppressed) if(r) set.add(String(r)); }
    else if(b.ruleId!=null){ const rid=String(b.ruleId); if(b.suppress===false) set.delete(rid); else set.add(rid); }
    else return res.status(400).json({error:"ruleId or suppressed[] required"});
    saveSuppressed(set);
    const removedAny=[...before].some(r=>!set.has(r));   // a rule was un-suppressed -> its hits must be rescanned
    let out=null;
    if(ACTIVE && fs.existsSync(EVENTS)){
      if(removedAny){ out=await runFullDetect(); }
      else if(fs.existsSync(DETS)){                       // additions only -> re-filter stored detections
        let stored={}; try{ stored=JSON.parse(fs.readFileSync(DETS,"utf8")); }catch{}
        const hits=stored.hits||{}; const rows=await eventRecords(DETECT_CAP); const meta=readMeta()||{};
        const byIdx=new Map();
        for(const k in hits){ const arr=(hits[k]||[]).filter(h=>!set.has(h.ruleId)); if(arr.length) byIdx.set(+k, arr); }
        const st=(stored.summary||{});
        out=assembleDetections(byIdx, rows, meta,
          { sigma:st.sigma, correlation:st.correlation, yara:st.yara, skipped:st.skipped, suppressed:set.size });
        fs.writeFileSync(DETS, JSON.stringify(out));       // mtime change -> search det index re-syncs on next query
      }
    }
    res.json({ ok:true, suppressed:[...set], rescanned:removedAny, ...(out?{detections:out}:{}) });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

app.get("/api/detections", (req,res)=>{
  if(!fs.existsSync(DETS)) return res.json({ ok:true, hits:{}, summary:null });
  res.type("application/json"); fs.createReadStream(DETS).pipe(res);
});

// full-log dashboard aggregates (so big windowed cases still get an overview of the WHOLE log)
app.get("/api/dashboard", async (req,res)=>{
  try{
  if(!fs.existsSync(EVENTS)) return res.json({ ok:true, total:0 });
  const provs=new Map(), comps=new Map(), users=new Map(), eids=new Map(), hours=new Map();
  let total=0, fail=0, susp=0, tMin=null, tMax=null, fwCount=0, vpnCount=0;
  const bump=(m,k)=>{ if(k!=null&&k!=="") m.set(k,(m.get(k)||0)+1); };
  const SUSP=new Set(["4625","4720","4728","4732","4756","4724","1102","104","7045","4698","4697","1116","1117"]);
  await forEachEvent((ev)=>{
    if(ev._cat==="firewall"){ fwCount++; return; }               // those have their own sections
    if(ev._cat==="vpn"){ vpnCount++; return; }
    total++;
    const sys=(ev.Event&&ev.Event.System)||ev.System||{};
    const prov=getProvider(ev), eid=String(getEventId(sys)||""), comp=getComputer(ev), ts=getTime(ev), data=getData(ev);
    bump(provs,prov); bump(comps,comp); bump(eids,eid);
    for(const k of ["TargetUserName","SubjectUserName","User","AccountName"]){ const v=data&&data[k];
      if(v&&v!=="-"&&typeof v!=="object"){ bump(users,String(v)); break; } }
    if(eid==="4625") fail++;
    if(SUSP.has(eid)) susp++;
    if(ts){ if(tMin===null||ts<tMin)tMin=ts; if(tMax===null||ts>tMax)tMax=ts;
      const h=ts.slice(0,13); bump(hours,h); }   // hourly histogram (bounded)
  });
  const top=(m,n)=>[...m.entries()].sort((a,b)=>b[1]-a[1]).slice(0,n);
  res.json({ ok:true, total, fail, susp, tsMin:tMin, tsMax:tMax, fwCount, vpnCount,
    providers: top(provs,15), computers: top(comps,12), users: top(users,12),
    eids: top(eids,30), hours: [...hours.entries()].sort() });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});


app.get("/api/event/:idx", async (req,res)=>{
  const idx=parseInt(req.params.idx,10); if(isNaN(idx)||idx<0) return res.status(400).end();
  if(!fs.existsSync(EVENTS)) return res.status(404).end();
  try{ const [line]=await readBodies([idx]);
    if(line==null) return res.status(404).end();
    res.type("application/json").send(line);
  }catch(err){ res.status(500).json({error:String(err.message||err)}); }
});

/* ---------- fetch-on-scroll: server-side search + body fetch --------------------
   The grid holds only the visible rows. /api/search returns the ordered global ids
   (and detection level) matching the active filter across the WHOLE log; /api/bodies
   returns just the event bodies for the ids currently on screen. Semantics mirror the
   client's applyFilter so behavior is identical whether windowed or streamed.        */
const SEVNUM_S={critical:4,high:3,medium:2,low:1,informational:0,info:0};
function sevNumS(l){ const n=SEVNUM_S[String(l||"").toLowerCase()]; return n==null?2:n; }

app.post("/api/bodies", async (req,res)=>{
  try{
    const ids=Array.isArray(req.body&&req.body.ids)?req.body.ids.filter(n=>Number.isInteger(n)&&n>=0):[];
    res.type("application/x-ndjson");
    if(!ids.length) return res.end();
    const lines=await readBodies(ids);
    for(const s of lines) res.write((s==null?"null":s)+"\n");
    res.end();
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

// Server-side search over the SQLite index: structured filters + FTS free-text, sorted.
// Returns the ordered ids (+ detection level) for the whole match set, OR a page of them
// when {limit, offset} are given (true virtualization for 10M+ event cases).
app.post("/api/search", async (req,res)=>{
  try{
    if(!ACTIVE || !fs.existsSync(EVENTS)) return res.json({ ok:true, total:0, ids:[], levels:[] });
    const b=req.body||{};
    const ci=await caseIndex();
    if(!ci) return res.json({ ok:true, total:0, ids:[], levels:[] });
    const f={
      q: b.q||"",
      eid: (b.eid!=null&&b.eid!=="")?String(b.eid):"",
      provider: b.provider!=null ? b.provider : null,    // include-only
      src: b.src!=null ? b.src : null,
      excluded: Array.isArray(b.excluded) ? b.excluded : [],
      detOnly: !!b.det, ruleId: b.ruleId||"", technique: b.technique||"", flagged: !!b.flagged,
      timeRange: (b.timeRange&&isFinite(b.timeRange.from)&&isFinite(b.timeRange.to)) ? b.timeRange : null };
    const sortKey=(b.sort&&b.sort.key)||"ts", sortDir=(b.sort&&b.sort.dir===-1)?-1:1;
    const r=ci.search(f, { sortKey, sortDir, limit: parseInt(b.limit||0,10)||0, offset: parseInt(b.offset||0,10)||0 });
    res.json({ ok:true, total:r.total, ids:r.ids, levels:r.levels });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

/* ---------- fetch-on-scroll support: Firewall/VPN listing + server-side Evidence ----
   In true fetch-on-scroll mode the browser holds no dense rows[], so these tabs are
   served from the stored log instead of mined in the browser.                          */
function svSummary(data){ let o="",n=0; for(const k in data){ if(n++)o+="  ·  "; const v=data[k];
  o+=k+"="+(v==null?"":(typeof v==="object"?JSON.stringify(v):String(v))); if(o.length>400)break; } return o; }

// Firewall / VPN events (kept out of the main grid) — bounded list for their dedicated tabs
app.post("/api/cat", async (req,res)=>{
  try{
    if(!fs.existsSync(EVENTS)) return res.json({ ok:true, total:0, rows:[] });
    const cat=(req.body&&req.body.cat)==="vpn"?"vpn":"firewall";
    const CAP=20000; const out=[]; let total=0;
    await forEachEvent((ev, i)=>{
      if(ev._cat!==cat) return; total++;
      if(out.length<CAP){ const data=getData(ev);
        out.push({ i, ts:getTime(ev), src:ev._src||ev._source||"", msg:(data&&data.Message)||svSummary(data) }); }
    });
    res.json({ ok:true, total, rows:out });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

// Map/Set-preserving JSON so the browser rebuilds the exact Evidence structure renderEvidence expects
function mapSetReplacer(k,v){ if(v instanceof Map) return {__t:"M",v:[...v.entries()]};
  if(v instanceof Set) return {__t:"S",v:[...v]}; return v; }
function privIp(ip){ const m=/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip||""); if(!m)return true;
  const a=+m[1],b=+m[2]; return a===10||a===127||a===0||(a===192&&b===168)||(a===172&&b>=16&&b<=31)||(a===169&&b===254); }
function isExtIp(ip){ return ip && ip!=="-" && ip!=="::1" && /^\d+\.\d+\.\d+\.\d+$/.test(ip) && !privIp(ip); }

// Server-side Evidence extraction — mirrors the client buildEvidence() exactly (same EIDs, same fields, same global i)
app.get("/api/evidence", async (req,res)=>{
  try{
    if(!fs.existsSync(EVENTS)) return res.json({ ok:true, evidence:null });
    const AR=20000;   // per-array cap (plain lists); Maps/Sets are naturally bounded by cardinality
    const E={ accountsCreated:[], groupAdds:[], pwResets:[], acctState:[], explicitCreds:[],
      extLogons:new Map(), failedBySrc:new Map(), specialPriv:new Map(),
      procs:[], psBlocks:[], services:[], tasks:[], runKeys:[], fileWrites:[],
      netConns:new Map(), dns:new Map(), shareAccess:[], logCleared:[], defender:[],
      kerberos:[], kerbRoast:0, ntlm:[], auditChanges:[], wmiPersist:[], rdpSessions:[], bits:[],
      lsassAccess:[], remoteThread:[], rawAccess:[], procTamper:[], appBlocks:[], timeChange:[],
      ips:new Map(), users:new Set(), hosts:new Set(), hashes:new Set(), domains:new Set(), sessions:[] };
    const push=(a,x)=>{ if(a.length<AR)a.push(x); };
    const isSys=p=>/sysmon/i.test(p||"");
    // process-based LSASS credential dumping (procdump/comsvcs/rundll32 MiniDump, nanodump, dumpert, mimikatz, etc.)
    const LSASS_DUMP=/procdump(64)?(\.exe)?[^\n]*\blsass|comsvcs(\.dll)?[^\n]*minidump|minidump[^\n]*lsass|lsass[^\n]*minidump|rundll32[^\n]*comsvcs|nanodump|dumpert|handlekatz|createdump[^\n]*lsass|sqldumper[^\n]*lsass|sekurlsa|invoke-mimikatz|out-minidump|lsass\.dmp|-ma\s+lsass|\blsass\.exe\b[^\n]*(dump|dmp)/i;
    // recover account/group/task/service artifacts from a process command line (audit-independent)
    const addProcArtifacts=(i,cmd,by,ts)=>{ if(!cmd)return; const pa=Engine.parseProcessArtifacts(cmd);
      for(const a of pa.accounts) push(E.accountsCreated,{i,user:a.user,by,ts,via:"cmdline"});
      for(const g of pa.groups)   push(E.groupAdds,{i,member:g.member,group:g.group,by,ts,via:"cmdline"});
      for(const t of pa.tasks)    push(E.tasks,{i,name:t.name,act:"created (cmdline)",cmd:t.cmd,ts,via:"cmdline"});
      for(const sv of pa.services)push(E.services,{i,name:sv.name,path:sv.path,ts,via:"cmdline"}); };
    const sessById=new Map();                 // TargetLogonId -> session (paired 4624 logon / 4634-4647 logoff)
    const SESS_TYPES=new Set(["2","3","7","9","10","11"]);   // interactive/network/unlock/newcred/remote/cached
    await forEachEvent((ev, i)=>{
      const sys=(ev.Event&&ev.Event.System)||ev.System||{};
      const provider=getProvider(ev), computer=getComputer(ev), ts=getTime(ev), d=getData(ev)||{};
      const id=String(getEventId(sys)||"");
      const U=k=>d[k]!=null?String(d[k]):"";
      if(computer)E.hosts.add(computer);
      switch(id){
        case "4720": { const u=U("TargetUserName"); push(E.accountsCreated,{i,user:u,by:U("SubjectUserName"),ts}); if(u)E.users.add(u); break; }
        case "4741": { const u=U("TargetUserName"); push(E.accountsCreated,{i,user:u,by:U("SubjectUserName"),ts,kind:"computer"}); break; }   // computer account created
        case "4722": case "4725": case "4726": case "4738":
          push(E.acctState,{i,user:U("TargetUserName"),act:{"4722":"enabled","4725":"disabled","4726":"deleted","4738":"changed"}[id],ts}); break;
        case "4723": case "4724": push(E.pwResets,{i,user:U("TargetUserName"),act:id==="4724"?"reset by admin":"changed",by:U("SubjectUserName"),ts}); break;
        case "4728": case "4732": case "4756":
          push(E.groupAdds,{i,member:U("MemberName")||U("MemberSid"),group:U("TargetUserName")||U("GroupName"),by:U("SubjectUserName"),ts}); break;
        case "4672": { const u=U("SubjectUserName"); if(u&&!/\$$/.test(u))E.specialPriv.set(u,(E.specialPriv.get(u)||0)+1); break; }
        case "4624": { const ip=U("IpAddress"), lt=U("LogonType"), u=U("TargetUserName");
          if(u)E.users.add(u);
          if(lt==="10"||isExtIp(ip)){ const key=u+"|"+ip+"|"+lt; const e=E.extLogons.get(key)||{i,user:u,ip,lt,count:0}; e.count++; e.i=i; E.extLogons.set(key,e); }
          if(isExtIp(ip))E.ips.set(ip,(E.ips.get(ip)||0)+1);
          const lid=U("TargetLogonId")||U("LogonId");
          if(lid && SESS_TYPES.has(lt) && u && !/\$$/.test(u) && sessById.size<AR && !sessById.has(lid))
            sessById.set(lid,{i,user:u,lt,ip,ws:U("WorkstationName"),onTms:(ts?Date.parse(ts):NaN),onTs:ts,offTms:null});
          break; }
        case "4634": case "4647": { const lid=U("TargetLogonId")||U("LogonId"); const s=lid&&sessById.get(lid);
          if(s && s.offTms==null){ s.offTms=(ts?Date.parse(ts):NaN); } break; }
        case "4625": { const ip=U("IpAddress")||"(none)"; const e=E.failedBySrc.get(ip)||{i,ip,users:new Set(),count:0}; e.count++; e.i=i; if(U("TargetUserName"))e.users.add(U("TargetUserName")); E.failedBySrc.set(ip,e); if(isExtIp(ip))E.ips.set(ip,(E.ips.get(ip)||0)+1); break; }
        case "4648": push(E.explicitCreds,{i,subj:U("SubjectUserName"),target:U("TargetUserName"),server:U("TargetServerName")||U("TargetInfo"),ip:U("IpAddress"),ts}); break;
        case "4688": { const cmd=U("CommandLine")||U("NewProcessName"); if(cmd){ push(E.procs,{i,cmd,parent:U("ParentProcessName"),user:U("SubjectUserName"),ts});
          if(LSASS_DUMP.test(cmd)) push(E.lsassAccess,{i,src:U("NewProcessName")||cmd.slice(0,90),ga:"process dump",user:U("SubjectUserName"),ts,via:"process"});
          addProcArtifacts(i,cmd,U("SubjectUserName"),ts); } break; }
        case "1": if(isSys(provider)){ const cmd=U("CommandLine")||U("Image"); if(cmd){ push(E.procs,{i,cmd,parent:U("ParentImage"),user:U("User"),ts});
          if(LSASS_DUMP.test(cmd)) push(E.lsassAccess,{i,src:U("Image")||cmd.slice(0,90),ga:"process dump",user:U("User"),ts,via:"process"});
          addProcArtifacts(i,cmd,U("User"),ts); }
          const h=U("Hashes"); if(h)h.split(",").forEach(x=>{x=x.trim();if(x)E.hashes.add(x);}); } break;
        case "4104": { const sb=U("ScriptBlockText"); if(sb&&sb.length>3)push(E.psBlocks,{i,text:sb,ts}); break; }
        case "7045": push(E.services,{i,name:U("ServiceName"),path:U("ImagePath"),start:U("StartType"),ts}); break;
        case "4697": push(E.services,{i,name:U("ServiceName"),path:U("ServiceFileName"),ts}); break;
        case "4698": case "4702": case "4699": case "4700": case "4701": {
          const xml=U("TaskContent")||U("TaskContentNew")||U("NewTaskContent")||"";
          const c=(/<Command>([^<]+)<\/Command>/i.exec(xml)||[])[1]||"", ar=(/<Arguments>([^<]+)<\/Arguments>/i.exec(xml)||[])[1]||"";
          push(E.tasks,{i,name:U("TaskName"),act:{"4698":"created","4699":"deleted","4700":"enabled","4701":"disabled","4702":"updated"}[id],cmd:(c+" "+ar).trim(),ts}); break; }
        case "106": case "140": case "141": if(/task\s*scheduler/i.test(provider))
          push(E.tasks,{i,name:U("TaskName")||U("Path")||U("Name"),act:{"106":"registered","140":"updated","141":"deleted"}[id],ts}); break;
        case "3": if(isSys(provider)){ const ip=U("DestinationIp"),port=U("DestinationPort"); const key=ip+":"+port;
          const e=E.netConns.get(key)||{i,ip,port,host:U("DestinationHostname"),image:U("Image"),count:0}; e.count++; e.i=i; E.netConns.set(key,e);
          if(isExtIp(ip))E.ips.set(ip,(E.ips.get(ip)||0)+1); } break;
        case "22": if(isSys(provider)){ const q=U("QueryName"); if(q){ E.dns.set(q,(E.dns.get(q)||0)+1); E.domains.add(q);} } break;
        case "13": if(isSys(provider)){ const tgt=U("TargetObject"); if(/\\Run\\|\\RunOnce|CurrentVersion\\Run/i.test(tgt))push(E.runKeys,{i,key:tgt,val:U("Details"),image:U("Image"),ts}); } break;
        case "11": if(isSys(provider)){ const f=U("TargetFilename"); if(f)push(E.fileWrites,{i,file:f,image:U("Image"),ts}); } break;
        case "5140": case "5145": push(E.shareAccess,{i,share:U("ShareName"),ip:U("IpAddress"),user:U("SubjectUserName"),ts}); break;
        case "1102": case "104": push(E.logCleared,{i,prov:provider,by:U("SubjectUserName"),ts}); break;
        case "1116": case "1117": case "1006": case "1015": case "5001": case "5007":
          push(E.defender,{i,eid:id,threat:U("Threat Name")||U("ThreatName")||U("Product Name")||"(setting change)",ts}); break;
        case "4769": case "4768": { const enc=U("TicketEncryptionType"); const svc=U("ServiceName"); const usr=U("TargetUserName")||U("UserName");
          const rc4=/0x17|0x18/.test(enc); push(E.kerberos,{i,user:usr,service:svc,enc,rc4,ip:U("IpAddress"),ts}); if(rc4)E.kerbRoast++; break; }
        case "4776": push(E.ntlm,{i,user:U("TargetUserName")||U("UserName"),workstation:U("Workstation")||U("WorkstationName"),status:U("Status"),ts}); break;
        case "4719": push(E.auditChanges,{i,by:U("SubjectUserName"),cat:U("CategoryId")||U("SubcategoryGuid")||U("Subcategory"),ts}); break;
        case "19": case "20": case "21": if(isSys(provider))
          push(E.wmiPersist,{i,kind:{"19":"FilterToConsumerBinding","20":"ConsumerToFilter","21":"FilterActivity"}[id]||"WMI",name:U("Name")||U("Operation")||U("Consumer")||U("Filter"),user:U("User"),ts}); break;
        case "1149": push(E.rdpSessions,{i,user:U("User")||U("Param1"),ip:U("Address")||U("Param3")||U("SourceNetworkAddress"),ts}); break;
        case "59": case "60": if(/bits/i.test(provider||"")) push(E.bits,{i,url:U("url")||U("Url")||U("RemoteName"),file:U("name")||U("LocalName"),ts}); break;
        case "10": { const tgt=U("TargetImage"), ga=U("GrantedAccess");   // Sysmon ProcessAccess (lsass target is distinctive; don't require provider match)
          if(/lsass\.exe/i.test(tgt)) push(E.lsassAccess,{i,src:U("SourceImage"),ga,user:U("SourceUser")||U("User"),ts,via:"handle"}); break; }
        case "4656": case "4663": { const obj=U("ObjectName");   // handle/object access to lsass (Security auditing)
          if(/lsass\.exe/i.test(obj)) push(E.lsassAccess,{i,src:U("ProcessName")||U("Image"),ga:U("AccessMask")||U("Accesses")||"object access",user:U("SubjectUserName"),ts,via:"handle"}); break; }
        case "8": if(isSys(provider)) push(E.remoteThread,{i,src:U("SourceImage"),tgt:U("TargetImage"),start:U("StartFunction")||U("StartModule"),ts}); break;
        case "9": if(isSys(provider)) push(E.rawAccess,{i,img:U("Image"),dev:U("Device"),ts}); break;
        case "25": if(isSys(provider)) push(E.procTamper,{i,img:U("Image"),type:U("Type"),ts}); break;
        case "8003": case "8004": case "8006": case "8007":
          push(E.appBlocks,{i,kind:(id==="8004"||id==="8007")?"blocked":"audit",file:U("FullFilePath")||U("FilePath")||U("TargetFilename"),src:"AppLocker",ts}); break;
        case "3077": case "3033":
          push(E.appBlocks,{i,kind:"blocked",file:U("File Name")||U("FileNameBuffer")||U("ProcessNameBuffer")||U("FileName"),src:"CodeIntegrity",ts}); break;
        case "4616": { const u=U("SubjectUserName"); if(u && !/\$$/.test(u) && !/^(LOCAL SERVICE|SYSTEM|NETWORK SERVICE)$/i.test(u))
          push(E.timeChange,{i,by:u,prev:U("PreviousTime"),nw:U("NewTime"),ts}); break; }
      }
    });
    // finalize logon sessions (newest first), compute duration
    E.sessions=[...sessById.values()].map(s=>({ i:s.i, user:s.user, lt:s.lt, ip:s.ip, ws:s.ws, onTs:s.onTs,
      onTms:s.onTms, offTms:s.offTms, durationMs:(s.offTms&&s.onTms&&s.offTms>=s.onTms)?(s.offTms-s.onTms):null }))
      .sort((a,b)=>(b.onTms||0)-(a.onTms||0)).slice(0,5000);
    res.type("application/json").send(JSON.stringify({ ok:true, evidence:E }, mapSetReplacer));
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

// Entity dossier: everything about one user / host / IP across the whole log + its detections
app.get("/api/entity", async (req,res)=>{
  try{
    if(!fs.existsSync(EVENTS)) return res.json({ ok:true, profile:null });
    const type=String(req.query.type||"").toLowerCase();
    const name=String(req.query.name||"");
    if(!name || !["user","host","ip"].includes(type)) return res.status(400).json({ error:"type (user|host|ip) + name required" });
    const nameLc=name.toLowerCase();
    let hits={}; try{ hits=JSON.parse(fs.readFileSync(DETS,"utf8")).hits||{}; }catch{ hits={}; }
    const SEVW={critical:100,high:40,medium:12,low:4,informational:1,info:1};
    const sevn=l=>{const r={critical:4,high:3,medium:2,low:1,informational:0,info:0}[String(l||"").toLowerCase()];return r==null?2:r;};
    const eids=new Map(), provs=new Map(), coUsers=new Map(), coHosts=new Map(), coIps=new Map(), logonTypes=new Map();
    const bySev={critical:0,high:0,medium:0,low:0,info:0}; const techSet=new Set(); const ruleAgg=new Map();
    let count=0, tMin=null, tMax=null, detCount=0, logonOk=0, logonFail=0;
    const detSamples=[]; const recent=[]; const RECENT=40;
    const bump=(m,k)=>{ if(k!=null&&k!=="") m.set(k,(m.get(k)||0)+1); };
    const rl=readline.createInterface({ input: fs.createReadStream(EVENTS,{encoding:"utf8"}), crlfDelay:Infinity });
    let i=-1;
    for await (const ln of rl){ i++; if(!ln) continue; let ev; try{ ev=JSON.parse(ln); }catch{ continue; }
      const sys=(ev.Event&&ev.Event.System)||ev.System||{};
      const data=getData(ev)||{}, comp=getComputer(ev), prov=getProvider(ev), ts=getTime(ev), eid=String(getEventId(sys)||"");
      const ents=Engine.extractEntities(data, comp);
      const pool = type==="user"?ents.users : type==="host"?ents.hosts : ents.ips;
      if(!pool.some(x=>String(x).toLowerCase()===nameLc)) continue;
      count++;
      if(ts){ if(tMin===null||ts<tMin)tMin=ts; if(tMax===null||ts>tMax)tMax=ts; }
      bump(eids,eid); bump(provs,prov);
      for(const u of ents.users) if(!(type==="user"&&u.toLowerCase()===nameLc)) bump(coUsers,u);
      for(const hh of ents.hosts) if(!(type==="host"&&hh.toLowerCase()===nameLc)) bump(coHosts,hh);
      for(const ip of ents.ips) if(!(type==="ip"&&ip.toLowerCase()===nameLc)) bump(coIps,ip);
      if(eid==="4624"){ logonOk++; bump(logonTypes,String(data.LogonType||"?")); } else if(eid==="4625"){ logonFail++; }
      const hit=hits[i];
      if(hit&&hit.length){ detCount++;
        for(const h of hit){ const lv=String(h.level).toLowerCase(); bySev[lv]=(bySev[lv]||0)+1;
          const rk=h.ruleId||h.title; let ra=ruleAgg.get(rk);
          if(!ra){ ra={ruleId:rk,title:h.title||rk,level:h.level,source:h.source,count:0}; ruleAgg.set(rk,ra); }
          ra.count++; if(sevn(h.level)>sevn(ra.level))ra.level=h.level;
          for(const t of Engine.parseAttack(h.tags).techniques) techSet.add(t.id);
          if(detSamples.length<60) detSamples.push({idx:i,ts,level:h.level,title:h.title||rk,source:h.source}); } }
      recent.push({idx:i,ts,eid,prov:String(prov).slice(0,40),comp}); if(recent.length>RECENT)recent.shift();
    }
    let risk=0; for(const ra of ruleAgg.values()) risk += (SEVW[String(ra.level).toLowerCase()]||4)*(1+Math.log2(ra.count));
    let level="info"; for(const k in bySev){ if(bySev[k]&&sevn(k)>sevn(level))level=k; }
    const top=(m,n)=>[...m.entries()].sort((a,b)=>b[1]-a[1]).slice(0,n).map(([k,v])=>({name:k,count:v}));
    res.json({ ok:true, profile:{ type, name, count, tMin, tMax, detCount, risk:Math.round(risk), level,
      bySev, techniques:[...techSet],
      rules:[...ruleAgg.values()].sort((a,b)=>sevn(b.level)-sevn(a.level)||b.count-a.count).slice(0,30),
      eids: top(eids,15), providers: top(provs,10),
      coUsers: top(coUsers,14), coHosts: top(coHosts,14), coIps: top(coIps,14),
      logonOk, logonFail, logonTypes: top(logonTypes,8),
      detSamples, recent: recent.slice().reverse() } });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

// Super-timeline: merged chronological stream of notable events (detections + high-value EIDs
// + firewall/VPN) plus a full-log activity histogram with detection density.
const TL_NOTABLE=new Map([["1102","anti-forensics"],["104","anti-forensics"],["4720","account"],["4726","account"],
  ["4728","priv-group"],["4732","priv-group"],["4756","priv-group"],["7045","persistence"],["4697","persistence"],
  ["4698","persistence"],["1149","rdp"]]);
const TL_KIND_LVL={"anti-forensics":"high","priv-group":"high","persistence":"medium","account":"medium","rdp":"low","logon":"low","lateral":"medium","firewall":"info","vpn":"info"};
function tlTitle(eid, data){ const U=k=>data&&data[k]!=null&&typeof data[k]!=="object"?String(data[k]):"";
  switch(eid){ case "1102": case "104": return "Event log cleared"+(U("SubjectUserName")?" by "+U("SubjectUserName"):"");
    case "4720": return "Account created: "+U("TargetUserName"); case "4726": return "Account deleted: "+U("TargetUserName");
    case "4728": case "4732": case "4756": return "Added to privileged group: "+(U("MemberName")||U("MemberSid"));
    case "7045": case "4697": return "Service installed: "+U("ServiceName");
    case "4698": return "Scheduled task created: "+U("TaskName");
    case "1149": return "RDP authentication: "+(U("Param1")||U("User")||U("SourceNetworkAddress"));
    default: return "EID "+eid; } }
app.get("/api/timeline", async (req,res)=>{
  try{
    if(!fs.existsSync(EVENTS)) return res.json({ ok:true, events:[], buckets:[] });
    const meta=readMeta()||{};
    let hits={}; try{ hits=JSON.parse(fs.readFileSync(DETS,"utf8")).hits||{}; }catch{ hits={}; }
    const t0=meta.tsMin?Date.parse(meta.tsMin):null, t1=meta.tsMax?Date.parse(meta.tsMax):null;
    const NB=200, haveSpan=(t0!=null&&t1!=null&&t1>t0), span=haveSpan?(t1-t0):1;
    const buckets=Array.from({length:NB},()=>({n:0,d:0,lvl:-1}));
    const events=[]; const CAP=12000, COLLECT=80000; let notableTotal=0, detTotal=0;
    await forEachEvent((ev, i)=>{
      const sys=(ev.Event&&ev.Event.System)||ev.System||{};
      const ts=getTime(ev), tms=ts?Date.parse(ts):NaN, cat=ev._cat||"", eid=String(getEventId(sys)||"");
      let b=-1; if(haveSpan && !Number.isNaN(tms)){ b=Math.floor((tms-t0)/span*NB); if(b>=NB)b=NB-1; if(b<0)b=0; buckets[b].n++; }
      const hit=hits[i];
      let kind=null, level=null, title=null;
      if(hit&&hit.length){ kind="detection"; let mx=-1; for(const h of hit){ const n=sevNumS(h.level); if(n>mx){ mx=n; level=h.level; title=h.title||h.ruleId; } } detTotal++; }
      else if(cat==="firewall"||cat==="vpn"){ const data=getData(ev); kind=cat; level="info"; title=(data&&data.Message)||svSummary(data); }
      else if(TL_NOTABLE.has(eid)){ kind=TL_NOTABLE.get(eid); level=TL_KIND_LVL[kind]||"low"; title=tlTitle(eid,getData(ev)); }
      else if(eid==="4624"){ const d=getData(ev); const lt=String(d.LogonType||""); const u=d.TargetUserName!=null?String(d.TargetUserName):"";
        if(lt==="10" && u && !/\$$/.test(u)){ kind="logon"; level="low"; title="Remote (RDP) logon: "+u+((d.IpAddress&&d.IpAddress!=="-")?" from "+d.IpAddress:""); } }
      else if(eid==="4648"){ const d=getData(ev); const u=d.SubjectUserName!=null?String(d.SubjectUserName):"";
        if(u && !/\$$/.test(u)){ kind="lateral"; level="medium"; title="Explicit credentials: "+u+" → "+(d.TargetUserName||"?")+((d.TargetServerName&&d.TargetServerName!=="localhost")?" @ "+d.TargetServerName:""); } }
      if(kind){ notableTotal++;
        if(b>=0){ buckets[b].d++; const n=sevNumS(level); if(n>buckets[b].lvl)buckets[b].lvl=n; }
        if(events.length<COLLECT) events.push({ idx:i, tms:Number.isNaN(tms)?null:tms, ts, kind, level, eid, host:getComputer(ev), title:String(title||"").slice(0,180) });
      }
    });
    // 1) select the highest-signal events (severity, then rare non-detection artifacts, then recency)
    events.sort((a,c)=> (sevNumS(c.level)-sevNumS(a.level)) || ((c.kind!=="detection")-(a.kind!=="detection")) || ((c.tms||0)-(a.tms||0)) );
    const truncated=events.length>CAP;
    // 2) present them as a clean chronological flow: strictly by time, then log order as a stable tiebreaker
    const feed=events.slice(0,CAP);
    feed.sort((a,c)=> ((a.tms==null?Infinity:a.tms)-(c.tms==null?Infinity:c.tms)) || (a.idx-c.idx));
    res.json({ ok:true, tMin:meta.tsMin, tMax:meta.tsMax, notableTotal, detTotal, truncated,
      buckets: buckets.map((x,k)=>({ t: haveSpan?Math.round(t0+(k+0.5)*span/NB):null, n:x.n, d:x.d, lvl:x.lvl })),
      events: feed });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

// Process-tree reconstruction — build ancestry forests from Sysmon EID 1 (ProcessGuid/
// ParentProcessGuid), enriched with detection severity per process. EID 5 supplies end times.
app.get("/api/proctree", async (req,res)=>{
  try{
    if(!fs.existsSync(EVENTS)) return res.json({ ok:true, roots:[], count:0, hosts:[] });
    let hits={}; try{ hits=JSON.parse(fs.readFileSync(DETS,"utf8")).hits||{}; }catch{}
    const CAP=30000; const procs=[]; const ends=new Map(); let truncated=false;
    await forEachEvent((ev, i)=>{
      const sys=(ev.Event&&ev.Event.System)||ev.System||{};
      if(!/sysmon/i.test(getProvider(ev))) return;              // ProcessGuid trees come from Sysmon
      const eid=String(getEventId(sys)||""); const d=getData(ev)||{};
      if(eid==="1"){
        if(procs.length>=CAP){ truncated=true; return; }
        const hit=hits[i]; let det=0; if(hit&&hit.length){ for(const h of hit){ const n=sevNumS(h.level); if(n>det)det=n; } }
        const ts=getTime(ev);
        procs.push({ idx:i, guid:d.ProcessGuid||"", pid:d.ProcessId||"", image:d.Image||"", cmd:d.CommandLine||"",
          pguid:d.ParentProcessGuid||"", pimage:d.ParentImage||"", user:d.User||"", ts, tms:ts?Date.parse(ts):NaN,
          host:getComputer(ev), det });
      } else if(eid==="5"){ const g=d.ProcessGuid; if(g) ends.set(g, getTime(ev)); }
    });
    for(const p of procs){ if(ends.has(p.guid)) p.end=ends.get(p.guid); }
    const tree=Engine.buildProcessTree(procs);
    res.json({ ok:true, roots:tree.roots, count:tree.count, hosts:tree.hosts, truncated });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

// Logon-session reconstruction: pair 4624 logon with its 4634/4647 logoff by LogonId,
// compute duration, decode logon type, flag RDP / external-source sessions.
const LOGON_TYPE_NAME={ "2":"Interactive","3":"Network","4":"Batch","5":"Service","7":"Unlock",
  "8":"NetworkCleartext","9":"NewCredentials","10":"RemoteInteractive (RDP)","11":"CachedInteractive" };
app.get("/api/sessions", async (req,res)=>{
  try{
    if(!fs.existsSync(EVENTS)) return res.json({ ok:true, sessions:[], count:0 });
    let hits={}; try{ hits=JSON.parse(fs.readFileSync(DETS,"utf8")).hits||{}; }catch{}
    const detLvl=i=>{ const h=hits[i]; if(!h||!h.length)return 0; let m=0; for(const x of h){ const n=sevNumS(x.level); if(n>m)m=n; } return m; };
    const CAP=20000; const byId=new Map(); const open=[]; let truncated=false;
    await forEachEvent((ev, i)=>{
      const sys=(ev.Event&&ev.Event.System)||ev.System||{};
      const eid=String(getEventId(sys)||""); if(eid!=="4624"&&eid!=="4634"&&eid!=="4647") return;
      const d=getData(ev)||{}; const U=k=>d[k]!=null?String(d[k]):"";
      const lid=U("TargetLogonId")||U("LogonId"); if(!lid||lid==="0x0"||lid==="0x3e7") return;   // skip SYSTEM
      const ts=getTime(ev), tms=ts?Date.parse(ts):NaN;
      if(eid==="4624"){
        const u=U("TargetUserName"); const lt=U("LogonType");
        if(!u||/\$$/.test(u)||/^(ANONYMOUS LOGON|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d|UMFD-\d)$/i.test(u)) return;
        if(byId.has(lid)) return;
        if(byId.size>=CAP){ truncated=true; return; }
        const ip=U("IpAddress"); const proc=U("LogonProcessName");
        byId.set(lid,{ idx:i, id:lid, user:u, domain:U("TargetDomainName"), lt, ltName:LOGON_TYPE_NAME[lt]||("Type "+lt),
          ip:(ip&&ip!=="-")?ip:"", ws:U("WorkstationName"), host:getComputer(ev), proc,
          onTs:ts, onTms:Number.isNaN(tms)?null:tms, offTs:null, offTms:null,
          rdp:lt==="10", ext:isExtIp(ip), det:detLvl(i) });
      } else {
        const s=byId.get(lid);
        if(s && s.offTms==null){ s.offTs=ts; s.offTms=Number.isNaN(tms)?null:tms; }
      }
    });
    const sessions=[...byId.values()].map(s=>({ ...s,
      durationMs:(s.onTms!=null&&s.offTms!=null&&s.offTms>=s.onTms)?(s.offTms-s.onTms):null }))
      .sort((a,b)=>(b.det-a.det)||((b.onTms||0)-(a.onTms||0))).slice(0,CAP);
    res.json({ ok:true, sessions, count:sessions.length, truncated });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

// Cross-host lateral-movement graph: derive host<->host / IP->host movement from auth,
// explicit-credential, RDP, NTLM and share-access events, then aggregate into a node-link graph.
app.get("/api/lateral", async (req,res)=>{
  try{
    if(!fs.existsSync(EVENTS)) return res.json({ ok:true, nodes:[], edges:[] });
    let hits={}; try{ hits=JSON.parse(fs.readFileSync(DETS,"utf8")).hits||{}; }catch{}
    const detLvl=i=>{ const h=hits[i]; if(!h||!h.length)return 0; let m=0; for(const x of h){ const n=sevNumS(x.level); if(n>m)m=n; } return m; };
    const ip4=/^\d+\.\d+\.\d+\.\d+$/;
    const clean=s=>{ s=String(s||"").trim(); if(!s||s==="-"||s==="::1"||/^127\./.test(s)||/^ANONYMOUS/i.test(s))return ""; return s; };
    const bare=h=>String(h||"").toUpperCase().split(".")[0];
    const raw=[]; const CAP=300000; let truncated=false;
    await forEachEvent((ev, i)=>{
      if(raw.length>=CAP){ truncated=true; return; }
      const sys=(ev.Event&&ev.Event.System)||ev.System||{};
      const eid=String(getEventId(sys)||"");
      if(!(eid==="4624"||eid==="4648"||eid==="4776"||eid==="1149"||eid==="5140"||eid==="5145")) return;
      const provider=getProvider(ev), host=getComputer(ev), d=getData(ev)||{};
      const U=k=>d[k]!=null?String(d[k]):"";
      const ts=getTime(ev), tms=ts?Date.parse(ts):NaN;
      const det=detLvl(i);
      const push=(from,ftype,to,ttype,kind,user)=>{ from=clean(from); to=clean(to);
        if(!from||!to||bare(from)===bare(to)) return;
        raw.push({ from, ftype, to, ttype, kind, user:clean(user), idx:i, tms:Number.isNaN(tms)?null:tms, det }); };
      switch(eid){
        case "4624":{ const lt=U("LogonType"); if(lt!=="3"&&lt!=="10") break;
          const u=U("TargetUserName"); if(!u||/\$$/.test(u)) break;
          let src=clean(U("IpAddress")), stype="ip";
          if(!src){ src=clean(U("WorkstationName")); stype="host"; }
          if(!src) break;
          push(src, ip4.test(src)?"ip":"host", host, "host", lt==="10"?"rdp":"network", u); break; }
        case "4648":{ push(host, "host", U("TargetServerName")||U("TargetInfo"), "host", "explicit-cred", U("TargetUserName")); break; }
        case "4776":{ const u=U("TargetUserName")||U("UserName"); if(u&&/\$$/.test(u)) break;
          push(U("Workstation")||U("WorkstationName"), "host", host, "host", "ntlm", u); break; }
        case "1149":{ push(U("Address")||U("Param3")||U("SourceNetworkAddress"), "ip", host, "host", "rdp", U("User")||U("Param1")); break; }
        case "5140": case "5145":{ const share=U("ShareName"); const k=/\$$/.test(share||"")?"admin-share":"share";
          push(U("IpAddress"), "ip", host, "host", k, U("SubjectUserName")); break; }
      }
    });
    const g=Engine.buildLateralGraph(raw);
    res.json({ ok:true, nodes:g.nodes, edges:g.edges, count:g.nodes.length, edgeCount:g.edges.length, truncated });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

// ---- IOC watchlist: manage the indicator list + scan the active case for matches ----
app.get("/api/watchlist", (req,res)=> res.json({ ok:true, iocs:loadWatchlist() }));
app.post("/api/watchlist", (req,res)=>{
  try{
    const b=req.body||{};
    if(b.clear){ saveWatchlist([]); return res.json({ ok:true, iocs:[] }); }
    let list=loadWatchlist();
    if(b.text!=null || Array.isArray(b.add)){
      const add = b.text!=null ? parseIocInput(b.text)
        : b.add.map(x=> typeof x==="string" ? { value:x, type:Engine.iocType(x), label:"" } : { value:x.value, type:x.type||Engine.iocType(x.value), label:x.label||"" });
      list=mergeIocs(list, add);
    }
    if(Array.isArray(b.remove) && b.remove.length){ const rm=new Set(b.remove.map(v=>String(v).toLowerCase())); list=list.filter(x=>!rm.has(String(x.value).toLowerCase())); }
    saveWatchlist(list);
    res.json({ ok:true, iocs:list });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});
app.get("/api/watchlist/scan", async (req,res)=>{
  try{
    const iocs=loadWatchlist();
    if(!iocs.length) return res.json({ ok:true, hits:[], iocCount:0, eventCount:0, matchedEvents:0 });
    if(!fs.existsSync(EVENTS)) return res.json({ ok:true, hits:[], iocCount:iocs.length, eventCount:0, matchedEvents:0 });
    let detHits={}; try{ detHits=JSON.parse(fs.readFileSync(DETS,"utf8")).hits||{}; }catch{}
    const matcher=Engine.buildIocMatcher(iocs);
    const metaByLower=matcher.meta;                          // lower -> {value,type}
    const agg=new Map();                                     // lower -> {value,type,count,hosts:Set,samples:[],det,firstTms,lastTms}
    let eventCount=0, matchedEvents=0;
    await forEachEvent((ev, i)=>{
      eventCount++;
      const found=matcher.scan(bodyText(ev));                // bodyText is already lowercased
      if(!found.size) return;
      matchedEvents++;
      const host=getComputer(ev), ts=getTime(ev), tms=ts?Date.parse(ts):NaN;
      const dh=detHits[i]; let det=0; if(dh&&dh.length){ for(const h of dh){ const n=sevNumS(h.level); if(n>det)det=n; } }
      for(const lv of found){
        let a=agg.get(lv);
        if(!a){ const md=metaByLower.get(lv)||{ value:lv, type:"string" }; a={ value:md.value, type:md.type, count:0, hosts:new Set(), samples:[], det:0, firstTms:null, lastTms:null }; agg.set(lv,a); }
        a.count++;
        if(host) a.hosts.add(host);
        if(a.samples.length<12) a.samples.push(i);
        if(det>a.det) a.det=det;
        if(!Number.isNaN(tms)){ if(a.firstTms==null||tms<a.firstTms)a.firstTms=tms; if(a.lastTms==null||tms>a.lastTms)a.lastTms=tms; }
      }
    });
    const hits=[...agg.values()].map(a=>({ value:a.value, type:a.type, count:a.count, det:a.det,
      hosts:[...a.hosts].slice(0,20), samples:a.samples, firstTms:a.firstTms, lastTms:a.lastTms }))
      .sort((x,y)=>(y.det-x.det)||(y.count-x.count));
    res.json({ ok:true, hits, iocCount:iocs.length, matched:hits.length, eventCount, matchedEvents });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

// ---- Observed indicators: carve the IPs / hashes / domains actually present in the case,
//      so an analyst can see them and check each against threat intel. ----
app.get("/api/observed", async (req,res)=>{
  try{
    if(!fs.existsSync(EVENTS)) return res.json({ ok:true, ips:[], hashes:[], domains:[], eventCount:0 });
    let detHits={}; try{ detHits=JSON.parse(fs.readFileSync(DETS,"utf8")).hits||{}; }catch{}
    const detLvl=i=>{ const h=detHits[i]; if(!h||!h.length)return 0; let m=0; for(const x of h){ const n=sevNumS(x.level); if(n>m)m=n; } return m; };
    const CAP=8000;
    const ips=new Map(), hashes=new Map(), domains=new Map();
    const add=(map, key, extra, host, i, tms, det)=>{
      let a=map.get(key);
      if(!a){ if(map.size>=CAP) return; a={ value:key, count:0, hosts:new Set(), samples:[], firstTms:null, lastTms:null, det:0, ...extra }; map.set(key, a); }
      a.count++; if(host)a.hosts.add(host); if(a.samples.length<12)a.samples.push(i); if(det>a.det)a.det=det;
      if(tms!=null){ if(a.firstTms==null||tms<a.firstTms)a.firstTms=tms; if(a.lastTms==null||tms>a.lastTms)a.lastTms=tms; }
    };
    const IP_FIELDS=["IpAddress","DestinationIp","SourceIp","DestAddress","SourceAddress","ClientAddress","Address","DestinationAddress"];
    const HASH_ALGO=/^(md5|sha1|sha256)$/i;
    let eventCount=0;
    await forEachEvent((ev, i)=>{
      eventCount++;
      const d=getData(ev)||{}; const host=getComputer(ev); const ts=getTime(ev); const tms=ts?Date.parse(ts):NaN; const T=Number.isNaN(tms)?null:tms;
      const det=detLvl(i);
      // IPs — from known address fields (reliable; avoids body-scan noise)
      const seenIp=new Set();
      for(const k of IP_FIELDS){ const v=d[k]; if(v==null) continue;
        const m=String(v).match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/); if(!m) continue;
        const ip=m[0]; if(ip==="0.0.0.0"||ip==="255.255.255.255"||seenIp.has(ip)) continue; seenIp.add(ip);
        add(ips, ip, { type:"ip", external:isExtIp(ip) }, host, i, T, det); }
      // Hashes — from Sysmon "Hashes"/"Hash" fields ("SHA256=..,MD5=..,IMPHASH=..") + explicit algo fields
      const hraw=[]; if(d.Hashes)hraw.push(String(d.Hashes)); if(d.Hash)hraw.push(String(d.Hash));
      for(const algo of ["SHA256","SHA1","MD5"]){ if(d[algo])hraw.push(algo+"="+d[algo]); }
      for(const blob of hraw){ for(const part of blob.split(",")){ const p=part.trim(); if(!p) continue;
        const eq=p.indexOf("="); let algo="", hv=p;
        if(eq>0){ algo=p.slice(0,eq); hv=p.slice(eq+1); if(!HASH_ALGO.test(algo)) continue; }   // skip IMPHASH etc.
        hv=hv.trim().toLowerCase();
        if(/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(hv)) add(hashes, hv, { type:"hash", algo:(algo||({32:"MD5",40:"SHA1",64:"SHA256"}[hv.length])||"").toUpperCase() }, host, i, T, det);
      } }
      // Domains — from Sysmon DNS queries (EID 22)
      const q=d.QueryName; if(q){ const dn=String(q).trim().toLowerCase().replace(/\.$/,"");
        if(/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(dn) && !/\.(arpa|local)$/.test(dn)) add(domains, dn, { type:"domain" }, host, i, T, det); }
    });
    const pack=map=>[...map.values()].map(a=>({ value:a.value, type:a.type, algo:a.algo, external:a.external,
      count:a.count, det:a.det, hosts:[...a.hosts].slice(0,20), samples:a.samples, firstTms:a.firstTms, lastTms:a.lastTms }))
      .sort((x,y)=>(y.det-x.det)||(y.count-x.count));
    res.json({ ok:true, ips:pack(ips), hashes:pack(hashes), domains:pack(domains), eventCount,
      capped:{ ips:ips.size>=CAP, hashes:hashes.size>=CAP, domains:domains.size>=CAP } });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

// ---- Rarity / stacking: frequency analysis (rarest-first) to surface long-tail anomalies ----
app.get("/api/rarity", async (req,res)=>{
  try{
    if(!fs.existsSync(EVENTS)) return res.json({ ok:true, processes:null, parentChild:null, logons:null, services:null, eventCount:0 });
    let detHits={}; try{ detHits=JSON.parse(fs.readFileSync(DETS,"utf8")).hits||{}; }catch{}
    const detLvl=i=>{ const h=detHits[i]; if(!h||!h.length)return 0; let m=0; for(const x of h){ const n=sevNumS(x.level); if(n>m)m=n; } return m; };
    const procItems=[], pcItems=[], logonItems=[], svcItems=[];
    let eventCount=0;
    await forEachEvent((ev, i)=>{
      eventCount++;
      const sys=(ev.Event&&ev.Event.System)||ev.System||{};
      const eid=String(getEventId(sys)||""); const prov=getProvider(ev); const d=getData(ev)||{};
      const host=getComputer(ev); const ts=getTime(ev); const tms=ts?Date.parse(ts):NaN; const T=Number.isNaN(tms)?null:tms; const det=detLvl(i);
      const U=k=>d[k]!=null?String(d[k]):"";
      // process creation — Sysmon EID 1 or Security 4688
      let image="", parent="", user="";
      if(eid==="1" && /sysmon/i.test(prov)){ image=U("Image"); parent=U("ParentImage"); user=U("User"); }
      else if(eid==="4688"){ image=U("NewProcessName"); parent=U("ParentProcessName"); user=U("SubjectUserName"); }
      if(image){ const bi=Engine.baseName(image).toLowerCase();
        procItems.push({ key:bi, host, user, idx:i, tms:T, det });
        if(parent){ const bp=Engine.baseName(parent).toLowerCase();
          pcItems.push({ key:bp+" → "+bi, host, user, idx:i, tms:T, det,
            extra:{ parent:bp, child:bi, suspicious:Engine.suspiciousParentChild(parent, image) } }); } }
      // logon origin — 4624 for real (non-machine) users
      if(eid==="4624"){ const lt=U("LogonType"); const u=U("TargetUserName");
        if(u && !/\$$/.test(u) && !/^(SYSTEM|ANONYMOUS LOGON|LOCAL SERVICE|NETWORK SERVICE|DWM-\d|UMFD-\d)$/i.test(u)){
          const ipv=U("IpAddress"); const src=(ipv&&ipv!=="-")?ipv:(U("WorkstationName")||"local");
          logonItems.push({ key:u+" @ "+(host||"?")+" · type "+lt+" · from "+src, host, user:u, idx:i, tms:T, det }); } }
      // service install — 7045 (System) / 4697 (Security)
      if(eid==="7045"||eid==="4697"){ const n=U("ServiceName"); const p=U("ImagePath")||U("ServiceFileName");
        if(n) svcItems.push({ key:n+(p?"  ["+p+"]":""), host, user:U("SubjectUserName"), idx:i, tms:T, det }); }
    });
    res.json({ ok:true, eventCount,
      processes: Engine.buildStacks(procItems),
      parentChild: Engine.buildStacks(pcItems),
      logons: Engine.buildStacks(logonItems),
      services: Engine.buildStacks(svcItems) });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

// ---- Settings: report which intel providers are configured; save keys (never returned) ----
// ---- AI Support: provider config + generic completion endpoint (Claude / OpenAI / Gemini) ----
const AI_PROVIDERS=["anthropic","openai","gemini"];
const AI_DEFAULT_MODEL={ anthropic:"claude-sonnet-5", openai:"gpt-4o-mini", gemini:"gemini-1.5-flash" };
const AI_PROVIDER_LABEL={ anthropic:"Claude", openai:"ChatGPT", gemini:"Gemini" };
function aiConfig(){ const s=loadSettings();
  const provider=AI_PROVIDERS.includes(s.aiProvider)?s.aiProvider:"anthropic";
  const model=(s.aiModel&&String(s.aiModel).trim())||AI_DEFAULT_MODEL[provider];
  return { provider, model, key:getApiKey(provider) };
}
function settingsPayload(){ const { provider, model }=aiConfig();
  return { ok:true, abuseipdbConfigured:!!getApiKey("abuseipdb"), virustotalConfigured:!!getApiKey("virustotal"),
    anthropicConfigured:!!getApiKey("anthropic"), openaiConfigured:!!getApiKey("openai"), geminiConfigured:!!getApiKey("gemini"),
    aiProvider:provider, aiModel:model, aiDefaults:AI_DEFAULT_MODEL, enrichTtlHours:Math.round(ENRICH_TTL_MS/3600000) };
}
app.get("/api/settings", (req,res)=> res.json(settingsPayload()));
app.post("/api/settings", (req,res)=>{
  try{
    const b=req.body||{}; const s=loadSettings();
    // a provided string sets/replaces the key; an explicit empty string clears it; undefined leaves it
    for(const p of ["abuseipdb","virustotal","anthropic","openai","gemini"]){
      const k=p+"ApiKey"; if(b[k]!==undefined){ const v=String(b[k]).trim(); if(v)s[k]=v; else delete s[k]; } }
    if(b.aiProvider!==undefined && AI_PROVIDERS.includes(b.aiProvider)) s.aiProvider=b.aiProvider;
    if(b.aiModel!==undefined){ const v=String(b.aiModel).trim(); if(v)s.aiModel=v; else delete s.aiModel; }
    saveSettings(s);
    res.json(settingsPayload());
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});
async function callAnthropic(model,key,system,prompt,maxTokens){
  const r=await fetchWithTimeout("https://api.anthropic.com/v1/messages",{ method:"POST",
    headers:{ "x-api-key":key, "anthropic-version":"2023-06-01", "content-type":"application/json" },
    body:JSON.stringify({ model, max_tokens:maxTokens||900, system, messages:[{role:"user",content:prompt}] }) }, 45000);
  const d=await r.json().catch(()=>null);
  if(!r.ok) throw new Error((d&&d.error&&d.error.message)||("HTTP "+r.status));
  return (d&&Array.isArray(d.content)&&d.content.map(c=>c.text||"").join("").trim())||"";
}
async function callOpenAI(model,key,system,prompt,maxTokens){
  const r=await fetchWithTimeout("https://api.openai.com/v1/chat/completions",{ method:"POST",
    headers:{ "Authorization":"Bearer "+key, "content-type":"application/json" },
    body:JSON.stringify({ model, temperature:0.2, max_tokens:maxTokens||900, messages:[{role:"system",content:system},{role:"user",content:prompt}] }) }, 45000);
  const d=await r.json().catch(()=>null);
  if(!r.ok) throw new Error((d&&d.error&&d.error.message)||("HTTP "+r.status));
  return (d&&d.choices&&d.choices[0]&&d.choices[0].message&&d.choices[0].message.content||"").trim();
}
async function callGemini(model,key,system,prompt,maxTokens){
  const url="https://generativelanguage.googleapis.com/v1beta/models/"+encodeURIComponent(model)+":generateContent?key="+encodeURIComponent(key);
  const r=await fetchWithTimeout(url,{ method:"POST", headers:{ "content-type":"application/json" },
    body:JSON.stringify({ system_instruction:{ parts:[{ text:system }] }, contents:[{ parts:[{ text:prompt }] }], generationConfig:{ maxOutputTokens:maxTokens||900, temperature:0.2 } }) }, 45000);
  const d=await r.json().catch(()=>null);
  if(!r.ok) throw new Error((d&&d.error&&d.error.message)||("HTTP "+r.status));
  const c=d&&d.candidates&&d.candidates[0];
  return (c&&c.content&&c.content.parts&&c.content.parts.map(p=>p.text||"").join("").trim())||"";
}
app.post("/api/ai", async (req,res)=>{
  try{
    const b=req.body||{};
    const system=String(b.system||"You are a senior DFIR / SOC analyst helping triage Windows event logs.").slice(0,8000);
    const prompt=String(b.prompt||"").slice(0,80000);
    if(!prompt) return res.status(400).json({error:"no prompt"});
    const { provider, model, key }=aiConfig();
    if(!key) return res.json({ ok:false, error:"No API key set for "+(AI_PROVIDER_LABEL[provider]||provider)+". Pick a model and add its key in ⚙ Settings." });
    const maxTokens=Math.min(8000, parseInt(b.maxTokens,10)||900);
    let text="";
    if(provider==="anthropic") text=await callAnthropic(model,key,system,prompt,maxTokens);
    else if(provider==="openai") text=await callOpenAI(model,key,system,prompt,maxTokens);
    else text=await callGemini(model,key,system,prompt,maxTokens);
    res.json({ ok:true, text, provider, model, label:AI_PROVIDER_LABEL[provider] });
  }catch(err){ res.json({ ok:false, error:String(err.message||err) }); }
});
// ---- Threat-intel enrichment for a single indicator (IP -> AbuseIPDB+VT, hash -> VT) ----
app.post("/api/enrich", async (req,res)=>{
  try{
    const b=req.body||{}; const value=String(b.value||"").trim();
    if(!value) return res.status(400).json({ error:"no value" });
    const type=b.type||Engine.iocType(value);
    if(type!=="ip"&&type!=="hash") return res.json({ ok:false, error:"Only IP and file-hash indicators can be checked against threat intel." });
    const cache=loadEnrichCache(); const ckey=type+":"+value.toLowerCase();
    if(!b.refresh && cache[ckey] && (Date.now()-cache[ckey].at < ENRICH_TTL_MS))
      return res.json({ ok:true, value, type, results:cache[ckey].results, cached:true, at:cache[ckey].at });
    const results=[], errors=[];
    if(type==="ip"){
      const ak=getApiKey("abuseipdb"); if(ak){ try{ results.push(await abuseipdbCheck(value, ak)); }catch(e){ errors.push("AbuseIPDB: "+e.message); } }
      const vk=getApiKey("virustotal"); if(vk){ try{ results.push(await virustotalCheck(value, "ip", vk)); }catch(e){ errors.push("VirusTotal: "+e.message); } }
    } else {
      const vk=getApiKey("virustotal"); if(vk){ try{ results.push(await virustotalCheck(value, "file", vk)); }catch(e){ errors.push("VirusTotal: "+e.message); } }
    }
    if(!results.length && !errors.length)
      return res.json({ ok:false, error:"No API key configured for "+(type==="ip"?"IP":"hash")+" lookups. Add one in ⚙ Settings." });
    if(results.length){ cache[ckey]={ at:Date.now(), results }; saveEnrichCache(cache); }
    res.json({ ok:true, value, type, results, errors, cached:false, at:Date.now() });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});
// All still-valid cached verdicts — lets the client restore results after a page refresh
// without re-querying the providers.
app.get("/api/enrich/cache", (req,res)=>{
  try{ const c=loadEnrichCache(); const now=Date.now(); const entries=[];
    for(const k in c){ const e=c[k]; if(!e || !(now-e.at < ENRICH_TTL_MS)) continue;
      const sep=k.indexOf(":"); entries.push({ type:k.slice(0,sep), value:k.slice(sep+1), at:e.at, results:e.results }); }
    res.json({ ok:true, entries });
  }catch(err){ res.status(500).json({error:String(err.message||err)}); }
});

// flagged events (★) — persisted so they survive a refresh; indices align with the stored log
app.get("/api/flags", (req,res)=>{ let a=[]; try{ a=JSON.parse(fs.readFileSync(FLAGS,"utf8")); }catch{} res.json({ ok:true, indices:a }); });
app.post("/api/flags", (req,res)=>{
  const a=Array.isArray(req.body&&req.body.indices)?req.body.indices.filter(n=>Number.isInteger(n)&&n>=0):[];
  try{ fs.writeFileSync(FLAGS, JSON.stringify(a)); }catch(e){ return res.status(500).json({error:String(e.message||e)}); }
  res.json({ ok:true, count:a.length });
});

// ---- Casework: per-case analyst verdicts, tags, notes + case findings/narrative ----
function caseworkFile(){ return CASE_DIR ? path.join(CASE_DIR, "casework.json") : null; }
function loadCasework(){ const f=caseworkFile();
  if(f){ try{ const o=JSON.parse(fs.readFileSync(f,"utf8")); return { summary:o.summary||"", findings:Array.isArray(o.findings)?o.findings:[], annotations:o.annotations||{} }; }catch{} }
  return { summary:"", findings:[], annotations:{} }; }
function saveCasework(cw){ const f=caseworkFile(); if(!f)return; try{ fs.writeFileSync(f, JSON.stringify(cw)); }catch(e){ console.error(e); } }
const VERDICTS=new Set(["tp","fp","suspicious","benign","reviewed"]);
app.get("/api/casework", (req,res)=> res.json({ ok:true, casework:loadCasework() }));
app.post("/api/casework/summary", (req,res)=>{ const cw=loadCasework(); cw.summary=String((req.body&&req.body.summary)||"").slice(0,20000); saveCasework(cw); res.json({ ok:true }); });
app.post("/api/casework/annotate", (req,res)=>{
  const b=req.body||{}; const idx=parseInt(b.idx,10);
  if(!Number.isInteger(idx)||idx<0) return res.status(400).json({error:"idx required"});
  const cw=loadCasework();
  const verdict=VERDICTS.has(String(b.verdict))?String(b.verdict):"";
  const tags=Array.isArray(b.tags)?[...new Set(b.tags.map(t=>String(t).trim()).filter(Boolean))].slice(0,20):[];
  const note=String(b.note||"").slice(0,4000);
  if(b.clear || (!verdict && !note && !tags.length)) delete cw.annotations[idx];
  else cw.annotations[idx]={ verdict, tags, note, at:new Date().toISOString() };
  saveCasework(cw); res.json({ ok:true, annotation:cw.annotations[idx]||null, count:Object.keys(cw.annotations).length });
});
app.post("/api/casework/finding", (req,res)=>{
  const b=req.body||{}; const cw=loadCasework();
  if(b.remove){ cw.findings=cw.findings.filter(f=>f.id!==b.id); }
  else { const f={ id:b.id||("f"+Date.now().toString(36)+Math.random().toString(36).slice(2,5)),
      title:String(b.title||"").slice(0,300), severity:["critical","high","medium","low","info"].includes(b.severity)?b.severity:"medium",
      note:String(b.note||"").slice(0,8000), at:new Date().toISOString() };
    if(!f.title) return res.status(400).json({error:"title required"});
    const i=cw.findings.findIndex(x=>x.id===f.id); if(i>=0){ f.at=cw.findings[i].at; cw.findings[i]=f; } else cw.findings.push(f); }
  saveCasework(cw); res.json({ ok:true, findings:cw.findings });
});

// "Remove Current Log" — wipe the active case's log + detections + flags + index, keep saved rules
app.post("/api/reset", (req,res)=>{
  if(!ACTIVE) return res.json({ ok:true });
  if(_caseIndex){ _caseIndex.close(); _caseIndex=null; }
  for(const f of [EVENTS,META,DETS,FLAGS,EVENTS_IDX,CASE_DB,caseworkFile()]){ try{ if(f)fs.unlinkSync(f); }catch{} }
  try{ fs.unlinkSync(CASE_DB+"-wal"); }catch{} try{ fs.unlinkSync(CASE_DB+"-shm"); }catch{}
  catalog.clearCustody(ACTIVE);
  catalog.upsertCase({ id:ACTIVE, name:(catalog.getCase(ACTIVE)||{}).name, createdAt:(catalog.getCase(ACTIVE)||{}).createdAt, count:0, tsMin:null, tsMax:null });
  res.json({ ok:true });
});

// never cache the app shell or API, so redeploys take effect immediately (fixes stale-JS issues)
app.use((req,res,next)=>{ if(req.path==="/"||req.path==="/index.html"||req.path.startsWith("/api/"))
  res.set("Cache-Control","no-store, no-cache, must-revalidate"); next(); });
app.use(express.static(path.join(__dirname,"public"), { etag:false, lastModified:false, setHeaders(res,p){ if(p.endsWith("index.html")) res.set("Cache-Control","no-store"); } }));
app.get("/", (req,res)=>{ res.set("Cache-Control","no-store"); res.sendFile(path.join(__dirname,"public","index.html")); });

// only bind a port when run directly (node server.mjs); importing it (tests) won't listen
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const [maj, min] = process.versions.node.split(".").map(n=>parseInt(n,10));
  if (maj < 22 || (maj === 22 && min < 5)) {   // node:sqlite (the case index) needs Node >=22.5
    console.error(`\n  Node ${process.versions.node} is too old. EVTX Triage needs Node 22.5+ (uses the built-in node:sqlite).`);
    console.error("  Install a newer Node, e.g.:  nvm install 22   (or)   https://nodejs.org/\n");
    process.exit(1);
  }
  app.listen(PORT, ()=> console.log(`EVTX Triage server on http://localhost:${PORT}  (data: ${DATA})`));
}

export { app, DATA };
