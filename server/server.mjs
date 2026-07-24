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
const RULES_DIR = path.join(DATA, "rules");
const SIGMA_DIR = path.join(RULES_DIR, "sigma");
const YARA_DIR = path.join(RULES_DIR, "yara");
const EVENTS = path.join(DATA, "events.jsonl");
const META = path.join(DATA, "meta.json");
const DETS = path.join(DATA, "detections.json");
const FLAGS = path.join(DATA, "flags.json");
const TMP = path.join(DATA, "tmp");
for (const d of [DATA, RULES_DIR, SIGMA_DIR, YARA_DIR, TMP]) fs.mkdirSync(d, { recursive: true });

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
function getData(ev){ let d=(ev.Event&&ev.Event.EventData)||ev.EventData||{};
  if(d&&Array.isArray(d.Data)){ const o={}; let i=0;
    for(const it of d.Data){ if(it&&typeof it==="object"&&it.Name!==undefined) o[it.Name]=it["#text"]!=null?it["#text"]:(it.Value!=null?it.Value:"");
      else o["Data"+(++i)]=it; }
    for(const k in d) if(k!=="Data") o[k]=d[k]; return o; }
  return (d&&typeof d==="object")?d:{value:d}; }
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
function loadSigmaRules(){ const rules=[]; let skipped=0, errors=0;
  for(const f of listRuleFiles(SIGMA_DIR)){ try{ const res=Engine.parseSigmaDocs(fs.readFileSync(f,"utf8"), yaml.loadAll);
    rules.push(...res.rules); skipped+=res.skipped.length; errors+=res.errors.length; }catch{ errors++; } }
  return { rules, skipped, errors }; }
function loadYaraRules(){ let txt=""; for(const f of listRuleFiles(YARA_DIR)){ try{ txt+="\n"+fs.readFileSync(f,"utf8"); }catch{} }
  if(!txt.trim())return { rules:[], errors:0 };
  try{ const r=Engine.compileYaraRules(txt); return { rules:r.rules, errors:r.errors.length }; }catch{ return { rules:[], errors:1 }; } }
function ruleCounts(){ return { sigmaFiles:listRuleFiles(SIGMA_DIR).length, yaraFiles:listRuleFiles(YARA_DIR).length }; }
function safeName(s){ return String(s||"rule").replace(/[^a-zA-Z0-9._-]/g,"_").slice(0,120); }

/* ---------- meta / events ---------- */
const DETECT_CAP = parseInt(process.env.EVTX_DETECT_CAP || "2000000", 10); // max events scanned in one pass
function readMeta(){ try{ return JSON.parse(fs.readFileSync(META,"utf8")); }catch{ return null; } }
// stream events.jsonl into engine records, capped, never loading the whole file as one string
async function eventRecords(cap){
  const recs=[]; if(!fs.existsSync(EVENTS))return recs;
  const rl=readline.createInterface({ input: fs.createReadStream(EVENTS,{encoding:"utf8"}), crlfDelay:Infinity });
  for await (const ln of rl){ if(!ln.trim())continue;
    try{ recs.push(recordOf(JSON.parse(ln))); }catch{}
    if(cap && recs.length>=cap){ rl.close(); break; } }
  return recs; }

/* ---------- byte-offset index (random access into events.jsonl) ----------------
   events.jsonl is one JSON event per line. events.idx holds the byte offset of each
   line start as consecutive little-endian Float64 (safe past 2^53 bytes). This lets
   any event be fetched by index with a single seek+read instead of scanning the file,
   powering fetch-on-scroll and server-side search without loading bodies into RAM.   */
const EVENTS_IDX = path.join(DATA, "events.idx");
let _idxCache = null;   // { mtimeMs, size, offsets: Float64Array }
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

/* =====================  ROUTES  ===================== */
app.get("/api/meta", (req,res)=> res.json({ ok:true, meta:readMeta(), rules:ruleCounts(),
  hasDetections: fs.existsSync(DETS), browseCap: BROWSE_CAP }));

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
    const append = String(req.query.mode||"")==="append" && fs.existsSync(EVENTS);
    const cat = (req.query.cat==="firewall"||req.query.cat==="vpn") ? req.query.cat : null;
    const prev = append ? (readMeta()||{}) : {};
    const ws = fs.createWriteStream(EVENTS, append ? { flags:"a" } : {}); // append -> add to case
    let total = append ? (prev.count||0) : 0;
    let tsMin = append ? (prev.tsMin||null) : null, tsMax = append ? (prev.tsMax||null) : null;
    const sources = append ? (prev.sources||[]).slice() : [];
    for(const f of req.files){
      const label=f.originalname; let c=0, sMin=null, sMax=null;
      const onMeta=(ts)=>{ total++; c++;
        if(ts){ if(tsMin===null||ts<tsMin)tsMin=ts; if(tsMax===null||ts>tsMax)tsMax=ts;
          if(sMin===null||ts<sMin)sMin=ts; if(sMax===null||ts>sMax)sMax=ts; } };
      try{ await streamParseToFile(f.path, f.originalname, ws, onMeta, label, cat); }
      finally{ try{ fs.unlinkSync(f.path); }catch{} }
      sources.push({ name:label, type:(cat==="firewall"?"Firewall":cat==="vpn"?"VPN":logType(label)), count:c, tsMin:sMin, tsMax:sMax, cat:cat||undefined });
    }
    await new Promise(r=>ws.end(r));
    const caseId = append ? (prev.caseId || ("c"+Date.now().toString(36)+Math.random().toString(36).slice(2,8)))
                          : ("c"+Date.now().toString(36)+Math.random().toString(36).slice(2,8));
    const meta={ caseId, count:total, tsMin, tsMax, sources, files:sources.map(s=>s.name), uploadedAt:new Date().toISOString() };
    fs.writeFileSync(META, JSON.stringify(meta));
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
app.post("/api/detect", async (req,res)=>{
  try{
    const rows=await eventRecords(DETECT_CAP);
    if(!rows.length) return res.status(400).json({error:"no log loaded"});
    const meta=readMeta()||{};
    const truncated = meta.count && meta.count>rows.length;
    const sig=loadSigmaRules(), yar=loadYaraRules();
    const byIdx=new Map();
    const add=(i,h)=>{ let a=byIdx.get(i); if(!a){a=[];byIdx.set(i,a);} if(!a.some(x=>x.ruleId===h.ruleId&&x.source===h.source))a.push(h); };
    for(const h of Engine.runHeuristics(rows)) add(h.idx,{ruleId:h.ruleId,title:h.title,level:h.level,source:"heuristic",why:h.why});
    if(sig.rules.length||yar.rules.length){ const index=Engine.buildIndex(sig.rules);
      const m=Engine.runRules(rows,sig.rules,yar.rules,{index}); for(const [i,hits] of m)for(const h of hits)add(i,h); }
    // build self-contained timeline + aggregations so the UI renders the full picture (not just the loaded grid window)
    const SEV={critical:4,high:3,medium:2,low:1,informational:0,info:0};
    const sevn=l=>{const n=SEV[String(l||"").toLowerCase()];return n==null?2:n;};
    const obj={}; let total=0; const timeline=[]; const byRule=new Map(); const byComp=new Map();
    const bySev={critical:0,high:0,medium:0,low:0,info:0}; const bySrc={sigma:0,yara:0,heuristic:0};
    for(const [i,a] of byIdx){ obj[i]=a; total+=a.length; const r=rows[i];
      byComp.set(r.computer||"(none)",(byComp.get(r.computer||"(none)")||0)+1);
      for(const h of a){ const key=h.source+"|"+(h.ruleId||h.title);
        let g=byRule.get(key); if(!g){g={ruleId:h.ruleId||h.title,title:h.title||h.ruleId,source:h.source,level:h.level,count:0};byRule.set(key,g);}
        g.count++; if(sevn(h.level)>sevn(g.level))g.level=h.level;
        bySev[String(h.level).toLowerCase()]=(bySev[String(h.level).toLowerCase()]||0)+1; bySrc[h.source]=(bySrc[h.source]||0)+1;
        if(timeline.length<TIMELINE_CAP) timeline.push({idx:i,ts:r.ts,tms:r.tms,computer:r.computer,channel:r.channel||r.provider,eid:r.eventId,level:h.level,title:h.title||h.ruleId,source:h.source});
      } }
    timeline.sort((a,b)=>(b.tms||0)-(a.tms||0));
    const out={ hits:obj,
      timeline,
      byRule:[...byRule.values()].sort((a,b)=>sevn(b.level)-sevn(a.level)||b.count-a.count),
      byComputer:[...byComp.entries()].sort((a,b)=>b[1]-a[1]).slice(0,20).map(([c,n])=>({computer:c,count:n})),
      bySev, bySrc,
      summary:{ events:rows.length, scanned:rows.length, fullCount:meta.count||rows.length, truncated:!!truncated,
        withDetections:byIdx.size, total, sigma:sig.rules.length, yara:yar.rules.length, skipped:sig.skipped } };
    fs.writeFileSync(DETS, JSON.stringify(out));
    res.json({ ok:true, ...out });
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

app.get("/api/detections", (req,res)=>{
  if(!fs.existsSync(DETS)) return res.json({ ok:true, hits:{}, summary:null });
  res.type("application/json"); fs.createReadStream(DETS).pipe(res);
});

// full-log dashboard aggregates (so big windowed cases still get an overview of the WHOLE log)
app.get("/api/dashboard", (req,res)=>{
  if(!fs.existsSync(EVENTS)) return res.json({ ok:true, total:0 });
  const provs=new Map(), comps=new Map(), users=new Map(), eids=new Map(), hours=new Map();
  let total=0, fail=0, susp=0, tMin=null, tMax=null;
  const bump=(m,k)=>{ if(k!=null&&k!=="") m.set(k,(m.get(k)||0)+1); };
  const SUSP=new Set(["4625","4720","4728","4732","4756","4724","1102","104","7045","4698","4697","1116","1117"]);
  const rl=readline.createInterface({ input: fs.createReadStream(EVENTS,{encoding:"utf8"}), crlfDelay:Infinity });
  rl.on("line", l=>{ if(!l) return; let ev; try{ ev=JSON.parse(l); }catch{ return; }
    if(ev._cat==="firewall"||ev._cat==="vpn") return;            // those have their own sections
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
  rl.on("close", ()=>{
    const top=(m,n)=>[...m.entries()].sort((a,b)=>b[1]-a[1]).slice(0,n);
    res.json({ ok:true, total, fail, susp, tsMin:tMin, tsMax:tMax,
      providers: top(provs,15), computers: top(comps,12), users: top(users,12),
      eids: top(eids,30), hours: [...hours.entries()].sort() });
  });
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

app.post("/api/search", async (req,res)=>{
  try{
    if(!fs.existsSync(EVENTS)) return res.json({ ok:true, total:0, ids:[], levels:[] });
    const b=req.body||{};
    const q=String(b.q||"").toLowerCase();
    const eid=(b.eid!=null&&b.eid!=="")?String(b.eid):"";
    const src=b.src||null, provider=b.provider||null;   // provider = include-only
    const excluded=new Set(Array.isArray(b.excluded)?b.excluded:[]);
    const detOnly=!!b.det, ruleId=b.ruleId||"", flaggedOnly=!!b.flagged;
    const tr=(b.timeRange&&isFinite(b.timeRange.from)&&isFinite(b.timeRange.to))?b.timeRange:null;
    const sortKey=(b.sort&&b.sort.key)||"ts", sortDir=(b.sort&&b.sort.dir===-1)?-1:1;

    let hits={}; try{ hits=JSON.parse(fs.readFileSync(DETS,"utf8")).hits||{}; }catch{ hits={}; }
    let flags=null; if(flaggedOnly){ try{ flags=new Set(JSON.parse(fs.readFileSync(FLAGS,"utf8"))); }catch{ flags=new Set(); } }

    const matched=[];
    const rl=readline.createInterface({ input: fs.createReadStream(EVENTS,{encoding:"utf8"}), crlfDelay:Infinity });
    let i=-1;
    for await (const ln of rl){ i++; if(!ln) continue; let ev; try{ ev=JSON.parse(ln); }catch{ continue; }
      if(ev._cat==="firewall"||ev._cat==="vpn") continue;
      const sys=(ev.Event&&ev.Event.System)||ev.System||{};
      const prov=getProvider(ev);
      if(provider){ if(prov!==provider) continue; } else if(excluded.has(prov)) continue;
      const eidv=String(getEventId(sys)||"");
      if(eid && eidv!==eid) continue;
      const srcv=ev._src||ev._source||"";
      if(src && srcv!==src) continue;
      if(flaggedOnly && !flags.has(i)) continue;
      const hit=hits[i];
      if(detOnly && !(hit&&hit.length)) continue;
      if(ruleId && !(hit&&hit.some(h=>h.ruleId===ruleId))) continue;
      const ts=getTime(ev); const tms=ts?Date.parse(ts):NaN;
      if(tr){ if(!(tms>=tr.from&&tms<tr.to)) continue; }
      if(q){ const comp=getComputer(ev), data=getData(ev);
        let s=prov+" "+eidv+" "+comp+" "+srcv;
        for(const k in data){ const v=data[k]; s+=" "+(v==null?"":(typeof v==="object"?JSON.stringify(v):v)); }
        if(s.toLowerCase().indexOf(q)===-1) continue; }
      let lvl=-1; if(hit&&hit.length){ for(const h of hit){ const n=sevNumS(h.level); if(n>lvl)lvl=n; } }
      let sv; switch(sortKey){
        case "eventId": sv=Number(eidv); if(Number.isNaN(sv))sv=eidv; break;
        case "provider": sv=prov; break;
        case "computer": sv=getComputer(ev); break;
        case "det": sv=lvl; break;
        default: sv=ts||""; }
      matched.push({ i, sv, lvl });
    }
    matched.sort((a,c)=>{ let x=a.sv,y=c.sv; const nx=+x,ny=+y;
      if(x!==""&&y!==""&&!Number.isNaN(nx)&&!Number.isNaN(ny)) return (nx-ny)*sortDir;
      x=x==null?"":String(x); y=y==null?"":String(y); return x<y?-sortDir:x>y?sortDir:0; });
    const ids=new Array(matched.length), levels=new Array(matched.length);
    for(let k=0;k<matched.length;k++){ ids[k]=matched[k].i; levels[k]=matched[k].lvl; }
    res.json({ ok:true, total:ids.length, ids, levels });
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
    const rl=readline.createInterface({ input: fs.createReadStream(EVENTS,{encoding:"utf8"}), crlfDelay:Infinity });
    let i=-1;
    for await (const ln of rl){ i++; if(!ln) continue; let ev; try{ ev=JSON.parse(ln); }catch{ continue; }
      if(ev._cat!==cat) continue; total++;
      if(out.length<CAP){ const data=getData(ev);
        out.push({ i, ts:getTime(ev), src:ev._src||ev._source||"", msg:(data&&data.Message)||svSummary(data) }); }
    }
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
      ips:new Map(), users:new Set(), hosts:new Set(), hashes:new Set(), domains:new Set() };
    const push=(a,x)=>{ if(a.length<AR)a.push(x); };
    const isSys=p=>/sysmon/i.test(p||"");
    const rl=readline.createInterface({ input: fs.createReadStream(EVENTS,{encoding:"utf8"}), crlfDelay:Infinity });
    let i=-1;
    for await (const ln of rl){ i++; if(!ln) continue; let ev; try{ ev=JSON.parse(ln); }catch{ continue; }
      const sys=(ev.Event&&ev.Event.System)||ev.System||{};
      const provider=getProvider(ev), computer=getComputer(ev), ts=getTime(ev), d=getData(ev)||{};
      const id=String(getEventId(sys)||"");
      const U=k=>d[k]!=null?String(d[k]):"";
      if(computer)E.hosts.add(computer);
      switch(id){
        case "4720": { const u=U("TargetUserName"); push(E.accountsCreated,{i,user:u,by:U("SubjectUserName"),ts}); if(u)E.users.add(u); break; }
        case "4722": case "4725": case "4726": case "4738":
          push(E.acctState,{i,user:U("TargetUserName"),act:{"4722":"enabled","4725":"disabled","4726":"deleted","4738":"changed"}[id],ts}); break;
        case "4723": case "4724": push(E.pwResets,{i,user:U("TargetUserName"),act:id==="4724"?"reset by admin":"changed",by:U("SubjectUserName"),ts}); break;
        case "4728": case "4732": case "4756":
          push(E.groupAdds,{i,member:U("MemberName")||U("MemberSid"),group:U("TargetUserName")||U("GroupName"),by:U("SubjectUserName"),ts}); break;
        case "4672": { const u=U("SubjectUserName"); if(u&&!/\$$/.test(u))E.specialPriv.set(u,(E.specialPriv.get(u)||0)+1); break; }
        case "4624": { const ip=U("IpAddress"), lt=U("LogonType"), u=U("TargetUserName");
          if(u)E.users.add(u);
          if(lt==="10"||isExtIp(ip)){ const key=u+"|"+ip+"|"+lt; const e=E.extLogons.get(key)||{i,user:u,ip,lt,count:0}; e.count++; e.i=i; E.extLogons.set(key,e); }
          if(isExtIp(ip))E.ips.set(ip,(E.ips.get(ip)||0)+1); break; }
        case "4625": { const ip=U("IpAddress")||"(none)"; const e=E.failedBySrc.get(ip)||{i,ip,users:new Set(),count:0}; e.count++; e.i=i; if(U("TargetUserName"))e.users.add(U("TargetUserName")); E.failedBySrc.set(ip,e); if(isExtIp(ip))E.ips.set(ip,(E.ips.get(ip)||0)+1); break; }
        case "4648": push(E.explicitCreds,{i,subj:U("SubjectUserName"),target:U("TargetUserName"),server:U("TargetServerName")||U("TargetInfo"),ip:U("IpAddress"),ts}); break;
        case "4688": { const cmd=U("CommandLine")||U("NewProcessName"); if(cmd)push(E.procs,{i,cmd,parent:U("ParentProcessName"),user:U("SubjectUserName"),ts}); break; }
        case "1": if(isSys(provider)){ const cmd=U("CommandLine")||U("Image"); if(cmd)push(E.procs,{i,cmd,parent:U("ParentImage"),user:U("User"),ts});
          const h=U("Hashes"); if(h)h.split(",").forEach(x=>{x=x.trim();if(x)E.hashes.add(x);}); } break;
        case "4104": { const sb=U("ScriptBlockText"); if(sb&&sb.length>3)push(E.psBlocks,{i,text:sb,ts}); break; }
        case "7045": push(E.services,{i,name:U("ServiceName"),path:U("ImagePath"),start:U("StartType"),ts}); break;
        case "4697": push(E.services,{i,name:U("ServiceName"),path:U("ServiceFileName"),ts}); break;
        case "4698": case "4702": case "4699": case "4700": case "4701":
          push(E.tasks,{i,name:U("TaskName"),act:{"4698":"created","4699":"deleted","4700":"enabled","4701":"disabled","4702":"updated"}[id],ts}); break;
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
        case "10": if(isSys(provider)){ const tgt=U("TargetImage"), ga=U("GrantedAccess");
          if(/lsass\.exe/i.test(tgt)) push(E.lsassAccess,{i,src:U("SourceImage"),ga,user:U("SourceUser")||U("User"),ts}); } break;
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
    }
    res.type("application/json").send(JSON.stringify({ ok:true, evidence:E }, mapSetReplacer));
  }catch(err){ console.error(err); res.status(500).json({error:String(err.message||err)}); }
});

// flagged events (★) — persisted so they survive a refresh; indices align with the stored log
app.get("/api/flags", (req,res)=>{ let a=[]; try{ a=JSON.parse(fs.readFileSync(FLAGS,"utf8")); }catch{} res.json({ ok:true, indices:a }); });
app.post("/api/flags", (req,res)=>{
  const a=Array.isArray(req.body&&req.body.indices)?req.body.indices.filter(n=>Number.isInteger(n)&&n>=0):[];
  try{ fs.writeFileSync(FLAGS, JSON.stringify(a)); }catch(e){ return res.status(500).json({error:String(e.message||e)}); }
  res.json({ ok:true, count:a.length });
});

// "Remove Current Log" — wipe the log + detections + flags, keep saved rules
app.post("/api/reset", (req,res)=>{
  for(const f of [EVENTS,META,DETS,FLAGS]){ try{ fs.unlinkSync(f); }catch{} }
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
  const major = parseInt(process.versions.node.split(".")[0], 10);
  if (major < 14) {
    console.error(`\n  Node ${process.versions.node} is too old. EVTX Triage needs Node 14.18+ (18 LTS recommended).`);
    console.error("  Install a newer Node, e.g.:  nvm install 20   (or)   https://nodejs.org/\n");
    process.exit(1);
  }
  app.listen(PORT, ()=> console.log(`EVTX Triage server on http://localhost:${PORT}  (data: ${DATA})`));
}

export { app, DATA };
