// EVTX Triage — SQLite store (Phase 1)
// A pure-JS persistence layer built on Node's built-in `node:sqlite` (no native
// dependency, so the Alpine/Docker image stays build-free). Two roles:
//   1. Catalog  (data/catalog.db)  — the list of cases + SHA-256 chain of custody.
//   2. CaseIndex (cases/<id>/index.db) — a disk-backed event index + FTS5 so search
//      and pagination scale past RAM instead of holding the whole log in memory.
//
// events.jsonl stays the raw-body store (random-access via events.idx); this layer
// only indexes event *metadata* + a bounded fulltext blob, keyed by the global event
// index `i` (line number) so ids line up with detections/flags/fetch-on-scroll.
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";

// FTS body cap — bounds index.db size on huge cases (mirrors the old in-memory FT_CAP)
const BODY_CAP = 1000;

function tune(db){
  db.exec("PRAGMA journal_mode=WAL");
  db.exec("PRAGMA synchronous=NORMAL");
  db.exec("PRAGMA temp_store=MEMORY");
}

/* ============================ CATALOG ============================ */
export class Catalog {
  constructor(dataDir){
    this.path = path.join(dataDir, "catalog.db");
    this.db = new DatabaseSync(this.path);
    tune(this.db);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS cases(
        id TEXT PRIMARY KEY,
        name TEXT,
        createdAt TEXT,
        count INTEGER DEFAULT 0,
        tsMin TEXT, tsMax TEXT
      );
      CREATE TABLE IF NOT EXISTS custody(
        caseId TEXT, name TEXT, sha256 TEXT, bytes INTEGER,
        type TEXT, count INTEGER, ingestedAt TEXT
      );
      CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
    `);
  }
  getActive(){ const r=this.db.prepare("SELECT v FROM kv WHERE k='active'").get(); return r?r.v:null; }
  setActive(id){ this.db.prepare("INSERT INTO kv(k,v) VALUES('active',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").run(id); }
  upsertCase(c){
    this.db.prepare(`INSERT INTO cases(id,name,createdAt,count,tsMin,tsMax)
      VALUES(@id,@name,@createdAt,@count,@tsMin,@tsMax)
      ON CONFLICT(id) DO UPDATE SET name=excluded.name, count=excluded.count,
        tsMin=excluded.tsMin, tsMax=excluded.tsMax`).run({
      id:c.id, name:c.name||null, createdAt:c.createdAt||new Date().toISOString(),
      count:c.count||0, tsMin:c.tsMin||null, tsMax:c.tsMax||null });
  }
  getCase(id){ return this.db.prepare("SELECT * FROM cases WHERE id=?").get(id) || null; }
  listCases(){ return this.db.prepare("SELECT * FROM cases ORDER BY createdAt DESC").all(); }
  deleteCase(id){
    this.db.prepare("DELETE FROM cases WHERE id=?").run(id);
    this.db.prepare("DELETE FROM custody WHERE caseId=?").run(id);
    if(this.getActive()===id) this.db.prepare("DELETE FROM kv WHERE k='active'").run();
  }
  addCustody(caseId, rec){
    this.db.prepare(`INSERT INTO custody(caseId,name,sha256,bytes,type,count,ingestedAt)
      VALUES(?,?,?,?,?,?,?)`).run(caseId, rec.name, rec.sha256||null, rec.bytes||0,
      rec.type||null, rec.count||0, rec.ingestedAt||new Date().toISOString());
  }
  getCustody(caseId){ return this.db.prepare("SELECT name,sha256,bytes,type,count,ingestedAt FROM custody WHERE caseId=? ORDER BY rowid").all(caseId); }
  clearCustody(caseId){ this.db.prepare("DELETE FROM custody WHERE caseId=?").run(caseId); }
  close(){ try{ this.db.close(); }catch{} }
}

/* ============================ CASE INDEX ============================ */
export class CaseIndex {
  constructor(dbPath){
    this.path = dbPath;
    this.db = new DatabaseSync(dbPath);
    tune(this.db);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS events(
        idx INTEGER PRIMARY KEY,
        ts TEXT, tms INTEGER,
        provider TEXT, eid TEXT, computer TEXT, channel TEXT, src TEXT, cat TEXT
      );
      CREATE INDEX IF NOT EXISTS ix_eid  ON events(eid);
      CREATE INDEX IF NOT EXISTS ix_prov ON events(provider);
      CREATE INDEX IF NOT EXISTS ix_src  ON events(src);
      CREATE INDEX IF NOT EXISTS ix_tms  ON events(tms);
      CREATE INDEX IF NOT EXISTS ix_comp ON events(computer);
      CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(body);
      CREATE TABLE IF NOT EXISTS idxmeta(k TEXT PRIMARY KEY, v);
      CREATE TABLE IF NOT EXISTS det(idx INTEGER PRIMARY KEY, lvl INTEGER);
      CREATE TABLE IF NOT EXISTS det_rule(idx INTEGER, ruleId TEXT);
      CREATE TABLE IF NOT EXISTS det_tech(idx INTEGER, tech TEXT);
      CREATE INDEX IF NOT EXISTS ix_dr ON det_rule(ruleId, idx);
      CREATE INDEX IF NOT EXISTS ix_dt ON det_tech(tech, idx);
      CREATE TABLE IF NOT EXISTS flags(idx INTEGER PRIMARY KEY);
    `);
    this._insEv  = this.db.prepare("INSERT OR REPLACE INTO events(idx,ts,tms,provider,eid,computer,channel,src,cat) VALUES(?,?,?,?,?,?,?,?,?)");
    this._insFts = this.db.prepare("INSERT INTO events_fts(rowid,body) VALUES(?,?)");
  }
  _meta(k){ const r=this.db.prepare("SELECT v FROM idxmeta WHERE k=?").get(k); return r?r.v:null; }
  _setMeta(k,v){ this.db.prepare("INSERT INTO idxmeta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").run(k,String(v)); }

  indexedBytes(){ return parseInt(this._meta("indexedBytes")||"0",10); }
  indexedCount(){ return parseInt(this._meta("indexedCount")||"0",10); }

  // Full reset of the event index (kept det/flags cleared too — a new/empty log).
  resetEvents(){
    this.db.exec("DELETE FROM events; DELETE FROM events_fts; DELETE FROM det; DELETE FROM det_rule; DELETE FROM det_tech; DELETE FROM flags;");
    this._setMeta("indexedBytes",0); this._setMeta("indexedCount",0);
    this._setMeta("detSig",""); this._setMeta("flagSig","");
  }

  // Bulk-load a batch of rows in one transaction. rows: {idx,ts,tms,provider,eid,computer,channel,src,cat,body}
  ingest(rows, afterBytes, afterCount){
    this.db.exec("BEGIN");
    try{
      for(const r of rows){
        this._insEv.run(r.idx, r.ts||null, Number.isFinite(r.tms)?r.tms:null,
          r.provider||"", r.eid||"", r.computer||"", r.channel||"", r.src||"", r.cat||"");
        this._insFts.run(r.idx, (r.body||"").slice(0,BODY_CAP));
      }
      this._setMeta("indexedBytes", afterBytes);
      this._setMeta("indexedCount", afterCount);
      this.db.exec("COMMIT");
    }catch(e){ this.db.exec("ROLLBACK"); throw e; }
  }

  /* ---- detection / flag sync (kept in the DB so search filters + pagination are one SQL query) ---- */
  detSig(){ return this._meta("detSig")||""; }
  flagSig(){ return this._meta("flagSig")||""; }
  // hits: { idx: [ {ruleId,title,level,tags?}, ... ] }  ; sevNum: level->0..4
  syncDetections(hits, sevNum, techFromTag, sig){
    this.db.exec("BEGIN");
    try{
      this.db.exec("DELETE FROM det; DELETE FROM det_rule; DELETE FROM det_tech;");
      const insD=this.db.prepare("INSERT OR REPLACE INTO det(idx,lvl) VALUES(?,?)");
      const insR=this.db.prepare("INSERT INTO det_rule(idx,ruleId) VALUES(?,?)");
      const insT=this.db.prepare("INSERT INTO det_tech(idx,tech) VALUES(?,?)");
      for(const k in hits){ const i=+k; const arr=hits[k]; if(!arr||!arr.length) continue;
        let mx=-1; const rules=new Set(), techs=new Set();
        for(const h of arr){ const n=sevNum(h.level); if(n>mx)mx=n;
          if(h.ruleId||h.title) rules.add(h.ruleId||h.title);
          for(const tg of (h.tags||[])){ const t=techFromTag(tg); if(t)techs.add(t); } }
        insD.run(i,mx);
        for(const r of rules) insR.run(i,r);
        for(const t of techs) insT.run(i,t);
      }
      this._setMeta("detSig", sig);
      this.db.exec("COMMIT");
    }catch(e){ this.db.exec("ROLLBACK"); throw e; }
  }
  syncFlags(indices, sig){
    this.db.exec("BEGIN");
    try{
      this.db.exec("DELETE FROM flags;");
      const ins=this.db.prepare("INSERT OR REPLACE INTO flags(idx) VALUES(?)");
      for(const i of indices) if(Number.isInteger(i)&&i>=0) ins.run(i);
      this._setMeta("flagSig", sig);
      this.db.exec("COMMIT");
    }catch(e){ this.db.exec("ROLLBACK"); throw e; }
  }

  /* ---- search: structured filters + FTS/substring free-text, sorted + paginated ---- */
  // f: { q, eid, provider, src, excluded[], detOnly, ruleId, technique, flagged, timeRange:{from,to} }
  // opt: { sortKey, sortDir(1|-1), limit, offset }
  search(f, opt){
    f=f||{}; opt=opt||{};
    const where=[]; const params=[];
    // firewall/vpn live in their own sections — excluded from the main grid (mirrors old behavior)
    where.push("(e.cat IS NULL OR e.cat='' OR (e.cat<>'firewall' AND e.cat<>'vpn'))");
    let ftsJoin="";
    const q=String(f.q||"").trim();
    if(q){
      if(/^[\p{L}\p{N} ]+$/u.test(q)){
        // token/prefix search via FTS5 — scales to millions of rows
        const expr=q.split(/\s+/).filter(Boolean).map(t=>`"${t.replace(/"/g,'""')}"*`).join(" AND ");
        ftsJoin=" JOIN events_fts fts ON fts.rowid=e.idx AND events_fts MATCH ?";
        params.unshift(expr);   // FTS param binds before the WHERE params -> handled below
      } else {
        // punctuated query (IP / path / hash frag) -> faithful substring via LIKE
        where.push("EXISTS(SELECT 1 FROM events_fts fx WHERE fx.rowid=e.idx AND fx.body LIKE ?)");
        params.push("%"+q.toLowerCase().replace(/[%_\\]/g,"\\$&")+"%"); // escaped LIKE
      }
    }
    if(f.provider!=null){ where.push("e.provider=?"); params.push(String(f.provider)); }
    else if(Array.isArray(f.excluded)&&f.excluded.length){
      where.push("e.provider NOT IN ("+f.excluded.map(()=>"?").join(",")+")"); params.push(...f.excluded.map(String));
    }
    if(f.eid!=null&&f.eid!==""){ where.push("e.eid=?"); params.push(String(f.eid)); }
    if(f.src!=null){ where.push("e.src=?"); params.push(String(f.src)); }
    if(f.flagged){ where.push("EXISTS(SELECT 1 FROM flags fl WHERE fl.idx=e.idx)"); }
    if(f.detOnly){ where.push("EXISTS(SELECT 1 FROM det d0 WHERE d0.idx=e.idx)"); }
    if(f.ruleId){ where.push("EXISTS(SELECT 1 FROM det_rule dr WHERE dr.idx=e.idx AND dr.ruleId=?)"); params.push(String(f.ruleId)); }
    if(f.technique){ where.push("EXISTS(SELECT 1 FROM det_tech dt WHERE dt.idx=e.idx AND dt.tech=?)"); params.push(String(f.technique)); }
    const tr=f.timeRange;
    if(tr&&isFinite(tr.from)&&isFinite(tr.to)){ where.push("e.tms>=? AND e.tms<?"); params.push(tr.from,tr.to); }

    // LIKE escape needs an ESCAPE clause
    let whereSql=where.join(" AND ");
    if(q && !/^[\p{L}\p{N} ]+$/u.test(q)) whereSql=whereSql.replace("fx.body LIKE ?","fx.body LIKE ? ESCAPE '\\'");

    // handle the FTS param ordering: if FTS join is used, its param must bind first
    let sqlParams=params;
    if(ftsJoin){ /* params.unshift already put FTS expr first */ }

    const sortKey=opt.sortKey||"ts", dir=(opt.sortDir===-1)?"DESC":"ASC";
    let orderCol;
    switch(sortKey){
      case "eventId": orderCol=`(CASE WHEN e.eid GLOB '[0-9]*' THEN CAST(e.eid AS INTEGER) ELSE 9223372036854775807 END) ${dir}, e.eid ${dir}`; break;
      case "provider": orderCol=`e.provider ${dir}`; break;
      case "computer": orderCol=`e.computer ${dir}`; break;
      case "det": orderCol=`IFNULL((SELECT lvl FROM det d1 WHERE d1.idx=e.idx),-1) ${dir}`; break;
      default: orderCol=`e.ts ${dir}`;
    }
    const base=`FROM events e${ftsJoin} WHERE ${whereSql}`;
    const total=this.db.prepare(`SELECT COUNT(*) c ${base}`).get(...sqlParams).c;

    let lim="", limParams=[];
    const limit=parseInt(opt.limit||0,10)||0, offset=Math.max(0,parseInt(opt.offset||0,10)||0);
    if(limit>0){ lim=" LIMIT ? OFFSET ?"; limParams=[limit,offset]; }
    const rows=this.db.prepare(
      `SELECT e.idx AS idx, IFNULL((SELECT lvl FROM det d2 WHERE d2.idx=e.idx),-1) AS lvl
       ${base} ORDER BY ${orderCol}, e.idx ASC${lim}`).all(...sqlParams, ...limParams);
    const ids=new Array(rows.length), levels=new Array(rows.length);
    for(let k=0;k<rows.length;k++){ ids[k]=rows[k].idx; levels[k]=rows[k].lvl; }
    return { total, ids, levels };
  }

  count(){ return this.db.prepare("SELECT COUNT(*) c FROM events").get().c; }
  close(){ try{ this.db.close(); }catch{} }
}

export { BODY_CAP };
