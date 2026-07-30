/* ============================================================================
   Vigil DFIR — Detection Engine
   Self-contained. Works in browser (inlined) and Node (module.exports at end).
   Three layers:
     1. Heuristics  — behavioral, always-on, no rules required
     2. Sigma       — common detection subset + Windows field mapping
     3. YARA-lite   — string/regex/hex matching over each record's raw text
   Designed for recall + clarity over spec-completeness; unsupported constructs
   are skipped explicitly (never silently mis-evaluated).
   ========================================================================== */
(function (root) {
"use strict";

function isObj(v){ return v && typeof v === "object" && !Array.isArray(v); }
function asArray(v){ return Array.isArray(v) ? v : [v]; }
function lc(s){ return String(s).toLowerCase(); }

// glob (Sigma wildcard) -> RegExp. * any, ? single, \* literal.
function globToRe(pat, flags){
  let out = "";
  for (let i = 0; i < pat.length; i++){
    const c = pat[i];
    if (c === "\\"){
      const n = pat[i+1];
      if (n === "*" || n === "?" || n === "\\"){ out += n.replace(/[.*+?^${}()|[\]\\]/g,"\\$&"); i++; continue; }
      out += "\\\\"; continue;
    }
    if (c === "*"){ out += ".*"; continue; }
    if (c === "?"){ out += "."; continue; }
    out += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp("^" + out + "$", flags);
}
function hasGlob(s){ return /(?:^|[^\\])[*?]/.test(s) || /^[*?]/.test(s); }
function b64(s){ try { return (typeof Buffer!=="undefined") ? Buffer.from(s,"utf8").toString("base64") : btoa(unescape(encodeURIComponent(s))); } catch(_) { return ""; } }
function base64OffsetVariants(s){
  const out = new Set();
  const seed = ["","X","XX"];      // 0,1,2 byte prefix
  const drop = [0,2,3];            // chars that encode the prefix
  for (let i=0;i<3;i++){
    let e = b64(seed[i]+s).slice(drop[i]).replace(/=+$/,"");
    if (e) out.add(e);
  }
  return [...out];
}

/* ----------------- FIELD RESOLUTION ----------------------------------------
   record shape from host app:
     { ts, tms, provider, eventId, computer, channel, data:{...}, raw }     */
const FIELD_SYNONYMS = {
  "eventid":["EventID","eventId"],
  "computername":["Computer","computer"],
  "image":["Image","NewProcessName","ProcessName","Application"],
  "parentimage":["ParentImage","ParentProcessName"],
  "commandline":["CommandLine","ProcessCommandLine"],
  "parentcommandline":["ParentCommandLine"],
  "originalfilename":["OriginalFileName"],
  "targetfilename":["TargetFilename","TargetFileName"],
  "user":["User","SubjectUserName","TargetUserName","AccountName"],
  "targetusername":["TargetUserName"],
  "subjectusername":["SubjectUserName"],
  "ipaddress":["IpAddress","SourceIp","DestinationIp"],
  "destinationip":["DestinationIp","DestAddress"],
  "sourceip":["SourceIp","SourceAddress","IpAddress"],
  "logontype":["LogonType"],
  "servicename":["ServiceName","param1"],
  "service_file_name":["ServiceFileName","ImagePath"],
  "imageloaded":["ImageLoaded"],
  "scriptblocktext":["ScriptBlockText"],
  "queryname":["QueryName"],
  "pipename":["PipeName"],
  "targetobject":["TargetObject"],
  "details":["Details"],
  "provider_name":["provider"],
  "channel":["channel","Channel"],
  "hashes":["Hashes"]
};
function sysGet(rec, key){
  switch(lc(key)){
    case "eventid": return rec.eventId;
    case "computer": case "computername": return rec.computer;
    case "provider": case "provider_name": return rec.provider;
    case "channel": return rec.channel || "";
  }
  return undefined;
}
function resolveField(rec, field){
  const d = rec.data || {};
  if (field in d) return d[field];
  const sv = sysGet(rec, field);
  if (sv !== undefined) return sv;
  const lf = lc(field);
  for (const k in d) if (lc(k) === lf) return d[k];
  const syn = FIELD_SYNONYMS[lf];
  if (syn){
    for (const cand of syn){
      if (cand in d) return d[cand];
      const csv = sysGet(rec, cand);
      if (csv !== undefined) return csv;
      for (const k in d) if (lc(k) === lc(cand)) return d[k];
    }
  }
  return undefined;
}

/* ----------------- SIGMA ENGINE -------------------------------------------- */
function compileFieldMatcher(rawKey, rawVal){
  const parts = rawKey.split("|");
  const mods = parts.slice(1).map(lc);
  let values = (rawVal === null) ? [null] : asArray(rawVal);
  const flagAll = mods.includes("all");
  const cased = mods.includes("cased");
  const reFlags = cased ? "" : "i";

  if (mods.includes("base64offset")){
    let nv=[]; for (const v of values) nv=nv.concat(base64OffsetVariants(String(v))); 
    return makeContains(nv, reFlags, flagAll);
  }
  if (mods.includes("base64")){
    return makeContains(values.map(v=>b64(String(v))), reFlags, flagAll);
  }
  if (mods.includes("re")){
    const res = values.map(v=>{ try{return new RegExp(String(v),reFlags);}catch(_){return null;} });
    return (val)=>{ if(val==null)return false; const s=String(val); const t=r=>r&&r.test(s);
      return flagAll?res.every(t):res.some(t); };
  }
  if (mods.includes("cidr")){
    const nets = values.map(parseCidr).filter(Boolean);
    return (val)=>{ if(val==null)return false; const ipn=ipToInt(String(val)); if(ipn==null)return false;
      const t=n=>(ipn&n.mask)===(n.net&n.mask); return flagAll?nets.every(t):nets.some(t); };
  }
  for (const op of ["gt","gte","lt","lte"]){
    if (mods.includes(op)){
      const nums=values.map(Number);
      return (val)=>{ const n=Number(val); if(Number.isNaN(n))return false;
        const t=x=>op==="gt"?n>x:op==="gte"?n>=x:op==="lt"?n<x:n<=x;
        return flagAll?nums.every(t):nums.some(t); };
    }
  }
  if (mods.includes("exists")){
    const want=String(values[0]).toLowerCase()!=="false";
    return (val)=>(val!==undefined&&val!==null)===want;
  }
  const contains=mods.includes("contains"), startswith=mods.includes("startswith"),
        endswith=mods.includes("endswith"), windash=mods.includes("windash");
  const testers = values.map(v=>{
    if (v===null) return (val)=> val===null||val===undefined||val==="";
    let sv=String(v);
    const variants = windash ? dashVariants(sv) : [sv];
    if (contains||startswith||endswith){
      const res = variants.map(s=>{
        const body=s.replace(/[.*+?^${}()|[\]\\]/g,"\\$&").replace(/\\\*/g,".*").replace(/\\\?/g,".");
        const anchored = startswith?"^"+body : endswith?body+"$" : body;
        return new RegExp(anchored, reFlags);
      });
      return (val)=>{ if(val==null)return false; const s=String(val); return res.some(r=>r.test(s)); };
    }
    if (variants.some(hasGlob)){
      const res=variants.map(s=>globToRe(s,reFlags));
      return (val)=>{ if(val==null)return false; const s=String(val); return res.some(r=>r.test(s)); };
    }
    return (val)=>{ if(val==null)return false; return cased?String(val)===sv:lc(val)===lc(sv); };
  });
  return (val)=> flagAll ? testers.every(t=>t(val)) : testers.some(t=>t(val));
}
function makeContains(values, reFlags, flagAll){
  const res=values.filter(Boolean).map(s=>new RegExp(String(s).replace(/[.*+?^${}()|[\]\\]/g,"\\$&"),reFlags));
  return (val)=>{ if(val==null)return false; const s=String(val); return flagAll?res.every(r=>r.test(s)):res.some(r=>r.test(s)); };
}
function dashVariants(s){
  const dashes=["-","/","\u2013","\u2014","\u2015"]; const out=new Set([s]);
  for (const d of dashes) out.add(s.replace(/[-\/\u2013\u2014\u2015]/g,d));
  return [...out];
}
function ipToInt(ip){ const m=/^(\d+)\.(\d+)\.(\d+)\.(\d+)/.exec(String(ip)); if(!m)return null;
  return (((+m[1])<<24)>>>0)+((+m[2])<<16)+((+m[3])<<8)+(+m[4]); }
function parseCidr(c){ const m=/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(String(c)); if(!m)return null;
  const net=ipToInt(m[1]); const bits=+m[2]; const mask=bits===0?0:((~((1<<(32-bits))-1))>>>0); return {net,mask}; }

function compileSelection(sel){
  if (Array.isArray(sel) && sel.every(x=>typeof x!=="object"||x===null)){
    const kw=sel.map(v=>lc(v));
    return { test:(rec)=>{ const hay=lc(rec._fulltext||""); return kw.some(k=>hay.includes(k)); } };
  }
  if (Array.isArray(sel)){
    const subs=sel.map(compileMapSelection);
    return { test:(rec)=>subs.some(s=>s(rec)) };
  }
  if (isObj(sel)) return { test: compileMapSelection(sel) };
  const k=lc(sel);
  return { test:(rec)=>lc(rec._fulltext||"").includes(k) };
}
function compileMapSelection(map){
  const matchers=[];
  for (const key in map){
    const field=key.split("|")[0];
    matchers.push({ field, isKeyword: lc(field)==="keywords", m: compileFieldMatcher(key, map[key]) });
  }
  return (rec)=> matchers.every(({field,isKeyword,m})=>{
    if (isKeyword) return m(rec._fulltext||"");
    const v=resolveField(rec, field);
    if (Array.isArray(v)) return v.some(x=>m(x));
    return m(v);
  });
}

function tokenizeCond(str){
  const re=/\(|\)|\b(?:and|or|not)\b|\ball of them\b|\bany of them\b|\b1 of them\b|\b\d+ of them\b|\ball of\b|\bany of\b|\b\d+ of\b|them|of|[A-Za-z0-9_*]+/gi;
  const toks=[]; let m; while((m=re.exec(str))!==null) toks.push(m[0]); return toks;
}
function compileCondition(condStr, selNames){
  if (/\|\s*count|\bnear\b|\|\s*(sum|avg|min|max)/i.test(condStr)) return { unsupported:true };
  const toks=tokenizeCond(condStr); let pos=0;
  const peek=()=>toks[pos], next=()=>toks[pos++];
  const matchNames=(pat)=>{ if(pat==="them")return selNames.slice();
    if(pat.includes("*")){ const re=globToRe(pat,""); return selNames.filter(n=>re.test(n)); }
    return selNames.includes(pat)?[pat]:[]; };
  function qFromTarget(kind){
    let target;
    if(lc(peek())==="them"){ next(); target=selNames.slice(); }
    else target=matchNames(next());
    const need=kind==="all"?target.length:kind==="any"?1:Math.min(kind,target.length);
    return (rec,ev)=>{ let c=0; for(const n of target){ if(ev(n,rec)){c++; if(c>=need)return true;} } return target.length?c>=need:false; };
  }
  function primary(){
    const t=peek(); if(!t) return ()=>false;
    if(t==="("){ next(); const e=orE(); if(peek()===")")next(); return e; }
    const lt=lc(t); let dm;
    if(lt==="all of them"){ next(); return qFromTargetThem("all"); }
    if(lt==="any of them"){ next(); return qFromTargetThem("any"); }
    if(lt==="1 of them"){ next(); return qFromTargetThem(1); }
    if((dm=/^(\d+) of them$/i.exec(t))){ next(); return qFromTargetThem(+dm[1]); }
    if(lt==="all of"){ next(); return qFromTarget("all"); }
    if(lt==="any of"){ next(); return qFromTarget("any"); }
    if((dm=/^(\d+) of$/i.exec(t))){ next(); return qFromTarget(+dm[1]); }
    if(lt==="all"){ next(); if(lc(peek())==="of")next(); return qFromTarget("all"); }
    if(lt==="any"){ next(); if(lc(peek())==="of")next(); return qFromTarget("any"); }
    if(/^\d+$/.test(t)){ const num=+t; next(); if(lc(peek())==="of")next(); return qFromTarget(num); }
    next(); const names=matchNames(t);
    return (rec,ev)=> names.length?names.some(n=>ev(n,rec)):false;
  }
  function qFromTargetThem(kind){
    const target=selNames.slice();
    const need=kind==="all"?target.length:kind==="any"?1:Math.min(kind,target.length);
    return (rec,ev)=>{ let c=0; for(const n of target){ if(ev(n,rec)){c++; if(c>=need)return true;} } return target.length?c>=need:false; };
  }
  function notE(){ if(lc(peek())==="not"){ next(); const e=notE(); return (r,ev)=>!e(r,ev);} return primary(); }
  function andE(){ let l=notE(); while(lc(peek())==="and"){ next(); const r=notE(); const a=l,b=r; l=(rec,ev)=>a(rec,ev)&&b(rec,ev);} return l; }
  function orE(){ let l=andE(); while(lc(peek())==="or"){ next(); const r=andE(); const a=l,b=r; l=(rec,ev)=>a(rec,ev)||b(rec,ev);} return l; }
  return { fn: orE() };
}

/* ----------------- SIGMA AGGREGATION / CORRELATION ------------------------------
   Sigma v1 pipe-aggregations (e.g. `selection | count() by User > 5`) used to be
   dropped as unsupported. We now compile them into an aggRule: a base matcher (the
   search-expression left of the pipe) plus an aggregate spec, evaluated in a sliding
   `timeframe` window grouped by a field. This lights up brute force / password spray /
   Kerberoasting-style detections that a per-event engine can't express.               */
function parseTimeframeMs(tf){
  if(tf==null) return null;
  const m=/^(\d+)\s*([smhd])$/i.exec(String(tf).trim()); if(!m) return null;
  const mult={s:1000,m:60000,h:3600000,d:86400000}[m[2].toLowerCase()];
  return (+m[1])*mult;
}
// Split "<search> | <func>(<field>?) [by <group>] <op> <n>" into a base expr + agg spec.
function parseAggCondition(condStr){
  const pipe=condStr.lastIndexOf("|");
  if(pipe<0) return { error:"no pipe" };
  const base=condStr.slice(0,pipe).trim();
  const agg=condStr.slice(pipe+1).trim();
  const m=/^(count|sum|min|max|avg)\s*\(\s*([A-Za-z0-9_.\-]*)\s*\)\s*(?:by\s+([A-Za-z0-9_.\-]+)\s*)?(>=|<=|==|=|>|<)\s*(\d+(?:\.\d+)?)$/i.exec(agg);
  if(!m) return { error:"aggregation not recognized" };
  return { base, agg:{ func:m[1].toLowerCase(), field:m[2]||"", groupBy:m[3]||"", op:m[4]==="="?"==":m[4], threshold:parseFloat(m[5]) } };
}
function aggCompare(v,op,t){
  switch(op){ case ">":return v>t; case ">=":return v>=t; case "<":return v<t; case "<=":return v<=t;
    case "==":return v===t; default:return false; }
}
function collectEidHints(det, selNames){
  const set=new Set();
  for (const n of selNames){
    const maps = Array.isArray(det[n]) ? det[n] : [det[n]];
    for (const map of maps){ if(!isObj(map))continue;
      for (const k in map){ if(k.split("|")[0].toLowerCase()==="eventid"){
        for (const v of asArray(map[k])){ const num=Number(v); if(!Number.isNaN(num))set.add(num); } } }
    }
  }
  return set.size?set:null;
}
/* Sigma logsource category -> the Windows EventIDs that carry it. Lets category
   rules (which omit EventID in the detection) be indexed instead of run on every event. */
const CAT_EIDS={
  process_creation:[1,4688], ps_script:[4104], ps_module:[4103],
  ps_classic_start:[400,403,600], ps_classic_provider_start:[600], ps_classic_script:[800],
  image_load:[7], driver_load:[6], file_event:[11], file_delete:[23,26], file_change:[2],
  file_rename:[2], registry_set:[13], registry_add:[12], registry_delete:[12],
  registry_event:[12,13,14], registry_rename:[14], network_connection:[3], dns_query:[22],
  pipe_created:[17,18], create_remote_thread:[8], process_access:[10], raw_access_thread:[9],
  process_tampering:[25], create_stream_hash:[15], sysmon_error:[255], wmi_event:[19,20,21],
  clipboard_capture:[24], process_termination:[5]
};
/* Extract necessary literal substrings so we can skip rules whose tokens are
   absent from an event (Aho-Corasick prescreen). Disabled when a regex modifier
   is present (can't derive a safe literal) so such rules always run. */
function extractLits(det){
  const lits=new Set(); let hasRe=false;
  const add=(v)=>{ if(typeof v!=="string")return; const s=v;
    if(/[*?]/.test(s)){ for(const seg of s.split(/[*?]+/)) if(seg.length>=4) lits.add(seg.toLowerCase()); }
    else if(s.length>=4) lits.add(s.toLowerCase()); };
  const walk=(node)=>{ if(node==null)return;
    if(Array.isArray(node)){ for(const x of node)walk(x); return; }
    if(isObj(node)){ for(const k in node){ if(k==="condition"||k==="timeframe")continue;
      if(/\|re\b/i.test(k)){ hasRe=true; continue; } walk(node[k]); } return; }
    add(node); };
  for(const k in det){ if(k==="condition"||k==="timeframe")continue; walk(det[k]); }
  return { lits:[...lits], hasRe };
}
function compileSigmaRule(doc){
  if (!doc || !doc.detection || !doc.detection.condition) return { error:"missing detection/condition" };
  const det=doc.detection;
  const selNames=Object.keys(det).filter(k=>k!=="condition"&&k!=="timeframe");
  const compiled={};
  for (const n of selNames){ try{ compiled[n]=compileSelection(det[n]); }catch(e){ return {error:"selection '"+n+"': "+e.message}; } }
  const conds=asArray(det.condition);
  const ls0=doc.logsource||{};
  // Pipe-aggregation (count/sum/min/max/avg): compile as a windowed correlation rule.
  if (conds.length===1 && /\|\s*(count|sum|min|max|avg)\s*\(/i.test(String(conds[0]))){
    const parsed=parseAggCondition(String(conds[0]));
    if(parsed.error) return { unsupported:true, reason:"aggregation: "+parsed.error };
    const baseCC=compileCondition(parsed.base, selNames);
    if(baseCC.unsupported) return { unsupported:true, reason:"aggregation base unsupported" };
    return { aggRule:{
      id:doc.id||"", title:doc.title||"(untitled sigma rule)", level:lc(doc.level||"medium"),
      tags:doc.tags||[], description:doc.description||"", source:"sigma",
      product:lc(ls0.product||""), service:lc(ls0.service||""), category:lc(ls0.category||""),
      agg:parsed.agg, timeframeMs:parseTimeframeMs(det.timeframe),
      baseTest(rec){ const ev=(name,r)=>compiled[name]?compiled[name].test(r):false; return baseCC.fn(rec,ev); }
    }};
  }
  const condFns=[];
  for (const c of conds){ const cc=compileCondition(String(c),selNames); if(cc.unsupported) return {unsupported:true,reason:"aggregation/correlation"}; condFns.push(cc.fn); }
  const ls=doc.logsource||{};
  const cat=lc(ls.category||"");
  let eidHints=collectEidHints(det, selNames);
  if(!eidHints && CAT_EIDS[cat]) eidHints=new Set(CAT_EIDS[cat]);
  const { lits, hasRe }=extractLits(det);
  return { rule:{
    id:doc.id||"", title:doc.title||"(untitled sigma rule)", level:lc(doc.level||"medium"),
    tags:doc.tags||[], description:doc.description||"", source:"sigma",
    product:lc(ls.product||""), service:lc(ls.service||""), category:cat,
    eidHints,
    _lits: lits, _prescreen: lits.length>0 && !hasRe,
    test(rec){ const ev=(name,r)=>compiled[name]?compiled[name].test(r):false;
      for (const fn of condFns){ if(fn(rec,ev))return true; } return false; }
  }};
}

/* ----------------- YARA-LITE ENGINE ---------------------------------------- */
function compileYaraRules(text){
  const rules=[], errors=[];
  const re=/\brule\s+([A-Za-z_]\w*)\s*(:\s*[^\{]+)?\{/g;
  const idxs=[]; let m;
  while((m=re.exec(text))!==null) idxs.push({name:m[1], tags:(m[2]||"").replace(/^:/,"").trim(), bodyStart:re.lastIndex});
  for (let i=0;i<idxs.length;i++){
    const body=extractBraces(text, idxs[i].bodyStart-1);
    if (body==null){ errors.push(idxs[i].name+": unbalanced braces"); continue; }
    try{ rules.push(parseYaraRule(idxs[i].name, idxs[i].tags, body)); }
    catch(e){ errors.push(idxs[i].name+": "+e.message); }
  }
  return { rules, errors };
}
function extractBraces(text, openIdx){
  let depth=0;
  for (let i=openIdx;i<text.length;i++){
    const c=text[i];
    if (c==='"'||c==="'"){ i=skipStr(text,i,c); continue; }
    if (c==="{"){ depth++; } else if (c==="}"){ depth--; if(depth===0)return text.slice(openIdx+1,i); }
  }
  return null;
}
function skipStr(text,i,q){ for(let j=i+1;j<text.length;j++){ if(text[j]==="\\"){j++;continue;} if(text[j]===q)return j; } return text.length; }
function parseYaraRule(name, tags, body){
  body=body.replace(/\/\*[\s\S]*?\*\//g,"").replace(/(^|\s)\/\/[^\n]*/g,"$1");
  const strSec=/strings\s*:/.exec(body), condSec=/condition\s*:/.exec(body);
  if (!condSec) throw new Error("no condition");
  const strBlock = strSec ? body.slice(strSec.index+strSec[0].length, condSec.index) : "";
  const condBlock = body.slice(condSec.index+condSec[0].length).trim();
  const strings={};
  const sre=/(\$[A-Za-z0-9_*]+)\s*=\s*/g; const defs=[]; let sm;
  while((sm=sre.exec(strBlock))!==null) defs.push({id:sm[1], start:sm.index, at:sre.lastIndex});
  for (let i=0;i<defs.length;i++){
    // value runs from just after this "$id =" up to the start of the next definition
    const end = i+1<defs.length ? defs[i+1].start : strBlock.length;
    const seg = strBlock.slice(defs[i].at, end).trim();
    strings[defs[i].id] = parseYaraString(seg);
  }
  const cond = compileYaraCondition(condBlock, Object.keys(strings));
  return { name, tags, level: tags&&/high|crit/i.test(tags)?"high":"medium", source:"yara",
    test(rawText){ const counts={}; for(const id in strings) counts[id]=strings[id].count(rawText); return cond(counts); } };
}
function parseYaraString(seg){
  const nocase=/\bnocase\b/.test(seg), wide=/\bwide\b/.test(seg), ascii=/\bascii\b/.test(seg)||!wide;
  let core=seg.replace(/\s+\b(nocase|wide|ascii|fullword|private|xor|base64|base64wide)\b.*$/s,"").trim();
  let re;
  if (core[0]==='"'){
    let lit; try{ lit=JSON.parse(core); }catch(_){ lit=core.slice(1,-1); }
    re=new RegExp(litToRe(lit,wide,ascii), nocase?"gi":"g");
  } else if (core[0]==="/"){
    const lm=/^\/(.*)\/([a-z]*)$/s.exec(core); if(!lm)throw new Error("bad regex string");
    re=new RegExp(lm[1], "g"+((nocase||/i/.test(lm[2]))?"i":"")+(/s/.test(lm[2])?"s":""));
  } else if (core[0]==="{"){
    re=new RegExp(hexToRe(core),"g");
  } else throw new Error("unrecognized string def");
  return { count(text){ re.lastIndex=0; let c=0,g; while((g=re.exec(text))!==null){ c++; if(re.lastIndex===g.index)re.lastIndex++; } return c; } };
}
function litToRe(lit, wide, ascii){
  const e=lit.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");
  if (wide&&!ascii) return e.split("").map(ch=>ch+"\\x00?").join("");
  if (wide&&ascii) return "(?:"+e+"|"+e.split("").map(ch=>ch+"\\x00").join("")+")";
  return e;
}
function hexToRe(hex){
  const inner=hex.replace(/^\{|\}$/g,"").trim();
  const toks=inner.split(/\s+/).filter(Boolean); let out="";
  for (let i=0;i<toks.length;i++){
    let t=toks[i];
    if (t==="??"){ out+="[\\s\\S]"; continue; }
    let jm=/^\[(\d+)(?:-(\d+))?\]$/.exec(t);
    if (jm){ out += jm[2]!==undefined?`[\\s\\S]{${jm[1]},${jm[2]}}`:`[\\s\\S]{${jm[1]}}`; continue; }
    if (/^[0-9A-Fa-f]{2}$/.test(t)){ out+="\\x"+("0"+parseInt(t,16).toString(16)).slice(-2); continue; }
    if (/^[0-9A-Fa-f?]{2}$/.test(t)){ out+="[\\s\\S]"; continue; }
  }
  return out;
}
function compileYaraCondition(cond, ids){
  cond=cond.trim().replace(/\s+/g," ");
  const re=/\(|\)|\bany of them\b|\ball of them\b|\bnone of them\b|\b\d+ of them\b|\bany of\b|\ball of\b|\b\d+ of\b|\band\b|\bor\b|\bnot\b|#[A-Za-z0-9_]+|\$[A-Za-z0-9_*]+|>=|<=|==|>|<|\d+|them|of|filesize|entrypoint|at|in/gi;
  const toks=[]; let m; while((m=re.exec(cond))!==null) toks.push(m[0]);
  let pos=0; const peek=()=>toks[pos], next=()=>toks[pos++];
  const matchIds=pat=>{ if(pat==="them")return ids.slice();
    if(pat.includes("*")){ const r=globToRe(pat,""); return ids.filter(n=>r.test(n)); }
    return ids.includes(pat)?[pat]:[]; };
  function ofExpr(kindTok){
    const mm=/^(\d+|all|any|none)\s+of(?:\s+them)?$/i.exec(kindTok); const kind=mm[1].toLowerCase();
    let target;
    if (/them$/i.test(kindTok)) target=ids.slice();
    else { let nt=peek();
      if(nt==="("){ next(); target=[]; while(peek()&&peek()!==")"){ const id=next(); if(id!==",")target=target.concat(matchIds(id)); } if(peek()===")")next(); }
      else if(lc(nt)==="them"){ next(); target=ids.slice(); }
      else { next(); target=matchIds(nt); } }
    const uniq=[...new Set(target)];
    return (counts)=>{ let c=0; for(const id of uniq){ if((counts[id]||0)>0)c++; }
      if(kind==="all")return uniq.length>0&&c===uniq.length;
      if(kind==="any")return c>0; if(kind==="none")return c===0; return c>=(+kind); };
  }
  function primary(){
    let t=peek(); if(!t)return ()=>false;
    if(t==="("){ next(); const e=orE(); if(peek()===")")next(); return e; }
    if(/of them$/i.test(t)||/^(?:\d+|all|any|none) of$/i.test(t)){ next(); return ofExpr(t); }
    if(/^(all|any|none|\d+)$/i.test(t)&&lc(toks[pos+1])==="of"){ const k=next(); next(); return ofExpr(k+" of"); }
    if(t==="filesize"||t==="entrypoint"||lc(t)==="at"||lc(t)==="in"){ next(); while(peek()&&!/^(and|or|\))$/i.test(peek()))next(); return ()=>false; }
    if(t[0]==="#"){ next(); const id="$"+t.slice(1); const op=next(); const num=+next();
      return (counts)=>{ const c=counts[id]||0; return op===">"?c>num:op===">="?c>=num:op==="<"?c<num:op==="<="?c<=num:op==="=="?c===num:false; }; }
    if(t[0]==="$"){ next(); const tg=matchIds(t); return (counts)=>tg.some(id=>(counts[id]||0)>0); }
    next(); return ()=>false;
  }
  function notE(){ if(lc(peek())==="not"){ next(); const e=notE(); return c=>!e(c);} return primary(); }
  function andE(){ let l=notE(); while(lc(peek())==="and"){ next(); const r=notE(); const a=l,b=r; l=c=>a(c)&&b(c);} return l; }
  function orE(){ let l=andE(); while(lc(peek())==="or"){ next(); const r=andE(); const a=l,b=r; l=c=>a(c)||b(c);} return l; }
  return orE();
}

/* ----------------- COMMAND-LINE ARTIFACT EXTRACTION -----------------------
   Smart DFIR: recover forensic artifacts from process command lines even when the
   dedicated Security audit events (4720/4728/4698/7045…) were never logged — a very
   common real-world gap. Pure + testable; used by the Evidence extractor.          */
function parseProcessArtifacts(cmd){
  const out={ accounts:[], groups:[], tasks:[], services:[] };
  if(!cmd) return out; const s=String(cmd); let m;
  // local account creation:  net user <name> <pw> /add   |   New-LocalUser <name>
  if((m=/\bnet1?\s+user\s+([^\s\/"']+)\b[^\/]*\/add\b/i.exec(s))) out.accounts.push({user:m[1]});
  else if((m=/\bnew-localuser\b[^\n]*?(?:-name\s+)?["']?([A-Za-z0-9._$-]{1,64})["']?/i.exec(s))) out.accounts.push({user:m[1]});
  // privileged group membership:  net localgroup "Administrators" <member> /add  | Add-LocalGroupMember | Add-ADGroupMember
  if((m=/\bnet1?\s+localgroup\s+["']?([^"'\/]+?)["']?\s+([^\s\/"']+)\s+[^\/]*\/add\b/i.exec(s))) out.groups.push({group:m[1].trim(),member:m[2]});
  else if((m=/\badd-localgroupmember\b[^\n]*?-group\s+["']?([^"'\s]+)["']?[^\n]*?-member\s+["']?([^"'\s]+)/i.exec(s))) out.groups.push({group:m[1],member:m[2]});
  else if((m=/\badd-adgroupmember\b[^\n]*?["']?([^"'\s]+)["']?[^\n]*?-members?\s+["']?([^"'\s]+)/i.exec(s))) out.groups.push({group:m[1],member:m[2]});
  // scheduled task creation:  schtasks /create /tn <name> /tr <cmd>   |   Register-ScheduledTask
  if(/\bschtasks(?:\.exe)?\b[^\n]*\/create\b/i.test(s)){
    const tn=/\/tn\s+["']?([^"'\r\n]+?)["']?(?:\s+\/|\s*$)/i.exec(s), tr=/\/tr\s+["']?([^"'\r\n]+?)["']?(?:\s+\/|\s*$)/i.exec(s);
    out.tasks.push({name:tn?tn[1].trim():"(unnamed)", cmd:tr?tr[1].trim():""}); }
  else if(/\bregister-scheduledtask\b/i.test(s)){ const tn=/-taskname\s+["']?([^"'\s]+)/i.exec(s); out.tasks.push({name:tn?tn[1]:"(PowerShell task)", cmd:""}); }
  // service creation:  sc create <name> binPath= <path>   |   New-Service
  if((m=/\bsc(?:\.exe)?\s+(?:\\\\[^\s]+\s+)?create\s+([^\s]+)/i.exec(s))){ const bp=/binpath=\s*["']?([^"'\r\n]+?)["']?(?:\s|$)/i.exec(s); out.services.push({name:m[1],path:bp?bp[1].trim():""}); }
  else if((m=/\bnew-service\b[^\n]*?-name\s+["']?([^"'\s]+)/i.exec(s))){ const bp=/-binarypathname\s+["']?([^"'\r\n]+?)["']?(?:\s|$)/i.exec(s); out.services.push({name:m[1],path:bp?bp[1]:""}); }
  return out;
}

/* ----------------- MITRE ATT&CK -------------------------------------------
   Sigma rules already carry attack.* tags; heuristics get tagged below. These
   helpers turn tags into technique/tactic facts the UI aggregates + exports as a
   Navigator layer. Names are a curated subset (unknown ids fall back to the id). */
const ATTACK_TACTIC_NAMES={
  "reconnaissance":"Reconnaissance","resource-development":"Resource Development","initial-access":"Initial Access",
  "execution":"Execution","persistence":"Persistence","privilege-escalation":"Privilege Escalation",
  "defense-evasion":"Defense Evasion","credential-access":"Credential Access","discovery":"Discovery",
  "lateral-movement":"Lateral Movement","collection":"Collection","command-and-control":"Command and Control",
  "exfiltration":"Exfiltration","impact":"Impact"
};
const ATTACK_TACTIC_ORDER=Object.keys(ATTACK_TACTIC_NAMES);
// technique id -> { name, tactic }  (curated: heuristics + techniques common to the shipped Sigma set)
const ATTACK_TECHNIQUES={
  "T1003":{name:"OS Credential Dumping",tactic:"credential-access"},
  "T1003.001":{name:"LSASS Memory",tactic:"credential-access"},
  "T1003.002":{name:"Security Account Manager",tactic:"credential-access"},
  "T1003.003":{name:"NTDS",tactic:"credential-access"},
  "T1003.006":{name:"DCSync",tactic:"credential-access"},
  "T1021.001":{name:"Remote Desktop Protocol",tactic:"lateral-movement"},
  "T1021.002":{name:"SMB/Windows Admin Shares",tactic:"lateral-movement"},
  "T1027":{name:"Obfuscated Files or Information",tactic:"defense-evasion"},
  "T1036":{name:"Masquerading",tactic:"defense-evasion"},
  "T1036.003":{name:"Rename System Utilities",tactic:"defense-evasion"},
  "T1047":{name:"Windows Management Instrumentation",tactic:"execution"},
  "T1053.005":{name:"Scheduled Task",tactic:"execution"},
  "T1055":{name:"Process Injection",tactic:"defense-evasion"},
  "T1059":{name:"Command and Scripting Interpreter",tactic:"execution"},
  "T1059.001":{name:"PowerShell",tactic:"execution"},
  "T1059.003":{name:"Windows Command Shell",tactic:"execution"},
  "T1068":{name:"Exploitation for Privilege Escalation",tactic:"privilege-escalation"},
  "T1070":{name:"Indicator Removal",tactic:"defense-evasion"},
  "T1070.001":{name:"Clear Windows Event Logs",tactic:"defense-evasion"},
  "T1078":{name:"Valid Accounts",tactic:"persistence"},
  "T1090":{name:"Proxy",tactic:"command-and-control"},
  "T1098":{name:"Account Manipulation",tactic:"persistence"},
  "T1105":{name:"Ingress Tool Transfer",tactic:"command-and-control"},
  "T1112":{name:"Modify Registry",tactic:"defense-evasion"},
  "T1134":{name:"Access Token Manipulation",tactic:"privilege-escalation"},
  "T1136.001":{name:"Create Account: Local Account",tactic:"persistence"},
  "T1190":{name:"Exploit Public-Facing Application",tactic:"initial-access"},
  "T1197":{name:"BITS Jobs",tactic:"defense-evasion"},
  "T1210":{name:"Exploitation of Remote Services",tactic:"lateral-movement"},
  "T1218":{name:"System Binary Proxy Execution",tactic:"defense-evasion"},
  "T1218.005":{name:"Mshta",tactic:"defense-evasion"},
  "T1218.011":{name:"Rundll32",tactic:"defense-evasion"},
  "T1219":{name:"Remote Access Software",tactic:"command-and-control"},
  "T1482":{name:"Domain Trust Discovery",tactic:"discovery"},
  "T1543.003":{name:"Windows Service",tactic:"persistence"},
  "T1547.001":{name:"Registry Run Keys / Startup Folder",tactic:"persistence"},
  "T1548":{name:"Abuse Elevation Control Mechanism",tactic:"privilege-escalation"},
  "T1548.002":{name:"Bypass User Account Control",tactic:"privilege-escalation"},
  "T1550":{name:"Use Alternate Authentication Material",tactic:"lateral-movement"},
  "T1552":{name:"Unsecured Credentials",tactic:"credential-access"},
  "T1557":{name:"Adversary-in-the-Middle",tactic:"credential-access"},
  "T1558":{name:"Steal or Forge Kerberos Tickets",tactic:"credential-access"},
  "T1558.003":{name:"Kerberoasting",tactic:"credential-access"},
  "T1562":{name:"Impair Defenses",tactic:"defense-evasion"},
  "T1562.001":{name:"Disable or Modify Tools",tactic:"defense-evasion"},
  "T1562.002":{name:"Disable Windows Event Logging",tactic:"defense-evasion"},
  "T1569.002":{name:"Service Execution",tactic:"execution"},
  "T1570":{name:"Lateral Tool Transfer",tactic:"lateral-movement"},
  "T1110":{name:"Brute Force",tactic:"credential-access"},
  "T1110.003":{name:"Password Spraying",tactic:"credential-access"},
  "T1136":{name:"Create Account",tactic:"persistence"},
  "T1185":{name:"Browser Session Hijacking",tactic:"collection"},
  "T1204":{name:"User Execution",tactic:"execution"},
  "T1505.003":{name:"Web Shell",tactic:"persistence"},
  "T1518.001":{name:"Security Software Discovery",tactic:"discovery"},
  "T1564.003":{name:"Hidden Window",tactic:"defense-evasion"},
  "T1574":{name:"Hijack Execution Flow",tactic:"persistence"},
  "T1574.002":{name:"DLL Side-Loading",tactic:"persistence"},
  "T1620":{name:"Reflective Code Loading",tactic:"defense-evasion"}
};
function techniqueFromTag(tag){ const m=/^attack\.(t\d{4}(?:\.\d{3})?)$/i.exec(String(tag||"")); return m?m[1].toUpperCase():null; }
function tacticFromTag(tag){ const m=/^attack\.([a-z][a-z0-9_-]+)$/i.exec(String(tag||"")); if(!m)return null;
  const slug=m[1].toLowerCase().replace(/_/g,"-"); return ATTACK_TACTIC_NAMES[slug]?slug:null; }
// parse a hit's tags -> { techniques:[{id,name,tactic}], tactics:[slug] }
function parseAttack(tags){
  const techniques=[], tSet=new Set(), tacSet=new Set(), explicit=[];
  for(const tag of (tags||[])){
    const tech=techniqueFromTag(tag);
    if(tech){ if(!tSet.has(tech)){ tSet.add(tech); const ref=ATTACK_TECHNIQUES[tech]||ATTACK_TECHNIQUES[tech.split(".")[0]];
      const tactic=ref?ref.tactic:null; techniques.push({id:tech,name:ref?ref.name:tech,tactic}); if(tactic)tacSet.add(tactic); } continue; }
    const tac=tacticFromTag(tag); if(tac){ tacSet.add(tac); explicit.push(tac); }
  }
  // techniques not in the curated map inherit the rule's own tactic tag (Sigma rules carry both)
  const fallback = explicit.length?explicit[0]:null;
  if(fallback) for(const t of techniques) if(!t.tactic) t.tactic=fallback;
  return { techniques, tactics:[...tacSet] };
}

/* ----------------- ENTITY RISK SCORING ------------------------------------
   Score each user / host / IP by the severity + diversity of detections tied to
   it. Higher = look here first. Fed per (hit, record); result() ranks them.       */
const SEV_RANK={critical:4,high:3,medium:2,low:1,informational:0,info:0};
function sevRank(l){ const n=SEV_RANK[String(l||"").toLowerCase()]; return n==null?2:n; }
const SEV_WEIGHT={critical:100,high:40,medium:12,low:4,informational:1,info:1};
const NOISE_USERS=/^(?:-|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|LOCAL SYSTEM)$/i;
// pull candidate entities out of one event's data (+ its computer)
function extractEntities(data, computer){
  data=data||{}; const users=new Set(), hosts=new Set(), ips=new Set();
  if(computer) hosts.add(String(computer));
  const U=k=>{ const v=data[k]; return (v==null||typeof v==="object")?"":String(v); };
  for(const k of ["TargetUserName","SubjectUserName","User","AccountName","SamAccountName"]){
    const v=U(k); if(v && !NOISE_USERS.test(v)) users.add(v); }
  for(const k of ["IpAddress","SourceIp","SourceAddress","DestinationIp","ClientIP","Address","SourceNetworkAddress"]){
    const v=U(k); if(v && v!=="-" && v!=="::1" && /^\d+\.\d+\.\d+\.\d+$/.test(v)) ips.add(v); }
  for(const k of ["Computer","WorkstationName","Workstation","ComputerName"]){ const v=U(k); if(v && v!=="-") hosts.add(v); }
  return { users:[...users], hosts:[...hosts], ips:[...ips] };
}
// accumulator: feed (hit, rec) via feed(), then result(topN).
// Dedup: a rule's contribution to an entity grows as weight*(1+log2 count), so 4,700
// repeated Defender hits can't drown out a single critical from a different rule.
function makeEntityScorer(){
  const map=new Map();   // "type|name" -> aggregate
  const bump=(type,name,hit,tms)=>{ if(!name)return; const key=type+"|"+name; let g=map.get(key);
    if(!g){ g={type,name,level:"info",hits:0,ruleAgg:new Map(),techniques:new Set(),firstTms:null,lastTms:null}; map.set(key,g); }
    const rk=hit.ruleId||hit.title||"?"; let ra=g.ruleAgg.get(rk);
    if(!ra){ ra={count:0,level:hit.level}; g.ruleAgg.set(rk,ra); }
    ra.count++; if(sevRank(hit.level)>sevRank(ra.level)) ra.level=hit.level;
    g.hits++; if(sevRank(hit.level)>sevRank(g.level)) g.level=hit.level;
    for(const t of parseAttack(hit.tags).techniques) g.techniques.add(t.id);
    if(tms!=null && !Number.isNaN(tms)){ if(g.firstTms==null||tms<g.firstTms)g.firstTms=tms; if(g.lastTms==null||tms>g.lastTms)g.lastTms=tms; }
  };
  return {
    feed(hit, rec){ const e=extractEntities(rec&&rec.data, rec&&rec.computer); const tms=rec&&rec.tms;
      for(const u of e.users) bump("user",u,hit,tms);
      for(const h of e.hosts) bump("host",h,hit,tms);
      for(const ip of e.ips) bump("ip",ip,hit,tms); },
    result(topN){
      const arr=[...map.values()].map(g=>{
        let base=0; for(const ra of g.ruleAgg.values()) base += (SEV_WEIGHT[String(ra.level).toLowerCase()]||4)*(1+Math.log2(ra.count));
        // diversity multiplier: distinct ATT&CK techniques + distinct rules broaden the risk
        const div = 1 + 0.12*Math.max(0,g.techniques.size-1) + 0.05*Math.max(0,g.ruleAgg.size-1);
        return { type:g.type, name:g.name, score:Math.round(base*div), level:g.level, hits:g.hits,
          rules:g.ruleAgg.size, techniques:[...g.techniques], firstTms:g.firstTms, lastTms:g.lastTms }; });
      arr.sort((a,b)=> b.score-a.score || sevRank(b.level)-sevRank(a.level) || b.hits-a.hits);
      return topN?arr.slice(0,topN):arr;
    }
  };
}

/* ----------------- ATTACK-CHAIN CORRELATION -------------------------------
   Group detections per host into time-bounded bursts, then promote a burst to an
   "attack chain" when it spans multiple ATT&CK tactics (progression) or is a
   sustained high-severity cluster. Pure + testable: feed detection items, get
   ranked named chains. items: {idx,tms,host,user,level,title,source,ruleId,tags} */
function buildAttackChains(items, opts){
  opts=opts||{};
  const GAP = opts.gapMs || 30*60*1000;         // >30 min quiet gap ends a burst
  const MAX_SPAN = opts.maxSpanMs || 24*60*60*1000;  // cap a chain to a 24h window (else it's a host summary)
  const MIN_TACTICS = opts.minTactics || 2;     // multi-tactic = progression
  const MAX_CHAINS = opts.maxChains || 40;
  const byHost=new Map();
  for(const it of (items||[])){ const host=it.host||it.user||"(unknown host)";
    let a=byHost.get(host); if(!a){ a=[]; byHost.set(host,a); } a.push(it); }
  const chains=[];
  for(const [host,arr] of byHost){
    arr.sort((a,b)=>(a.tms||0)-(b.tms||0));
    let session=[], prev=null;
    const flush=()=>{ if(session.length) consider(host,session); session=[]; };
    for(const it of arr){ const t=it.tms||0;
      if(session.length && ((t-prev)>GAP || (t-session[0].tms)>MAX_SPAN)) flush();
      session.push(it); prev=t; }
    flush();
  }
  chains.sort((a,b)=> b.score-a.score || (b.endTms||0)-(a.endTms||0));
  return chains.slice(0, MAX_CHAINS);

  function consider(host, session){
    const tacSet=new Set(), techSet=new Set(), users=new Set(); let maxLvl="info";
    // collapse repeated same-technique detections into one ordered step (the story, not the noise)
    const stepMap=new Map();
    for(const it of session){ const pa=parseAttack(it.tags);
      for(const tac of pa.tactics) tacSet.add(tac);
      for(const t of pa.techniques) techSet.add(t.id);
      if(it.user) users.add(it.user);
      if(sevRank(it.level)>sevRank(maxLvl)) maxLvl=it.level;
      const tech=(pa.techniques[0]&&pa.techniques[0].id)||null;
      const key=tech||it.ruleId||it.title||("_"+it.idx);
      let st=stepMap.get(key);
      if(!st){ st={ idx:it.idx, tms:it.tms, title:it.title||it.ruleId, level:it.level, source:it.source,
        tactic:(pa.techniques[0]&&pa.techniques[0].tactic)||pa.tactics[0]||null, technique:tech, count:0 }; stepMap.set(key,st); }
      st.count++; if(sevRank(it.level)>sevRank(st.level))st.level=it.level;
      if((it.tms||0)<(st.tms||Infinity))st.tms=it.tms;    // keep earliest occurrence time
    }
    const nTac=tacSet.size, hiBurst=(sevRank(maxLvl)>=3 && session.length>=3);
    if(nTac<MIN_TACTICS && !hiBurst) return;                 // not a progression, not a sustained burst
    const steps=[...stepMap.values()].sort((a,b)=>(a.tms||0)-(b.tms||0));
    const orderedTac=ATTACK_TACTIC_ORDER.filter(s=>tacSet.has(s));
    const startTms=session[0].tms, endTms=session[session.length-1].tms;
    const score = nTac*100 + (SEV_WEIGHT[String(maxLvl).toLowerCase()]||1)*3 + Math.min(session.length,50);
    const names=orderedTac.map(s=>ATTACK_TACTIC_NAMES[s]||s);
    chains.push({ host, users:[...users], startTms, endTms, durationMs:(endTms-startTms)||0,
      count:session.length, steps, tactics:orderedTac, techniques:[...techSet], level:maxLvl, score,
      name: names.length?names.join(" → "):("Activity burst on "+host) });
  }
}

/* ----------------- PROCESS-TREE RECONSTRUCTION ----------------------------------
   Rebuild process ancestry from Sysmon EID 1 records via ProcessGuid/ParentProcessGuid
   (globally unique, so links are reliable across PID reuse). Returns a forest: roots are
   processes whose parent wasn't captured. subDet carries the max detection severity in a
   node's subtree so the UI can highlight branches that contain detections.               */
function buildProcessTree(procs, opts){
  opts=opts||{};
  const byGuid=new Map(); const nodes=[];
  for(const p of procs){
    if(!p.guid || byGuid.has(p.guid)) continue;          // one node per ProcessGuid (creation event)
    const node={ idx:p.idx, guid:p.guid, pid:p.pid||"", image:p.image||"", cmd:p.cmd||"",
      pguid:p.pguid||"", pimage:p.pimage||"", user:p.user||"", ts:p.ts||"", tms:Number.isFinite(p.tms)?p.tms:null,
      host:p.host||"", end:p.end||null, det:p.det||0, children:[] };
    byGuid.set(p.guid, node); nodes.push(node);
  }
  const roots=[];
  for(const n of nodes){
    const parent = n.pguid && byGuid.get(n.pguid);
    // link to parent only if it was created no later than the child (prevents guid-reuse cycles)
    if(parent && parent!==n && (parent.tms==null || n.tms==null || parent.tms<=n.tms)) parent.children.push(n);
    else roots.push(n);
  }
  const byTime=(a,b)=>((a.tms==null?Infinity:a.tms)-(b.tms==null?Infinity:b.tms));
  for(const n of nodes) n.children.sort(byTime);
  roots.sort((a,b)=> String(a.host||"").localeCompare(String(b.host||"")) || byTime(a,b));
  const markDet=(n,seen)=>{ if(seen.has(n))return n.subDet||0; seen.add(n);
    let m=n.det||0; for(const c of n.children){ const cm=markDet(c,seen); if(cm>m)m=cm; } n.subDet=m; return m; };
  for(const r of roots) markDet(r, new Set());
  const hosts=[...new Set(nodes.map(n=>n.host||"").filter(Boolean))].sort();
  return { roots, count:nodes.length, hosts };
}

/* Lateral-movement graph: aggregate raw movement edges (one per relevant auth/share/RDP
   event) into a de-duplicated node-link graph. Each raw edge is
   { from, ftype, to, ttype, kind, user, idx, tms, det }. Nodes are hosts / source IPs,
   edges collapse repeats and keep per-technique counts, involved users, sample event
   indices and a first/last timestamp. Pure + deterministic so it's unit-testable. */
function buildLateralGraph(raw, opts){
  opts=opts||{};
  const nodes=new Map(), edges=new Map();
  const touch=(id,type)=>{
    if(!id) return null;
    let n=nodes.get(id);
    if(!n){ n={ id, type:type||"host", label:id, count:0, out:0, in:0, det:0 }; nodes.set(id,n); }
    else if(type==="ip") n.type="ip";                    // an id seen as an IP anywhere is an IP
    return n;
  };
  for(const e of (raw||[])){
    if(!e || !e.from || !e.to || e.from===e.to) continue;
    const a=touch(e.from, e.ftype), b=touch(e.to, e.ttype);
    if(!a||!b) continue;
    a.count++; a.out++; b.count++; b.in++;
    const lvl=e.det||0; if(lvl>a.det)a.det=lvl; if(lvl>b.det)b.det=lvl;
    const key=e.from+" "+e.to;
    let ed=edges.get(key);
    if(!ed){ ed={ from:e.from, to:e.to, count:0, det:0, kinds:{}, users:new Set(), samples:[], firstTms:null, lastTms:null }; edges.set(key,ed); }
    ed.count++;
    if(lvl>ed.det) ed.det=lvl;
    if(e.kind) ed.kinds[e.kind]=(ed.kinds[e.kind]||0)+1;
    if(e.user) ed.users.add(e.user);
    if(ed.samples.length<8 && e.idx!=null) ed.samples.push(e.idx);
    const t=Number.isFinite(e.tms)?e.tms:null;
    if(t!=null){ if(ed.firstTms==null||t<ed.firstTms)ed.firstTms=t; if(ed.lastTms==null||t>ed.lastTms)ed.lastTms=t; }
  }
  const nodeArr=[...nodes.values()].sort((x,y)=>(y.det-x.det)||(y.count-x.count)||String(x.id).localeCompare(String(y.id)));
  const edgeArr=[...edges.values()].map(ed=>({
    from:ed.from, to:ed.to, count:ed.count, det:ed.det, kinds:ed.kinds,
    users:[...ed.users].slice(0,12), samples:ed.samples, firstTms:ed.firstTms, lastTms:ed.lastTms
  })).sort((x,y)=>(y.det-x.det)||(y.count-x.count));
  return { nodes:nodeArr, edges:edgeArr };
}

/* ----------------- IOC WATCHLIST MATCHING ---------------------------------- */
// Guess an IOC's type from its value so the matcher can pick exact-token vs substring matching.
function iocType(v){
  v=String(v||"").trim();
  if(/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return "ip";
  if(/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(v)) return "hash";
  if(/[\\/]/.test(v) || /\.(exe|dll|ps1|bat|vbs|scr|js|hta|cmd|sys|tmp|dat|bin|jar|lnk|docm|xlsm|iso|img|reg)$/i.test(v)) return "file";
  if(/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i.test(v)) return "domain";
  return "string";
}
// Aho-Corasick multi-string matcher — one pass finds all substring needles in a haystack.
function buildAho(needles){
  const goto=[{}], out=[[]], fail=[0];
  for(const w of needles){ if(!w) continue; let s=0;
    for(const ch of w){ if(goto[s][ch]==null){ goto.push({}); out.push([]); fail.push(0); goto[s][ch]=goto.length-1; } s=goto[s][ch]; }
    out[s].push(w); }
  const q=[];
  for(const ch in goto[0]){ const s=goto[0][ch]; fail[s]=0; q.push(s); }
  while(q.length){ const r=q.shift();
    for(const ch in goto[r]){ const s=goto[r][ch]; q.push(s);
      let f=fail[r]; while(f && goto[f][ch]==null) f=fail[f];
      fail[s]=(goto[f][ch]!=null && goto[f][ch]!==s)?goto[f][ch]:0;
      if(out[fail[s]].length) out[s]=out[s].concat(out[fail[s]]); } }
  return { goto, out, fail };
}
function ahoSearch(ac, text){
  let s=0; const found=new Set();
  for(let i=0;i<text.length;i++){ const ch=text[i];
    while(s && ac.goto[s][ch]==null) s=ac.fail[s];
    s=ac.goto[s][ch]!=null?ac.goto[s][ch]:0;
    if(ac.out[s].length) for(const w of ac.out[s]) found.add(w); }
  return found;
}
// Build a scanner over a list of IOCs ({value,type}). scan(lowercasedText) -> Set of matched
// (lowercased) IOC values. IPs/hashes/domains use exact-token intersection (no substring false
// positives); files/users/generic strings use Aho-Corasick substring search.
function buildIocMatcher(iocs){
  const ipSet=new Set(), hashSet=new Set(), domainSet=new Set(), strNeedles=[];
  const meta=new Map();
  for(const it of (iocs||[])){
    const v=String((it&&it.value)!=null?it.value:it||"").trim(); if(!v) continue;
    const lv=v.toLowerCase(); if(meta.has(lv)) continue;
    const type=(it&&it.type)||iocType(v); meta.set(lv,{ value:v, type });
    if(type==="ip") ipSet.add(lv);
    else if(type==="hash") hashSet.add(lv);
    else if(type==="domain") domainSet.add(lv);
    else strNeedles.push(lv);
  }
  const ac = strNeedles.length ? buildAho(strNeedles) : null;
  const IPRE=/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, HEXRE=/[a-f0-9]{32,64}/g, DOMRE=/[a-z0-9][a-z0-9.-]*\.[a-z]{2,}/g;
  return {
    count: meta.size, meta,
    scan(text){
      text=String(text||"");
      const hits=new Set();
      if(ipSet.size){ const m=text.match(IPRE); if(m) for(const t of m) if(ipSet.has(t)) hits.add(t); }
      if(hashSet.size){ const m=text.match(HEXRE); if(m) for(const t of m) if(hashSet.has(t)) hits.add(t); }
      if(domainSet.size){ const m=text.match(DOMRE); if(m) for(let t of m){
        let d=t; let guard=0;
        while(d.indexOf(".")>=0 && guard++<8){ if(domainSet.has(d)) hits.add(d); d=d.slice(d.indexOf(".")+1); }
      } }
      if(ac) for(const w of ahoSearch(ac, text)) hits.add(w);
      return hits;
    }
  };
}

/* ----------------- RARITY / STACKING (long-tail hunting) ------------------- */
function baseName(p){ const s=String(p||""); const i=Math.max(s.lastIndexOf("\\"),s.lastIndexOf("/")); return i>=0?s.slice(i+1):s; }
// Flag classic "abnormal ancestry": an office / web-server / WMI process spawning a shell or LOLBIN.
function suspiciousParentChild(parentImage, childImage){
  const p=baseName(parentImage).toLowerCase(), c=baseName(childImage).toLowerCase();
  const shellChild=/^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|schtasks|nltest|whoami|net|net1|installutil|msbuild|hh|forfiles|curl|wget)\.exe$/;
  const spawnParent=/^(winword|excel|powerpnt|outlook|onenote|mspub|visio|w3wp|httpd|nginx|tomcat\d*|java|sqlservr|wmiprvse|mysqld|php-cgi|spoolsv)\.exe$/;
  return spawnParent.test(p) && shellChild.test(c);
}
// Group items by key and return buckets sorted RAREST-FIRST (ascending count) — the long tail
// is where the anomalies hide. items: [{ key, host, user, idx, tms, det, extra? }].
function buildStacks(items, opts){
  opts=opts||{}; const cap=opts.cap||6000; const rareThreshold=opts.rareThreshold||2;
  const m=new Map();
  for(const it of (items||[])){
    const k=it&&it.key; if(k==null||k==="") continue;
    let a=m.get(k);
    if(!a){ if(m.size>=cap) continue; a={ value:k, count:0, hosts:new Set(), users:new Set(), samples:[], firstTms:null, lastTms:null, det:0, ...(it.extra||{}) }; m.set(k,a); }
    a.count++;
    if(it.host)a.hosts.add(it.host);
    if(it.user)a.users.add(it.user);
    if(a.samples.length<10 && it.idx!=null)a.samples.push(it.idx);
    if((it.det||0)>a.det)a.det=it.det;
    const t=Number.isFinite(it.tms)?it.tms:null;
    if(t!=null){ if(a.firstTms==null||t<a.firstTms)a.firstTms=t; if(a.lastTms==null||t>a.lastTms)a.lastTms=t; }
  }
  const arr=[...m.values()];
  const total=arr.reduce((s,a)=>s+a.count,0);
  arr.sort((x,y)=>(x.count-y.count)||(String(x.value)<String(y.value)?-1:1));
  return { total, distinct:arr.length, rows:arr.map(a=>({
    value:a.value, count:a.count, rare:a.count<=rareThreshold, pct:total?a.count/total:0,
    hosts:[...a.hosts].slice(0,20), users:[...a.users].slice(0,20), samples:a.samples,
    firstTms:a.firstTms, lastTms:a.lastTms, det:a.det,
    parent:a.parent, child:a.child, suspicious:!!a.suspicious, algo:a.algo, image:a.image })) };
}

/* ----------------- HEURISTICS ---------------------------------------------- */
function isPrivateIp(ip){
  if(!ip||ip==="-"||ip==="::1")return true;
  const n=ipToInt(ip); if(n==null)return true;
  const inR=(a,b)=> n>=ipToInt(a)&&n<=ipToInt(b);
  return inR("10.0.0.0","10.255.255.255")||inR("172.16.0.0","172.31.255.255")||
         inR("192.168.0.0","192.168.255.255")||inR("127.0.0.0","127.255.255.255");
}
const ENCODED_PS=/(?:-enc(?:odedcommand)?\b|frombase64string|-e[ncodmand]*\s+[A-Za-z0-9+\/]{20,}|iex\s*\(|invoke-expression|downloadstring|downloadfile|-nop\b|-noni\b|-w\s+hidden|-windowstyle\s+hidden|bypass\b)/i;
const SUSP_PATH=/\\(?:temp|tmp|programdata|public|windows\\temp)\\|\\appdata\\|\.tmp\b/i;
const LOLBINish=/\b(?:powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|installutil|msbuild)\b/i;

// ruleId -> ATT&CK tags (attack.* format, same as Sigma) so heuristics feed the ATT&CK matrix
const HEUR_ATTACK={
  "H-LOGCLEAR":["attack.defense-evasion","attack.t1070.001"],
  "H-BRUTE":["attack.credential-access","attack.t1110"],
  "H-SPRAY":["attack.credential-access","attack.t1110.003"],
  "H-ENCPS":["attack.execution","attack.t1059.001","attack.defense-evasion","attack.t1027"],
  "H-NEWSVC":["attack.persistence","attack.t1543.003"],
  "H-EXTRDP":["attack.lateral-movement","attack.t1021.001"],
  "H-NEWUSER":["attack.persistence","attack.t1136.001"],
  "H-ADMINADD":["attack.persistence","attack.t1098"],
  "H-AVHIT":[],
  "H-AVOFF":["attack.defense-evasion","attack.t1562.001"],
  "H-KERBEROAST":["attack.credential-access","attack.t1558.003"],
  "H-DCSYNC":["attack.credential-access","attack.t1003.006"],
  "H-LSASSDUMP":["attack.credential-access","attack.t1003.001"],
  "H-PSEXEC":["attack.lateral-movement","attack.t1021.002","attack.execution","attack.t1569.002"],
  "H-PTH":["attack.lateral-movement","attack.t1550"],
  "H-SCHTASK":["attack.execution","attack.t1053.005"]
};
function runHeuristics(rows){
  const hits=[];
  const add=(idx,ruleId,title,level,why)=>hits.push({idx,ruleId,title,level,why,source:"heuristic",tags:HEUR_ATTACK[ruleId]||[]});
  const byEid=new Map();
  for (let i=0;i<rows.length;i++){ const e=Number(rows[i].eventId); if(!byEid.has(e))byEid.set(e,[]); byEid.get(e).push(i); }

  for (const e of [1102,104]) for (const i of (byEid.get(e)||[]))
    add(i,"H-LOGCLEAR","Security/event log cleared","high","EventID "+e+" — audit-log clearing, classic anti-forensics");

  const fails=(byEid.get(4625)||[]);
  if (fails.length){
    const byIp=new Map(), ipUsers=new Map();
    for (const i of fails){ const d=rows[i].data||{}; const ip=d.IpAddress||d.SourceIp||d.SourceAddress||"?"; const u=d.TargetUserName||"?";
      if(ip!=="-"&&ip!=="?"){ if(!byIp.has(ip))byIp.set(ip,[]); byIp.get(ip).push(i); }
      if(!ipUsers.has(ip))ipUsers.set(ip,new Set()); ipUsers.get(ip).add(u); }
    for (const [ip,arr] of byIp){ if(arr.length>=10){ const ext=!isPrivateIp(ip);
      for (const i of arr) add(i,"H-BRUTE","Failed-logon burst (possible brute force)",ext?"high":"medium",
        arr.length+" failed logons (4625) from "+ip+(ext?" — external source":"")); } }
    for (const [ip,set] of ipUsers){ if(set.size>=8&&ip!=="?"){
      for (const i of fails){ if(((rows[i].data||{}).IpAddress||"?")===ip) add(i,"H-SPRAY","Password-spray pattern","high",ip+" hit "+set.size+" distinct accounts"); } } }
  }

  for (const e of [4688,1,4104,800]) for (const i of (byEid.get(e)||[])){ const d=rows[i].data||{};
    const cmd=d.CommandLine||d.ProcessCommandLine||d.ScriptBlockText||"";
    if (cmd&&ENCODED_PS.test(cmd)) add(i,"H-ENCPS","Encoded/obfuscated PowerShell or download cradle","high","Command line: "+String(cmd).slice(0,90)); }

  for (const e of [7045,4697]) for (const i of (byEid.get(e)||[])){ const d=rows[i].data||{};
    const path=d.ImagePath||d.ServiceFileName||""; const susp=SUSP_PATH.test(path)||LOLBINish.test(path);
    add(i,"H-NEWSVC",susp?"New service with suspicious binary path":"New service installed",susp?"high":"medium",
      "Service '"+(d.ServiceName||d.param1||"?")+"'"+(path?" -> "+String(path).slice(0,80):"")); }

  for (const i of (byEid.get(4624)||[])){ const d=rows[i].data||{};
    if (String(d.LogonType)==="10"&&!isPrivateIp(d.IpAddress)) add(i,"H-EXTRDP","Interactive RDP logon from external IP","high","Type-10 logon from "+d.IpAddress); }
  for (const i of (byEid.get(1149)||[])){ const d=rows[i].data||{}; const ip=d.Param3||d.IpAddress||d.ClientIP;
    if(ip&&!isPrivateIp(ip)) add(i,"H-EXTRDP","RDP authentication from external IP","medium","Source "+ip); }

  for (const i of (byEid.get(4720)||[])){ const u=(rows[i].data||{}).TargetUserName;
    add(i,"H-NEWUSER","New user account created","medium","Account '"+(u||"?")+"' created (4720) — verify it is authorized"); }
  for (const e of [4732,4728,4756]) for (const i of (byEid.get(e)||[]))
    add(i,"H-ADMINADD","Member added to privileged group","high","Membership change ("+e+") — confirm target group");

  for (const e of [1006,1015,1116]) for (const i of (byEid.get(e)||[])) add(i,"H-AVHIT","Defender detected malware","high","Defender event "+e);
  for (const e of [5001,1117]) for (const i of (byEid.get(e)||[])) add(i,"H-AVOFF","Defender protection change / action","high","Defender event "+e+" — protection may be disabled");

  const tgs=(byEid.get(4769)||[]); const rc4=[];
  for (const i of tgs){ const enc=String((rows[i].data||{}).TicketEncryptionType||(rows[i].data||{}).EncryptionType||""); if(/0x17|rc4/i.test(enc))rc4.push(i); }
  if (rc4.length>=10) for (const i of rc4) add(i,"H-KERBEROAST","Possible Kerberoasting (RC4 service tickets)","medium",rc4.length+" RC4 (0x17) TGS requests (4769)");

  // --- DCSync: AD replication rights exercised by a non-machine account (4662) ---
  const REPL_GUID=/1131f6a[abcd]-9c07-11d1-f79f-00c04fc2dcd2|9923a32a-3607-11d2-b9be-0000f87a36b2/i;
  for (const i of (byEid.get(4662)||[])){ const d=rows[i].data||{};
    const props=String(d.Properties||d.AccessMaskString||d.ObjectType||""); const subj=String(d.SubjectUserName||"");
    if (REPL_GUID.test(props) && subj && !/\$$/.test(subj))
      add(i,"H-DCSYNC","Directory replication rights used (possible DCSync)","critical","'"+subj+"' exercised AD replication (4662) — DCSync credential theft"); }

  // --- LSASS memory access with dump-grade rights (Sysmon 10) ---
  for (const i of (byEid.get(10)||[])){ const d=rows[i].data||{}; const tgt=String(d.TargetImage||"");
    if (/\\lsass\.exe$/i.test(tgt)){ const ga=String(d.GrantedAccess||"").toLowerCase();
      if (/0x1010|0x1410|0x1438|0x143a|0x1fffff|0x1f1fff|0x1f3fff/.test(ga))
        add(i,"H-LSASSDUMP","LSASS memory access (possible credential dumping)","high","'"+String(d.SourceImage||"?")+"' opened lsass with "+(d.GrantedAccess||"?")); } }

  // --- PsExec-style remote service execution ---
  for (const e of [7045,4697]) for (const i of (byEid.get(e)||[])){ const d=rows[i].data||{};
    const blob=String(d.ServiceName||d.param1||"")+" "+String(d.ImagePath||d.ServiceFileName||"");
    if (/psexe|paexec|csexec|remcom|xcmd/i.test(blob))
      add(i,"H-PSEXEC","PsExec-style remote service execution","high","Service '"+String(d.ServiceName||d.param1||"?")+"' — remote exec tool"); }
  for (const i of (byEid.get(5145)||[])){ const d=rows[i].data||{}; const rel=String(d.RelativeTargetName||d.ShareName||"");
    if (/psexesvc|paexec|remcom/i.test(rel)) add(i,"H-PSEXEC","PsExec named-pipe / share access","high","Access to '"+rel+"' — PsExec lateral movement"); }

  // --- Overpass-the-hash / NewCredentials logon (4624 type 9) ---
  for (const i of (byEid.get(4624)||[])){ const d=rows[i].data||{};
    if (String(d.LogonType)==="9" && /seclogo/i.test(String(d.LogonProcessName||"")))
      add(i,"H-PTH","NewCredentials logon (overpass-the-hash / runas /netonly)","medium","Type-9 logon by '"+String(d.TargetUserName||"?")+"' — alternate credentials used"); }

  // --- Scheduled task registered with a suspicious action (4698) ---
  const SCHT_SUSP=/powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|\\temp\\|\\appdata\\|programdata|-enc|downloadstring|frombase64|https?:\/\//i;
  for (const i of (byEid.get(4698)||[])){ const d=rows[i].data||{};
    const xml=String(d.TaskContent||d.TaskContentNew||d.NewTaskContent||""), nm=String(d.TaskName||"");
    if (SCHT_SUSP.test(xml)||SCHT_SUSP.test(nm)) add(i,"H-SCHTASK","Scheduled task with suspicious action","high","Task '"+(nm||"?")+"' runs a suspicious command (4698)"); }

  return hits;
}

/* ----------------- PUBLIC API ---------------------------------------------- */
function buildFulltext(rec){
  let s=(rec.provider||"")+" "+(rec.eventId||"")+" "+(rec.computer||"");
  const d=rec.data||{};
  for (const k in d){ const v=d[k]; s+=" "+k+"="+(v==null?"":(typeof v==="object"?JSON.stringify(v):v)); }
  if (rec.raw) s+=" "+rec.raw;
  return s;
}
const Engine={
  resolveField, compileSigmaRule, compileYaraRules, runHeuristics, buildFulltext, base64OffsetVariants, compileCondition,
  parseAttack, techniqueFromTag, tacticFromTag,
  attack:{ tactics:ATTACK_TACTIC_NAMES, tacticOrder:ATTACK_TACTIC_ORDER, techniques:ATTACK_TECHNIQUES },
  extractEntities, makeEntityScorer, buildAttackChains, buildProcessTree, buildLateralGraph,
  iocType, buildIocMatcher, buildStacks, suspiciousParentChild, baseName, parseProcessArtifacts,
  parseSigmaDocs(yamlText, yamlLoadAll){
    const docs=yamlLoadAll(yamlText)||[]; const rules=[], aggRules=[], skipped=[], errors=[];
    for (const doc of docs){
      if(!doc||typeof doc!=="object"||!doc.detection)continue;
      const r=compileSigmaRule(doc);
      if(r.rule)rules.push(r.rule);
      else if(r.aggRule)aggRules.push(r.aggRule);
      else if(r.unsupported)skipped.push({title:doc.title||doc.id||"(rule)",reason:r.reason||"unsupported"});
      else errors.push({title:doc.title||doc.id||"(rule)",error:r.error||"unknown"});
    }
    return { rules, aggRules, skipped, errors };
  },
  /* Windowed Sigma aggregations. Collect the events each aggRule's base matches, group
     by its `by` field, and slide a `timeframe` window; emit one hit per burst (when the
     window aggregate first crosses the threshold) on the triggering event.              */
  runCorrelations(rows, aggRules, opts){
    opts=opts||{}; const hitsByIdx=new Map();
    if(!aggRules||!aggRules.length) return hitsByIdx;
    const push=(i,hit)=>{ if(!hitsByIdx.has(i))hitsByIdx.set(i,[]); hitsByIdx.get(i).push(hit); };
    const indices=opts.indices||null; const N=indices?indices.length:rows.length; const getIdx=k=>indices?indices[k]:k;
    const matchesPer=aggRules.map(()=>[]);
    for(let k=0;k<N;k++){ const ix=getIdx(k); const rec=rows[ix];
      if(!rec._fulltext)rec._fulltext=buildFulltext(rec);
      for(let a=0;a<aggRules.length;a++){ const ar=aggRules[a];
        let ok=false; try{ ok=ar.baseTest(rec); }catch(_){}
        if(!ok)continue;
        const g=ar.agg.groupBy ? String(resolveField(rec,ar.agg.groupBy)??"") : "";
        let fv=null; if(ar.agg.field){ const rv=resolveField(rec,ar.agg.field); fv=(rv==null?"":String(rv)); }
        matchesPer[a].push({ idx:ix, tms:Number.isFinite(rec.tms)?rec.tms:null, g, fv });
      }
    }
    for(let a=0;a<aggRules.length;a++){ const ar=aggRules[a], all=matchesPer[a]; if(!all.length)continue;
      const groups=new Map(); for(const m of all){ let arr=groups.get(m.g); if(!arr){arr=[];groups.set(m.g,arr);} arr.push(m); }
      for(const [g,arr] of groups) windowAgg(ar, g, arr, push);
    }
    return hitsByIdx;
  },
  /* Build a reusable scan index. Strategy: extract selective literals (rare across the
     ruleset), build an Aho-Corasick automaton over them, and map each literal -> rules.
     At scan time a single AC pass yields the matched literals, whose rules are the only
     ones we fully test. Rules with no selective literal fall back to EID-bucketed testing. */
  buildIndex(sigmaRules){
    const CAP=40;                          // literals in >CAP rules are non-selective
    const df=new Map();
    for(const r of sigmaRules){ if(!r._prescreen)continue;
      const seen=new Set(); for(const l of r._lits){ if(seen.has(l))continue; seen.add(l); df.set(l,(df.get(l)||0)+1); } }
    const litToRules=new Map(); const patterns=[];
    const eidIndexed=new Map(), anyEid=[];   // always-run fallback (no selective literal)
    const addBucket=(r)=>{ if(r.eidHints){ for(const e of r.eidHints){ if(!eidIndexed.has(e))eidIndexed.set(e,[]); eidIndexed.get(e).push(r);} } else anyEid.push(r); };
    for(const r of sigmaRules){
      if(!r._prescreen){ addBucket(r); continue; }
      const sel=r._lits.filter(l=>(df.get(l)||0)<=CAP);
      if(!sel.length){ addBucket(r); continue; } // only common tokens -> always-run
      r._sel=sel;
      for(const l of sel){ let a=litToRules.get(l); if(!a){ a=[]; litToRules.set(l,a); patterns.push(l);} a.push(r); }
    }
    const ac=buildAC(patterns);
    return { litToRules, ac, eidIndexed, anyEid, n:sigmaRules.length };
  },
  runRules(rows, sigmaRules, yaraRules, opts){
    opts=opts||{}; const onProgress=opts.onProgress||(()=>{}); const indices=opts.indices||null;
    const idx=opts.index||((sigmaRules&&sigmaRules.length)?Engine.buildIndex(sigmaRules):{litToRules:new Map(),ac:null,eidIndexed:new Map(),anyEid:[]});
    const { litToRules, ac, eidIndexed, anyEid }=idx;
    const haveSigma=litToRules.size||eidIndexed.size||anyEid.length;
    const hitsByIdx=new Map();
    const push=(i,hit)=>{ if(!hitsByIdx.has(i))hitsByIdx.set(i,[]); hitsByIdx.get(i).push(hit); };
    const N=indices?indices.length:rows.length; const getIdx=k=>indices?indices[k]:k;
    for (let k=0;k<N;k++){
      const ix=getIdx(k); const rec=rows[ix];
      if(!rec._fulltext)rec._fulltext=buildFulltext(rec);
      const eid=Number(rec.eventId);
      if(haveSigma){
        const ftLow=lc(rec._fulltext);
        const tested=rec._seen||(rec._seen=new Set()); tested.clear();
        // 1) keyword-matched rules
        if(ac){ const matched=acSearch(ac,ftLow);
          if(matched.size){ for(const p of matched){ const rs=litToRules.get(p); if(!rs)continue;
            for(const r of rs){ if(tested.has(r))continue; tested.add(r);
              if(r.eidHints && !r.eidHints.has(eid))continue;
              try{ if(r.test(rec))push(ix,sigHit(r)); }catch(_){} } } } }
        // 2) always-run fallback rules for this EID
        const fb=eidIndexed.get(eid); if(fb)for(const r of fb){ if(tested.has(r))continue;
          try{ if(r.test(rec))push(ix,sigHit(r)); }catch(_){} }
        for(const r of anyEid){ if(tested.has(r))continue; try{ if(r.test(rec))push(ix,sigHit(r)); }catch(_){} }
      }
      if (yaraRules.length){ const txt=rec._fulltext;
        for (const y of yaraRules){ try{ if(y.test(txt))push(ix,{ruleId:y.name,title:y.name,level:y.level,source:"yara",why:y.tags||""}); }catch(_){} } }
      if ((k&8191)===0) onProgress(k,N);
    }
    onProgress(N,N);
    return hitsByIdx;
  }
};
function sigHit(r){ return {ruleId:r.id||r.title,title:r.title,level:r.level,source:"sigma",why:r.description||"",tags:r.tags}; }
/* Slide a timeframe window over one group's (time-sorted) matches, emitting a hit each
   time the aggregate first satisfies the comparison (dedup per contiguous burst). */
function windowAgg(ar, g, arr, push){
  const { func, field, op, threshold }=ar.agg;
  const tf=ar.timeframeMs;
  arr.sort((x,y)=>(x.tms==null?Infinity:x.tms)-(y.tms==null?Infinity:y.tms));
  let left=0, firing=false;
  const distinct=new Map(); let dsize=0, sum=0, num=0;   // incremental window state
  const addVal=(v)=>{ if(field){ const key=v.fv==null?"":v.fv; distinct.set(key,(distinct.get(key)||0)+1); if(distinct.get(key)===1)dsize++;
      const n=Number(v.fv); if(!Number.isNaN(n)){ sum+=n; num++; } } };
  const remVal=(v)=>{ if(field){ const key=v.fv==null?"":v.fv; const c=(distinct.get(key)||0)-1; if(c<=0){distinct.delete(key);dsize--;} else distinct.set(key,c);
      const n=Number(v.fv); if(!Number.isNaN(n)){ sum-=n; num--; } } };
  const value=(l,r)=>{
    switch(func){
      case "count": return field?dsize:(r-l+1);              // count() = events; count(field) = distinct values
      case "sum": return sum;
      case "avg": return num?sum/num:0;
      case "min": case "max": { let acc=null; for(let i=l;i<=r;i++){ const n=Number(arr[i].fv); if(Number.isNaN(n))continue;
          acc=acc==null?n:(func==="min"?Math.min(acc,n):Math.max(acc,n)); } return acc==null?0:acc; }
      default: return 0;
    }
  };
  for(let r=0;r<arr.length;r++){
    addVal(arr[r]);
    if(tf!=null){ while(left<r && arr[r].tms!=null && arr[left].tms!=null && (arr[r].tms-arr[left].tms)>tf){ remVal(arr[left]); left++; } }
    const v=value(left,r);
    if(aggCompare(v,op,threshold)){ if(!firing){ firing=true; push(arr[r].idx, aggHit(ar, g, v)); } }
    else firing=false;
  }
}
function aggHit(ar, g, v){
  const a=ar.agg;
  const what=a.func+"("+(a.field||"")+")"+(a.groupBy?(" by "+a.groupBy+(g!==""?("="+g):"")):"");
  const win=ar.timeframeMs?(" within "+Math.round(ar.timeframeMs/1000)+"s"):"";
  const why=(ar.description?ar.description+" — ":"")+what+" = "+(Number.isInteger(v)?v:v.toFixed(2))+" "+a.op+" "+a.threshold+win;
  return { ruleId:ar.id||ar.title, title:ar.title, level:ar.level, source:"sigma", why, tags:ar.tags, agg:true };
}
const EMPTY=[];
function someLit(lits,set){ for(let i=0;i<lits.length;i++) if(set.has(lits[i]))return true; return false; }
/* ---- Aho-Corasick multi-substring matcher (returns set of matched patterns) ---- */
function buildAC(patterns){
  const next=[Object.create(null)], fail=[0], out=[null]; let n=1;
  for(const p of patterns){ if(!p)continue; let s=0;
    for(let i=0;i<p.length;i++){ const ch=p[i];
      if(next[s][ch]==null){ next[s][ch]=n; next[n]=Object.create(null); fail[n]=0; out[n]=null; n++; }
      s=next[s][ch]; }
    (out[s]||(out[s]=[])).push(p);
  }
  const q=[]; for(const ch in next[0]){ const s=next[0][ch]; fail[s]=0; q.push(s); }
  let qi=0;
  while(qi<q.length){ const r=q[qi++];
    for(const ch in next[r]){ const s=next[r][ch]; q.push(s);
      let f=fail[r]; while(f&&next[f][ch]==null)f=fail[f];
      fail[s]=(next[f][ch]!=null&&next[f][ch]!==s)?next[f][ch]:0;
      if(out[fail[s]]) out[s]=(out[s]||[]).concat(out[fail[s]]);
    } }
  return { next, fail, out };
}
function acSearch(ac,text){
  const found=new Set(); const next=ac.next,fail=ac.fail,out=ac.out; let s=0;
  for(let i=0;i<text.length;i++){ const ch=text[i];
    while(s&&next[s][ch]==null)s=fail[s];
    s=next[s][ch]!=null?next[s][ch]:0;
    const o=out[s]; if(o)for(let j=0;j<o.length;j++)found.add(o[j]);
  }
  return found;
}
if (typeof module!=="undefined"&&module.exports) module.exports=Engine;
root.DetEngine=Engine;
})(typeof window!=="undefined"?window:globalThis);
