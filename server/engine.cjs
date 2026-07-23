/* ============================================================================
   EVTX Triage — Detection Engine
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
  const conds=asArray(det.condition); const condFns=[];
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
  while((sm=sre.exec(strBlock))!==null) defs.push({id:sm[1], at:sre.lastIndex});
  for (let i=0;i<defs.length;i++){
    const end = i+1<defs.length ? defs[i+1].at - defs[i+1].id.length - 1 : strBlock.length;
    let seg = strBlock.slice(defs[i].at, end).trim();
    seg = seg.replace(/\$[A-Za-z0-9_*]+\s*=\s*$/,"").trim();
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

function runHeuristics(rows){
  const hits=[];
  const add=(idx,ruleId,title,level,why)=>hits.push({idx,ruleId,title,level,why,source:"heuristic"});
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
  parseSigmaDocs(yamlText, yamlLoadAll){
    const docs=yamlLoadAll(yamlText)||[]; const rules=[], skipped=[], errors=[];
    for (const doc of docs){
      if(!doc||typeof doc!=="object"||!doc.detection)continue;
      const r=compileSigmaRule(doc);
      if(r.rule)rules.push(r.rule);
      else if(r.unsupported)skipped.push({title:doc.title||doc.id||"(rule)",reason:r.reason||"unsupported"});
      else errors.push({title:doc.title||doc.id||"(rule)",error:r.error||"unknown"});
    }
    return { rules, skipped, errors };
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
