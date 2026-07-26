// Phase 1 store regression tests (SQLite case index + catalog + chain of custody).
// Dependency-free; run via `npm test` (after the engine harness).
import { CaseIndex, Catalog } from "../store.mjs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

let pass = 0, fail = 0;
const eq = (got, want, msg) => {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g === w) { pass++; }
  else { fail++; console.error("  ✗ " + msg + "\n      got:  " + g + "\n      want: " + w); }
};

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vigil-store-"));
try {
  const ci = new CaseIndex(path.join(dir, "index.db"));
  const rows = [
    { idx:0, ts:"2025-01-01T01:00:00Z", tms:Date.parse("2025-01-01T01:00:00Z"), provider:"Security-Auditing", eid:"4624", computer:"DC01", channel:"Security", src:"Security.evtx", cat:"", body:"4624 dc01 logon administrator 10.0.0.5 mimikatz" },
    { idx:1, ts:"2025-01-01T02:00:00Z", tms:Date.parse("2025-01-01T02:00:00Z"), provider:"Sysmon", eid:"1", computer:"WS01", channel:"Sysmon", src:"Sysmon.evtx", cat:"", body:"sysmon 1 powershell -enc aaaa 192.168.1.50" },
    { idx:2, ts:"2025-01-01T03:00:00Z", tms:Date.parse("2025-01-01T03:00:00Z"), provider:"pfSense", eid:"", computer:"", channel:"fw", src:"fw.log", cat:"firewall", body:"firewall block 8.8.8.8" },
  ];
  ci.ingest(rows, 999, 3);

  eq(ci.count(), 3, "count() after ingest");
  eq([ci.indexedBytes(), ci.indexedCount()], [999, 3], "indexed byte/count checkpoint");

  // free-text: FTS token/prefix
  eq(ci.search({ q:"mimi" }, {}).ids, [0], "FTS prefix 'mimi' -> mimikatz");
  eq(ci.search({ q:"power" }, {}).ids, [1], "FTS prefix 'power' -> powershell");
  // free-text: punctuated -> substring fallback
  eq(ci.search({ q:"192.168" }, {}).ids, [1], "substring '192.168'");
  eq(ci.search({ q:"10.0.0.5" }, {}).ids, [0], "substring '10.0.0.5'");
  // structured filters
  eq(ci.search({ eid:"4624" }, {}).ids, [0], "filter eid");
  eq(ci.search({ provider:"Sysmon" }, {}).ids, [1], "filter provider (include)");
  eq(ci.search({ excluded:["Sysmon"] }, {}).ids, [0], "filter provider (exclude)");
  // firewall/vpn are excluded from the main grid
  eq(ci.search({}, {}).ids, [0, 1], "firewall row excluded from grid");
  eq(ci.search({ src:"Sysmon.evtx" }, {}).ids, [1], "filter src");
  eq(ci.search({ timeRange:{ from:Date.parse("2025-01-01T01:30:00Z"), to:Date.parse("2025-01-01T02:30:00Z") } }, {}).ids, [1], "filter timeRange");

  // detection sync + detection-dependent filters + det sort
  const sevNum = l => ({ critical:4, high:3, medium:2, low:1, info:0, informational:0 }[String(l||"").toLowerCase()] ?? 2);
  const techFromTag = t => { const m = /^attack\.(t\d{4}(?:\.\d{3})?)$/i.exec(String(t||"")); return m ? m[1].toUpperCase() : null; };
  ci.syncDetections({ 0:[{ ruleId:"R1", title:"Mimi", level:"critical", tags:["attack.t1003.001"] }] }, sevNum, techFromTag, "sig1");
  eq(ci.search({ detOnly:true }, {}).ids, [0], "detOnly");
  eq(ci.search({ ruleId:"R1" }, {}).ids, [0], "filter ruleId");
  eq(ci.search({ technique:"T1003.001" }, {}).ids, [0], "filter technique");
  eq(ci.search({}, { sortKey:"det", sortDir:-1 }).ids, [0, 1], "sort by detection level desc");

  // flags
  ci.syncFlags([1], "flag1");
  eq(ci.search({ flagged:true }, {}).ids, [1], "filter flagged");

  // pagination
  const pg = ci.search({}, { sortKey:"ts", sortDir:1, limit:1, offset:1 });
  eq([pg.ids, pg.total], [[1], 2], "pagination limit/offset (+ full total)");

  // sig-based no-op: re-sync with same signature should be idempotent
  ci.syncDetections({ 0:[{ ruleId:"R1", level:"critical" }] }, sevNum, techFromTag, "sig1");
  eq(ci.search({ detOnly:true }, {}).ids, [0], "det re-sync idempotent");
  ci.close();

  // catalog + chain of custody
  const cat = new Catalog(dir);
  cat.upsertCase({ id:"c1", name:"Test", count:3, tsMin:rows[0].ts, tsMax:rows[2].ts });
  cat.setActive("c1");
  cat.addCustody("c1", { name:"Security.evtx", sha256:"abc123", bytes:1000, type:"Security", count:1 });
  eq(cat.getActive(), "c1", "catalog active pointer");
  eq(cat.listCases().length, 1, "catalog lists case");
  eq(cat.getCustody("c1").map(c => c.sha256), ["abc123"], "custody sha recorded");
  cat.deleteCase("c1");
  eq(cat.listCases().length, 0, "catalog deleteCase");
  eq(cat.getActive(), null, "active cleared on delete of active case");
  cat.close();
} finally {
  fs.rmSync(dir, { recursive:true, force:true });
}

console.log(`\nstore.mjs tests: ${pass} passed, ${fail} failed`);
if (fail) { console.error("STORE TESTS FAILED ❌"); process.exit(1); }
console.log("STORE GREEN ✅");
