/* DFIR report rendering — turns the report model the browser already builds (reportData())
   into a real PDF or DOCX byte buffer, so the "PDF report" / "Word report" buttons produce
   proper downloadable files instead of a print dialog / hand-rolled zip. Kept pure: the client
   flattens its rich model to plain JSON and POSTs it; this module only lays it out.
   PDF uses pdfkit's built-in Helvetica (no font assets to ship); DOCX uses the `docx` lib. */
import PDFDocument from "pdfkit";
import {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  WidthType, BorderStyle, AlignmentType, HeadingLevel, ShadingType,
  Footer, PageNumber,
} from "docx";

/* ---------- palette ---------- */
const BAND = "122c4f", ACCENT = "1f5fbf", GREY = "69727d", INK = "1f2933",
      LINE = "d7dbe0", ZEBRA = "f5f8fc", HEADBG = "f5f8fc";
const SEV = { critical:"a8261c", high:"b4460f", medium:"8a6d1a", low:"274b9f", info:"274b9f", informational:"274b9f" };
const POSTURE_COLOR = { CRITICAL:"a8261c", HIGH:"b4460f", ELEVATED:"8a6d1a", GUARDED:"274b9f", LOW:"3f7a4f" };
const sevColor = (s)=> SEV[String(s||"").toLowerCase()] || GREY;
const postureColor = (p)=> POSTURE_COLOR[String(p||"").toUpperCase()] || GREY;

/* ---------- value helpers ---------- */
const S = (v, n=4000)=> (v==null?"":String(v)).slice(0, n);
const arr = (v, n=300)=> Array.isArray(v) ? v.slice(0, n) : [];
const num = (v)=> (v==null?"":String(v));

/* ===================================================================== *
 *  PDF                                                                   *
 * ===================================================================== */
/* pdfkit's Helvetica is WinAnsi-only — remap the few non-WinAnsi glyphs we emit. */
function deWinAnsi(v){
  if(typeof v==="string") return v.replace(/[→⟶]/g,"->").replace(/[←⟵]/g,"<-").replace(/↔/g,"<->").replace(/⇒/g,"=>").replace(/[•·]/g,"·").replace(/[–—]/g,"-").replace(/×/g,"x");
  if(Array.isArray(v)) return v.map(deWinAnsi);
  if(v && typeof v==="object"){ const o={}; for(const k in v) o[k]=deWinAnsi(v[k]); return o; }
  return v;
}

export function renderPdf(rawData){
  const R = deWinAnsi(rawData||{});
  return new Promise((resolve, reject)=>{
    try{
      const meta = R.meta||{};
      const doc = new PDFDocument({ size:"A4", margins:{ top:52, bottom:64, left:50, right:50 },
        info:{ Title:"DFIR Report — "+S(meta.caseName||meta.caseId,120), Author:"Vigil DFIR" }, bufferPages:true });
      const chunks=[]; doc.on("data",c=>chunks.push(c)); doc.on("end",()=>resolve(Buffer.concat(chunks))); doc.on("error",reject);

      const M=doc.page.margins, L=M.left, Rx=doc.page.width-M.right, W=Rx-L;
      const bottom = ()=> doc.page.height - M.bottom;
      const ensure = (h)=>{ if(doc.y+h > bottom()) doc.addPage(); };
      const gap = (h)=>{ doc.y += h; };

      let secN=0;
      function h2(t){ ensure(46); gap(14);
        doc.font("Helvetica-Bold").fontSize(13.5).fillColor("#"+BAND).text((++secN)+".  "+t, L, doc.y);
        doc.moveTo(L, doc.y+2).lineTo(Rx, doc.y+2).lineWidth(1.4).strokeColor("#"+BAND).stroke(); gap(8); }
      function h3(t){ ensure(28); gap(6); doc.font("Helvetica-Bold").fontSize(10).fillColor("#"+BAND).text(t, L, doc.y); gap(3); }
      function para(t, o={}){ if(t==null||t==="") return;
        doc.font(o.bold?"Helvetica-Bold":"Helvetica").fontSize(o.size||9.5).fillColor("#"+(o.color||INK))
          .text(S(t), L, doc.y, { width:W, align:o.align||"left" }); gap(o.after==null?2:o.after); }
      function small(t){ para(t, { size:8, color:GREY, after:2 }); }

      /* banner: filled rounded box, title + optional wrapped body */
      function banner(color, title, body){
        const padX=12, padY=9, innerW=W-padX*2;
        doc.font("Helvetica-Bold").fontSize(12); const th=doc.heightOfString(title,{width:innerW});
        doc.font("Helvetica").fontSize(9.5); const bh=body?doc.heightOfString(body,{width:innerW}):0;
        const h=padY*2+th+(body?4+bh:0); ensure(h+6); const y0=doc.y;
        doc.roundedRect(L,y0,W,h,4).fill("#"+color);
        doc.fillColor("#ffffff").font("Helvetica-Bold").fontSize(12).text(title, L+padX, y0+padY, {width:innerW});
        if(body) doc.font("Helvetica").fontSize(9.5).fillColor("#ffffff").text(body, L+padX, y0+padY+th+4, {width:innerW});
        doc.y=y0+h+8; doc.x=L;
      }

      /* wrapping table with zebra rows, header repeat across page breaks.
         cols:[{title,w,align?}], rows:[[str,...]] ; sevCol → colour that cell's text by severity */
      function table(cols, rows, opt={}){
        const totalW=cols.reduce((a,c)=>a+c.w,0), widths=cols.map(c=>W*c.w/totalW);
        const xs=[]; { let x=L; for(const w of widths){ xs.push(x); x+=w; } }
        const padX=5, padY=4, fs=opt.fs||8.2, hfs=8.2;
        const measure=(cells,font,size)=>{ doc.font(font).fontSize(size); let h=0;
          for(let i=0;i<cells.length;i++) h=Math.max(h, doc.heightOfString(S(cells[i],3000),{width:widths[i]-padX*2})); return h+padY*2; };
        const drawRow=(cells,{bg,font,size,color,sev})=>{
          const rh=measure(cells,font,size), y0=doc.y;
          if(bg) doc.rect(L,y0,W,rh).fill("#"+bg);
          for(let i=0;i<cells.length;i++){
            const c=(sev&&i===sev.col)? sevColor(cells[i]) : color;
            doc.font((sev&&i===sev.col)?"Helvetica-Bold":font).fontSize(size).fillColor("#"+c)
              .text(S(cells[i],3000), xs[i]+padX, y0+padY, { width:widths[i]-padX*2, align:cols[i].align||"left" });
          }
          doc.lineWidth(0.4).strokeColor("#"+LINE).rect(L,y0,W,rh).stroke();
          for(let i=1;i<xs.length;i++) doc.moveTo(xs[i],y0).lineTo(xs[i],y0+rh).stroke();
          doc.y=y0+rh; doc.x=L;
        };
        const header=()=> drawRow(cols.map(c=>c.title),{ bg:HEADBG, font:"Helvetica-Bold", size:hfs, color:GREY });
        ensure(measure(cols.map(c=>c.title),"Helvetica-Bold",hfs)*2); header();
        let z=0;
        for(const r of rows){
          const rh=measure(r,"Helvetica",fs);
          if(doc.y+rh>bottom()){ doc.addPage(); header(); }
          drawRow(r,{ bg:(z++%2)?"ffffff":ZEBRA, font:"Helvetica", size:fs, color:INK, sev:opt.sev });
        }
        doc.x=L;
      }

      /* headerless key/value facts table */
      function facts(pairs){
        const w0=W*0.26, w1=W*0.74, padX=6, padY=4, fs=8.6;
        for(const [k,v] of pairs){
          doc.font("Helvetica-Bold").fontSize(fs); const hk=doc.heightOfString(k,{width:w0-padX*2});
          doc.font("Helvetica").fontSize(fs); const hv=doc.heightOfString(S(v),{width:w1-padX*2});
          const rh=Math.max(hk,hv)+padY*2; ensure(rh); const y0=doc.y;
          doc.rect(L,y0,w0,rh).fill("#"+ZEBRA);
          doc.lineWidth(0.4).strokeColor("#"+LINE).rect(L,y0,W,rh).stroke().moveTo(L+w0,y0).lineTo(L+w0,y0+rh).stroke();
          doc.font("Helvetica-Bold").fontSize(fs).fillColor("#"+GREY).text(k, L+padX, y0+padY, {width:w0-padX*2});
          doc.font("Helvetica").fontSize(fs).fillColor("#"+INK).text(S(v), L+w0+padX, y0+padY, {width:w1-padX*2});
          doc.y=y0+rh; doc.x=L;
        }
      }

      /* ---- Cover ---- */
      doc.font("Helvetica-Bold").fontSize(10).fillColor("#"+ACCENT)
        .text("INCIDENT RESPONSE · DIGITAL FORENSICS", L, doc.y, { characterSpacing:1.5 });
      doc.moveTo(L,doc.y+3).lineTo(Rx,doc.y+3).lineWidth(3).strokeColor("#"+BAND).stroke(); gap(8);
      doc.font("Helvetica-Bold").fontSize(23).fillColor("#"+BAND).text(S(meta.title||"Windows Event Log Triage Report",160), L, doc.y); gap(4);
      // classification chip
      { const lbl=S(meta.classification||"CONFIDENTIAL",40); doc.font("Helvetica-Bold").fontSize(8.5);
        const wchip=doc.widthOfString(lbl)+14, y0=doc.y; doc.roundedRect(L,y0,wchip,15,3).fill("#fdecea");
        doc.fillColor("#a8261c").text(lbl, L+7, y0+3.5); doc.y=y0+15; doc.x=L; }
      gap(10);
      facts([
        ["Case reference", meta.caseId||"—"],
        ["Report generated", meta.generated||"—"],
        ["Analysis window", meta.span||"—"],
        ["Scope", meta.scope||"—"],
        ["Hosts", (meta.hosts&&meta.hosts.length)? meta.hosts.join(", ") : "—"],
        ["Source logs", (meta.files&&meta.files.length)? meta.files.join(", ") : "—"],
        ["Assessed posture", S(R.posture||"—")],
        ["Prepared by", meta.preparedBy || (meta.analyst? meta.analyst+" · Vigil DFIR" : "Vigil DFIR (automated analysis)")],
      ]);
      gap(6);
      banner(postureColor(R.posture), "ASSESSED POSTURE: "+S(R.posture||"UNDETERMINED",40).toUpperCase(), S(R.bannerText||""));

      /* ---- 1. Executive Summary ---- */
      h2("Executive Summary");
      para(R.exec, { size:10.5, after:6 });
      const cards=arr(R.cards,8);
      if(cards.length) table([{title:"Metric",w:0.62},{title:"Value",w:0.38,align:"right"}], cards.map(c=>[c.l, num(c.n)]));

      /* ---- Analyst Assessment ---- */
      const an=R.analyst||{};
      if(an.summary || arr(an.findings).length || arr(an.verdicts).length){
        h2("Analyst Assessment");
        if(an.summary) para(an.summary, {after:6});
        const fs=arr(an.findings,60);
        if(fs.length){ h3("Key findings");
          table([{title:"Severity",w:0.16},{title:"Finding",w:0.84}],
            fs.map(f=>[S(f.severity,20).toUpperCase(), S(f.title,300)+(f.note?"  —  "+S(f.note,2000):"")], ),
            { sev:{col:0} }); }
        if(an.verdictSummary) small("Event verdicts recorded — "+S(an.verdictSummary,400));
        const vs=arr(an.verdicts,40);
        if(vs.length) table([{title:"Verdict",w:0.2},{title:"Event #",w:0.14},{title:"Tags",w:0.28},{title:"Analyst note",w:0.38}],
          vs.map(v=>[S(v.verdict,40),num(v.idx),S(v.tags,120),S(v.note,400)]));
      }

      /* ---- Incident Overview ---- */
      const bs=R.bySev||{};
      h2("Incident Overview");
      table([{title:"Critical",w:1,align:"center"},{title:"High",w:1,align:"center"},{title:"Medium",w:1,align:"center"},{title:"Low / Info",w:1,align:"center"}],
        [[num(bs.crit||0),num(bs.high||0),num(bs.med||0),num(bs.low||0)]]);
      if(R.engineLine) small(R.engineLine);

      /* ---- MITRE ATT&CK ---- */
      const A=R.attack||{};
      if(arr(A.techniques).length){
        h2("MITRE ATT&CK Coverage");
        if(A.tacticsLine) para("Tactics observed: "+A.tacticsLine, {color:GREY, size:8.5, after:4});
        table([{title:"Technique",w:0.2},{title:"Name",w:0.66},{title:"Events",w:0.14,align:"center"}],
          arr(A.techniques,30).map(t=>[S(t.id,20),S(t.name,160),num(t.count)]));
      }

      /* ---- Attack Narrative ---- */
      const ch=arr(R.chains,10);
      if(ch.length){
        h2("Attack Narrative");
        para("Related detections correlated per host into chronological chains progressing across ATT&CK tactics.", {color:GREY, size:8.5, after:6});
        for(const c of ch){
          ensure(46);
          const y0=doc.y; const boxPadX=10;
          doc.font("Helvetica-Bold").fontSize(9.5).fillColor("#"+BAND).text(S(c.name,200), L+boxPadX, y0+6, {width:W-boxPadX*2});
          if(c.meta){ doc.font("Helvetica").fontSize(8).fillColor("#"+GREY).text(S(c.meta,400), L+boxPadX, doc.y+1, {width:W-boxPadX*2}); }
          if(c.steps){ doc.font("Helvetica").fontSize(8).fillColor("#"+INK).text("Steps: "+S(c.steps,2000), L+boxPadX, doc.y+2, {width:W-boxPadX*2}); }
          const h=doc.y-y0+7;
          doc.lineWidth(0.5).strokeColor("#"+LINE).rect(L,y0,W,h).stroke();
          doc.rect(L,y0,3,h).fill("#"+ACCENT);
          doc.y=y0+h; doc.x=L; gap(7);
        }
      }

      /* ---- Affected Entities ---- */
      const ent=arr(R.entities,15);
      if(ent.length){
        h2("Affected Entities");
        table([{title:"Type",w:0.16},{title:"Entity",w:0.4},{title:"Risk",w:0.14,align:"center"},{title:"Detections",w:0.16,align:"center"},{title:"Techniques",w:0.14,align:"center"}],
          ent.map(e=>[S(e.type,30),S(e.name,160),num(e.score),num(e.hits),num(e.techniques)]));
      }

      /* ---- Detection Summary ---- */
      const br=arr(R.byRule,30);
      if(br.length){
        h2("Detection Summary");
        table([{title:"Severity",w:0.14},{title:"Detection",w:0.56},{title:"Source",w:0.16},{title:"Events",w:0.14,align:"center"}],
          br.map(g=>[S(g.level,20).toUpperCase(),S(g.title,220),S(g.source,40),num(g.count)]), { sev:{col:0} });
      }

      /* ---- Forensic Evidence ---- */
      const evd=arr(R.evidence,20);
      if(evd.length){
        h2("Forensic Evidence");
        table([{title:"Artifact",w:0.7},{title:"Count",w:0.3,align:"center"}], evd.map(e=>[S(e.artifact,120),num(e.count)]));
      }

      /* ---- Indicators of Compromise ---- */
      const io=R.iocs||{};
      if(arr(io.ips).length||arr(io.domains).length||arr(io.hashes).length){
        h2("Indicators of Compromise");
        if(arr(io.ips).length){ h3("External IP addresses ("+io.ips.length+")");
          para(arr(io.ips,60).map(x=>x.v+(x.n?" x"+x.n:"")).join("   "), {size:8, color:INK}); }
        if(arr(io.domains).length){ h3("Domains ("+io.domains.length+")");
          para(arr(io.domains,60).join("   "), {size:8, color:INK}); }
        if(arr(io.hashes).length){ h3("File hashes ("+io.hashes.length+")");
          para(arr(io.hashes,50).join("\n"), {size:7.5, color:GREY}); }
      }

      /* ---- Recommendations ---- */
      const rec=arr(R.recommendations,30);
      if(rec.length){
        h2("Recommendations");
        for(const r of rec){ ensure(20);
          const y0=doc.y; doc.font("Helvetica-Bold").fontSize(9.5).fillColor("#"+ACCENT).text("»", L, y0, {width:14});
          doc.font("Helvetica").fontSize(9.5).fillColor("#"+INK).text(S(r), L+16, y0, {width:W-16}); gap(5); }
      }

      /* ---- disclaimer ---- */
      gap(10);
      small(S(R.disclaimer || "Generated by Vigil DFIR — automated triage aid; findings are heuristic and rule-based and require analyst validation. CONFIDENTIAL — handle per your organisation's data-classification policy.", 800));

      /* ---- footers ---- */
      const range=doc.bufferedPageRange();
      for(let i=0;i<range.count;i++){ doc.switchToPage(range.start+i);
        const y=doc.page.height-30; doc.font("Helvetica").fontSize(7.5).fillColor("#"+GREY);
        doc.text("Vigil DFIR — "+S(meta.caseId||"DFIR Report",60), L, y, {lineBreak:false});
        doc.text("Page "+(i+1)+" of "+range.count, L, y, {width:W, align:"right", lineBreak:false}); }

      doc.end();
    }catch(err){ reject(err); }
  });
}

/* ===================================================================== *
 *  DOCX                                                                  *
 * ===================================================================== */
const HEX = (h)=> String(h).toUpperCase();
const run = (t, o={})=> new TextRun({ text:S(t,6000), bold:!!o.bold, italics:!!o.italic, size:o.size||19, color:HEX(o.color||INK) });
const P = (t, o={})=> new Paragraph({ spacing:{ before:o.before||0, after:o.after==null?70:o.after }, alignment:o.align||AlignmentType.LEFT,
  children: Array.isArray(t)? t : [ run(t,o) ] });
function H2(t, n){ return new Paragraph({ spacing:{before:260,after:100}, border:{ bottom:{ style:BorderStyle.SINGLE, size:12, color:HEX(BAND), space:2 } },
  children:[ run((n?n+".  ":"")+t, { bold:true, color:BAND, size:26 }) ] }); }
const H3 = (t)=> new Paragraph({ spacing:{before:140,after:50}, children:[ run(t,{bold:true,color:BAND,size:20}) ] });

const cell = (text, o={})=> new TableCell({
  width: o.w!=null ? { size:o.w, type:WidthType.PERCENTAGE } : undefined,
  shading: o.bg ? { type:ShadingType.CLEAR, fill:HEX(o.bg), color:"auto" } : undefined,
  margins:{ top:40, bottom:40, left:70, right:70 },
  children:[ new Paragraph({ alignment:o.align||AlignmentType.LEFT, children:[ run(text, { bold:o.bold, color:o.color||INK, size:o.size||16 }) ] }) ],
});
const TBORDER = { style:BorderStyle.SINGLE, size:4, color:HEX(LINE) };
const BORDERS = { top:TBORDER, bottom:TBORDER, left:TBORDER, right:TBORDER, insideHorizontal:TBORDER, insideVertical:TBORDER };
const NOBORDER = { top:{style:BorderStyle.NONE},bottom:{style:BorderStyle.NONE},left:{style:BorderStyle.NONE},right:{style:BorderStyle.NONE},insideHorizontal:{style:BorderStyle.NONE},insideVertical:{style:BorderStyle.NONE} };
function dtable(headers, rows, opt={}){
  const head = new TableRow({ tableHeader:true, children: headers.map(h=> cell(h.t,{bold:true,color:GREY,bg:HEADBG,w:h.w,align:h.align})) });
  const body = rows.map((r,i)=> new TableRow({ children: r.map((c,ci)=>{
    const sev = opt.sev && ci===opt.sev.col;
    return cell(c, { bg:(i%2)?undefined:ZEBRA, w:headers[ci]&&headers[ci].w, align:headers[ci]&&headers[ci].align,
      bold:sev, color: sev? sevColor(c) : INK }); }) }));
  return new Table({ width:{size:100,type:WidthType.PERCENTAGE}, borders:BORDERS, rows:[head,...body] });
}
function bannerTable(color, title, body){
  return new Table({ width:{size:100,type:WidthType.PERCENTAGE}, borders:NOBORDER, rows:[ new TableRow({ children:[ new TableCell({
    shading:{ type:ShadingType.CLEAR, fill:HEX(color), color:"auto" }, margins:{top:120,bottom:120,left:160,right:160},
    children:[ new Paragraph({ children:[ run(title,{bold:true,color:"FFFFFF",size:24}) ] },),
      ...(body? [ new Paragraph({ spacing:{before:40}, children:[ run(body,{color:"FFFFFF",size:19}) ] }) ] : []) ] }) ] }) ] });
}

export async function renderDocx(rawData){
  const R = rawData||{}, meta=R.meta||{};
  const body=[]; let secN=0; const nx=()=>++secN;

  /* cover */
  body.push(P([ run("INCIDENT RESPONSE · DIGITAL FORENSICS",{bold:true,color:ACCENT,size:18}) ], {after:20}));
  body.push(P([ run(S(meta.title||"Windows Event Log Triage Report",160),{bold:true,color:BAND,size:44}) ], {after:40}));
  body.push(new Table({ width:{size:26,type:WidthType.PERCENTAGE}, borders:NOBORDER, rows:[ new TableRow({ children:[ new TableCell({
    shading:{type:ShadingType.CLEAR,fill:"FDECEA",color:"auto"}, margins:{top:20,bottom:20,left:80,right:80},
    children:[ new Paragraph({ children:[ run(S(meta.classification||"CONFIDENTIAL",40),{bold:true,color:"A8261C",size:16}) ] }) ] }) ] }) ] }));
  body.push(P("", {after:60}));
  { const factRows=[
      ["Case reference", meta.caseId||"—"], ["Report generated", meta.generated||"—"],
      ["Analysis window", meta.span||"—"], ["Scope", meta.scope||"—"],
      ["Hosts", (meta.hosts&&meta.hosts.length)? meta.hosts.join(", "):"—"],
      ["Source logs", (meta.files&&meta.files.length)? meta.files.join(", "):"—"],
      ["Assessed posture", S(R.posture||"—")],
      ["Prepared by", meta.preparedBy || (meta.analyst? meta.analyst+" · Vigil DFIR":"Vigil DFIR (automated analysis)")],
    ].map(([k,v])=> new TableRow({ children:[ cell(k,{bold:true,color:GREY,bg:ZEBRA,w:26}), cell(v,{w:74}) ] }));
    body.push(new Table({ width:{size:100,type:WidthType.PERCENTAGE}, borders:BORDERS, rows:factRows })); }
  body.push(P("", {after:60}));
  body.push(bannerTable(postureColor(R.posture), "ASSESSED POSTURE: "+S(R.posture||"UNDETERMINED",40).toUpperCase(), S(R.bannerText||"")));

  /* 1. Executive Summary */
  body.push(H2("Executive Summary", nx()));
  if(R.exec) body.push(P(R.exec, {after:100}));
  const cards=arr(R.cards,8);
  if(cards.length) body.push(dtable([{t:"Metric",w:62},{t:"Value",w:38,align:AlignmentType.RIGHT}], cards.map(c=>[c.l,num(c.n)])));

  /* Analyst Assessment */
  const an=R.analyst||{};
  if(an.summary || arr(an.findings).length || arr(an.verdicts).length){
    body.push(H2("Analyst Assessment", nx()));
    if(an.summary) body.push(P(an.summary, {after:80}));
    const fs=arr(an.findings,60);
    if(fs.length){ body.push(H3("Key findings"));
      body.push(dtable([{t:"Severity",w:16},{t:"Finding",w:84}],
        fs.map(f=>[S(f.severity,20).toUpperCase(), S(f.title,300)+(f.note?"  —  "+S(f.note,2000):"")]), {sev:{col:0}})); }
    if(an.verdictSummary) body.push(P("Event verdicts recorded — "+S(an.verdictSummary,400), {color:GREY,size:16}));
    const vs=arr(an.verdicts,40);
    if(vs.length) body.push(dtable([{t:"Verdict",w:20},{t:"Event #",w:14,align:AlignmentType.CENTER},{t:"Tags",w:28},{t:"Analyst note",w:38}],
      vs.map(v=>[S(v.verdict,40),num(v.idx),S(v.tags,120),S(v.note,400)])));
  }

  /* Incident Overview */
  const bs=R.bySev||{};
  body.push(H2("Incident Overview", nx()));
  body.push(dtable([{t:"Critical",w:25,align:AlignmentType.CENTER},{t:"High",w:25,align:AlignmentType.CENTER},{t:"Medium",w:25,align:AlignmentType.CENTER},{t:"Low / Info",w:25,align:AlignmentType.CENTER}],
    [[num(bs.crit||0),num(bs.high||0),num(bs.med||0),num(bs.low||0)]]));
  if(R.engineLine) body.push(P(R.engineLine, {color:GREY,size:16,before:50}));

  /* ATT&CK */
  const A=R.attack||{};
  if(arr(A.techniques).length){
    body.push(H2("MITRE ATT&CK Coverage", nx()));
    if(A.tacticsLine) body.push(P("Tactics observed: "+A.tacticsLine, {color:GREY,size:16,after:40}));
    body.push(dtable([{t:"Technique",w:20},{t:"Name",w:66},{t:"Events",w:14,align:AlignmentType.CENTER}],
      arr(A.techniques,30).map(t=>[S(t.id,20),S(t.name,160),num(t.count)])));
  }

  /* Attack Narrative */
  const ch=arr(R.chains,10);
  if(ch.length){
    body.push(H2("Attack Narrative", nx()));
    body.push(P("Related detections correlated per host into chronological chains progressing across ATT&CK tactics.", {color:GREY,size:16,after:60}));
    for(const c of ch){
      body.push(new Table({ width:{size:100,type:WidthType.PERCENTAGE},
        borders:{ ...NOBORDER, left:{style:BorderStyle.SINGLE,size:18,color:HEX(ACCENT)} },
        rows:[ new TableRow({ children:[ new TableCell({ shading:{type:ShadingType.CLEAR,fill:"F7FAFF",color:"auto"}, margins:{top:60,bottom:60,left:120,right:120},
          children:[ P([run(S(c.name,200),{bold:true,color:BAND,size:19})],{after:20}),
            ...(c.meta? [P([run(S(c.meta,400),{color:GREY,size:16})],{after:20})] : []),
            ...(c.steps? [P([run("Steps: "+S(c.steps,2000),{size:16})],{after:0})] : []) ] }) ] }) ] }));
      body.push(P("", {after:60}));
    }
  }

  /* Affected Entities */
  const ent=arr(R.entities,15);
  if(ent.length){
    body.push(H2("Affected Entities", nx()));
    body.push(dtable([{t:"Type",w:16},{t:"Entity",w:40},{t:"Risk",w:14,align:AlignmentType.CENTER},{t:"Detections",w:16,align:AlignmentType.CENTER},{t:"Techniques",w:14,align:AlignmentType.CENTER}],
      ent.map(e=>[S(e.type,30),S(e.name,160),num(e.score),num(e.hits),num(e.techniques)])));
  }

  /* Detection Summary */
  const br=arr(R.byRule,30);
  if(br.length){
    body.push(H2("Detection Summary", nx()));
    body.push(dtable([{t:"Severity",w:14},{t:"Detection",w:56},{t:"Source",w:16},{t:"Events",w:14,align:AlignmentType.CENTER}],
      br.map(g=>[S(g.level,20).toUpperCase(),S(g.title,220),S(g.source,40),num(g.count)]), {sev:{col:0}}));
  }

  /* Forensic Evidence */
  const evd=arr(R.evidence,20);
  if(evd.length){
    body.push(H2("Forensic Evidence", nx()));
    body.push(dtable([{t:"Artifact",w:70},{t:"Count",w:30,align:AlignmentType.CENTER}], evd.map(e=>[S(e.artifact,120),num(e.count)])));
  }

  /* IOCs */
  const io=R.iocs||{};
  if(arr(io.ips).length||arr(io.domains).length||arr(io.hashes).length){
    body.push(H2("Indicators of Compromise", nx()));
    if(arr(io.ips).length){ body.push(H3("External IP addresses ("+io.ips.length+")"));
      body.push(P(arr(io.ips,60).map(x=>x.v+(x.n?" ×"+x.n:"")).join("   "), {size:15})); }
    if(arr(io.domains).length){ body.push(H3("Domains ("+io.domains.length+")"));
      body.push(P(arr(io.domains,60).join("   "), {size:15})); }
    if(arr(io.hashes).length){ body.push(H3("File hashes ("+io.hashes.length+")"));
      body.push(P(arr(io.hashes,50).join("\n"), {size:14,color:GREY})); }
  }

  /* Recommendations */
  const rec=arr(R.recommendations,30);
  if(rec.length){
    body.push(H2("Recommendations", nx()));
    for(const r of rec) body.push(P([ run("»  ",{bold:true,color:ACCENT}), run(S(r)) ], {after:60}));
  }

  body.push(P(S(R.disclaimer || "Generated by Vigil DFIR — automated triage aid; findings are heuristic and rule-based and require analyst validation. CONFIDENTIAL — handle per your organisation's data-classification policy.",800),
    {color:GREY,size:15,before:120}));

  const doc = new Document({
    creator:"Vigil DFIR", title:"DFIR Report — "+S(meta.caseName||meta.caseId,120),
    styles:{ default:{ document:{ run:{ font:"Calibri" } } } },
    sections:[{
      properties:{ page:{ margin:{ top:900, bottom:1000, left:960, right:960 } } },
      footers:{ default: new Footer({ children:[ new Paragraph({ alignment:AlignmentType.CENTER, children:[
        run("Vigil DFIR — "+S(meta.caseId||"DFIR Report",60)+" · Page ", {size:15,color:GREY}),
        new TextRun({ children:[PageNumber.CURRENT], size:15, color:HEX(GREY) }),
        run(" of ", {size:15,color:GREY}),
        new TextRun({ children:[PageNumber.TOTAL_PAGES], size:15, color:HEX(GREY) }),
      ] }) ] }) },
      children: body,
    }],
  });
  return await Packer.toBuffer(doc);
}
