(function(){
"use strict";

/* ---------- state ---------- */
const KEY="tickmark.v1";
function today(){const d=new Date();return d.toISOString().slice(0,10)}
function addDays(iso,n){const d=new Date(iso+"T12:00:00");d.setDate(d.getDate()+n);return d.toISOString().slice(0,10)}
function defaultSetup(){
  return {fw:"",audit:"point",fieldwork:addDays(today(),56),pstart:addDays(today(),-300),pend:addDays(today(),56),org:"",size:"mid",
    domains:DOMAINS.map(d=>d[0]),stack:{cloud:"azure",idp:"Microsoft Entra ID",ticket:"ServiceNow",edr:"Microsoft Defender for Endpoint",siem:"Microsoft Sentinel",vuln:"Tenable",mdm:"Microsoft Intune",hris:"Workday",vcs:"Azure DevOps",lms:"KnowBe4",docs:"SharePoint"},notes:""};
}
let S = load() || {view:"setup",setup:defaultSetup(),items:[]};
let F = {q:"",status:"all",owner:"all"};
function load(){try{const r=localStorage.getItem(KEY);return r?JSON.parse(r):null}catch(e){return null}}
function save(){try{localStorage.setItem(KEY,JSON.stringify(S))}catch(e){}}

/* ---------- helpers ---------- */
const $=(s,r=document)=>r.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const noDash=s=>String(s||"").replace(/\s*\u2014\s*/g,", ").replace(/\u2013/g,"-");
function fmtDate(iso){if(!iso)return"";const d=new Date(iso+"T12:00:00");return d.toLocaleDateString(undefined,{month:"short",day:"numeric",year:"numeric"})}
function fillSrc(src,stack){const c=CLOUD[stack.cloud]||CLOUD.azure;const map={...stack,...c,cloud:STACK.cloud.opts[stack.cloud]};return src.replace(/\{(\w+)\}/g,(m,k)=>map[k]||m)}
function toast(msg){const t=$("#toast");t.textContent=msg;t.style.display="block";clearTimeout(toast._t);toast._t=setTimeout(()=>t.style.display="none",2600)}
function ownerTitles(){return [...new Set(Object.values(OWNERS[S.setup.size]||OWNERS.mid))]}
function topicsFor(fw,domains){return TOPICS.filter(t=>domains.includes(t.d)&&t.m[fw]&&t.m[fw].length)}
function sampleNote(it){
  if(!it.sample)return"";
  const s=S.setup;
  if(s.audit==="period")return "Provide the full population from "+fmtDate(s.pstart)+" to "+fmtDate(s.pend)+". The auditor selects the samples.";
  return "Provide a recent example (last 90 days) showing the control operating.";
}
const TICK='<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 13.5c2 1.2 3.4 2.8 4.6 4.6C11 12 14.6 7.4 20 4" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';
function face(st){
  if(st==="accepted")return TICK;
  if(st==="received")return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 13.5c2 1.2 3.4 2.8 4.6 4.6C10 15.4 11.5 13.2 13 11.4" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  if(st==="requested")return '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3.4" fill="currentColor"/></svg>';
  if(st==="na")return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 12h12" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg>';
  return "";
}

/* ---------- generate ---------- */
function generate(setup, demo){
  const fw=setup.fw, own=OWNERS[setup.size];
  const items=[];
  topicsFor(fw,setup.domains).forEach(t=>{
    t.e.forEach((e,i)=>{
      const [name,type,src,sample,ov]=e;
      const due=setup.fieldwork?addDays(setup.fieldwork,-7*(LEAD[type]||4)):"";
      items.push({id:t.id+"-"+i,topic:t.id,domain:t.d,group:t.t,controls:t.m[fw].slice(),name,type,source:fillSrc(src,setup.stack),sample:!!sample,owner:own[ov||t.o],due,status:"not_started",note:""});
    });
  });
  if(demo){
    const pattern=["accepted","accepted","received","requested","accepted","not_started","received","requested","accepted","not_started","received","accepted"];
    items.forEach((it,i)=>{it.status=pattern[i%pattern.length]});
    const n=items.find(i=>i.topic==="mfa"); if(n)n.note="Two service accounts excluded from MFA. Compensating control: IP allowlist. Exception approved by CISO.";
  }
  return items;
}

/* ---------- SETUP VIEW ---------- */
function renderSetup(){
  const s=S.setup;
  $("#projName").textContent=""; $("#newBtn").hidden=true;
  const count=s.fw?topicsFor(s.fw,s.domains).reduce((a,t)=>a+t.e.length,0):0;
  const ctrlCount=s.fw?new Set(topicsFor(s.fw,s.domains).flatMap(t=>t.m[s.fw])).size:0;
  $("#main").innerHTML=`
  <section class="wrap hero">
    <div>
      <h1>Know what your auditor will ask for before they ask.</h1>
    </div>
    <div>
      <p>Pick a framework and describe your environment. Tickmark builds the evidence request list: every artifact mapped to its control, where to pull it from, who owns it, and when it is due.</p>
      <div class="ctas"><a class="btn primary" href="#build">Start an assessment</a><button class="btn" type="button" id="demoBtn">Open a sample CMMC assessment</button></div>
    </div>
  </section>
  <section class="wrap" aria-hidden="true">
    <div class="ledger">
      <div class="lh"><span>Control</span><span>Evidence requested</span><span></span></div>
      <div class="lr"><b>A.8.5</b><span>MFA enforcement policy, Entra ID conditional access</span>${'<svg class="tick" viewBox="0 0 24 24"><path d="M4 13.5c2 1.2 3.4 2.8 4.6 4.6C11 12 14.6 7.4 20 4" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>'}</div>
      <div class="lr"><b>CC6.2</b><span>Access requests with manager approval, full population for the period</span>${'<svg class="tick" viewBox="0 0 24 24"><path d="M4 13.5c2 1.2 3.4 2.8 4.6 4.6C11 12 14.6 7.4 20 4" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>'}</div>
      <div class="lr"><b>RA-5</b><span>Tenable scan results across the review period</span>${'<svg class="tick" viewBox="0 0 24 24"><path d="M4 13.5c2 1.2 3.4 2.8 4.6 4.6C11 12 14.6 7.4 20 4" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>'}</div>
      <div class="lr"><b>3.12.4</b><span>System security plan with boundary and data flow diagrams</span>${'<svg class="tick" viewBox="0 0 24 24"><path d="M4 13.5c2 1.2 3.4 2.8 4.6 4.6C11 12 14.6 7.4 20 4" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>'}</div>
    </div>
  </section>

  <form class="wrap setup" id="build" onsubmit="return false" novalidate>
    <div class="step"><h2>Framework<small>Each artifact also shows the controls it satisfies in the other six frameworks.</small></h2>
      <div class="body"><div class="fw-grid" role="group" aria-label="Framework">
        ${FW_ORDER.map(k=>`<button type="button" class="fw" data-fw="${k}" aria-pressed="${s.fw===k}"><b>${FW[k].short}</b><span>${FW[k].blurb}</span></button>`).join("")}
      </div></div></div>

    <div class="step"><h2>Audit<small>Due dates count back from fieldwork. Sampling guidance follows the audit type.</small></h2>
      <div class="body">
        <div class="field" style="margin-bottom:16px"><span class="lab" id="atl">Audit type</span>
          <div class="seg" role="group" aria-labelledby="atl">${Object.entries(AUDIT).map(([k,v])=>`<button type="button" data-audit="${k}" aria-pressed="${s.audit===k}" title="${v.hint}">${v.label}</button>`).join("")}</div>
          <span class="hint">${AUDIT[s.audit].hint}</span></div>
        <div class="fields">
          <div class="field"><label for="fieldwork">Fieldwork starts</label><input class="input" type="date" id="fieldwork" value="${s.fieldwork}"></div>
          ${s.audit==="period"?`<div class="field"><label for="pstart">Review period start</label><input class="input" type="date" id="pstart" value="${s.pstart}"></div>
          <div class="field"><label for="pend">Review period end</label><input class="input" type="date" id="pend" value="${s.pend}"></div>`:""}
        </div>
      </div></div>

    <div class="step"><h2>Organization<small>Size sets default owner titles. You can reassign any item later.</small></h2>
      <div class="body"><div class="fields">
        <div class="field"><label for="org">Organization name</label><input class="input" id="org" value="${esc(s.org)}" placeholder="Acme Federal" autocomplete="organization"></div>
        <div class="field"><label for="size">Headcount</label><select class="input" id="size">${Object.entries(SIZES).map(([k,v])=>`<option value="${k}" ${s.size===k?"selected":""}>${v}</option>`).join("")}</select></div>
      </div>
      <div class="field" style="margin-top:16px"><label for="notes">Scope notes <span style="font-weight:400;color:var(--graphite)">(optional, used by AI suggestions)</span></label>
        <textarea class="input" id="notes" placeholder="Example: 120-person contractor, CUI for one Army contract, enclave in Azure Government, two remote offices">${esc(s.notes)}</textarea></div>
      </div></div>

    <div class="step"><h2>Scope<small>Uncheck areas outside the audit boundary.</small></h2>
      <div class="body"><div class="checks">
        ${DOMAINS.map(([k,n,dsc])=>`<label class="check ${s.domains.includes(k)?"":"off"}"><input type="checkbox" data-dom="${k}" ${s.domains.includes(k)?"checked":""}><div><b>${n}</b><span>${dsc}</span></div></label>`).join("")}
      </div></div></div>

    <div class="step"><h2>Tools<small>Sources name the exact system to pull each artifact from.</small></h2>
      <div class="body"><div class="fields">
        ${Object.entries(STACK).map(([k,v])=>{const opts=Array.isArray(v.opts)?v.opts.map(o=>[o,o]):Object.entries(v.opts);return `<div class="field"><label for="st-${k}">${v.label}</label><select class="input" id="st-${k}" data-stack="${k}">${opts.map(([val,lab])=>`<option value="${esc(val)}" ${s.stack[k]===val?"selected":""}>${esc(lab)}</option>`).join("")}</select></div>`}).join("")}
      </div></div></div>

    <div class="gen">
      <button type="button" class="btn primary" id="genBtn">Build evidence list</button>
      <span class="count" id="genCount">${s.fw?`${count} evidence items across ${ctrlCount} ${FW[s.fw].short} controls`:"Choose a framework to continue"}</span>
      <span class="err" id="genErr" role="alert"></span>
    </div>
  </form>`;
  bindSetup();
}
function bindSetup(){
  const s=S.setup;
  const rerender=(keepY=true)=>{const y=scrollY;renderSetup();if(keepY)scrollTo(0,y)};
  document.querySelectorAll("[data-fw]").forEach(b=>b.onclick=()=>{s.fw=b.dataset.fw;save();rerender()});
  document.querySelectorAll("[data-audit]").forEach(b=>b.onclick=()=>{s.audit=b.dataset.audit;save();rerender()});
  document.querySelectorAll("[data-dom]").forEach(c=>c.onchange=()=>{const k=c.dataset.dom;s.domains=c.checked?[...new Set([...s.domains,k])]:s.domains.filter(x=>x!==k);save();rerender()});
  document.querySelectorAll("[data-stack]").forEach(c=>c.onchange=()=>{s.stack[c.dataset.stack]=c.value;save()});
  ["fieldwork","pstart","pend","org","notes"].forEach(id=>{const el=$("#"+id);if(el)el.oninput=()=>{s[id]=el.value;save()}});
  $("#size").onchange=e=>{s.size=e.target.value;save()};
  $("#demoBtn").onclick=startDemo;
  $("#genBtn").onclick=()=>{
    const err=$("#genErr");
    if(!s.fw){err.textContent="Choose a framework first.";$(".fw").focus();return}
    if(!s.domains.length){err.textContent="Select at least one area in scope.";return}
    if(s.audit==="period"&&s.pstart>s.pend){err.textContent="The review period ends before it starts. Check the dates.";return}
    S.items=generate(s,false);S.view="work";save();F={q:"",status:"all",owner:"all"};render();scrollTo(0,0);
  };
}
function startDemo(){
  const s=defaultSetup();
  Object.assign(s,{fw:"cmmc",audit:"point",org:"Northwind Federal Systems",size:"mid",notes:"140-person defense contractor. CUI for two Army contracts lives in an Azure Government enclave. One headquarters office plus a lab."});
  S={view:"work",setup:s,items:generate(s,true)};F={q:"",status:"all",owner:"all"};save();render();scrollTo(0,0);
}

/* ---------- WORKSPACE VIEW ---------- */
function counts(list){const c={total:list.length,not_started:0,requested:0,received:0,accepted:0,na:0};list.forEach(i=>c[i.status]++);return c}
function renderWork(){
  const s=S.setup;
  $("#projName").textContent=(s.org||"Untitled")+" / "+FW[s.fw].short;
  $("#newBtn").hidden=false;
  $("#main").innerHTML=`
  <section class="wrap ws-head">
    <div><h1>${esc(s.org||"Untitled organization")}: ${FW[s.fw].full}</h1>
      <div class="meta">${AUDIT[s.audit].label}${s.fieldwork?", fieldwork "+fmtDate(s.fieldwork):""}${s.audit==="period"?", period "+fmtDate(s.pstart)+" to "+fmtDate(s.pend):""}</div></div>
    <div class="acts">
      <button class="btn" type="button" id="suggestBtn" hidden>Suggest missing evidence</button>
      <button class="btn" type="button" id="addBtn">Add item</button>
      <button class="btn" type="button" id="exportBtn">Export CSV</button>
      <button class="btn ghost" type="button" id="editSetup">Edit setup</button>
    </div>
  </section>
  <section class="wrap" id="summary"></section>
  <section class="wrap ws">
    <nav class="side" aria-label="Areas"><h3>Areas in scope</h3><ul class="dnav" id="dnav"></ul>
      <p class="note">Statuses are saved in this browser. Export to CSV to share the list with control owners or load it into your GRC platform.</p></nav>
    <div>
      <div class="tools">
        <label class="sr" for="q">Search evidence</label><input class="input search" id="q" type="search" placeholder="Search evidence, control IDs, sources" value="${esc(F.q)}">
        <label class="sr" for="fs">Status</label><select class="input" id="fs"><option value="all">All statuses</option><option value="open">Still open</option><option value="overdue">Overdue</option>${STATUS.map(([k,v])=>`<option value="${k}">${v}</option>`).join("")}</select>
        <label class="sr" for="fo">Owner</label><select class="input" id="fo"><option value="all">All owners</option>${[...new Set(S.items.map(i=>i.owner))].sort().map(o=>`<option>${esc(o)}</option>`).join("")}</select>
      </div>
      <div id="list"></div>
    </div>
  </section>`;
  $("#fs").value=F.status; $("#fo").value=[...$("#fo").options].some(o=>o.value===F.owner)?F.owner:"all";
  $("#q").oninput=e=>{F.q=e.target.value;renderList()};
  $("#fs").onchange=e=>{F.status=e.target.value;renderList()};
  $("#fo").onchange=e=>{F.owner=e.target.value;renderList()};
  $("#editSetup").onclick=()=>{if(confirm("Rebuilding from setup replaces this list and its statuses. Continue to setup?")){S.view="setup";save();render();scrollTo(0,0)}};
  $("#addBtn").onclick=openAdd;
  $("#exportBtn").onclick=exportCSV;
  $("#suggestBtn").onclick=openSuggest;
  if(sampleFn)$("#suggestBtn").hidden=false;
  renderSummary();renderList();
}
function renderSummary(){
  const live=S.items.filter(i=>i.status!=="na");const c=counts(live);
  const pct=n=>live.length?(n/live.length*100):0;
  const t=today();
  const overdue=live.filter(i=>i.due&&i.due<t&&i.status!=="accepted"&&i.status!=="received").length;
  const next=live.filter(i=>i.due&&i.status==="not_started").map(i=>i.due).sort()[0];
  $("#summary").innerHTML=`<div class="summary">
    <div><div class="k">Accepted</div><div class="v">${Math.round(pct(c.accepted))}% <small>${c.accepted} of ${live.length} items</small></div>
      <div class="meter" aria-hidden="true"><i class="a" style="width:${pct(c.accepted)}%"></i><i class="r" style="width:${pct(c.received)}%"></i><i class="q" style="width:${pct(c.requested)}%"></i></div>
      <div class="legend"><span><i style="background:var(--red)"></i>Accepted</span><span><i style="background:var(--blue)"></i>Received</span><span><i style="background:var(--amber)"></i>Requested</span></div></div>
    <div><div class="k">Not started</div><div class="v">${c.not_started}</div></div>
    <div><div class="k">With owners</div><div class="v">${c.requested+c.received}</div></div>
    <div><div class="k">Overdue</div><div class="v" style="${overdue?"color:var(--amber)":""}">${overdue}</div></div>
    <div><div class="k">Next due</div><div class="v" style="font-size:18px;padding-top:6px">${next?fmtDate(next):"None"}</div></div>
  </div>`;
  const doms=DOMAINS.filter(d=>S.items.some(i=>i.domain===d[0]));
  $("#dnav").innerHTML=doms.map(([k,n])=>{const l=S.items.filter(i=>i.domain===k&&i.status!=="na");const a=l.filter(i=>i.status==="accepted").length;return `<li><a href="#d-${k}"><span>${n}</span><em>${a}/${l.length}</em><span class="mini"><i style="width:${l.length?a/l.length*100:0}%"></i></span></a></li>`}).join("");
}
function matches(i){
  const t=today();
  if(F.status==="open"&&(i.status==="accepted"||i.status==="na"))return false;
  if(F.status==="overdue"&&!(i.due&&i.due<t&&(i.status==="not_started"||i.status==="requested")))return false;
  if(!["all","open","overdue"].includes(F.status)&&i.status!==F.status)return false;
  if(F.owner!=="all"&&i.owner!==F.owner)return false;
  if(F.q){const q=F.q.toLowerCase();const hay=[i.name,i.source,i.group,i.owner,i.note,...i.controls,...i.controls.map(c=>idLabel(S.setup.fw,c))].join(" ").toLowerCase();if(!hay.includes(q))return false}
  return true;
}
function crosswalk(topicId){
  const t=TOPICS.find(x=>x.id===topicId);if(!t)return"";
  const parts=FW_ORDER.filter(k=>k!==S.setup.fw&&t.m[k].length).map(k=>`<b>${FW[k].short}</b> ${t.m[k].map(id=>idLabel(k,id)).join(", ")}`);
  return parts.length?`<div class="xw">Also satisfies: ${parts.join("; ")}</div>`:"";
}
function renderList(){
  const fw=S.setup.fw, list=S.items.filter(matches), t=today();
  if(!list.length){$("#list").innerHTML=`<div class="empty">No evidence matches these filters. Clear the search or choose a different status.</div>`;return}
  const titles=ownerTitles();
  let html="";
  DOMAINS.forEach(([dk,dn])=>{
    const inD=list.filter(i=>i.domain===dk);if(!inD.length)return;
    html+=`<section class="domain"><h2 id="d-${dk}">${dn}<span>${inD.length} item${inD.length===1?"":"s"}</span></h2>`;
    const groups=[...new Set(inD.map(i=>i.group+"|"+i.topic))];
    groups.forEach(g=>{
      const gi=inD.filter(i=>i.group+"|"+i.topic===g);const f=gi[0];
      html+=`<article class="ctl"><div class="ctl-h"><div class="ids">${f.controls.map(c=>`<span class="id" title="${esc((NAMES[fw]&&NAMES[fw][c])||"")}">${esc(idLabel(fw,c))}</span>`).join("")}</div>
        <span class="nm">${esc(f.group)}${f.controls.length===1&&NAMES[fw]&&NAMES[fw][f.controls[0]]&&NAMES[fw][f.controls[0]]!==f.group?`<span style="font-weight:400;color:var(--graphite)">, ${esc(NAMES[fw][f.controls[0]])}</span>`:""}</span>
        ${f.custom?"":crosswalk(f.topic)}</div>`;
      gi.forEach(i=>{
        const over=i.due&&i.due<t&&(i.status==="not_started"||i.status==="requested");
        html+=`<div class="row s-${i.status} ${i.status==="na"?"na":""}" data-id="${i.id}">
          <div class="stat"><label class="sr" for="st-${i.id}">Status for ${esc(i.name)}</label><select id="st-${i.id}" data-k="status">${STATUS.map(([k,v])=>`<option value="${k}" ${i.status===k?"selected":""}>${v}</option>`).join("")}</select><div class="face">${face(i.status)}</div></div>
          <div class="cell c-main"><div class="ev">${esc(i.name)}</div>
            <div class="evm"><span class="type">${esc(i.type)}</span><span>${esc(i.source)}</span><span class="stlabel">${i.status==="not_started"?"":SLABEL[i.status]}</span></div>
            ${i.sample?`<div class="samp">${esc(sampleNote(i))}</div>`:""}</div>
          <div class="cells">
          <div class="cell c-owner"><label for="ow-${i.id}">Owner</label><input class="input" id="ow-${i.id}" data-k="owner" list="owners" value="${esc(i.owner)}"></div>
          <div class="cell c-due"><label for="du-${i.id}">Due</label><input class="input" type="date" id="du-${i.id}" data-k="due" value="${i.due||""}">${over?`<div class="due-over">Overdue</div>`:""}</div>
          </div>
          <div class="more"><label class="sr" for="nt-${i.id}">Notes</label><input class="input" id="nt-${i.id}" data-k="note" placeholder="Notes, file location, exceptions" value="${esc(i.note)}">${sampleFn?`<button class="btn small" type="button" data-ai="${i.id}">Draft request</button>`:""}${i.custom?`<button class="btn ghost small" type="button" data-del="${i.id}">Remove</button>`:""}</div>
        </div>`;
      });
      html+=`</article>`;
    });
    html+=`</section>`;
  });
  html+=`<datalist id="owners">${titles.map(o=>`<option value="${esc(o)}">`).join("")}</datalist>`;
  $("#list").innerHTML=html;
  $("#list").querySelectorAll("[data-k]").forEach(el=>{
    const id=el.closest(".row").dataset.id;const k=el.dataset.k;
    const ev=(k==="note"||k==="owner")?"input":"change";
    el.addEventListener(ev,()=>{const it=S.items.find(x=>x.id===id);it[k]=el.value;save();
      if(k==="status"||k==="due"){renderSummary();const row=el.closest(".row");if(k==="status"){row.className=`row s-${it.status} ${it.status==="na"?"na":""}`;row.querySelector(".face").innerHTML=face(it.status);row.querySelector(".stlabel").textContent=it.status==="not_started"?"":SLABEL[it.status]}}
    });
    if(k==="owner")el.addEventListener("change",()=>renderSummary());
  });
  $("#list").querySelectorAll("[data-ai]").forEach(b=>b.onclick=()=>openAssist(b.dataset.ai));
  $("#list").querySelectorAll("[data-del]").forEach(b=>b.onclick=()=>{S.items=S.items.filter(x=>x.id!==b.dataset.del);save();renderSummary();renderList()});
}

/* ---------- drawer ---------- */
function openDrawer(html){const d=$("#drawer");d.innerHTML=html;document.body.classList.add("open");const f=d.querySelector("button,input,select,textarea");f&&f.focus();d.querySelectorAll("[data-close]").forEach(b=>b.onclick=closeDrawer)}
function closeDrawer(){document.body.classList.remove("open");if(ctl)ctl.abort()}
$("#scrim").onclick=closeDrawer;
document.addEventListener("keydown",e=>{if(e.key==="Escape"&&document.body.classList.contains("open"))closeDrawer()});

function openAdd(){
  const fw=S.setup.fw;
  openDrawer(`<header><div style="flex:1"><h2 id="dTitle">Add an evidence item</h2><p>For controls outside the core set, or anything your auditor requested.</p></div><button class="btn ghost small" data-close type="button">Close</button></header>
  <div class="content"><div class="formgrid">
    <div class="field"><label for="a-ctl">${FW[fw].short} control ID</label><input class="input" id="a-ctl" placeholder="${fw==="iso"?"8.12":fw==="soc2"?"CC6.7":fw==="csf"?"PR.DS-10":fw==="n53"?"SC-13":fw==="pci"?"11.6.1":fw==="hipaa"?"164.312(c)(1)":"SC.L2-3.13.11"}"></div>
    <div class="field"><label for="a-dom">Area</label><select class="input" id="a-dom">${DOMAINS.map(([k,n])=>`<option value="${k}">${n}</option>`).join("")}</select></div>
    <div class="field full"><label for="a-name">Evidence requested</label><input class="input" id="a-name" placeholder="What the artifact must show"></div>
    <div class="field"><label for="a-type">Type</label><select class="input" id="a-type">${TYPES.map(t=>`<option>${t}</option>`).join("")}</select></div>
    <div class="field"><label for="a-owner">Owner</label><input class="input" id="a-owner" list="owners" value="${esc(OWNERS[S.setup.size].comp)}"></div>
    <div class="field full"><label for="a-src">Source</label><input class="input" id="a-src" placeholder="System or location to pull it from"></div>
  </div><p class="err" id="a-err" role="alert"></p></div>
  <footer><button class="btn" data-close type="button">Cancel</button><button class="btn primary" id="a-save" type="button">Add item</button></footer>`);
  $("#a-save").onclick=()=>{
    const v=id=>$("#"+id).value.trim();
    if(!v("a-ctl")||!v("a-name")){$("#a-err").textContent="Enter a control ID and the evidence requested.";return}
    addCustom({control:v("a-ctl"),domain:v("a-dom"),name:v("a-name"),type:v("a-type"),owner:v("a-owner"),source:v("a-src")||"To be confirmed"});
    closeDrawer();toast("Item added");
  };
}
function addCustom(o){
  const type=TYPES.includes(o.type)?o.type:"Document";
  const dom=DNAME[o.domain]?o.domain:"governance";
  const id="custom-"+Date.now().toString(36)+Math.random().toString(36).slice(2,6);
  const ctl=String(o.control).replace(/^A\./,"").trim();
  const nm=(NAMES[S.setup.fw]&&NAMES[S.setup.fw][ctl])||o.controlName||"Added item";
  S.items.push({id,topic:id,domain:dom,group:nm,controls:[ctl],name:noDash(o.name),type,source:noDash(o.source),sample:type==="Sample set",owner:o.owner||OWNERS[S.setup.size].comp,due:S.setup.fieldwork?addDays(S.setup.fieldwork,-7*(LEAD[type]||4)):"",status:"not_started",note:"",custom:true});
  save();
  if(S.view==="work"){renderSummary();renderList()}
}

/* ---------- export ---------- */
function toCSV(){
  const fw=S.setup.fw;
  const head=["Framework","Control IDs","Control","Area","Evidence requested","Type","Source","Owner","Due","Status","Sampling","Notes","Also satisfies"];
  const rows=S.items.map(i=>{const t=TOPICS.find(x=>x.id===i.topic);
    const xw=t?FW_ORDER.filter(k=>k!==fw&&t.m[k].length).map(k=>FW[k].short+": "+t.m[k].map(id=>idLabel(k,id)).join(", ")).join(" | "):"";
    return [FW[fw].full,i.controls.map(c=>idLabel(fw,c)).join(", "),i.group,DNAME[i.domain],i.name,i.type,i.source,i.owner,i.due,SLABEL[i.status],sampleNote(i),i.note,xw]});
  return [head,...rows].map(r=>r.map(c=>{c=String(c??"");return /[",\n]/.test(c)?'"'+c.replace(/"/g,'""')+'"':c}).join(",")).join("\r\n");
}
async function exportCSV(){
  const csv=toCSV();
  const name=((S.setup.org||"evidence").replace(/[^\w]+/g,"-").toLowerCase()+"-"+S.setup.fw+"-evidence-list.csv");
  if(downloadsFn){
    try{await downloadsFn.save({filename:name,data:csv});toast("CSV saved");return}
    catch(e){if(e&&e.code==="declined")return;if(e&&e.code==="rate_limited"){toast("A save prompt is already open.");return}}
  }
  try{
    const blob=new Blob(["\ufeff"+csv],{type:"text/csv;charset=utf-8"});
    const url=URL.createObjectURL(blob);const link=document.createElement("a");
    link.href=url;link.download=name;document.body.appendChild(link);link.click();link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1000);toast("CSV downloaded");return;
  }catch(e){}
  try{await navigator.clipboard.writeText(csv);toast("CSV copied to clipboard. Paste it into a spreadsheet.")}
  catch(e){toast("Export is not available in this view.")}
}

/* ---------- AI ---------- */
let sampleFn=null, downloadsFn=null, ctl=null;
function ctxBlock(){
  const s=S.setup;
  return `Organization: ${s.org||"unnamed"} (${SIZES[s.size]}). Framework: ${FW[s.fw].full}. Audit: ${AUDIT[s.audit].label}${s.fieldwork?", fieldwork starts "+s.fieldwork:""}${s.audit==="period"?", review period "+s.pstart+" to "+s.pend:""}.
Tools: hosting ${STACK.cloud.opts[s.stack.cloud]}, identity ${s.stack.idp}, ticketing ${s.stack.ticket}, EDR ${s.stack.edr}, SIEM ${s.stack.siem}, scanner ${s.stack.vuln}, MDM ${s.stack.mdm}, HR ${s.stack.hris}, code ${s.stack.vcs}, training ${s.stack.lms}, documents ${s.stack.docs}.
Scope notes: ${s.notes||"none"}`;
}
function errCopy(e){
  const c=e&&e.code;
  if(c==="not_granted")return "AI assist needs your permission to run. Reopen the page to be asked again.";
  if(c==="rate_limited")return "Too many requests at once. Wait a moment, then try again.";
  if(c==="cancelled")return "";
  return "The request did not complete. Try again.";
}
function openAssist(id){
  const i=S.items.find(x=>x.id===id);const fw=S.setup.fw;
  const ids=i.controls.map(c=>idLabel(fw,c)).join(", ");
  openDrawer(`<header><div style="flex:1"><h2 id="dTitle">${esc(i.name)}</h2><p>${esc(ids)}, owner ${esc(i.owner)}</p></div><button class="btn ghost small" data-close type="button">Close</button></header>
  <div class="tabs seg" role="group" aria-label="Assist mode"><button type="button" data-mode="request" aria-pressed="true">Request to owner</button><button type="button" data-mode="tips" aria-pressed="false">What the auditor checks</button></div>
  <div class="content"><div class="out" id="aiOut" aria-live="polite"></div></div>
  <footer><button class="btn" type="button" id="aiStop" hidden>Stop</button><button class="btn" type="button" id="aiCopy" disabled>Copy</button><button class="btn primary" type="button" id="aiMark" ${i.status!=="not_started"?"hidden":""}>Mark as requested</button></footer>`);
  const run=mode=>{
    document.querySelectorAll("[data-mode]").forEach(b=>b.setAttribute("aria-pressed",b.dataset.mode===mode));
    const prompt = mode==="request"
      ? `You are a senior IT audit and GRC practitioner preparing for an audit.\n${ctxBlock()}\n\nWrite a short evidence request to the control owner (${i.owner}) for this item.\nControl: ${ids} (${i.group}).\nEvidence: ${i.name}. Type: ${i.type}. Source: ${i.source}.${i.sample?" Sampling: "+sampleNote(i):""}${i.due?" Due: "+i.due+".":""}\n\nInclude: a one-line reason it is needed, numbered steps to pull it from the named system, what makes it acceptable to an auditor (visible date and system name, complete population, no cropping, reviewer or approver visible where relevant), and the due date. Plain text suitable for email or chat. Under 180 words. No subject line, no markdown symbols, never use em dashes.`
      : `You are a senior IT auditor.\n${ctxBlock()}\n\nExplain how an auditor testing ${FW[fw].full} ${ids} (${i.group}) will evaluate this evidence: ${i.name} (${i.type}, from ${i.source}).\nGive: what they verify for design versus operating effectiveness, the most common reasons this evidence gets rejected, and two practical tips to make it audit-ready on the first submission. Use short lines starting with "- ". Under 170 words. Plain text, no markdown headings, never use em dashes.`;
    callAI(prompt);
  };
  document.querySelectorAll("[data-mode]").forEach(b=>b.onclick=()=>run(b.dataset.mode));
  $("#aiCopy").onclick=async()=>{try{await navigator.clipboard.writeText($("#aiOut").textContent);toast("Copied")}catch(e){toast("Select the text to copy it.")}};
  $("#aiMark").onclick=()=>{i.status="requested";save();renderSummary();renderList();closeDrawer();toast("Marked as requested")};
  run("request");
}
async function callAI(prompt){
  const out=$("#aiOut"),stop=$("#aiStop"),copy=$("#aiCopy");
  if(ctl)ctl.abort();ctl=new AbortController();const my=ctl;
  out.className="out thinking";out.textContent="Thinking...";copy.disabled=true;stop.hidden=false;stop.onclick=()=>my.abort();
  try{
    const r=await sampleFn(prompt,{signal:my.signal,modelTier:"default",onText:({text})=>{out.className="out";out.textContent=noDash(text)}});
    out.className="out";out.textContent=noDash(r.text);copy.disabled=false;
  }catch(e){
    if(my!==ctl&&e&&e.code==="cancelled")return;
    out.className="out";out.textContent=noDash(e&&e.text||"")||errCopy(e);if(e&&e.text)copy.disabled=false;
  }finally{if(my===ctl)stop.hidden=true}
}
function openSuggest(){
  const fw=S.setup.fw;
  openDrawer(`<header><div style="flex:1"><h2 id="dTitle">Suggest missing evidence</h2><p>Reviews this list against your scope notes and ${FW[fw].short}, then proposes items to add.</p></div><button class="btn ghost small" data-close type="button">Close</button></header>
  <div class="content"><div class="field" style="margin-bottom:12px"><label for="sgNotes">Scope notes</label><textarea class="input" id="sgNotes" placeholder="Anything special about this environment">${esc(S.setup.notes)}</textarea></div>
  <div id="sgOut"></div></div>
  <footer><button class="btn" type="button" id="sgStop" hidden>Stop</button><button class="btn primary" type="button" id="sgRun">Find gaps</button></footer>`);
  $("#sgRun").onclick=async()=>{
    S.setup.notes=$("#sgNotes").value;save();
    const have=[...new Set(S.items.map(i=>i.controls.map(c=>idLabel(fw,c)).join("/")+" "+i.group))].join("; ");
    const prompt=`You are a senior GRC auditor reviewing an evidence request list for gaps.\n${ctxBlock()}\n\nThe list already covers: ${have}.\n\nPropose up to 6 additional evidence items that an auditor for ${FW[fw].full} would likely request given this scope and that the list does not already cover. Use real ${FW[fw].short} control identifiers${fw==="iso"?" (Annex A numbers like 8.12 without the A. prefix)":""}. Return ONLY a JSON array, no prose, where each element is {"control":"id","controlName":"short official name","domain":one of ${JSON.stringify(DOMAINS.map(d=>d[0]))},"evidence":"what the artifact must show","type":one of ${JSON.stringify(TYPES)},"source":"system to pull from, using the named tools","why":"one sentence on why this scope needs it"}. Never use em dashes.`;
    const out=$("#sgOut"),run=$("#sgRun"),stop=$("#sgStop");
    if(ctl)ctl.abort();ctl=new AbortController();const my=ctl;
    run.disabled=true;stop.hidden=false;stop.onclick=()=>my.abort();
    out.innerHTML=`<div class="out thinking">Reviewing ${S.items.length} items against your scope. This can take up to a minute.</div>`;
    try{
      let data=await sampleFn.json(prompt,{signal:my.signal,modelTier:"default"});
      if(data&&!Array.isArray(data))data=data.items||data.suggestions||[];
      const list=(data||[]).filter(x=>x&&x.control&&x.evidence).slice(0,6);
      if(!list.length){out.innerHTML=`<div class="out">No gaps found for this scope. Add detail to the scope notes and try again.</div>`;return}
      out.innerHTML=list.map((x,k)=>`<div class="sugg"><div class="top"><span><span class="id">${esc(idLabel(fw,String(x.control).replace(/^A\./,"")))}</span> <b style="font-size:14px">${esc(noDash(x.controlName||""))}</b></span><button class="btn small" type="button" data-add="${k}">Add</button></div>
        <div style="font-weight:600;margin-top:8px;font-size:14px">${esc(noDash(x.evidence))}</div><p>${esc(TYPES.includes(x.type)?x.type:"Document")}, ${esc(noDash(x.source||""))}</p><p>${esc(noDash(x.why||""))}</p></div>`).join("");
      out.querySelectorAll("[data-add]").forEach(b=>b.onclick=()=>{const x=list[+b.dataset.add];addCustom({control:x.control,controlName:noDash(x.controlName),domain:x.domain,name:x.evidence,type:x.type,source:x.source||"To be confirmed"});b.textContent="Added";b.disabled=true});
    }catch(e){out.innerHTML=`<div class="out">${esc(errCopy(e)||"Stopped.")}</div>`}
    finally{run.disabled=false;stop.hidden=true}
  };
}

/* ---------- shell ---------- */
function render(){S.view==="work"&&S.items.length&&S.setup.fw?renderWork():renderSetup()}
$("#home").onclick=e=>{e.preventDefault();scrollTo(0,0)};
$("#newBtn").onclick=()=>{if(confirm("Start a new assessment? The current list and its statuses will be cleared.")){S={view:"setup",setup:defaultSetup(),items:[]};save();render();scrollTo(0,0)}};
$("#themeBtn").onclick=()=>{const r=document.documentElement;const dark=r.dataset.theme?r.dataset.theme==="dark":matchMedia("(prefers-color-scheme: dark)").matches;r.dataset.theme=dark?"light":"dark";try{localStorage.setItem("tickmark.theme",r.dataset.theme)}catch(e){}};
try{const th=localStorage.getItem("tickmark.theme");if(th)document.documentElement.dataset.theme=th}catch(e){}
render();

if(window.claude&&typeof window.claude.use==="function"){
  window.claude.use("sample").then(fn=>{if(fn){sampleFn=fn;if(S.view==="work")render()}}).catch(()=>{});
  window.claude.use("downloads").then(d=>{if(d)downloadsFn=d}).catch(()=>{});
}
})();
