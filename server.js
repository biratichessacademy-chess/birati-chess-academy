/* Birati Chess Academy™ — single-file server: API + embedded web app. Run: npm install && npm start */
const express=require("express"),bcrypt=require("bcryptjs"),jwt=require("jsonwebtoken"),
rateLimit=require("express-rate-limit"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const {JWT_SECRET,ADMIN_EMAIL,ADMIN_PASSWORD,PORT=3000}=process.env;
if(!JWT_SECRET||!ADMIN_EMAIL||!ADMIN_PASSWORD)throw new Error("Set JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD (in .env locally, or Render's Environment tab)");

/* ---------- database: pure Node.js JSON file (no native modules) ---------- */
const DB_PATH=process.env.DB_PATH||path.join(__dirname,"academy.json");
fs.mkdirSync(path.dirname(path.resolve(DB_PATH)),{recursive:true});
let data={admins:[],students:[],nextId:1};
try{data=JSON.parse(fs.readFileSync(DB_PATH,"utf8"))}catch(e){if(e.code!=="ENOENT")throw e}
// atomic write: write temp file, then rename, so a crash never corrupts the database
const persist=()=>{const t=DB_PATH+".tmp";fs.writeFileSync(t,JSON.stringify(data));fs.renameSync(t,DB_PATH)};
if(!data.admins.length){data.admins.push({email:ADMIN_EMAIL.toLowerCase(),password_hash:bcrypt.hashSync(ADMIN_PASSWORD,10)});persist()}

const get=id=>data.students.find(s=>s.id===+id);
const dto=(s,admin)=>({id:s.id,name:s.name,parent:s.parent,course:s.course,active:s.active,fee:s.fee,cc:s.cc,li:s.li,
 lessons:s.lessons,puzzles:s.puzzles,ratings:s.ratings,ccR:s.ratings.at(-1),win:s.win,games:s.games,...(admin?{code:s.access_code}:{})});
const newCode=()=>{let c;do{const h=crypto.randomBytes(4).toString("hex").toUpperCase();c=`BCA-${h.slice(0,4)}-${h.slice(4)}`}while(data.students.some(s=>s.access_code===c));return c};

/* ---------- auth ---------- */
const sign=p=>jwt.sign(p,JWT_SECRET,{expiresIn:"12h"});
// Checked on EVERY request: deactivating or deleting a student cuts access immediately.
const auth=role=>(q,r,n)=>{try{
 const t=jwt.verify((q.headers.authorization||"").slice(7),JWT_SECRET);if(t.role!==role)throw 0;
 if(role==="parent"){const s=get(t.sid);if(!s||!s.active)return r.status(403).json({error:"Access revoked. Please contact the academy."});q.st=s}
 n()}catch{r.status(401).json({error:"Please log in again"})}};
const A=auth("admin"),P=auth("parent");
const app=express();app.set("trust proxy",1);app.use(express.json());
const limiter=rateLimit({windowMs:15*60*1000,max:20,message:{error:"Too many attempts. Try again later."}});

app.post("/api/admin/login",limiter,(q,r)=>{
 const a=data.admins.find(x=>x.email===String(q.body.email||"").trim().toLowerCase());
 if(!a||!bcrypt.compareSync(String(q.body.password||""),a.password_hash))return r.status(401).json({error:"Invalid email or password"});
 r.json({token:sign({role:"admin"})})});
app.post("/api/parent/login",limiter,(q,r)=>{
 const s=data.students.find(x=>x.access_code===String(q.body.code||"").trim().toUpperCase());
 if(!s)return r.status(401).json({error:"Invalid access code"});
 if(!s.active)return r.status(403).json({error:"This account is inactive. Please contact the academy."});
 r.json({token:sign({role:"parent",sid:s.id}),student:dto(s)})});

/* ---------- admin ---------- */
app.get("/api/admin/students",A,(q,r)=>r.json({students:data.students.map(s=>dto(s,true))}));
app.post("/api/admin/students",A,(q,r)=>{const n=String(q.body.name||"").trim();if(!n)return r.status(400).json({error:"Name required"});
 const s={id:data.nextId++,name:n,parent:"",course:"Beginner",access_code:newCode(),active:true,fee:+q.body.fee||0,cc:"",li:"",
  lessons:[0],puzzles:[0],ratings:[800],win:0,games:0,created_at:new Date().toISOString()};
 data.students.push(s);persist();r.json({student:dto(s,true)})});
app.patch("/api/admin/students/:id",A,(q,r)=>{const s=get(q.params.id);if(!s)return r.sendStatus(404);
 if(q.body.active!==undefined)s.active=!!q.body.active;
 if(q.body.fee!==undefined)s.fee=+q.body.fee||0;persist();r.json({ok:1})});
app.delete("/api/admin/students/:id",A,(q,r)=>{data.students=data.students.filter(s=>s.id!==+q.params.id);persist();r.json({ok:1})});
app.post("/api/admin/students/:id/code",A,(q,r)=>{const s=get(q.params.id);if(!s)return r.sendStatus(404);s.access_code=newCode();persist();r.json({code:s.access_code})});
app.post("/api/admin/students/:id/progress",A,(q,r)=>{const s=get(q.params.id);if(!s)return r.sendStatus(404);
 const add=(a,v)=>[...a,+v||0].slice(-12);
 s.lessons=add(s.lessons,q.body.lessons);s.puzzles=add(s.puzzles,q.body.puzzles);s.ratings=add(s.ratings,q.body.rating);persist();r.json({ok:1})});

/* ---------- parent ---------- */
app.get("/api/parent/me",P,(q,r)=>r.json({student:dto(q.st)}));
app.patch("/api/parent/usernames",P,(q,r)=>{const ok=v=>/^[A-Za-z0-9_-]{0,30}$/.test(v||"");
 if(!ok(q.body.cc)||!ok(q.body.li))return r.status(400).json({error:"Invalid username"});
 q.st.cc=q.body.cc||"";q.st.li=q.body.li||"";persist();r.json({ok:1})});
app.get("/api/parent/ratings",P,async(q,r)=>{const o={},s=q.st;
 try{if(s.cc){const d=await(await fetch(`https://api.chess.com/pub/player/${s.cc}/stats`,{headers:{"User-Agent":"BiratiChessAcademy"}})).json();
  const b=d.chess_rapid||d.chess_blitz,c=b.record,t=c.win+c.loss+c.draw;o.chesscom=[b.last.rating,Math.round(c.win/t*100)+"%",t]}}catch{}
 try{if(s.li){const d=await(await fetch(`https://lichess.org/api/user/${s.li}`)).json();
  const p=d.perfs.rapid||d.perfs.blitz,c=d.count;o.lichess=[p.rating,Math.round(c.win/c.all*100)+"%",c.all]}}catch{}
 r.json(o)});

/* ---------- secure library (files never publicly served) ---------- */
const BOOKS=path.join(__dirname,"books"),list=()=>fs.existsSync(BOOKS)?fs.readdirSync(BOOKS).filter(f=>f.toLowerCase().endsWith(".pdf")):[];
app.get("/api/library",P,(q,r)=>r.json({books:list().map(f=>({id:f,title:f.replace(/\.pdf$/i,"").replace(/[-_]/g," ")}))}));
app.get("/api/library/:id/file",P,(q,r)=>{if(!list().includes(q.params.id))return r.sendStatus(404);
 r.set({"Cache-Control":"no-store","Content-Disposition":"inline","X-Content-Type-Options":"nosniff"});r.type("pdf").sendFile(path.join(BOOKS,q.params.id))});

/* ---------- embedded frontend (Tailwind UI: login, admin, parent portal) ---------- */
const HTML=`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Birati Chess Academy™ - Parent Portal & Management System</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<style>
:root{box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}
body{background:#f3f4f6;font-family:system-ui,-apple-system,Segoe UI,sans-serif}
.nav{background:#0b1e3f}.gold{color:#f5a623}.bgold{background:#f5a623}
.secure{user-select:none;-webkit-user-select:none}
@media print{#viewer{display:none!important}}
@media (prefers-color-scheme:dark){body{background:#e5e7eb}}
</style></head>
<body>
<div id="app"></div>
<script>
const VPAS=["9836614608-2@ybl","9836614608-2@ibl","9836614608-2@axl"];
let DB;try{DB=JSON.parse(localStorage.getItem("bca"))}catch(e){}
DB={students:[]};
const save=()=>{};
let S=null,tab="",err="";
const $=s=>document.querySelector(s), app=$("#app");
const ST=id=>DB.students.find(s=>s.id===id);
let TOKEN=null,poll;
const api=async(m,u,b)=>{const r=await fetch(u,{method:m,headers:{"Content-Type":"application/json",Authorization:"Bearer "+TOKEN},body:b?JSON.stringify(b):undefined});
 const d=await r.json().catch(()=>({}));
 if(!r.ok){if(S&&(r.status===401||r.status===403)){S=null;TOKEN=null;err=d.error||"Session ended";login()}throw new Error(d.error||"Request failed")}return d};
const load=async()=>{DB.students=(await api("GET","/api/admin/students")).students};
// parents are re-checked every 15s so deactivation locks them out quickly
const startPoll=()=>{clearInterval(poll);poll=setInterval(()=>{if(S&&S.role==="parent")api("GET","/api/parent/me").then(d=>{DB.students=[d.student]}).catch(()=>{})},15000)};

function login(){
 app.innerHTML=\`<div class="min-h-screen flex items-center justify-center p-4 nav"><div class="bg-white rounded-2xl shadow-xl w-full max-w-md p-8">
 <div class="text-center mb-6"><div class="text-5xl">♞</div><h1 class="text-xl font-bold text-[#0b1e3f]">Birati Chess Academy™</h1>
 <p class="text-sm text-gray-500">Parent Portal & Management System</p><p class="text-xs text-gray-400">MSME – Govt. of India Registered</p></div>
 <div class="flex mb-4 rounded-lg overflow-hidden border"><button id="tp" class="flex-1 py-2 bgold font-semibold">Parent</button><button id="ta" class="flex-1 py-2">Admin</button></div>
 <input id="cred" class="w-full border rounded-lg p-3 mb-3" placeholder="Access Code (e.g. BCA-1001)">
 <input id="pw" type="password" placeholder="Admin password" class="hidden w-full border rounded-lg p-3 mb-3"><button id="go" class="w-full py-3 rounded-lg bgold font-bold">Unlock</button>
 <p id="err" class="text-red-600 text-sm mt-3 min-h-[1.25rem]">\${err}</p>
 </div></div>\`;
 let mode="p";const c=$("#cred");
 $("#tp").onclick=()=>{mode="p";c.type="text";c.placeholder="Access Code (e.g. BCA-9F3A-1C2B)";$("#pw").classList.add("hidden");$("#tp").className="flex-1 py-2 bgold font-semibold";$("#ta").className="flex-1 py-2"};
 $("#ta").onclick=()=>{mode="a";c.type="text";c.placeholder="Admin email";$("#pw").classList.remove("hidden");$("#ta").className="flex-1 py-2 bgold font-semibold";$("#tp").className="flex-1 py-2"};
 $("#go").onclick=async()=>{try{
  if(mode==="a"){const d=await api("POST","/api/admin/login",{email:c.value.trim(),password:$("#pw").value});TOKEN=d.token;S={role:"admin"};tab="students";await load()}
  else{const d=await api("POST","/api/parent/login",{code:c.value.trim()});TOKEN=d.token;DB.students=[d.student];S={role:"parent",id:d.student.id};tab="overview";startPoll()}
  err="";shell()}catch(e){$("#err").textContent=e.message}};
}
function shell(){
 const admin=S.role==="admin";
 // live access check: inactive/deleted accounts lose access immediately
 if(!admin){const s=ST(S.id);if(!s||!s.active){S=null;err="Your access has been revoked. Contact the academy.";return login()}}
 const tabs=admin?[["students","👥 Students"],["fees","₹ Fees"]]:[["overview","📊 Overview"],["platforms","♟ Chess Sync"],["library","📚 Library"],["fees","₹ Fees & UPI"]];
 app.innerHTML=\`<div class="md:flex min-h-screen"><aside class="nav text-white md:w-60 md:min-h-screen p-4 flex md:block items-center gap-2 overflow-x-auto">
 <div class="hidden md:block mb-6"><div class="text-3xl gold">♞</div><b>Birati Chess Academy™</b><div class="text-xs text-gray-400">\${admin?"Admin Dashboard":"Parent Portal"}</div></div>
 \${tabs.map(t=>\`<button data-t="\${t[0]}" class="tb block md:w-full text-left whitespace-nowrap px-3 py-2 rounded-lg md:mb-1 \${t[0]===tab?"bgold text-black font-semibold":"hover:bg-white/10"}">\${t[1]}</button>\`).join("")}
 <button id="lo" class="md:mt-8 px-3 py-2 text-sm text-gray-300 whitespace-nowrap">⎋ Logout</button></aside>
 <main class="flex-1 p-4 md:p-8"><h1 class="text-lg font-bold text-[#0b1e3f] mb-4">Birati Chess Academy™ – \${admin?"Management System":"Parent Portal"}</h1><div id="v"></div></main></div>\`;
 document.querySelectorAll(".tb").forEach(b=>b.onclick=()=>{tab=b.dataset.t;shell()});
 $("#lo").onclick=()=>{S=null;login()};
 ({students:vStudents,fees:admin?vAdminFees:vFees,overview:vOverview,platforms:vPlatforms,library:vLibrary})[tab]();
}
const card=(h,c="")=>\`<div class="bg-white rounded-xl shadow-sm border p-4 \${c}">\${h}</div>\`;

/* ---------- ADMIN ---------- */
function vStudents(){
 $("#v").innerHTML=card(\`<div class="flex flex-wrap gap-2 mb-4"><input id="nn" placeholder="Student name" class="border rounded p-2 flex-1 min-w-[140px]"><input id="nf" type="number" placeholder="Monthly ₹" class="border rounded p-2 w-32"><button id="add" class="bgold px-4 rounded font-semibold">+ Add & generate code</button></div>
 <div class="overflow-x-auto"><table class="w-full text-sm"><thead><tr class="text-left text-gray-500 border-b"><th class="p-2">Student</th><th>Code</th><th>Fee</th><th>Status</th><th></th></tr></thead><tbody>
 \${DB.students.map(s=>\`<tr class="border-b"><td class="p-2 font-medium">\${s.name}<div class="text-xs text-gray-400">\${s.course}</div></td><td><code>\${s.code}</code></td><td>₹\${s.fee}</td>
 <td><button data-tg="\${s.id}" class="px-3 py-1 rounded-full text-xs font-semibold \${s.active?"bg-green-100 text-green-700":"bg-gray-200 text-gray-600"}">\${s.active?"● Active":"○ Inactive"}</button></td>
 <td><button data-pr="\${s.id}" class="text-blue-700 text-xs mr-2">+Progress</button><button data-rg="\${s.id}" class="text-gray-600 text-xs mr-2">New code</button><button data-del="\${s.id}" class="text-red-600 text-xs">Delete</button></td></tr>\`).join("")}</tbody></table></div>\`);
 document.querySelectorAll("[data-tg]").forEach(b=>b.onclick=async()=>{const s=ST(+b.dataset.tg);await api("PATCH","/api/admin/students/"+s.id,{active:!s.active});s.active=!s.active;vStudents()});
 document.querySelectorAll("[data-del]").forEach(b=>b.onclick=async()=>{if(confirm("Permanently delete this student account?")){await api("DELETE","/api/admin/students/"+b.dataset.del);DB.students=DB.students.filter(s=>s.id!==+b.dataset.del);vStudents()}});
 document.querySelectorAll("[data-rg]").forEach(b=>b.onclick=async()=>{const d=await api("POST","/api/admin/students/"+b.dataset.rg+"/code");await load();alert("New access code: "+d.code);vStudents()});
 document.querySelectorAll("[data-pr]").forEach(b=>b.onclick=async()=>{const v=prompt("Cumulative lessons, puzzles, rating (e.g. 28, 310, 1100)");if(!v)return;const[l,p,r]=v.split(",").map(Number);await api("POST","/api/admin/students/"+b.dataset.pr+"/progress",{lessons:l,puzzles:p,rating:r});await load();vStudents()});
 $("#add").onclick=async()=>{const n=$("#nn").value.trim();if(!n)return;const d=await api("POST","/api/admin/students",{name:n,fee:+$("#nf").value||1500});DB.students.push(d.student);alert("Access code for "+n+":\\n\\n"+d.student.code+"\\n\\nShare this with the parent.");vStudents()};
}
function vAdminFees(){
 $("#v").innerHTML=card(\`<h2 class="font-semibold mb-3">Assign custom monthly fee</h2>\${DB.students.map(s=>\`<div class="flex items-center gap-3 py-2 border-b"><span class="flex-1">\${s.name} <span class="text-xs text-gray-400">\${s.course}</span></span>₹<input data-f="\${s.id}" type="number" value="\${s.fee}" class="border rounded p-1 w-28"></div>\`).join("")}<button id="sf" class="bgold px-4 py-2 rounded font-semibold mt-4">Save fees</button>\`);
 $("#sf").onclick=async()=>{for(const i of document.querySelectorAll("[data-f]")){const v=+i.value||0;await api("PATCH","/api/admin/students/"+i.dataset.f,{fee:v});ST(+i.dataset.f).fee=v}$("#sf").textContent="Saved ✓"};
}

/* ---------- PARENT ---------- */
function vOverview(){
 const s=ST(S.id),r=s.ratings,mx=Math.max(...r),mn=Math.min(...r),W=460,H=140;
 const pts=r.map((v,i)=>\`\${10+i*(W-20)/Math.max(1,r.length-1)},\${H-10-(v-mn)/Math.max(1,mx-mn)*(H-30)}\`).join(" ");
 const last=a=>a[a.length-1];
 $("#v").innerHTML=\`<p class="mb-3 text-gray-600">Welcome, \${s.parent||"Parent"} — <b>\${s.name}</b> (\${s.course})</p>
 <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">\${[["Lessons",last(s.lessons)],["Puzzles solved",last(s.puzzles)],["Rating",last(r)],["Games",s.games]].map(x=>card(\`<div class="text-xs text-gray-500">\${x[0]}</div><div class="text-2xl font-bold gold">\${x[1]}</div>\`)).join("")}</div>
 \${card(\`<h2 class="font-semibold mb-2">Rating progression (last \${r.length} months)</h2><svg viewBox="0 0 \${W} \${H}" class="w-full"><polyline fill="none" stroke="#f5a623" stroke-width="3" points="\${pts}"/>\${pts.split(" ").map((p,i)=>\`<circle cx="\${p.split(",")[0]}" cy="\${p.split(",")[1]}" r="4" fill="#0b1e3f"><title>\${r[i]}</title></circle>\`).join("")}</svg>\`)}
 <div class="grid md:grid-cols-2 gap-3 mt-3">\${card(\`<b>Lessons (cumulative)</b>\${bars(s.lessons)}\`)}\${card(\`<b>Puzzles (cumulative)</b>\${bars(s.puzzles)}\`)}</div>\`;
}
const bars=a=>{const m=Math.max(...a,1);return\`<div class="flex items-end gap-2 h-24 mt-2">\${a.map(v=>\`<div class="flex-1 bg-[#0b1e3f] rounded-t" style="height:\${v/m*100}%" title="\${v}"></div>\`).join("")}</div>\`};
function vPlatforms(){
 const s=ST(S.id);
 $("#v").innerHTML=card(\`<h2 class="font-semibold mb-3">Link platform accounts</h2><div class="grid md:grid-cols-2 gap-3">
 <label class="text-sm">Chess.com username<input id="cc" value="\${s.cc}" class="border rounded p-2 w-full"></label>
 <label class="text-sm">Lichess username<input id="li" value="\${s.li}" class="border rounded p-2 w-full"></label></div>
 <button id="sy" class="bgold px-4 py-2 rounded font-semibold mt-3">Save & Sync</button><p id="sm" class="text-xs text-gray-500 mt-2"></p>\`)+\`<div id="stats" class="grid md:grid-cols-2 gap-3 mt-3"></div>\`;
 const show=(n,u,r,w,g,live)=>card(\`<div class="font-semibold">\${n}\${live?' <span class="text-green-600 text-xs">● live</span>':' <span class="text-gray-400 text-xs">(academy snapshot)</span>'}</div><div class="text-sm text-gray-500">@\${u||"—"}</div><div class="mt-2 grid grid-cols-3 text-center"><div><div class="text-xl font-bold gold">\${r}</div><div class="text-xs">Rating</div></div><div><div class="text-xl font-bold gold">\${w}</div><div class="text-xs">Win rate</div></div><div><div class="text-xl font-bold gold">\${g}</div><div class="text-xs">Games</div></div></div>\`);
 async function sync(){
  let cc=[s.ccR||"—",s.win+"%",s.games,false],li=["—","—","—",false];
  try{const r=await api("GET","/api/parent/ratings");if(r.chesscom)cc=[...r.chesscom,true];if(r.lichess)li=[...r.lichess,true]}catch(e){}
  $("#stats").innerHTML=show("Chess.com",s.cc,...cc)+show("Lichess",s.li,...li);
  $("#sm").textContent=(cc[3]||li[3])?"Live data fetched from public APIs.":"Live data unavailable — showing academy snapshot.";
 }
 $("#sy").onclick=async()=>{s.cc=$("#cc").value.trim();s.li=$("#li").value.trim();try{await api("PATCH","/api/parent/usernames",{cc:s.cc,li:s.li})}catch(e){return $("#sm").textContent=e.message}sync()};sync();
}
async function vLibrary(){
 const d=await api("GET","/api/library");
 $("#v").innerHTML=\`<div class="grid md:grid-cols-3 gap-3">\${d.books.map(b=>card(\`<div class="text-4xl">📕</div><div class="font-semibold mt-2">\${b.title}</div><button data-b="\${b.id}" data-t="\${b.title}" class="bgold px-3 py-1 rounded mt-3 text-sm font-semibold">Read online</button><div class="text-xs text-gray-400 mt-1">View-only • no download</div>\`)).join("")||"<p>No books yet.</p>"}</div>\`;
 document.querySelectorAll("[data-b]").forEach(b=>b.onclick=()=>openBook(b.dataset.b,b.dataset.t))}
async function openBook(id,title){
 pdfjsLib.GlobalWorkerOptions.workerSrc="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";
 const s=ST(S.id),v=document.createElement("div");v.id="viewer";v.className="fixed inset-0 z-50 bg-[#0b1e3f] flex flex-col items-center p-4 secure";
 const kd=e=>{if((e.ctrlKey||e.metaKey)&&"cspaxu".includes(e.key.toLowerCase())||e.key==="PrintScreen"||e.key==="F12")e.preventDefault()};
 const close=()=>{v.remove();document.removeEventListener("keydown",kd)};
 ["contextmenu","copy","cut","dragstart","selectstart"].forEach(ev=>v.addEventListener(ev,e=>e.preventDefault()));
 v.innerHTML=\`<div class="w-full max-w-3xl flex justify-between text-white mb-2"><b>\${title}</b><button id="x" class="px-3 bgold text-black rounded">Close ✕</button></div><div class="flex-1 w-full max-w-3xl overflow-auto flex justify-center bg-gray-300 rounded"><canvas id="cv" class="max-w-full h-fit"></canvas></div><div class="text-white mt-2 flex gap-4 items-center"><button id="pv" class="px-3 border rounded">‹</button><span id="pn"></span><button id="nx" class="px-3 border rounded">›</button></div>\`;
 document.addEventListener("keydown",kd);document.body.appendChild(v);$("#x").onclick=close;
 try{
  const r=await fetch("/api/library/"+encodeURIComponent(id)+"/file",{headers:{Authorization:"Bearer "+TOKEN}});if(!r.ok)throw 0;
  const pdf=await pdfjsLib.getDocument({data:await r.arrayBuffer()}).promise;let pg=1;
  const draw=async()=>{const p=await pdf.getPage(pg),vp=p.getViewport({scale:1.5}),cv=$("#cv"),x=cv.getContext("2d");cv.width=vp.width;cv.height=vp.height;
   await p.render({canvasContext:x,viewport:vp}).promise;
   x.save();x.globalAlpha=.12;x.fillStyle="#000";x.font="bold 34px sans-serif";x.textAlign="center";x.translate(vp.width/2,vp.height/2);x.rotate(-.5);
   x.fillText(s.name,0,0);x.fillText("Birati Chess Academy™",0,44);x.restore();$("#pn").textContent=\`Page \${pg} / \${pdf.numPages}\`};
  $("#pv").onclick=()=>{if(pg>1){pg--;draw()}};$("#nx").onclick=()=>{if(pg<pdf.numPages){pg++;draw()}};draw();
 }catch(e){close();alert("Could not open this book. Your access may have been revoked.")}}
function vFees(){
 const s=ST(S.id);let vi=0;
 const link=()=>\`upi://pay?pa=\${VPAS[vi]}&pn=\${encodeURIComponent("Birati Chess Academy")}&am=\${s.fee}.00&cu=INR&tn=\${encodeURIComponent("Fee - "+s.name)}\`;
 $("#v").innerHTML=card(\`<div class="text-sm text-gray-500">Monthly fee due for \${s.name} (\${s.course})</div><div class="text-4xl font-bold gold my-2">₹\${s.fee}</div>
 <label class="text-sm">Pay to<select id="vp" class="border rounded p-2 ml-2">\${VPAS.map((v,i)=>\`<option value="\${i}">\${v}</option>\`).join("")}</select></label>
 <div class="mt-4"><a id="pay" class="inline-block bgold px-5 py-3 rounded-lg font-bold">Pay via UPI / QR Code</a></div>
 <p class="text-xs text-gray-500 mt-2">Opens Google Pay, PhonePe, Paytm etc. with the amount pre-filled. On desktop, scan the QR with your phone.</p><div id="qr" class="mt-3"></div>\`,"max-w-md");
 const up=()=>{$("#pay").href=link();$("#qr").innerHTML="";new QRCode($("#qr"),{text:link(),width:180,height:180})};
 $("#vp").onchange=e=>{vi=+e.target.value;up()};up();
}
login();
</script></body></html>
`;

/* ---------- homepage, health check & fallbacks ---------- */
app.get("/healthz",(q,r)=>r.send("ok"));
app.use("/api",(q,r)=>r.status(404).json({error:"Not found"}));
app.get("/",(q,r)=>r.type("html").send(HTML));
app.get("*",(q,r)=>r.redirect("/"));   // any other page → login screen
app.use((e,q,r,n)=>{console.error(e);r.status(e.status||500).json({error:e.status===400?"Bad request":"Server error"})});

app.listen(PORT,"0.0.0.0",()=>console.log(`Birati Chess Academy running on port ${PORT}`));
