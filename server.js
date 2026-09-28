/* Birati Chess Academy™ — single-file server: Express API + embedded web app + MongoDB (mongoose). */
const express=require("express"),mongoose=require("mongoose"),bcrypt=require("bcryptjs"),jwt=require("jsonwebtoken"),
rateLimit=require("express-rate-limit"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const {DATABASE_URL,JWT_SECRET,ADMIN_EMAIL,ADMIN_PASSWORD}=process.env,PORT=process.env.PORT||3000;
const missing=["DATABASE_URL","JWT_SECRET","ADMIN_EMAIL","ADMIN_PASSWORD"].filter(k=>!process.env[k]);
if(missing.length)throw new Error("Missing environment variables: "+missing.join(", "));

/* ---------- MongoDB models ---------- */
const {Schema}=mongoose;
const Student=mongoose.model("Student",new Schema({
 id:{type:Number,unique:true,required:true},name:{type:String,required:true,trim:true},parent:{type:String,default:""},course:{type:String,default:"Beginner"},
 access_code:{type:String,unique:true,required:true},active:{type:Boolean,default:true},fee:{type:Number,default:0},
 cc:{type:String,default:""},li:{type:String,default:""},
 lessons:{type:[Number],default:[0]},puzzles:{type:[Number],default:[0]},ratings:{type:[Number],default:[800]},
 win:{type:Number,default:0},games:{type:Number,default:0}},{timestamps:true}));
const Admin=mongoose.model("Admin",new Schema({email:{type:String,unique:true,required:true,lowercase:true,trim:true},password_hash:{type:String,required:true}}));
const Counter=mongoose.model("Counter",new Schema({_id:String,seq:{type:Number,default:0}}));
const nextId=async()=>(await Counter.findOneAndUpdate({_id:"student"},{$inc:{seq:1}},{new:true,upsert:true})).seq;
const FIELDS=["id","name","parent","course","access_code","active","fee","cc","li","lessons","puzzles","ratings","win","games"];
const pick=s=>Object.fromEntries(FIELDS.filter(k=>s[k]!==undefined).map(k=>[k,s[k]]));
const dto=(s,admin)=>({id:s.id,name:s.name,parent:s.parent,course:s.course,active:s.active,fee:s.fee,cc:s.cc||"",li:s.li||"",
 lessons:s.lessons,puzzles:s.puzzles,ratings:s.ratings,ccR:s.ratings.at(-1),win:s.win,games:s.games,...(admin?{code:s.access_code}:{})});
const newCode=async()=>{for(;;){const h=crypto.randomBytes(4).toString("hex").toUpperCase(),c=`BCA-${h.slice(0,4)}-${h.slice(4)}`;if(!(await Student.exists({access_code:c})))return c}};

/* ---------- express + auth ---------- */
const app=express();app.set("trust proxy",1);app.use(express.json({limit:"5mb"}));
const h=fn=>(q,r,n)=>Promise.resolve(fn(q,r,n)).catch(n);          // forward async errors to the error handler
const sign=p=>jwt.sign(p,JWT_SECRET,{expiresIn:"12h"});
// Checked on EVERY request: deactivating or deleting a student cuts access immediately.
const auth=role=>h(async(q,r,n)=>{let t;
 try{t=jwt.verify((q.headers.authorization||"").slice(7),JWT_SECRET);if(t.role!==role)throw 0}catch{return r.status(401).json({error:"Please log in again"})}
 if(role==="parent"){const s=await Student.findOne({id:t.sid});if(!s||!s.active)return r.status(403).json({error:"Access revoked. Please contact the academy."});q.st=s}
 n()});
const A=auth("admin"),P=auth("parent");
const limiter=rateLimit({windowMs:15*60*1000,max:20,message:{error:"Too many attempts. Try again later."}});

app.post("/api/admin/login",limiter,h(async(q,r)=>{
 const a=await Admin.findOne({email:String(q.body.email||"").trim().toLowerCase()});
 if(!a||!bcrypt.compareSync(String(q.body.password||""),a.password_hash))return r.status(401).json({error:"Invalid email or password"});
 r.json({token:sign({role:"admin"})})}));
app.post("/api/parent/login",limiter,h(async(q,r)=>{
 const s=await Student.findOne({access_code:String(q.body.code||"").trim().toUpperCase()}).lean();
 if(!s)return r.status(401).json({error:"Invalid access code"});
 if(!s.active)return r.status(403).json({error:"This account is inactive. Please contact the academy."});
 r.json({token:sign({role:"parent",sid:s.id}),student:dto(s)})}));

/* ---------- admin ---------- */
app.get("/api/admin/students",A,h(async(q,r)=>r.json({students:(await Student.find().sort({id:1}).lean()).map(s=>dto(s,true))})));
app.post("/api/admin/students",A,h(async(q,r)=>{const n=String(q.body.name||"").trim();if(!n)return r.status(400).json({error:"Name required"});
 const s=await Student.create({id:await nextId(),name:n,fee:+q.body.fee||0,access_code:await newCode()});r.json({student:dto(s.toObject(),true)})}));
app.patch("/api/admin/students/:id",A,h(async(q,r)=>{const u={};
 if(q.body.active!==undefined)u.active=!!q.body.active;if(q.body.fee!==undefined)u.fee=+q.body.fee||0;
 if(!(await Student.findOneAndUpdate({id:+q.params.id},u)))return r.sendStatus(404);r.json({ok:1})}));
app.delete("/api/admin/students/:id",A,h(async(q,r)=>{await Student.deleteOne({id:+q.params.id});r.json({ok:1})}));
app.post("/api/admin/students/:id/code",A,h(async(q,r)=>{const s=await Student.findOne({id:+q.params.id});if(!s)return r.sendStatus(404);
 s.access_code=await newCode();await s.save();r.json({code:s.access_code})}));
app.post("/api/admin/students/:id/progress",A,h(async(q,r)=>{const s=await Student.findOne({id:+q.params.id});if(!s)return r.sendStatus(404);
 const add=(a,v)=>[...a,+v||0].slice(-12);
 s.lessons=add(s.lessons,q.body.lessons);s.puzzles=add(s.puzzles,q.body.puzzles);s.ratings=add(s.ratings,q.body.rating);await s.save();r.json({ok:1})}));

/* ---------- parent ---------- */
app.get("/api/parent/me",P,(q,r)=>r.json({student:dto(q.st.toObject())}));
app.patch("/api/parent/usernames",P,h(async(q,r)=>{const ok=v=>/^[A-Za-z0-9_-]{0,30}$/.test(v||"");
 if(!ok(q.body.cc)||!ok(q.body.li))return r.status(400).json({error:"Invalid username"});
 q.st.cc=q.body.cc||"";q.st.li=q.body.li||"";await q.st.save();r.json({ok:1})}));
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
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<meta name="application-name" content="Birati Chess">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="Birati Chess">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<link rel="icon" type="image/png" href="/icon-192.png">
<link rel="apple-touch-icon" href="/icon-192.png">
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
 <td><button data-pr="\${s.id}" class="text-blue-700 text-xs mr-2">+Progress</button><button data-rg="\${s.id}" class="text-gray-600 text-xs mr-2">New code</button><button data-del="\${s.id}" class="text-red-600 text-xs">Delete</button></td></tr>\`).join("")}</tbody></table></div><div class="mt-4 pt-3 border-t flex flex-wrap gap-2 items-center text-sm"><button id="bk" class="px-3 py-1 rounded border">⬇ Download backup</button><label class="px-3 py-1 rounded border cursor-pointer">⬆ Restore backup<input id="rs" type="file" accept=".json" class="hidden"></label><span class="text-xs text-gray-400">Download a backup after adding students.</span></div>\`);
 document.querySelectorAll("[data-tg]").forEach(b=>b.onclick=async()=>{const s=ST(+b.dataset.tg);await api("PATCH","/api/admin/students/"+s.id,{active:!s.active});s.active=!s.active;vStudents()});
 document.querySelectorAll("[data-del]").forEach(b=>b.onclick=async()=>{if(confirm("Permanently delete this student account?")){await api("DELETE","/api/admin/students/"+b.dataset.del);DB.students=DB.students.filter(s=>s.id!==+b.dataset.del);vStudents()}});
 document.querySelectorAll("[data-rg]").forEach(b=>b.onclick=async()=>{const d=await api("POST","/api/admin/students/"+b.dataset.rg+"/code");await load();alert("New access code: "+d.code);vStudents()});
 document.querySelectorAll("[data-pr]").forEach(b=>b.onclick=async()=>{const v=prompt("Cumulative lessons, puzzles, rating (e.g. 28, 310, 1100)");if(!v)return;const[l,p,r]=v.split(",").map(Number);await api("POST","/api/admin/students/"+b.dataset.pr+"/progress",{lessons:l,puzzles:p,rating:r});await load();vStudents()});
 $("#add").onclick=async()=>{const n=$("#nn").value.trim();if(!n)return;const d=await api("POST","/api/admin/students",{name:n,fee:+$("#nf").value||1500});DB.students.push(d.student);alert("Access code for "+n+":\\n\\n"+d.student.code+"\\n\\nShare this with the parent.");vStudents()};
 $("#bk").onclick=async()=>{const r=await fetch("/api/admin/backup",{headers:{Authorization:"Bearer "+TOKEN}});const u=URL.createObjectURL(await r.blob()),a=document.createElement("a");a.href=u;a.download="academy-backup-"+new Date().toISOString().slice(0,10)+".json";a.click();URL.revokeObjectURL(u)};
 $("#rs").onchange=async e=>{const f=e.target.files[0];if(!f||!confirm("Replace ALL current students with this backup?"))return;try{const d=await api("POST","/api/admin/restore",JSON.parse(await f.text()));await load();alert("Restored "+d.count+" students.");vStudents()}catch(x){alert("Restore failed: "+x.message)}};
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
</script>
<script>if("serviceWorker"in navigator)addEventListener("load",()=>navigator.serviceWorker.register("/sw.js").catch(()=>{}))</script></body></html>
`;

/* ---------- PWA: manifest, service worker, generated icons ---------- */
const MANIFEST={id:"/",name:"Birati Chess Academy",short_name:"Birati Chess",description:"Birati Chess Academy™ Parent Portal & Management System",
 start_url:"/",scope:"/",display:"standalone",orientation:"portrait-primary",theme_color:"#0f172a",background_color:"#0f172a",lang:"en",categories:["education"],
 icons:[192,512].flatMap(s=>["any","maskable"].map(p=>({src:`/icon-${s}.png`,sizes:`${s}x${s}`,type:"image/png",purpose:p})))};
const SW=`const V="bca-v1",SHELL=["/","/manifest.json","/icon-192.png"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(V).then(c=>c.addAll(SHELL)).then(()=>self.skipWaiting()))});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==V).map(x=>caches.delete(x)))).then(()=>self.clients.claim()))});
self.addEventListener("fetch",e=>{const r=e.request,u=new URL(r.url);
 if(r.method!=="GET"||u.origin!==location.origin||u.pathname.startsWith("/api/"))return; // never cache private data, PDFs or API calls
 if(r.mode==="navigate"){e.respondWith(fetch(r).then(x=>{if(u.pathname==="/"){const c=x.clone();caches.open(V).then(k=>k.put("/",c))}return x}).catch(()=>caches.match("/")));return}
 e.respondWith(caches.match(r).then(h=>h||fetch(r)))});`;
// tiny pure-Node PNG encoder: navy tile with a gold pawn (kept inside the maskable safe zone)
const zlib=require("zlib"),crcT=(()=>{const t=[];for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=c&1?0xEDB88320^(c>>>1):c>>>1;t[n]=c>>>0}return t})();
const crc32=b=>{let c=~0;for(const x of b)c=crcT[(c^x)&255]^(c>>>8);return~c>>>0};
const chunk=(t,d)=>{const l=Buffer.alloc(4),c=Buffer.alloc(4),td=Buffer.concat([Buffer.from(t),d]);l.writeUInt32BE(d.length);c.writeUInt32BE(crc32(td));return Buffer.concat([l,td,c])};
const pawn=(X,Y)=>{const dx=Math.abs(X-256);
 return dx*dx+(Y-185)**2<56**2||(Y>=236&&Y<=254&&dx<52)||(Y>254&&Y<=352&&dx<28+(Y-254)*.36)||(Y>352&&Y<=388&&dx<88)};
function makePng(n){const bg=[15,23,42],fg=[245,166,35],row=n*3+1,raw=Buffer.alloc(row*n),u=512/n;
 for(let y=0;y<n;y++){raw[y*row]=0;for(let x=0;x<n;x++){let a=0;
  for(let i=0;i<2;i++)for(let j=0;j<2;j++)if(pawn((x+i/2+.25)*u,(y+j/2+.25)*u))a++;a/=4;
  for(let k=0;k<3;k++)raw[y*row+1+x*3+k]=Math.round(bg[k]+(fg[k]-bg[k])*a)}}
 const h=Buffer.alloc(13);h.writeUInt32BE(n,0);h.writeUInt32BE(n,4);h[8]=8;h[9]=2;
 return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk("IHDR",h),chunk("IDAT",zlib.deflateSync(raw)),chunk("IEND",Buffer.alloc(0))])}
const icons={};
app.get("/manifest.json",(q,r)=>r.type("application/manifest+json").set("Cache-Control","no-cache").send(JSON.stringify(MANIFEST)));
app.get("/sw.js",(q,r)=>r.type("application/javascript").set({"Cache-Control":"no-cache","Service-Worker-Allowed":"/"}).send(SW));
app.get(["/icon-192.png","/icon-512.png"],(q,r)=>{const n=q.path.includes("512")?512:192;r.type("png").set("Cache-Control","public, max-age=86400").send(icons[n]||(icons[n]=makePng(n)))});

/* ---------- admin backup / restore ---------- */
app.get("/api/admin/backup",A,h(async(q,r)=>{r.set("Content-Disposition",'attachment; filename="academy-backup.json"');
 r.json({students:(await Student.find().sort({id:1}).lean()).map(pick)})}));
app.post("/api/admin/restore",A,h(async(q,r)=>{const st=q.body&&q.body.students;
 const ok=Array.isArray(st)&&st.every(s=>s&&Number.isInteger(s.id)&&s.name&&s.access_code&&Array.isArray(s.lessons)&&Array.isArray(s.puzzles)&&Array.isArray(s.ratings))
  &&new Set(st.map(s=>s.id)).size===st.length&&new Set(st.map(s=>s.access_code)).size===st.length;
 if(!ok)return r.status(400).json({error:"Not a valid academy backup file"});
 await Student.deleteMany({});if(st.length)await Student.insertMany(st.map(pick));
 await Counter.findOneAndUpdate({_id:"student"},{seq:Math.max(0,...st.map(s=>s.id))},{upsert:true});r.json({count:st.length})}));

/* ---------- homepage, health check & fallbacks ---------- */
app.get("/healthz",(q,r)=>mongoose.connection.readyState===1?r.send("ok"):r.status(503).send("database not connected"));
app.use("/api",(q,r)=>r.status(404).json({error:"Not found"}));
app.get("/",(q,r)=>r.type("html").send(HTML));
app.use(express.static(path.join(__dirname,"public")));   // optional: any extra static files in ./public
app.get("*",(q,r)=>r.redirect("/"));   // any other page → login screen
app.use((e,q,r,n)=>{console.error(e);r.status(e.status||500).json({error:e.status===400?"Bad request":"Server error"})});


/* ---------- start: connect to MongoDB first, then listen ---------- */
async function seed(){
 if(!(await Admin.exists({})))await Admin.create({email:ADMIN_EMAIL,password_hash:bcrypt.hashSync(ADMIN_PASSWORD,10)});
 // one-time import of a legacy academy.json from the old file-based version (only when the students collection is empty)
 const legacy=process.env.DB_PATH||path.join(__dirname,"academy.json");
 if(!(await Student.exists({}))&&fs.existsSync(legacy)){try{const d=JSON.parse(fs.readFileSync(legacy,"utf8"));
  if(Array.isArray(d.students)&&d.students.length){await Student.insertMany(d.students.map(pick));
   await Counter.findOneAndUpdate({_id:"student"},{seq:Math.max(...d.students.map(s=>s.id))},{upsert:true});console.log("Imported",d.students.length,"students from",legacy)}}
  catch(e){console.warn("Legacy import skipped:",e.message)}}}
mongoose.connect(DATABASE_URL,{serverSelectionTimeoutMS:15000})
 .then(async()=>{console.log("✅ MongoDB connected successfully");await seed();
  app.listen(PORT,"0.0.0.0",()=>console.log(`Birati Chess Academy running on port ${PORT}`))})
 .catch(err=>{console.error("❌ MongoDB connection failed:",err.message);process.exit(1)});
