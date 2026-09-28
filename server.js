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
const app=express();app.set("trust proxy",1);app.use(express.json());app.use(express.static(path.join(__dirname,"public")));
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

app.listen(PORT,"0.0.0.0",()=>console.log(`Birati Chess Academy running on port ${PORT}`));
