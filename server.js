const express=require("express"),Database=require("better-sqlite3"),bcrypt=require("bcryptjs"),jwt=require("jsonwebtoken"),
rateLimit=require("express-rate-limit"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const {JWT_SECRET,ADMIN_EMAIL,ADMIN_PASSWORD,PORT=3000}=process.env;
if(!JWT_SECRET||!ADMIN_EMAIL||!ADMIN_PASSWORD)throw new Error("Set JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD in .env");

/* ---------- database ---------- */
const db=new Database("academy.db");db.pragma("foreign_keys=ON");
db.exec(`
CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS students(
 id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,parent TEXT DEFAULT '',course TEXT DEFAULT 'Beginner',
 access_code TEXT UNIQUE NOT NULL,active INTEGER NOT NULL DEFAULT 1,fee REAL NOT NULL DEFAULT 0,
 cc TEXT DEFAULT '',li TEXT DEFAULT '',
 lessons TEXT DEFAULT '[0]',puzzles TEXT DEFAULT '[0]',ratings TEXT DEFAULT '[800]',   -- JSON arrays, one entry per progress update
 win INTEGER DEFAULT 0,games INTEGER DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);
if(!db.prepare("SELECT 1 FROM admins").get())
 db.prepare("INSERT INTO admins(email,password_hash) VALUES(?,?)").run(ADMIN_EMAIL.toLowerCase(),bcrypt.hashSync(ADMIN_PASSWORD,10));

const J=JSON.parse,get=id=>db.prepare("SELECT * FROM students WHERE id=?").get(id);
const dto=(s,admin)=>({id:s.id,name:s.name,parent:s.parent,course:s.course,active:!!s.active,fee:s.fee,cc:s.cc||"",li:s.li||"",
 lessons:J(s.lessons),puzzles:J(s.puzzles),ratings:J(s.ratings),ccR:J(s.ratings).at(-1),win:s.win,games:s.games,...(admin?{code:s.access_code}:{})});
const newCode=()=>{const h=crypto.randomBytes(4).toString("hex").toUpperCase();return`BCA-${h.slice(0,4)}-${h.slice(4)}`};

/* ---------- auth ---------- */
const sign=p=>jwt.sign(p,JWT_SECRET,{expiresIn:"12h"});
// Verified on EVERY request: deactivating or deleting a student cuts access immediately.
const auth=role=>(q,r,n)=>{try{
 const t=jwt.verify((q.headers.authorization||"").slice(7),JWT_SECRET);if(t.role!==role)throw 0;
 if(role==="parent"){const s=get(t.sid);if(!s||!s.active)return r.status(403).json({error:"Access revoked. Please contact the academy."});q.st=s}
 n()}catch{r.status(401).json({error:"Please log in again"})}};
const A=auth("admin"),P=auth("parent");
const app=express();app.use(express.json());app.use(express.static(path.join(__dirname,"public")));
const limiter=rateLimit({windowMs:15*60*1000,max:20,message:{error:"Too many attempts. Try again later."}});

app.post("/api/admin/login",limiter,(q,r)=>{
 const a=db.prepare("SELECT * FROM admins WHERE email=?").get(String(q.body.email||"").toLowerCase());
 if(!a||!bcrypt.compareSync(String(q.body.password||""),a.password_hash))return r.status(401).json({error:"Invalid email or password"});
 r.json({token:sign({role:"admin"})})});
app.post("/api/parent/login",limiter,(q,r)=>{
 const s=db.prepare("SELECT * FROM students WHERE access_code=?").get(String(q.body.code||"").trim().toUpperCase());
 if(!s)return r.status(401).json({error:"Invalid access code"});
 if(!s.active)return r.status(403).json({error:"This account is inactive. Please contact the academy."});
 r.json({token:sign({role:"parent",sid:s.id}),student:dto(s)})});

/* ---------- admin ---------- */
app.get("/api/admin/students",A,(q,r)=>r.json({students:db.prepare("SELECT * FROM students ORDER BY id").all().map(s=>dto(s,true))}));
app.post("/api/admin/students",A,(q,r)=>{const n=String(q.body.name||"").trim();if(!n)return r.status(400).json({error:"Name required"});
 const i=db.prepare("INSERT INTO students(name,fee,access_code) VALUES(?,?,?)").run(n,+q.body.fee||0,newCode());
 r.json({student:dto(get(i.lastInsertRowid),true)})});
app.patch("/api/admin/students/:id",A,(q,r)=>{const{active,fee}=q.body,id=q.params.id;
 if(active!==undefined)db.prepare("UPDATE students SET active=? WHERE id=?").run(active?1:0,id);
 if(fee!==undefined)db.prepare("UPDATE students SET fee=? WHERE id=?").run(+fee||0,id);r.json({ok:1})});
app.delete("/api/admin/students/:id",A,(q,r)=>{db.prepare("DELETE FROM students WHERE id=?").run(q.params.id);r.json({ok:1})});
app.post("/api/admin/students/:id/code",A,(q,r)=>{const c=newCode();db.prepare("UPDATE students SET access_code=? WHERE id=?").run(c,q.params.id);r.json({code:c})});
app.post("/api/admin/students/:id/progress",A,(q,r)=>{const s=get(q.params.id);if(!s)return r.sendStatus(404);
 const add=(k,v)=>JSON.stringify([...J(s[k]),+v||0].slice(-12));
 db.prepare("UPDATE students SET lessons=?,puzzles=?,ratings=? WHERE id=?").run(add("lessons",q.body.lessons),add("puzzles",q.body.puzzles),add("ratings",q.body.rating),s.id);r.json({ok:1})});

/* ---------- parent ---------- */
app.get("/api/parent/me",P,(q,r)=>r.json({student:dto(q.st)}));
app.patch("/api/parent/usernames",P,(q,r)=>{const ok=v=>/^[A-Za-z0-9_-]{0,30}$/.test(v||"");
 if(!ok(q.body.cc)||!ok(q.body.li))return r.status(400).json({error:"Invalid username"});
 db.prepare("UPDATE students SET cc=?,li=? WHERE id=?").run(q.body.cc||"",q.body.li||"",q.st.id);r.json({ok:1})});
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

app.listen(PORT,()=>console.log(`Birati Chess Academy running on http://localhost:${PORT}`));
