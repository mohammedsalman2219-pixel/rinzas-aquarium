const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const {DatabaseSync}=require("node:sqlite");
const PORT=process.env.PORT||3000,USER=process.env.ADMIN_USER||"owner",PASS=process.env.ADMIN_PASSWORD||"change-this-password";
const db=new DatabaseSync(path.join(__dirname,"rinzas.sqlite"));
db.exec(`CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,phone TEXT UNIQUE,password_hash TEXT,address TEXT,created_at TEXT);CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,customer_id INTEGER,customer_json TEXT,items_json TEXT,total REAL,address TEXT,status TEXT,date TEXT,created_at TEXT);`);
const sessions=new Map(),hash=x=>crypto.createHash("sha256").update(String(x)).digest("hex"),tok=()=>crypto.randomBytes(32).toString("hex");
const send=(r,s,d,t="application/json; charset=utf-8")=>{r.writeHead(s,{"Content-Type":t});r.end(t.startsWith("application/json")?JSON.stringify(d):d)};
const body=q=>new Promise((ok,no)=>{let s="";q.on("data",x=>s+=x);q.on("end",()=>{try{ok(s?JSON.parse(s):{})}catch(e){no(e)}})});
const auth=q=>{let h=q.headers.authorization||"",t=h.startsWith("Bearer ")?h.slice(7):"";return sessions.get(t)};
async function route(q,r){
 const u=new URL(q.url,"http://localhost"),p=u.pathname;
 if(q.method==="GET"&&p==="/api/health")return send(r,200,{ok:true,database:"SQLite"});
 if(q.method==="POST"&&p==="/api/customers/register"){let b=await body(q);if(!b.name||!b.phone||!b.password)return send(r,400,{error:"Name, phone and password required"});try{let x=db.prepare("INSERT INTO customers(name,phone,password_hash,address,created_at) VALUES(?,?,?,?,?)").run(b.name,b.phone,hash(b.password),b.address||"",new Date().toISOString());return send(r,201,{customer:db.prepare("SELECT id,name,phone,address,created_at FROM customers WHERE id=?").get(x.lastInsertRowid)})}catch(e){return send(r,409,{error:"Phone already registered"})}}
 if(q.method==="POST"&&p==="/api/customers/login"){let b=await body(q),c=db.prepare("SELECT id,name,phone,address,created_at FROM customers WHERE phone=? AND password_hash=?").get(b.phone,hash(b.password));if(!c)return send(r,401,{error:"Invalid login"});return send(r,200,{customer:c})}
 if(q.method==="POST"&&p==="/api/admin/login"){let b=await body(q);if(b.username!==USER||b.password!==PASS)return send(r,401,{error:"Invalid owner login"});let t=tok();sessions.set(t,{role:"admin"});return send(r,200,{token:t})}
 if(q.method==="GET"&&p==="/api/orders"){if(!auth(q))return send(r,401,{error:"Owner login required"});let rows=db.prepare("SELECT * FROM orders ORDER BY created_at DESC").all();return send(r,200,{orders:rows.map(x=>({...x,items:JSON.parse(x.items_json),customer:x.customer_json?JSON.parse(x.customer_json):null}))})}
 if(q.method==="POST"&&p==="/api/orders"){let b=await body(q);if(!b.id||!Array.isArray(b.items))return send(r,400,{error:"Invalid order"});db.prepare("INSERT OR REPLACE INTO orders(id,customer_id,customer_json,items_json,total,address,status,date,created_at) VALUES(?,?,?,?,?,?,?,?,?)").run(b.id,b.customerId||null,b.customer?JSON.stringify(b.customer):null,JSON.stringify(b.items),b.total||0,b.address||"",b.status||"Order Received",b.date||new Date().toLocaleString("en-IN"),new Date().toISOString());return send(r,201,{ok:true})}
 let m=p.match(/^\/api\/orders\/([^/]+)$/);if(m&&q.method==="PATCH"){if(!auth(q))return send(r,401,{error:"Owner login required"});let b=await body(q);db.prepare("UPDATE orders SET status=? WHERE id=?").run(b.status,decodeURIComponent(m[1]));return send(r,200,{ok:true})}
 let fp=p==="/" ? path.join(__dirname,"public","index.html"):path.join(__dirname,"public",path.normalize(p));if(!fp.startsWith(path.join(__dirname,"public")))return send(r,403,{error:"Forbidden"});fs.readFile(fp,(e,d)=>e?send(r,404,{error:"Not found"}):send(r,200,d,path.extname(fp)===".html"?"text/html; charset=utf-8":"application/octet-stream"))
}
http.createServer((q,r)=>route(q,r).catch(e=>send(r,500,{error:"Server error"}))).listen(PORT,()=>console.log("Rinzas Aquarium on http://localhost:"+PORT));
