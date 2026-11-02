import express from 'express';
import pg from 'pg';
import helmet from 'helmet';
import crypto from 'node:crypto';
import { rateLimit } from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
const pool = process.env.DATABASE_URL ? new pg.Pool({connectionString:process.env.DATABASE_URL, max:8, connectionTimeoutMillis:10000}) : null;
let ready = false;
const query = (sql,params=[]) => pool.query(sql,params);
const fail = (res,status,error) => res.status(status).json({error});
const wrap = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);
const rnd = (n=32) => crypto.randomBytes(n).toString('base64url');
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const passHash = (pw,salt=crypto.randomBytes(16).toString('hex')) => salt+':'+crypto.scryptSync(pw,salt,64).toString('hex');
function passOK(pw,hash){ try {const [salt,hex]=hash.split(':');return crypto.timingSafeEqual(Buffer.from(hex,'hex'),crypto.scryptSync(pw,salt,64));}catch{return false;} }
const txt = (s,n=180) => typeof s==='string' ? s.trim().slice(0,n) : '';
const emailOK = s => typeof s==='string' && s.length<255 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
const uuid = s => typeof s==='string' && /^[0-9a-f-]{36}$/i.test(s);
const kinds = new Set(['contacts','companies','deals','tasks']);
const roles = new Set(['admin','manager','member']);
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'","https://cdn.jsdelivr.net"],imgSrc:["'self'","data:","https://adornis.de"],fontSrc:["'self'","data:"],connectSrc:["'self'"],frameAncestors:["'none'"],objectSrc:["'none'"]}}}));
app.use(express.json({limit:'32kb'}));
app.use((req,res,next)=>{res.set('X-Robots-Tag','noindex,nofollow');next();});

async function initialize(){
  if(!pool)return;
  await query("CREATE TABLE IF NOT EXISTS tenants(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),name text NOT NULL)");
  await query("CREATE TABLE IF NOT EXISTS users(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),tenant_id uuid NOT NULL REFERENCES tenants(id),email text NOT NULL UNIQUE,full_name text NOT NULL,role text NOT NULL CHECK (role IN ('admin','manager','member')),team text NOT NULL,active boolean NOT NULL DEFAULT true,must_change_password boolean NOT NULL DEFAULT true,password_hash text NOT NULL)");
  await query("CREATE TABLE IF NOT EXISTS sessions(token_hash text PRIMARY KEY,user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,csrf text NOT NULL,expires_at timestamptz NOT NULL)");
  await query("CREATE TABLE IF NOT EXISTS records(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),tenant_id uuid NOT NULL REFERENCES tenants(id),kind text NOT NULL,title text NOT NULL,company text NOT NULL DEFAULT '',email text NOT NULL DEFAULT '',amount numeric(14,2) NOT NULL DEFAULT 0,stage text NOT NULL DEFAULT 'Lead',status text NOT NULL DEFAULT 'Offen',owner_id uuid NOT NULL REFERENCES users(id),team text NOT NULL,confidential boolean NOT NULL DEFAULT false,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now())");
  await query("CREATE INDEX IF NOT EXISTS record_scope ON records(tenant_id,kind,team,owner_id)");
  await query("CREATE TABLE IF NOT EXISTS audit(id bigserial PRIMARY KEY,tenant_id uuid NOT NULL,actor_id uuid NOT NULL,action text NOT NULL,kind text NOT NULL,record_id text,created_at timestamptz NOT NULL DEFAULT now())");
  const count=await query('SELECT count(*)::int AS total FROM users');
  if(count.rows[0].total===0){
    const email=txt(process.env.ADMIN_EMAIL,254).toLowerCase(),password=process.env.ADMIN_PASSWORD;
    if(!emailOK(email)||!password||password.length<16)throw new Error('ADMIN_EMAIL und ADMIN_PASSWORD (mind. 16 Zeichen) müssen in Render gesetzt sein');
    const client=await pool.connect();
    try{
      await client.query('BEGIN');
      const tenant=await client.query('INSERT INTO tenants(name) VALUES($1) RETURNING id',['Adornis CRM']);
      await client.query('INSERT INTO users(tenant_id,email,full_name,role,team,password_hash) VALUES($1,$2,$3,$4,$5,$6)',[tenant.rows[0].id,email,'Administrator','admin','Sales',passHash(password)]);
      await client.query('COMMIT');
    }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
  }
  ready=true;
}
if(pool)initialize().catch(e=>console.error('Initialisierung nicht bereit:',e.message));
app.get('/api/health',wrap(async(req,res)=>{
  if(!pool)return res.status(503).json({status:'configuration-required'});
  try{await query('SELECT 1');return res.status(ready?200:503).json({status:ready?'ready':'initializing',team:true});}
  catch{return res.status(503).json({status:'database-unavailable'});}
}));
app.use('/api',(req,res,next)=>{
  if(!['GET','HEAD','OPTIONS'].includes(req.method)&&req.get('origin')&&req.get('origin')!==req.protocol+'://'+req.get('host'))return fail(res,403,'Origin nicht erlaubt');
  next();
});
const cookie = (req,key) => (req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(key+'='))?.slice(key.length+1);
const setCookie=(res,value,maxAge=7*86400000)=>res.cookie('adornis_session',value,{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',path:'/',maxAge});
const safe=u=>({id:u.id,email:u.email,name:u.full_name,role:u.role,team:u.team,active:u.active,mustChangePassword:u.must_change_password});
async function auth(req,res,next){
  if(!ready)return fail(res,503,'CRM noch nicht eingerichtet');
  const token=cookie(req,'adornis_session');
  if(!token)return fail(res,401,'Bitte anmelden');
  const r=await query('SELECT u.*,s.csrf FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.active=true',[sha(token)]);
  if(!r.rowCount)return fail(res,401,'Sitzung abgelaufen');
  req.user=r.rows[0];req.tokenHash=sha(token);
  if(req.user.must_change_password&&!['/api/me','/api/password','/api/logout'].includes(req.path))return fail(res,403,'Bitte zuerst Passwort ändern');
  next();
}
const authorize=wrap(auth);
const csrf=(req,res,next)=>req.get('x-crm-csrf')&&req.get('x-crm-csrf')===req.user.csrf?next():fail(res,403,'Sicherheitstoken fehlt');
const onlyAdmin=(req,res,next)=>req.user.role==='admin'?next():fail(res,403,'Keine Administratorrechte');
const validKind=(req,res,next)=>kinds.has(req.params.kind)?next():fail(res,404,'Unbekannter Bereich');
const loginRate=rateLimit({windowMs:900000,limit:12,standardHeaders:'draft-7',legacyHeaders:false,message:{error:'Zu viele Anmeldeversuche'}});
app.post('/api/login',loginRate,wrap(async(req,res)=>{
  if(!ready)return fail(res,503,'CRM noch nicht eingerichtet');
  const email=txt(req.body?.email,254).toLowerCase(),password=req.body?.password;
  if(!emailOK(email)||typeof password!=='string'||password.length>256)return fail(res,400,'Ungültige Eingabe');
  const u=await query('SELECT * FROM users WHERE lower(email)=$1 AND active=true LIMIT 1',[email]);
  if(!u.rowCount||!passOK(password,u.rows[0].password_hash))return fail(res,401,'Anmeldedaten ungültig');
  const token=rnd(),csrfToken=rnd(24);
  await query("INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES($1,$2,$3,now()+interval '7 days')",[sha(token),u.rows[0].id,csrfToken]);
  setCookie(res,token);res.json({user:safe(u.rows[0]),csrf:csrfToken});
}));
app.get('/api/me',authorize,(req,res)=>res.json({user:safe(req.user),csrf:req.user.csrf}));
app.post('/api/logout',authorize,csrf,wrap(async(req,res)=>{await query('DELETE FROM sessions WHERE token_hash=$1',[req.tokenHash]);setCookie(res,'',0);res.json({ok:true});}));
app.post('/api/password',authorize,csrf,wrap(async(req,res)=>{
  const a=req.body||{},cur=a.currentPassword,newPass=a.newPassword;
  if(typeof cur!=='string'||typeof newPass!=='string'||newPass.length<12||newPass.length>256)return fail(res,400,'Neues Passwort benötigt mindestens 12 Zeichen');
  if(!passOK(cur,req.user.password_hash))return fail(res,403,'Altes Passwort falsch');
  await query('UPDATE users SET password_hash=$1,must_change_password=false WHERE id=$2',[passHash(newPass),req.user.id]);
  await query('DELETE FROM sessions WHERE user_id=$1 AND token_hash<>$2',[req.user.id,req.tokenHash]);
  res.json({ok:true});
}));
const canWrite=(u,r)=>u.role==='admin'||r.owner_id===u.id||(u.role==='manager'&&r.team===u.team);
const scope=(u,p=3)=>{
  if(u.role==='admin')return {sql:'',params:[]};
  if(u.role==='manager')return {sql:' AND (r.owner_id=$'+p+' OR r.team=$'+(p+1)+')',params:[u.id,u.team]};
  return {sql:' AND (r.owner_id=$'+p+' OR (r.team=$'+(p+1)+' AND NOT r.confidential))',params:[u.id,u.team]};
};
async function record(u,kind,id){
  const s=scope(u,4),r=await query('SELECT r.*,u.full_name AS owner_name FROM records r JOIN users u ON u.id=r.owner_id WHERE r.tenant_id=$1 AND r.kind=$2 AND r.id=$3'+s.sql,[u.tenant_id,kind,id,...s.params]);
  return r.rows[0];
}
async function log(u,action,kind,id){await query('INSERT INTO audit(tenant_id,actor_id,action,kind,record_id) VALUES($1,$2,$3,$4,$5)',[u.tenant_id,u.id,action,kind,String(id)]);}
function fields(body,kind){
  const title=txt(body.title),email=txt(body.email,254),amount=Number(body.amount||0);
  if(!title||email&&!emailOK(email)||!Number.isFinite(amount)||amount<0||amount>1e11)throw Object.assign(new Error('Ungültige Daten'),{status:400});
  return [title,txt(body.company,180),email,kind==='deals'?amount:0,txt(body.stage,40)||'Lead',txt(body.status,40)||'Offen',body.confidential===true];
}
app.get('/api/records/:kind',authorize,validKind,wrap(async(req,res)=>{
  const s=scope(req.user),r=await query('SELECT r.*,u.full_name AS owner_name FROM records r JOIN users u ON u.id=r.owner_id WHERE r.tenant_id=$1 AND r.kind=$2'+s.sql+' ORDER BY r.updated_at DESC LIMIT 500',[req.user.tenant_id,req.params.kind,...s.params]);
  res.json({records:r.rows});
}));
app.post('/api/records/:kind',authorize,csrf,validKind,wrap(async(req,res)=>{
  const f=fields(req.body||{},req.params.kind);
  const r=await query('INSERT INTO records(tenant_id,kind,title,company,email,amount,stage,status,confidential,owner_id,team) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id',[req.user.tenant_id,req.params.kind,...f,req.user.id,req.user.team]);
  await log(req.user,'create',req.params.kind,r.rows[0].id);res.status(201).json({id:r.rows[0].id});
}));
app.patch('/api/records/:kind/:id',authorize,csrf,validKind,wrap(async(req,res)=>{
  if(!uuid(req.params.id))return fail(res,400,'Ungültige ID');
  const old=await record(req.user,req.params.kind,req.params.id);
  if(!old)return fail(res,404,'Datensatz nicht sichtbar');
  if(!canWrite(req.user,old))return fail(res,403,'Bearbeitung nicht erlaubt');
  const f=fields({...old,...req.body},req.params.kind);
  await query('UPDATE records SET title=$1,company=$2,email=$3,amount=$4,stage=$5,status=$6,confidential=$7,updated_at=now() WHERE id=$8 AND tenant_id=$9',[...f,old.id,req.user.tenant_id]);
  await log(req.user,'update',req.params.kind,old.id);res.json({ok:true});
}));
app.delete('/api/records/:kind/:id',authorize,csrf,validKind,wrap(async(req,res)=>{
  if(!uuid(req.params.id))return fail(res,400,'Ungültige ID');
  const old=await record(req.user,req.params.kind,req.params.id);
  if(!old)return fail(res,404,'Datensatz nicht sichtbar');
  if(!canWrite(req.user,old))return fail(res,403,'Löschen nicht erlaubt');
  await query('DELETE FROM records WHERE tenant_id=$1 AND id=$2',[req.user.tenant_id,old.id]);
  await log(req.user,'delete',req.params.kind,old.id);res.json({ok:true});
}));
app.get('/api/team',authorize,wrap(async(req,res)=>{
  const r=await query('SELECT * FROM users WHERE tenant_id=$1 ORDER BY full_name',[req.user.tenant_id]);
  res.json({users:r.rows.filter(u=>req.user.role==='admin'||u.active).map(safe)});
}));
app.post('/api/team',authorize,csrf,onlyAdmin,wrap(async(req,res)=>{
  const b=req.body||{},email=txt(b.email,254).toLowerCase(),name=txt(b.name,120),team=txt(b.team,80)||'Sales';
  if(!emailOK(email)||!name||!roles.has(b.role))return fail(res,400,'Ungültige Benutzerdaten');
  const temp=rnd(20);
  try{
    const r=await query('INSERT INTO users(tenant_id,email,full_name,role,team,password_hash) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',[req.user.tenant_id,email,name,b.role,team,passHash(temp)]);
    await log(req.user,'create_user','users',r.rows[0].id);
    res.status(201).json({temporaryPassword:temp});
  }catch(e){if(e.code==='23505')return fail(res,409,'E-Mail bereits vorhanden');throw e;}
}));
app.patch('/api/team/:id',authorize,csrf,onlyAdmin,wrap(async(req,res)=>{
  const b=req.body||{};
  if(!uuid(req.params.id)||req.params.id===req.user.id||!roles.has(b.role)||typeof b.active!=='boolean'||!txt(b.team,80))return fail(res,400,'Ungültige Änderung');
  const r=await query('UPDATE users SET role=$1,active=$2,team=$3 WHERE id=$4 AND tenant_id=$5 RETURNING id',[b.role,b.active,txt(b.team,80),req.params.id,req.user.tenant_id]);
  if(!r.rowCount)return fail(res,404,'Benutzer nicht gefunden');
  await query('DELETE FROM sessions WHERE user_id=$1',[req.params.id]);
  await log(req.user,'update_user','users',req.params.id);res.json({ok:true});
}));
app.get('/api/audit',authorize,onlyAdmin,wrap(async(req,res)=>{
  const r=await query('SELECT a.action,a.kind,a.created_at,u.full_name AS actor FROM audit a JOIN users u ON u.id=a.actor_id WHERE a.tenant_id=$1 ORDER BY a.created_at DESC LIMIT 100',[req.user.tenant_id]);
  res.json({events:r.rows});
}));
app.use('/api',(req,res)=>fail(res,404,'API-Endpunkt nicht gefunden'));
const root=path.dirname(fileURLToPath(import.meta.url));
app.use(express.static(path.join(root,'public'),{maxAge:'1h'}));
app.get('*',(req,res)=>res.sendFile(path.join(root,'public/index.html')));
app.use((e,req,res,next)=>{console.error('Request:',e.message);if(res.headersSent)return next(e);fail(res,e.status||500,e.status?e.message:'Serverfehler');});
app.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('Adornis CRM Team gestartet'));
