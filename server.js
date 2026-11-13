// campusPay prototype backend: zero dependencies, Node 18+. Run: node server.js
const http=require('http'),fs=require('fs'),crypto=require('crypto'),path=require('path');
const FILE=path.join(__dirname,'data.json'),PORT=process.env.PORT||3000;
const H=s=>crypto.createHash('sha256').update(s).digest('hex');
const hashPw=p=>crypto.scryptSync(p,'campuspay-salt',32).toString('hex');
const fail=(m,s=400)=>{const e=new Error(m);e.status=s;throw e};
const sessions={};let db;

// ---- Ledger: hash-chained blocks (stand-in for the on-chain record) ----
function ledger(type,data){
  const p=db.ledger[db.ledger.length-1],b={i:db.ledger.length,ts:Date.now(),type,data,prev:p?p.hash:'0'.repeat(64)};
  b.hash=H(b.prev+b.i+b.ts+type+JSON.stringify(data));db.ledger.push(b);return b;
}
function verify(){
  for(let k=0;k<db.ledger.length;k++){
    const b=db.ledger[k],prev=k?db.ledger[k-1].hash:'0'.repeat(64);
    if(b.prev!==prev||b.hash!==H(b.prev+b.i+b.ts+b.type+JSON.stringify(b.data)))return{valid:false,brokenAt:b.i};
  }
  return{valid:true,blocks:db.ledger.length};
}
function seed(){
  const u=(email,name,role,extra={})=>({email,name,role,pw:hashPw('demo123'),...extra});
  db={users:[u('parent@campus.in','Meera (Parent)','parent'),u('student@campus.in','Arjun (Student)','student'),
    u('admin@campus.in','College Admin','admin'),u('canteen@campus.in','Campus Canteen','merchant',{merchantId:'m1'}),
    u('books@campus.in','Library Store','merchant',{merchantId:'m2'}),u('pixel@campus.in','PixelPlay Store','merchant',{merchantId:'m3'})],
    merchants:[{id:'m1',name:'Campus Canteen',category:'Food',approved:true},{id:'m2',name:'Library Store',category:'Education',approved:true},
      {id:'m3',name:'PixelPlay Store',category:'Gaming',approved:false}],
    wallet:{balance:0,dailyLimit:2000,rules:{Food:1500,Education:2000,Transport:1000,Other:500}},
    requests:[],txs:[],ledger:[]};
  ledger('GENESIS',{note:'campusPay ledger created'});save();
}
const save=()=>fs.writeFileSync(FILE,JSON.stringify(db,null,1));
try{db=JSON.parse(fs.readFileSync(FILE))}catch{seed()}

const spentIn=c=>db.txs.filter(t=>t.status==='APPROVED'&&t.category===c).reduce((s,t)=>s+t.amount,0);

// ---- Rule engine: mirrors what the Algorand smart contract's pay() enforces ----
function pay(requestId){
  const r=db.requests.find(x=>x.id===requestId);
  if(!r||r.status!=='open')fail('Payment request not found or already used');
  const m=db.merchants.find(x=>x.id===r.merchantId),w=db.wallet,today=new Date().toDateString();
  const day=db.txs.filter(t=>t.status==='APPROVED'&&new Date(t.ts).toDateString()===today).reduce((s,t)=>s+t.amount,0);
  let reason=null;
  if(Date.now()>r.expires)reason='Request expired';
  else if(!m.approved)reason='Merchant is not an approved campus merchant';
  else if(!(m.category in w.rules))reason=`No budget set for ${m.category}`;
  else if(r.amount>w.rules[m.category]-spentIn(m.category))reason=`${m.category} budget exceeded (₹${w.rules[m.category]-spentIn(m.category)} left)`;
  else if(day+r.amount>w.dailyLimit)reason=`Daily limit of ₹${w.dailyLimit} exceeded`;
  else if(r.amount>w.balance)reason='Insufficient wallet balance';
  const ok=!reason;
  const tx={id:'tx'+(db.txs.length+1),ts:Date.now(),merchantId:m.id,merchant:m.name,category:m.category,amount:r.amount,status:ok?'APPROVED':'BLOCKED',reason};
  if(ok)w.balance-=r.amount;
  r.status='done';
  tx.block=ledger(ok?'PAYMENT':'BLOCKED',{tx:tx.id,merchant:m.name,category:m.category,amount:r.amount,reason}).i;
  db.txs.push(tx);return tx;
}

const send=(r,c,o)=>{r.writeHead(c,{'Content-Type':'application/json'});r.end(JSON.stringify(o))};
function route(req,res,p,body){
  if(p==='/api/login'&&req.method==='POST'){
    const u=db.users.find(x=>x.email===body.email&&x.pw===hashPw(body.password||''));
    if(!u)fail('Wrong email or password',401);
    const t=crypto.randomBytes(24).toString('hex');sessions[t]=u;return send(res,200,{token:t});
  }
  const me=sessions[(req.headers.authorization||'').slice(7)];
  if(!me)fail('Please log in',401);
  const need=role=>{if(me.role!==role)fail('Only a '+role+' can do this',403)};
  const w=db.wallet;
  if(p==='/api/state'){
    const spent={};Object.keys(w.rules).forEach(c=>spent[c]=spentIn(c));
    let txs=db.txs,reqs=db.requests;
    if(me.role==='merchant'){txs=txs.filter(t=>t.merchantId===me.merchantId);reqs=reqs.filter(r=>r.merchantId===me.merchantId)}
    if(me.role==='student')reqs=reqs.filter(r=>r.status==='open');
    return send(res,200,{me:{name:me.name,role:me.role,merchantId:me.merchantId},wallet:me.role==='merchant'?null:{...w,spent},
      merchants:db.merchants,requests:reqs.slice(-8).reverse(),txs:txs.slice(-12).reverse(),ledger:db.ledger.slice(-8).reverse(),total:db.ledger.length});
  }
  if(p==='/api/verify')return send(res,200,verify());
  if(req.method!=='POST'&&req.method!=='PUT')fail('Not found',404);
  if(p==='/api/fund'){need('parent');const a=Math.floor(+body.amount);if(!(a>0))fail('Enter an amount above 0');
    w.balance+=a;ledger('DEPOSIT',{amount:a,by:me.name});}
  else if(p==='/api/rules'){need('parent');
    if(body.dailyLimit!==undefined){const d=Math.floor(+body.dailyLimit);if(!(d>=0))fail('Invalid limit');w.dailyLimit=d;ledger('RULE_SET',{dailyLimit:d,by:me.name})}
    else{const c=String(body.category||'').trim(),b=Math.floor(+body.budget);if(!c||!(b>=0))fail('Enter a category and budget');
      w.rules[c]=b;ledger('RULE_SET',{category:c,budget:b,by:me.name})}}
  else if(p==='/api/merchants/approve'){need('admin');const m=db.merchants.find(x=>x.id===body.id);if(!m)fail('Unknown merchant',404);
    m.approved=!!body.approved;ledger('MERCHANT',{merchant:m.name,approved:m.approved,by:me.name})}
  else if(p==='/api/requests'){need('merchant');const a=Math.floor(+body.amount);if(!(a>0))fail('Enter an amount above 0');
    const r={id:'PAY-'+crypto.randomBytes(3).toString('hex').toUpperCase(),merchantId:me.merchantId,amount:a,status:'open',expires:Date.now()+10*60000};
    db.requests.push(r);save();return send(res,200,r)}
  else if(p==='/api/pay'){need('student');const tx=pay(body.requestId);save();return send(res,200,tx)}
  else if(p==='/api/demo/tamper'){need('admin');const b=db.ledger.find(x=>x.type==='DEPOSIT')||db.ledger[0];b.data={...b.data,amount:999999}}
  else if(p==='/api/demo/reset'){need('admin');seed()}
  else fail('Not found',404);
  save();send(res,200,{ok:true});
}
http.createServer((req,res)=>{
  const u=new URL(req.url,'http://x');
  if(!u.pathname.startsWith('/api')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(fs.readFileSync(path.join(__dirname,'index.html')))}
  let b='';req.on('data',d=>b+=d);
  req.on('end',()=>{try{route(req,res,u.pathname,b?JSON.parse(b):{})}catch(e){send(res,e.status||500,{error:e.message})}});
}).listen(PORT,()=>console.log('campusPay running at http://localhost:'+PORT));