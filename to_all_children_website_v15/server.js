const express=require('express');
const crypto=require('crypto');
const path=require('path');
const Database=require('better-sqlite3');

const app=express();
app.disable('x-powered-by');
app.set('trust proxy',1);

const db=new Database(path.join(__dirname,'data','stories.db'));
db.pragma('journal_mode = WAL');

const sessions=new Map();

function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){
  return salt+':'+crypto.scryptSync(password,salt,64).toString('hex');
}

function verifyPassword(password,stored){
  const [salt,key]=stored.split(':');
  return crypto.timingSafeEqual(
    Buffer.from(key,'hex'),
    crypto.scryptSync(password,salt,64)
  );
}

function auth(req,res,next){
  const token=(req.headers.authorization||'').replace('Bearer ','');
  const uid=sessions.get(token);

  if(!uid){
    return res.status(401).json({error:'Please log in'});
  }

  req.userId=uid;
  next();
}

function adminAuth(req,res,next){
  auth(req,res,()=>{
    const user=db.prepare(
      'SELECT id,role FROM users WHERE id=?'
    ).get(req.userId);

    if(!user || user.role!=='admin'){
      return res.status(403).json({error:'Admin access required'});
    }

    next();
  });
}

db.exec(`
CREATE TABLE IF NOT EXISTS stories(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title_en TEXT NOT NULL,
  title_rw TEXT NOT NULL,
  body_en TEXT NOT NULL,
  body_rw TEXT NOT NULL,
  category TEXT DEFAULT 'General',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT,
  role TEXT DEFAULT 'parent',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS favorites(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  story_id INTEGER,
  UNIQUE(user_id,story_id)
);

CREATE TABLE IF NOT EXISTS progress(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  story_id INTEGER,
  percent INTEGER DEFAULT 0,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id,story_id)
);
`);

/* Create or update the Admin account from Render Environment Variables */
const adminEmail=(process.env.ADMIN_EMAIL||'').trim().toLowerCase();
const adminPassword=process.env.ADMIN_PASSWORD||'';

if(adminEmail && adminPassword.length>=12){
  const existing=db.prepare(
    'SELECT id FROM users WHERE email=?'
  ).get(adminEmail);

  const passwordHash=hashPassword(adminPassword);

  if(existing){
    db.prepare(
      'UPDATE users SET name=?,password_hash=?,role=? WHERE email=?'
    ).run('Administrator',passwordHash,'admin',adminEmail);
  }else{
    db.prepare(
      'INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)'
    ).run('Administrator',adminEmail,passwordHash,'admin');
  }
}

const count=db.prepare('SELECT COUNT(*) c FROM stories').get().c;

if(!count){
  db.prepare(`
    INSERT INTO stories(
      title_en,title_rw,body_en,body_rw,category
    ) VALUES(?,?,?,?,?)
  `).run(
    'The Little Bird',
    'Akanyoni gato',
    'Once there was a little bird who loved to help everyone.',
    'Habayeho akanyoni gato kakundaga gufasha buri wese.',
    'Kindness'
  );
}

app.use(express.json({limit:'1mb'}));

app.use(express.static(
  path.join(__dirname,'public'),
  {
    extensions:['html'],
    maxAge:process.env.NODE_ENV==='production'?'7d':0
  }
));

app.get('/health',(req,res)=>{
  res.json({
    ok:true,
    service:'to-all-children',
    version:'15.1.0'
  });
});

/* Authentication */
app.post('/api/auth/register',(req,res)=>{
  const {name,email,password}=req.body||{};

  if(!name||!email||!password||password.length<6){
    return res.status(400).json({
      error:'Name, email and a password of at least 6 characters are required'
    });
  }

  try{
    const r=db.prepare(
      'INSERT INTO users(name,email,password_hash) VALUES(?,?,?)'
    ).run(
      name,
      email.toLowerCase(),
      hashPassword(password)
    );

    const token=crypto.randomBytes(32).toString('hex');
    sessions.set(token,r.lastInsertRowid);

    res.json({
      token,
      user:{
        id:r.lastInsertRowid,
        name,
        email:email.toLowerCase(),
        role:'parent'
      }
    });
  }catch(e){
    res.status(409).json({
      error:'An account with that email already exists'
    });
  }
});

app.post('/api/auth/login',(req,res)=>{
  const {email,password}=req.body||{};

  const u=db.prepare(
    'SELECT * FROM users WHERE email=?'
  ).get((email||'').toLowerCase());

  if(
    !u ||
    !u.password_hash ||
    !verifyPassword(password||'',u.password_hash)
  ){
    return res.status(401).json({
      error:'Incorrect email or password'
    });
  }

  const token=crypto.randomBytes(32).toString('hex');
  sessions.set(token,u.id);

  res.json({
    token,
    user:{
      id:u.id,
      name:u.name,
      email:u.email,
      role:u.role
    }
  });
});

app.get('/api/auth/me',auth,(req,res)=>{
  const u=db.prepare(
    'SELECT id,name,email,role,created_at FROM users WHERE id=?'
  ).get(req.userId);

  res.json(u);
});

app.post('/api/auth/logout',auth,(req,res)=>{
  const token=(req.headers.authorization||'').replace('Bearer ','');
  sessions.delete(token);
  res.json({ok:true});
});

/* User features */
app.get('/api/me/favorites',auth,(req,res)=>{
  res.json(
    db.prepare(`
      SELECT s.*,f.id favorite_id
      FROM favorites f
      JOIN stories s ON s.id=f.story_id
      WHERE f.user_id=?
      ORDER BY f.id DESC
    `).all(req.userId)
  );
});

app.post('/api/me/favorites/:storyId',auth,(req,res)=>{
  const exists=db.prepare(
    'SELECT id FROM favorites WHERE user_id=? AND story_id=?'
  ).get(req.userId,req.params.storyId);

  if(exists){
    db.prepare('DELETE FROM favorites WHERE id=?').run(exists.id);
  }else{
    db.prepare(
      'INSERT OR IGNORE INTO favorites(user_id,story_id) VALUES(?,?)'
    ).run(req.userId,req.params.storyId);
  }

  res.json({favorite:!exists});
});

app.get('/api/me/progress',auth,(req,res)=>{
  res.json(
    db.prepare(`
      SELECT p.*,s.title_en,s.title_rw
      FROM progress p
      JOIN stories s ON s.id=p.story_id
      WHERE p.user_id=?
      ORDER BY p.updated_at DESC
    `).all(req.userId)
  );
});

app.put('/api/me/progress/:storyId',auth,(req,res)=>{
  let percent=Math.max(
    0,
    Math.min(100,Number(req.body.percent)||0)
  );

  db.prepare(`
    INSERT INTO progress(
      user_id,story_id,percent,updated_at
    ) VALUES(?,?,?,CURRENT_TIMESTAMP)
    ON CONFLICT(user_id,story_id)
    DO UPDATE SET
      percent=excluded.percent,
      updated_at=CURRENT_TIMESTAMP
  `).run(
    req.userId,
    req.params.storyId,
    percent
  );

  res.json({ok:true,percent});
});

/* Public stories */
app.get('/api/stories',(req,res)=>{
  res.json(
    db.prepare(
      'SELECT * FROM stories ORDER BY id DESC'
    ).all()
  );
});

/* Admin only */
app.get('/api/stats',adminAuth,(req,res)=>{
  res.json({
    stories:db.prepare(
      'SELECT COUNT(*) c FROM stories'
    ).get().c,

    users:db.prepare(
      'SELECT COUNT(*) c FROM users'
    ).get().c,

    favorites:db.prepare(
      'SELECT COUNT(*) c FROM favorites'
    ).get().c,

    progress:db.prepare(
      'SELECT COUNT(*) c FROM progress'
    ).get().c
  });
});

app.post('/api/stories',adminAuth,(req,res)=>{
  const {
    title_en,
    title_rw,
    body_en,
    body_rw,
    category='General'
  }=req.body;

  if(!title_en||!title_rw||!body_en||!body_rw){
    return res.status(400).json({
      error:'All story fields are required'
    });
  }

  const r=db.prepare(`
    INSERT INTO stories(
      title_en,title_rw,body_en,body_rw,category
    ) VALUES(?,?,?,?,?)
  `).run(
    title_en,
    title_rw,
    body_en,
    body_rw,
    category
  );

  res.json(
    db.prepare(
      'SELECT * FROM stories WHERE id=?'
    ).get(r.lastInsertRowid)
  );
});

app.put('/api/stories/:id',adminAuth,(req,res)=>{
  const {
    title_en,
    title_rw,
    body_en,
    body_rw,
    category='General'
  }=req.body;

  db.prepare(`
    UPDATE stories
    SET title_en=?,
        title_rw=?,
        body_en=?,
        body_rw=?,
        category=?
    WHERE id=?
  `).run(
    title_en,
    title_rw,
    body_en,
    body_rw,
    category,
    req.params.id
  );

  res.json({ok:true});
});

app.delete('/api/stories/:id',adminAuth,(req,res)=>{
  db.prepare(
    'DELETE FROM stories WHERE id=?'
  ).run(req.params.id);

  res.json({ok:true});
});

app.get('/api/users',adminAuth,(req,res)=>{
  res.json(
    db.prepare(`
      SELECT
        u.id,
        u.name,
        u.email,
        u.role,
        u.created_at,
        COUNT(DISTINCT f.id) favorites,
        COUNT(DISTINCT p.id) progress_items
      FROM users u
      LEFT JOIN favorites f ON f.user_id=u.id
      LEFT JOIN progress p ON p.user_id=u.id
      GROUP BY u.id
      ORDER BY u.id DESC
    `).all()
  );
});

app.get('/api/activity',adminAuth,(req,res)=>{
  res.json({
    favorites:db.prepare(`
      SELECT
        f.id,
        u.name,
        s.title_en,
        s.title_rw
      FROM favorites f
      LEFT JOIN users u ON u.id=f.user_id
      LEFT JOIN stories s ON s.id=f.story_id
      ORDER BY f.id DESC
      LIMIT 20
    `).all(),

    progress:db.prepare(`
      SELECT
        p.id,
        u.name,
        s.title_en,
        s.title_rw,
        p.percent,
        p.updated_at
      FROM progress p
      LEFT JOIN users u ON u.id=p.user_id
      LEFT JOIN stories s ON s.id=p.story_id
      ORDER BY p.updated_at DESC
      LIMIT 20
    `).all()
  });
});

/* Public website fallback */
app.use((req,res,next)=>{
  if(
    req.method==='GET' &&
    !req.path.startsWith('/api/')
  ){
    return res.sendFile(
      path.join(__dirname,'public','index.html')
    );
  }

  next();
});

const PORT=Number(process.env.PORT)||3000;

app.listen(PORT,'0.0.0.0',()=>{
  console.log(
    `TO ALL CHILDREN V15.1 running on ${PORT}`
  );
});
