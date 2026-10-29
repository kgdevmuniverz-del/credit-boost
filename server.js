'use strict';
const express = require('express');
const session = require('express-session');
const PgStore = require('connect-pg-simple')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const multer = require('multer');
const { parse } = require('csv-parse/sync');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USERNAME || 'kai';
if (!process.env.ADMIN_PASSWORD || !process.env.SESSION_SECRET) {
  console.error('Missing ADMIN_PASSWORD or SESSION_SECRET'); process.exit(1);
}
const USE_PG = !!process.env.DATABASE_URL;
// Hash the password once at boot; the plaintext is never stored or logged.
const ADMIN_HASH = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);

// Postgres when DATABASE_URL is set; otherwise an in-process, NON-persistent PGlite fallback.
let pool;
if (!USE_PG) { const { newDb } = require('pg-mem'); const { Pool: MemPool } = newDb().adapters.createPg(); pool = new MemPool(); }
else pool = new Pool({ connectionString: process.env.DATABASE_URL,
  ssl: /render\.com/.test(process.env.DATABASE_URL) ? { rejectUnauthorized: false } : false });
const q = (t, p) => pool.query(t, p);

async function migrate() {
  await q(`CREATE TABLE IF NOT EXISTS items (
    id SERIAL PRIMARY KEY, bureau TEXT NOT NULL, creditor TEXT NOT NULL, acct_last4 TEXT,
    type TEXT, status TEXT, date_opened DATE, dofd DATE, balance NUMERIC(12,2), credit_limit NUMERIC(12,2),
    notes TEXT, inaccurate BOOLEAN DEFAULT FALSE, inaccuracy_reason TEXT, created_at TIMESTAMPTZ DEFAULT now())`);
  await q(`CREATE TABLE IF NOT EXISTS disputes (
    id SERIAL PRIMARY KEY, item_id INT REFERENCES items(id) ON DELETE SET NULL, kind TEXT NOT NULL,
    recipient TEXT NOT NULL, date_sent DATE NOT NULL, after_free_report BOOLEAN DEFAULT FALSE,
    status TEXT DEFAULT 'open', response_date DATE, notes TEXT, created_at TIMESTAMPTZ DEFAULT now())`);
  await q(`CREATE TABLE IF NOT EXISTS profile (id INT PRIMARY KEY DEFAULT 1, full_name TEXT, address TEXT, CHECK (id=1))`);
  await q(`INSERT INTO profile (id) VALUES (1) ON CONFLICT DO NOTHING`);
}

// ---------- helpers ----------
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const SSN_RE = /\b\d{3}[-\s.]?\d{2}[-\s.]?\d{4}\b/g;
const hasSSN = s => typeof s === 'string' && new RegExp(SSN_RE.source).test(s);
const stripSSN = s => (s == null ? s : String(s).replace(SSN_RE, '[removed]'));
const clean = (s, max = 500) => { const v = stripSSN(String(s ?? '').trim()).slice(0, max); return v || null; };
const last4 = s => { const d = String(s ?? '').replace(/\D/g, ''); return d ? d.slice(-4) : null; };
const num = s => { const v = parseFloat(String(s ?? '').replace(/[$,\s]/g, '')); return Number.isFinite(v) ? v : null; };
const dt = s => { if (!s) return null; const d = new Date(s); return isNaN(d) ? null : d.toISOString().slice(0, 10); };
const fmtD = d => d ? new Date(d).toISOString().slice(0, 10) : '—';
const money = v => v == null ? '—' : '$' + Number(v).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const addDays = (d, n) => { const x = new Date(d); x.setUTCDate(x.getUTCDate() + n); return x; };
const BUREAUS = ['Equifax', 'Experian', 'TransUnion'];
const BUREAU_ADDR = {
  Equifax: 'Equifax Information Services LLC\nP.O. Box 740256\nAtlanta, GA 30374-0256',
  Experian: 'Experian\nP.O. Box 4500\nAllen, TX 75013',
  TransUnion: 'TransUnion LLC\nConsumer Dispute Center\nP.O. Box 2000\nChester, PA 19016',
};
const TYPES = ['Credit Card', 'Auto Loan', 'Mortgage', 'Student Loan', 'Personal Loan', 'Collection', 'Charge-off', 'Medical', 'Inquiry', 'Public Record', 'Bankruptcy Ch.7', 'Bankruptcy Ch.13', 'Other'];
const NEGATIVE = /late|delinq|collect|charge|default|repo|foreclos|bankrupt|judg|past due|derog/i;

function analyze(items) {
  const today = new Date();
  const groups = {};
  for (const it of items) {
    const k = (it.creditor || '').toLowerCase().replace(/[^a-z0-9]/g, '') + '|' + (it.acct_last4 || '');
    (groups[k] ||= []).push(it);
  }
  for (const it of items) {
    const f = [];
    if (it.inaccurate) f.push({ c: 'err', t: 'Marked inaccurate' + (it.inaccuracy_reason ? ': ' + it.inaccuracy_reason : '') });
    const missing = [];
    if (!it.status) missing.push('status');
    if (!it.date_opened && !/inquiry|public|bankrupt/i.test(it.type || '')) missing.push('date opened');
    if (!it.acct_last4 && !/inquiry|public|bankrupt/i.test(it.type || '')) missing.push('acct last 4');
    if (NEGATIVE.test((it.status || '') + ' ' + (it.type || '')) && !it.dofd) missing.push('date of first delinquency');
    if (missing.length) f.push({ c: 'warn', t: 'Missing: ' + missing.join(', ') });
    const sib = (groups[(it.creditor || '').toLowerCase().replace(/[^a-z0-9]/g, '') + '|' + (it.acct_last4 || '')] || []).filter(o => o.id !== it.id && o.bureau !== it.bureau);
    const mm = new Set();
    for (const o of sib) {
      if (o.balance != null && it.balance != null && Number(o.balance) !== Number(it.balance)) mm.add('balance');
      if ((o.status || '').toLowerCase() !== (it.status || '').toLowerCase() && o.status && it.status) mm.add('status');
      if (fmtD(o.date_opened) !== fmtD(it.date_opened) && o.date_opened && it.date_opened) mm.add('date opened');
      if (fmtD(o.dofd) !== fmtD(it.dofd) && o.dofd && it.dofd) mm.add('DOFD');
      if (o.credit_limit != null && it.credit_limit != null && Number(o.credit_limit) !== Number(it.credit_limit)) mm.add('limit');
    }
    if (mm.size) f.push({ c: 'err', t: 'Cross-bureau mismatch: ' + [...mm].join(', ') });
    if (it.dofd) {
      const yrs = /bankruptcy ch\.?\s*7/i.test(it.type || '') ? 10 : 7;
      const limit = addDays(new Date(it.dofd), Math.round(yrs * 365.25));
      if (limit <= today) f.push({ c: 'old', t: `Past ${yrs}-yr FCRA §605 reporting period (since ${fmtD(limit)}) — likely obsolete` });
      else if (addDays(limit, -180) <= today) f.push({ c: 'warn', t: `Ages off ~${fmtD(limit)} (FCRA §605)` });
    }
    it.flags = f;
  }
  return items;
}

// ---------- layout ----------
function page(req, title, body) {
  const nav = req.session.user ? `<nav><a href="/" class="brand">CREDIT<span>//</span>BOOST</a>
    <a href="/items">Items</a><a href="/items/new">Add</a><a href="/upload">CSV</a><a href="/letters">Letters</a>
    <a href="/deadlines">Deadlines</a><a href="/tips">Tips &amp; Utilization</a><a href="/profile">Profile</a>
    <form method="post" action="/logout" class="inline">${csrf(req)}<button class="ghost">Log out</button></form></nav>` : '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>${esc(title)} · Credit Boost</title><link rel="stylesheet" href="/style.css"></head>
<body><div class="grid-bg"></div>${nav}<main>${USE_PG ? '' : '<div class="flash">⚠ Storage is temporary (no DATABASE_URL set) — data is lost on restart.</div>'}${req.flash ? `<div class="flash">${esc(req.flash)}</div>` : ''}${body}</main>
<footer>Private tool for Kai Green · Educational, not legal advice · Disputes can only remove information that is inaccurate, incomplete, or unverifiable.</footer>
<script src="/app.js"></script></body></html>`;
}
const csrf = req => `<input type="hidden" name="_csrf" value="${esc(req.session.csrf)}">`;

// ---------- app ----------
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: { 'script-src': ["'self'"], 'img-src': ["'self'", 'data:'], 'connect-src': ["'self'"] } } }));
app.use(express.static('public', { maxAge: '1h' }));
app.use(express.urlencoded({ extended: false, limit: '200kb' }));
app.use(session({
  store: USE_PG ? new PgStore({ pool, createTableIfMissing: true }) : undefined,
  name: 'cb.sid', secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 3600 * 1000 },
}));
app.use((req, res, next) => {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(24).toString('hex');
  req.flash = req.session.flash; delete req.session.flash;
  res.set('Cache-Control', 'no-store');
  next();
});
function checkCsrf(req, res, next) {
  const t = (req.body && req.body._csrf) || '';
  const a = Buffer.from(String(t)), b = Buffer.from(req.session.csrf || '');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(403).send('Invalid CSRF token. Go back and reload.');
  next();
}
app.post('*', (req, res, next) => (req.is('multipart/form-data') ? next() : checkCsrf(req, res, next)));
const auth = (req, res, next) => (req.session.user ? next() : res.redirect('/login'));
const flash = (req, m) => { req.session.flash = m; };

app.get('/healthz', (req, res) => res.send('ok'));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: true, legacyHeaders: false,
  skipSuccessfulRequests: true, handler: (req, res) => res.status(429).send(page(req, 'Locked', '<div class="card"><h1>Too many attempts</h1><p>Try again in 15 minutes.</p></div>')) });

app.get('/login', (req, res) => res.send(page(req, 'Login', `<div class="login card glow">
  <h1 class="brand big">CREDIT<span>//</span>BOOST</h1><p class="muted">Secure access</p>
  <form method="post" action="/login">${csrf(req)}
  <label>Username<input name="username" autocomplete="username" required></label>
  <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
  <button>Enter</button></form></div>`)));
app.post('/login', loginLimiter, async (req, res) => {
  const { username = '', password = '' } = req.body;
  const ok = (await bcrypt.compare(String(password), ADMIN_HASH)) && String(username).trim().toLowerCase() === ADMIN_USER.toLowerCase();
  if (!ok) { flash(req, 'Invalid credentials'); return res.status(401).redirect('/login'); }
  const csrfTok = crypto.randomBytes(24).toString('hex');
  req.session.regenerate(err => {
    if (err) return res.status(500).send('Session error');
    req.session.user = ADMIN_USER; req.session.csrf = csrfTok;
    res.redirect('/');
  });
});
app.post('/logout', (req, res) => req.session.destroy(() => { res.clearCookie('cb.sid'); res.redirect('/login'); }));

app.use(auth);

// Dashboard
app.get('/', async (req, res) => {
  const items = analyze((await q('SELECT * FROM items ORDER BY creditor')).rows);
  const ds = (await q("SELECT * FROM disputes WHERE status='open'")).rows;
  const today = new Date();
  const overdue = ds.filter(d => addDays(d.date_sent, d.after_free_report ? 45 : 30) < today).length;
  const flagged = items.filter(i => i.flags.some(f => f.c === 'err')).length;
  const old = items.filter(i => i.flags.some(f => f.c === 'old')).length;
  const cards = items.filter(i => /credit card/i.test(i.type || '') && Number(i.credit_limit) > 0);
  const bal = cards.reduce((s, c) => s + Number(c.balance || 0), 0), lim = cards.reduce((s, c) => s + Number(c.credit_limit || 0), 0);
  const util = lim ? (bal / lim * 100) : null;
  res.send(page(req, 'Dashboard', `<h1 class="neon">Command Center</h1>
  <div class="stats">
   <a class="stat" href="/items"><b>${items.length}</b><span>Items tracked</span></a>
   <a class="stat mag" href="/items?f=err"><b>${flagged}</b><span>Possible errors</span></a>
   <a class="stat" href="/items?f=old"><b>${old}</b><span>Past §605 limit</span></a>
   <a class="stat ${overdue ? 'mag' : ''}" href="/deadlines"><b>${ds.length}</b><span>Open disputes · ${overdue} overdue</span></a>
   <a class="stat" href="/tips"><b>${util == null ? '—' : util.toFixed(1) + '%'}</b><span>Card utilization</span></a>
  </div>
  <div class="card"><h2>Next moves</h2><ol>
   <li>Pull free reports at <b>AnnualCreditReport.com</b> (the only federally authorized free source).</li>
   <li>Enter items or upload a CSV; mark anything you believe is inaccurate.</li>
   <li>Generate a §611 dispute letter for each flagged item; send certified mail, return receipt.</li>
   <li>Log the date sent under Deadlines — bureaus generally have 30 days (45 if you disputed after receiving your free annual report) to finish their investigation.</li>
  </ol></div>`));
});

// Items list
app.get('/items', async (req, res) => {
  let items = analyze((await q('SELECT * FROM items ORDER BY creditor, bureau')).rows);
  if (req.query.f === 'err') items = items.filter(i => i.flags.some(f => f.c === 'err'));
  if (req.query.f === 'old') items = items.filter(i => i.flags.some(f => f.c === 'old'));
  const rows = items.map(i => `<tr class="${i.flags.some(f => f.c === 'err') ? 'row-err' : ''}">
   <td><span class="tag">${esc(i.bureau)}</span></td><td><b>${esc(i.creditor)}</b><div class="muted">${i.acct_last4 ? '••••' + esc(i.acct_last4) : ''}</div></td>
   <td>${esc(i.type)}</td><td>${esc(i.status)}</td><td>${fmtD(i.date_opened)}</td><td>${fmtD(i.dofd)}</td>
   <td>${money(i.balance)}</td><td>${money(i.credit_limit)}</td>
   <td>${i.flags.map(f => `<span class="flag ${f.c}">${esc(f.t)}</span>`).join('') || '<span class="flag ok">No flags</span>'}</td>
   <td class="actions"><a href="/items/${i.id}/edit">Edit</a><a href="/letters?item=${i.id}">Letter</a>
   <form method="post" action="/items/${i.id}/delete" class="inline confirm">${csrf(req)}<button class="ghost sm">Delete</button></form></td></tr>`).join('');
  res.send(page(req, 'Items', `<h1 class="neon">Item Tracker</h1>
   <p><a href="/items">All</a> · <a href="/items?f=err">Possible errors</a> · <a href="/items?f=old">Past reporting limit</a></p>
   <div class="card scroll"><table><thead><tr><th>Bureau</th><th>Creditor</th><th>Type</th><th>Status</th><th>Opened</th><th>DOFD</th><th>Balance</th><th>Limit</th><th>Flags</th><th></th></tr></thead>
   <tbody>${rows || '<tr><td colspan="10" class="muted">No items yet. <a href="/items/new">Add one</a> or <a href="/upload">upload a CSV</a>.</td></tr>'}</tbody></table></div>
   <p class="muted">§605 timing is estimated from the date of first delinquency (7 years; 10 for Chapter 7 bankruptcy, measured from filing). Mismatches compare items with the same creditor + last 4 across bureaus.</p>`));
});

function itemForm(req, it = {}, action) {
  const opt = (arr, v) => arr.map(x => `<option ${x === v ? 'selected' : ''}>${esc(x)}</option>`).join('');
  return `<form method="post" action="${action}" class="card form-grid">${csrf(req)}
   <label>Bureau<select name="bureau" required>${opt(BUREAUS, it.bureau)}</select></label>
   <label>Creditor / furnisher<input name="creditor" required maxlength="120" value="${esc(it.creditor)}"></label>
   <label>Account number (only last 4 kept)<input name="acct" maxlength="30" inputmode="numeric" value="${esc(it.acct_last4)}" placeholder="last 4 only"></label>
   <label>Type<select name="type">${opt(TYPES, it.type)}</select></label>
   <label>Status<input name="status" maxlength="80" value="${esc(it.status)}" placeholder="Open, Paid, 30 days late, Collection..."></label>
   <label>Date opened<input type="date" name="date_opened" value="${it.date_opened ? fmtD(it.date_opened) : ''}"></label>
   <label>Date of first delinquency<input type="date" name="dofd" value="${it.dofd ? fmtD(it.dofd) : ''}"></label>
   <label>Balance<input name="balance" inputmode="decimal" value="${it.balance ?? ''}"></label>
   <label>Credit limit<input name="credit_limit" inputmode="decimal" value="${it.credit_limit ?? ''}"></label>
   <label class="full">Notes<textarea name="notes" maxlength="2000">${esc(it.notes)}</textarea></label>
   <label class="check full"><input type="checkbox" name="inaccurate" ${it.inaccurate ? 'checked' : ''}> I believe this item is inaccurate</label>
   <label class="full">What is inaccurate?<input name="inaccuracy_reason" maxlength="300" value="${esc(it.inaccuracy_reason)}" placeholder="e.g. Not my account; balance wrong; paid but shows open"></label>
   <p class="muted full">Never enter a Social Security number. Anything SSN-shaped is rejected.</p>
   <button class="full">Save item</button></form>`;
}
function readItem(b) {
  const fields = ['creditor', 'status', 'notes', 'inaccuracy_reason', 'acct'];
  if (fields.some(f => hasSSN(b[f]))) return { error: 'SSN-like number detected. Social Security numbers are never accepted — remove it and try again.' };
  const bureau = BUREAUS.find(x => x.toLowerCase() === String(b.bureau || '').trim().toLowerCase());
  const creditor = clean(b.creditor, 120);
  if (!bureau || !creditor) return { error: 'Bureau and creditor are required.' };
  return { v: [bureau, creditor, last4(b.acct), clean(b.type, 40), clean(b.status, 80), dt(b.date_opened), dt(b.dofd),
    num(b.balance), num(b.credit_limit), clean(b.notes, 2000), b.inaccurate === 'on' || /^(y|yes|true|1)$/i.test(b.inaccurate || ''), clean(b.inaccuracy_reason, 300)] };
}
app.get('/items/new', (req, res) => res.send(page(req, 'Add item', `<h1 class="neon">Add Item</h1>${itemForm(req, {}, '/items')}`)));
app.post('/items', async (req, res) => {
  const r = readItem(req.body); if (r.error) { flash(req, r.error); return res.redirect('/items/new'); }
  await q(`INSERT INTO items (bureau,creditor,acct_last4,type,status,date_opened,dofd,balance,credit_limit,notes,inaccurate,inaccuracy_reason) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, r.v);
  flash(req, 'Item saved.'); res.redirect('/items');
});
app.get('/items/:id/edit', async (req, res) => {
  const it = (await q('SELECT * FROM items WHERE id=$1', [parseInt(req.params.id) || 0])).rows[0];
  if (!it) return res.redirect('/items');
  res.send(page(req, 'Edit item', `<h1 class="neon">Edit Item</h1>${itemForm(req, it, `/items/${it.id}`)}`));
});
app.post('/items/:id', async (req, res) => {
  const id = parseInt(req.params.id) || 0;
  const r = readItem(req.body); if (r.error) { flash(req, r.error); return res.redirect(`/items/${id}/edit`); }
  await q(`UPDATE items SET bureau=$1,creditor=$2,acct_last4=$3,type=$4,status=$5,date_opened=$6,dofd=$7,balance=$8,credit_limit=$9,notes=$10,inaccurate=$11,inaccuracy_reason=$12 WHERE id=$13`, [...r.v, id]);
  flash(req, 'Item updated.'); res.redirect('/items');
});
app.post('/items/:id/delete', async (req, res) => { await q('DELETE FROM items WHERE id=$1', [parseInt(req.params.id) || 0]); flash(req, 'Item deleted.'); res.redirect('/items'); });

// CSV upload
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1024 * 1024, files: 1 } });
app.get('/upload', (req, res) => res.send(page(req, 'CSV upload', `<h1 class="neon">CSV Upload</h1>
 <div class="card"><form method="post" action="/upload" enctype="multipart/form-data">${csrf(req)}
 <input type="file" name="file" accept=".csv,text/csv" required><button>Import</button></form>
 <p>Header row (case-insensitive): <code>bureau, creditor, account, type, status, date_opened, dofd, balance, limit, notes, inaccurate, inaccuracy_reason</code></p>
 <p class="muted">Account numbers are reduced to the last 4 digits on import. Any SSN-shaped value is stripped from text, and a column named like "ssn" or "social" is ignored entirely.</p>
 <a href="/sample.csv">Download sample CSV</a></div>`)));
app.post('/upload', upload.single('file'), checkCsrf, async (req, res) => {
  if (!req.file) { flash(req, 'No file.'); return res.redirect('/upload'); }
  let rows;
  try { rows = parse(req.file.buffer.toString('utf8'), { columns: h => h.map(x => x.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_')), skip_empty_lines: true, trim: true, bom: true }); }
  catch (e) { flash(req, 'Could not parse CSV: ' + e.message.slice(0, 120)); return res.redirect('/upload'); }
  let ok = 0, bad = 0, stripped = 0;
  for (const r of rows.slice(0, 1000)) {
    for (const k of Object.keys(r)) if (/ssn|social|tax_?id|tin$/.test(k)) delete r[k];
    for (const k of Object.keys(r)) if (hasSSN(r[k]) && !/account|acct/.test(k)) { r[k] = stripSSN(r[k]); stripped++; }
    const b = { bureau: r.bureau, creditor: r.creditor || r.furnisher, acct: r.account || r.account_number || r.acct || r.acct_last4,
      type: r.type, status: r.status, date_opened: r.date_opened || r.opened, dofd: r.dofd || r.date_of_first_delinquency,
      balance: r.balance, credit_limit: r.limit || r.credit_limit, notes: r.notes, inaccurate: r.inaccurate, inaccuracy_reason: r.inaccuracy_reason };
    b.acct = last4(b.acct) || '';
    const x = readItem(b);
    if (x.error) { bad++; continue; }
    await q(`INSERT INTO items (bureau,creditor,acct_last4,type,status,date_opened,dofd,balance,credit_limit,notes,inaccurate,inaccuracy_reason) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, x.v);
    ok++;
  }
  flash(req, `Imported ${ok} item(s). Skipped ${bad}.${stripped ? ` Stripped ${stripped} SSN-like value(s).` : ''}`);
  res.redirect('/items');
});

// Profile (name/address for letters — no SSN)
app.get('/profile', async (req, res) => {
  const p = (await q('SELECT * FROM profile WHERE id=1')).rows[0] || {};
  res.send(page(req, 'Profile', `<h1 class="neon">Letter Profile</h1><form method="post" action="/profile" class="card">${csrf(req)}
   <label>Full name<input name="full_name" maxlength="120" value="${esc(p.full_name)}"></label>
   <label>Mailing address<textarea name="address" maxlength="400">${esc(p.address)}</textarea></label>
   <p class="muted">Used to fill letters. This app never stores an SSN; bureaus may ask you to add identifying details by hand before mailing.</p>
   <button>Save</button></form>`));
});
app.post('/profile', async (req, res) => {
  if (hasSSN(req.body.full_name) || hasSSN(req.body.address)) { flash(req, 'SSN-like number rejected.'); return res.redirect('/profile'); }
  await q('UPDATE profile SET full_name=$1, address=$2 WHERE id=1', [clean(req.body.full_name, 120), clean(req.body.address, 400)]);
  flash(req, 'Profile saved.'); res.redirect('/profile');
});

// Letters
function buildLetter(kind, it, p, opts) {
  const today = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const me = `${p.full_name || '[Your full name]'}\n${p.address || '[Your mailing address]'}`;
  const acct = it.acct_last4 ? `ending in ${it.acct_last4}` : '[account number, last 4 digits]';
  const reason = opts.reason || it.inaccuracy_reason || '[describe exactly what is inaccurate or incomplete]';
  if (kind === 'dispute') {
    const b = opts.bureau || it.bureau;
    return { to: b, subject: `Dispute of inaccurate information — ${it.creditor}`, text:
`${me}

${today}

${BUREAU_ADDR[b]}

RE: Request for reinvestigation under the Fair Credit Reporting Act, Section 611 (15 U.S.C. § 1681i)

To Whom It May Concern:

I am writing to dispute the following information in my ${b} credit file. I believe it is inaccurate or incomplete.

  Creditor/Furnisher: ${it.creditor}
  Account: ${acct}
  Type: ${it.type || '—'}   Reported status: ${it.status || '—'}
  Reported balance: ${money(it.balance)}   Date opened: ${fmtD(it.date_opened)}   Date of first delinquency: ${fmtD(it.dofd)}

Why this information is inaccurate:
  ${reason}

Under Section 611 of the FCRA, you are required to conduct a reasonable reinvestigation of the disputed information, generally within 30 days of receiving this letter, forward all relevant information I provide to the furnisher, and correct or delete any information found to be inaccurate, incomplete, or unverifiable. Please also send me written notice of the results and, if the information is changed or deleted, a free copy of my updated report. If the information is verified, I request a description of the procedure used to determine its accuracy, including the name, address, and telephone number of the furnisher contacted, as provided by Section 611(a)(6)-(7).

Enclosed are copies of a government-issued photo ID, proof of my current address, and any supporting documents.

Sincerely,

${p.full_name || '[Signature]'}

Enclosures: [list documents]` };
  }
  if (kind === 'goodwill') return { to: it.creditor, subject: `Goodwill adjustment request — ${it.creditor}`, text:
`${me}

${today}

${it.creditor}
[Creditor's correspondence address]

RE: Goodwill adjustment request — account ${acct}

Dear ${it.creditor} Customer Relations,

I am writing to ask for your consideration of a goodwill adjustment on the account referenced above. I value my relationship with ${it.creditor}, and I take responsibility for the late payment(s) reported on this account (${it.status || 'late payment'}).

${opts.reason || '[Briefly explain the circumstances — e.g., a medical issue, job loss, or a one-time oversight — and what has changed since.]'}

Since then I have worked to keep my account in good standing. I understand the information you reported may be accurate, and I am not disputing it. I am respectfully asking whether you would consider, as a gesture of goodwill, updating how this late payment is reported to the credit bureaus. I understand this decision is entirely at your discretion.

Thank you for your time and consideration.

Sincerely,

${p.full_name || '[Signature]'}` };
  return { to: it.creditor, subject: `Debt validation request — ${it.creditor}`, text:
`${me}

${today}

${it.creditor}
[Collector's mailing address]

RE: Request for validation of debt under the Fair Debt Collection Practices Act, Section 809 (15 U.S.C. § 1692g)
Reference: account ${acct}${it.balance != null ? `, amount claimed ${money(it.balance)}` : ''}

To Whom It May Concern:

I am responding to your contact about this alleged debt. Under Section 809(b) of the FDCPA, I dispute this debt and request validation. Please provide:

  1. The amount of the debt and an itemization of how it was calculated, including interest and fees;
  2. The name and address of the original creditor;
  3. Documentation showing that you own or are authorized to collect this debt;
  4. A copy of the agreement or other documentation that establishes my obligation.

Under Section 809(b), if this request is made within 30 days of your initial notice, you must cease collection of this debt until you mail me verification. This letter is not an acknowledgment that I owe this debt. If you report this account to a credit bureau, please note that it is disputed.

Please send all further communication in writing to the address above.

Sincerely,

${p.full_name || '[Signature]'}` };
}

app.get('/letters', async (req, res) => {
  const items = (await q('SELECT * FROM items ORDER BY creditor')).rows;
  const sel = parseInt(req.query.item) || '';
  const opts = items.map(i => `<option value="${i.id}" ${i.id === sel ? 'selected' : ''}>${esc(i.creditor)} ${i.acct_last4 ? '••' + esc(i.acct_last4) : ''} (${esc(i.bureau)})</option>`).join('');
  res.send(page(req, 'Letters', `<h1 class="neon">Letter Generator</h1>
  <form method="get" action="/letters/view" class="card form-grid">
   <label>Item<select name="item" required>${opts}</select></label>
   <label>Letter type<select name="kind" id="kind"><option value="dispute">Bureau dispute (FCRA §611)</option><option value="goodwill">Goodwill (creditor)</option><option value="validation">Debt validation (FDCPA §809)</option></select></label>
   <label>Bureau (disputes)<select name="bureau"><option value="">Item's bureau</option>${BUREAUS.map(b => `<option>${b}</option>`).join('')}</select></label>
   <label class="full">Explanation (optional)<textarea name="reason" maxlength="1500" placeholder="What is inaccurate, or your goodwill circumstances"></textarea></label>
   <button class="full">Generate</button></form>
  ${items.length ? '' : '<p class="muted">Add an item first.</p>'}
  <div class="card"><h3>Mail to the bureaus</h3><div class="addr3">${BUREAUS.map(b => `<pre>${esc(BUREAU_ADDR[b])}</pre>`).join('')}</div>
  <p class="muted">Send by certified mail with return receipt and keep copies. A dispute can lead to correction or deletion only of information that is inaccurate, incomplete, or cannot be verified — accurate negative information can lawfully stay for the full reporting period. Verify addresses on each bureau's website before mailing.</p></div>`));
});
app.get('/letters/view', async (req, res) => {
  const it = (await q('SELECT * FROM items WHERE id=$1', [parseInt(req.query.item) || 0])).rows[0];
  if (!it) return res.redirect('/letters');
  const p = (await q('SELECT * FROM profile WHERE id=1')).rows[0] || {};
  const kind = ['dispute', 'goodwill', 'validation'].includes(req.query.kind) ? req.query.kind : 'dispute';
  const bureau = BUREAUS.includes(req.query.bureau) ? req.query.bureau : null;
  const reason = clean(req.query.reason, 1500);
  const L = buildLetter(kind, it, p, { bureau, reason });
  if (req.query.download) {
    res.set('Content-Type', 'text/plain; charset=utf-8');
    res.set('Content-Disposition', `attachment; filename="${kind}-${String(it.creditor).replace(/[^a-z0-9]+/gi, '_')}.txt"`);
    return res.send(L.text);
  }
  const qs = new URLSearchParams({ item: it.id, kind, bureau: bureau || '', reason: reason || '', download: 1 }).toString();
  res.send(page(req, L.subject, `<div class="noprint"><h1 class="neon">${esc(L.subject)}</h1>
   <p><button class="print-btn">Print / Save PDF</button> <a class="btn" href="/letters/view?${esc(qs)}">Download .txt</a>
   <a class="btn ghost" href="/deadlines?item=${it.id}&kind=${kind}&to=${encodeURIComponent(L.to)}">Log as sent →</a></p></div>
   <article class="letter">${esc(L.text)}</article>`));
});

// Deadlines
app.get('/deadlines', async (req, res) => {
  const ds = (await q('SELECT d.*, i.creditor, i.bureau FROM disputes d LEFT JOIN items i ON i.id=d.item_id ORDER BY d.status, d.date_sent')).rows;
  const items = (await q('SELECT id, creditor, bureau, acct_last4 FROM items ORDER BY creditor')).rows;
  const today = new Date(new Date().toISOString().slice(0, 10));
  const rows = ds.map(d => {
    const due = addDays(d.date_sent, d.after_free_report ? 45 : 30);
    const left = Math.ceil((due - today) / 86400000);
    const cls = d.status !== 'open' ? 'done' : left < 0 ? 'overdue' : left <= 5 ? 'soon' : '';
    return `<tr class="${cls}"><td>${esc(d.kind)}</td><td>${esc(d.recipient)}</td><td>${esc(d.creditor || '—')}</td><td>${fmtD(d.date_sent)}</td>
     <td><b>${fmtD(due)}</b> <span class="muted">(${d.after_free_report ? 45 : 30}d)</span></td>
     <td>${d.status !== 'open' ? esc(d.status) : left < 0 ? `<span class="flag err">OVERDUE ${-left}d</span>` : `<span class="flag ${left <= 5 ? 'warn' : 'ok'}">${left}d left</span>`}</td>
     <td class="actions"><form method="post" action="/deadlines/${d.id}" class="inline">${csrf(req)}<select name="status">${['open', 'resolved - corrected', 'resolved - deleted', 'resolved - verified', 'no response'].map(s => `<option ${s === d.status ? 'selected' : ''}>${s}</option>`).join('')}</select><button class="sm">Update</button></form>
     <form method="post" action="/deadlines/${d.id}/delete" class="inline confirm">${csrf(req)}<button class="ghost sm">✕</button></form></td></tr>`;
  }).join('');
  const sel = parseInt(req.query.item) || 0;
  res.send(page(req, 'Deadlines', `<h1 class="neon">30-Day Deadline Tracker</h1>
   <form method="post" action="/deadlines" class="card form-grid">${csrf(req)}
    <label>Item<select name="item_id"><option value="">(none)</option>${items.map(i => `<option value="${i.id}" ${i.id === sel ? 'selected' : ''}>${esc(i.creditor)} (${esc(i.bureau)})</option>`).join('')}</select></label>
    <label>Type<select name="kind">${['dispute', 'goodwill', 'validation'].map(k => `<option ${k === req.query.kind ? 'selected' : ''}>${k}</option>`).join('')}</select></label>
    <label>Sent to<input name="recipient" required maxlength="120" value="${esc(req.query.to || '')}"></label>
    <label>Date sent<input type="date" name="date_sent" required value="${new Date().toISOString().slice(0, 10)}"></label>
    <label class="check full"><input type="checkbox" name="after_free_report"> This dispute followed my free annual credit report (45-day window)</label>
    <button class="full">Log letter</button></form>
   <div class="card scroll"><table><thead><tr><th>Type</th><th>To</th><th>Item</th><th>Sent</th><th>Due</th><th>Status</th><th></th></tr></thead>
   <tbody>${rows || '<tr><td colspan="7" class="muted">Nothing logged yet.</td></tr>'}</tbody></table></div>
   <p class="muted">FCRA §611 generally gives bureaus 30 days from receipt (45 if the dispute follows a free annual report). Due dates here count from the date sent; add mailing time. Goodwill letters carry no legal deadline.</p>`));
});
app.post('/deadlines', async (req, res) => {
  const b = req.body; const d = dt(b.date_sent);
  if (!d || !clean(b.recipient)) { flash(req, 'Recipient and date are required.'); return res.redirect('/deadlines'); }
  await q('INSERT INTO disputes (item_id, kind, recipient, date_sent, after_free_report) VALUES ($1,$2,$3,$4,$5)',
    [parseInt(b.item_id) || null, ['dispute', 'goodwill', 'validation'].includes(b.kind) ? b.kind : 'dispute', clean(b.recipient, 120), d, b.after_free_report === 'on']);
  flash(req, 'Logged.'); res.redirect('/deadlines');
});
app.post('/deadlines/:id', async (req, res) => {
  const s = ['open', 'resolved - corrected', 'resolved - deleted', 'resolved - verified', 'no response'].includes(req.body.status) ? req.body.status : 'open';
  await q('UPDATE disputes SET status=$1 WHERE id=$2', [s, parseInt(req.params.id) || 0]); res.redirect('/deadlines');
});
app.post('/deadlines/:id/delete', async (req, res) => { await q('DELETE FROM disputes WHERE id=$1', [parseInt(req.params.id) || 0]); res.redirect('/deadlines'); });

// Tips + utilization
app.get('/tips', async (req, res) => {
  const cards = (await q("SELECT creditor, acct_last4, balance, credit_limit FROM items WHERE type='Credit Card' ORDER BY creditor")).rows;
  const seed = JSON.stringify(cards.map(c => ({ n: c.creditor + (c.acct_last4 ? ' ••' + c.acct_last4 : ''), b: Number(c.balance || 0), l: Number(c.credit_limit || 0) })));
  res.send(page(req, 'Tips', `<h1 class="neon">Score Tips &amp; Utilization</h1>
  <div class="card glow"><h2>Utilization calculator</h2>
   <div id="util" data-seed="${esc(seed)}"></div>
   <p><button type="button" id="addcard" class="ghost">+ Add card</button></p>
   <div id="util-out"></div>
   <p class="muted">Targets: keep overall and each card under <b>30%</b>; under <b>10%</b> is ideal. Utilization is reported on your statement balance, so paying before the statement closes lowers it.</p></div>
  <div class="tips">
   <div class="card"><h3>⚡ Pay on time, every time</h3><p>Payment history is the single largest factor. Set autopay for at least the minimum. A payment is usually only reported late once it's 30+ days past due — if you slip, pay before day 30.</p></div>
   <div class="card"><h3>🔒 Secured cards</h3><p>A secured card (refundable deposit = limit) builds history if you have thin or damaged credit. Use it lightly, pay in full, and look for issuers that graduate you to unsecured.</p></div>
   <div class="card"><h3>🏠 Rent reporting</h3><p>Services and some landlords can report on-time rent to the bureaus. It may help newer scoring models (e.g., FICO 9/10, VantageScore); confirm which bureaus they report to and fees first.</p></div>
   <div class="card"><h3>📉 Keep old accounts open</h3><p>Age of credit and total available limit both help. Avoid closing your oldest no-fee cards.</p></div>
   <div class="card"><h3>🔍 Limit hard inquiries</h3><p>Apply only when needed. Rate-shopping for a mortgage, auto, or student loan within a short window typically counts as one inquiry.</p></div>
   <div class="card"><h3>🛡️ Avoid scams</h3><p>Never use a "CPN" or "new credit identity" — these are illegal and can amount to fraud. No one can legally remove accurate, timely negative information. Disputes are free; you don't need to pay anyone to file them.</p></div>
  </div>`));
});

app.use((err, req, res, next) => { console.error(err.message); res.status(500).send('Something went wrong.'); });

migrate().then(() => app.listen(PORT, () => console.log('Credit Boost listening on ' + PORT)))
  .catch(e => { console.error('DB init failed', e.message); process.exit(1); });
