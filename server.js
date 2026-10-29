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
const compression = require('compression');

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
  for (const c of ['due_day INT', 'close_day INT', 'settle_status TEXT', 'settle_amount NUMERIC(12,2)', 'settle_notes TEXT'])
    await q(`ALTER TABLE items ADD COLUMN IF NOT EXISTS ${c}`);
  for (const c of ['mail_days INT DEFAULT 0', 'first_notice DATE', 'outcome_date DATE', 'mov_sent DATE'])
    await q(`ALTER TABLE disputes ADD COLUMN IF NOT EXISTS ${c}`);
  await q(`CREATE TABLE IF NOT EXISTS scores (id SERIAL PRIMARY KEY, bureau TEXT NOT NULL, score INT NOT NULL,
    model TEXT, score_date DATE NOT NULL, created_at TIMESTAMPTZ DEFAULT now())`);
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
// Same account reported by several bureaus counts once (highest reported balance/limit).
function dedupeCards(cards) {
  const m = new Map();
  for (const c of cards) {
    const k = (c.creditor || '').toLowerCase().replace(/[^a-z0-9]/g, '') + '|' + (c.acct_last4 || '');
    const o = m.get(k);
    if (!o) m.set(k, { ...c });
    else { o.balance = Math.max(Number(o.balance || 0), Number(c.balance || 0)); o.credit_limit = Math.max(Number(o.credit_limit || 0), Number(c.credit_limit || 0)); }
  }
  return [...m.values()];
}
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
    if (it.dofd && new Date(it.dofd) > today) f.push({ c: 'err', t: 'Date of first delinquency is in the future — check entry' });
    if (it.dofd) {
      const yrs = /bankruptcy ch\.?\s*7/i.test(it.type || '') ? 10 : 7;
      const limit = addDays(new Date(it.dofd), Math.round(yrs * 365.25));
      if (limit <= today) f.push({ c: 'old', t: `Past ${yrs}-yr FCRA §605 reporting period (since ${fmtD(limit)}) — likely obsolete` });
      else if (addDays(limit, -180) <= today) f.push({ c: 'warn', t: `Ages off ~${fmtD(limit)} (FCRA §605)` });
    }
    if (it.settle_status) f.push({ c: 'ok', t: 'Payoff: ' + it.settle_status + (it.settle_amount != null ? ' (' + money(it.settle_amount) + ')' : '') });
    it.flags = f;
  }
  return items;
}

const todayUTC = () => new Date(new Date().toISOString().slice(0, 10));
const daysBetween = (a, b) => Math.round((b - a) / 86400000);
function nextDay(day, from = todayUTC()) { // next occurrence (today included) of a day-of-month, clamped to month length
  for (let m = 0; m < 3; m++) {
    const y = from.getUTCFullYear(), mo = from.getUTCMonth() + m;
    const last = new Date(Date.UTC(y, mo + 1, 0)).getUTCDate();
    const d = new Date(Date.UTC(y, mo, Math.min(day, last)));
    if (d >= from) return d;
  }
}
const OUTCOMES = ['open', 'deleted', 'updated', 'verified', 'no response'];
// Timing for one logged letter. Disputes: 30 days (45 after free annual report) from receipt = sent + mail days.
function timing(d) {
  const t = todayUTC(), sent = new Date(d.date_sent);
  if (d.kind === 'dispute') {
    const recv = addDays(sent, d.mail_days || 0), days = d.after_free_report ? 45 : 30, due = addDays(recv, days);
    return { due, days, recv, left: daysBetween(t, due) };
  }
  if (d.kind === 'validation' && d.first_notice) {
    const end = addDays(new Date(d.first_notice), 30);
    return { windowEnd: end, inWindow: sent <= end };
  }
  return {};
}
function payoffPlan(cards, budget) {
  const list = dedupeCards(cards).filter(c => Number(c.credit_limit) > 0).map(c => {
    const b = Number(c.balance || 0), l = Number(c.credit_limit);
    return { name: c.creditor + (c.acct_last4 ? ' ••' + c.acct_last4 : ''), b, l, u: b / l * 100, to30: Math.max(0, b - l * 0.3), to10: Math.max(0, b - l * 0.1), pay: 0 };
  }).sort((a, b) => b.u - a.u);
  let left = budget > 0 ? budget : 0;
  for (const tier of ['to30', 'to10']) for (const c of list) { // highest utilization first, first get all cards under 30%, then 10%
    const need = Math.max(0, c[tier] - c.pay); const x = Math.min(need, left); c.pay += x; left -= x;
  }
  const B = list.reduce((s, c) => s + c.b, 0), L = list.reduce((s, c) => s + c.l, 0), P = list.reduce((s, c) => s + c.pay, 0);
  return { list, B, L, P, util: L ? B / L * 100 : null, after: L ? (B - P) / L * 100 : null, leftover: left };
}
async function reminders() {
  const out = [], t = todayUTC();
  const ds = (await q("SELECT d.*, i.creditor FROM disputes d LEFT JOIN items i ON i.id=d.item_id WHERE d.status='open' OR d.mov_sent IS NOT NULL")).rows;
  for (const d of ds) {
    const x = timing(d);
    if (d.status === 'open' && x.due) {
      if (x.left < 0) out.push({ c: 'err', at: x.due, t: `Dispute to ${d.recipient} (${d.creditor || '—'}) is ${-x.left}d past its ${x.days}-day deadline — record the outcome, or send a follow-up / CFPB complaint.` });
      else if (x.left <= 7) out.push({ c: 'warn', at: x.due, t: `Dispute to ${d.recipient} (${d.creditor || '—'}) due in ${x.left}d (${fmtD(x.due)}).` });
    }
    if (d.kind === 'validation' && x.windowEnd && !x.inWindow && d.status === 'open')
      out.push({ c: 'warn', at: x.windowEnd, t: `Validation request to ${d.recipient} was sent after the 30-day window (ended ${fmtD(x.windowEnd)}); §809(b) cease-collection protection may not apply.` });
    if (d.mov_sent && !['deleted', 'updated'].includes(d.status)) {
      const due = addDays(new Date(d.mov_sent), 15), left = daysBetween(t, due);
      if (left <= 7) out.push({ c: left < 0 ? 'err' : 'warn', at: due, t: `Method-of-verification reply from ${d.recipient} ${left < 0 ? `is ${-left}d late` : `due in ${left}d`} (15 days from request, FCRA §611(a)(7)).` });
    }
  }
  const items = (await q('SELECT * FROM items')).rows;
  for (const it of dedupeCards(items.filter(i => i.due_day || i.close_day)).map(c => c)) {
    const name = it.creditor + (it.acct_last4 ? ' ••' + it.acct_last4 : '');
    if (it.due_day) { const d = nextDay(it.due_day), left = daysBetween(t, d); if (left <= 7) out.push({ c: left <= 2 ? 'err' : 'warn', at: d, t: `Payment due on ${name} ${left ? `in ${left}d` : 'TODAY'} (${fmtD(d)}).` }); }
    if (it.close_day && Number(it.credit_limit) > 0) {
      const d = nextDay(it.close_day), left = daysBetween(t, d), u = Number(it.balance || 0) / Number(it.credit_limit) * 100;
      if (left <= 5 && u >= 30) out.push({ c: 'warn', at: d, t: `Statement for ${name} closes in ${left}d at ${u.toFixed(0)}% utilization — pay ${money(Number(it.balance) - Number(it.credit_limit) * 0.29)} before then to report under 30%.` });
    }
  }
  for (const it of items.filter(i => i.settle_status === 'settlement agreed (in writing)'))
    out.push({ c: 'warn', at: t, t: `Settlement agreed with ${it.creditor}${it.settle_amount != null ? ' for ' + money(it.settle_amount) : ''} — pay by the agreed date and keep proof; mark it paid when done.` });
  return out.sort((a, b) => a.at - b.at);
}
const remindersHtml = rs => `<div class="card ${rs.length ? 'glow' : ''}"><h2>${ic('bell')} Reminders</h2>${rs.length ? '<ul class="rem">' + rs.map(r => `<li><span class="flag ${r.c}">${r.c === 'err' ? 'NOW' : 'SOON'}</span> ${esc(r.t)}</li>`).join('') + '</ul>' : empty('check', 'All clear — nothing due in the next 7 days.')}</div>`;

// ---------- layout ----------
const ICONS = {
  home: '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>', list: '<path d="M8 6h13M8 12h13M8 18h13"/><circle cx="3.5" cy="6" r="1"/><circle cx="3.5" cy="12" r="1"/><circle cx="3.5" cy="18" r="1"/>',
  plus: '<path d="M12 5v14M5 12h14"/>', upload: '<path d="M12 16V4M6 10l6-6 6 6"/><path d="M4 20h16"/>', mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/>', chart: '<path d="M3 20h18"/><path d="M5 16l5-6 4 3 6-8"/>', card: '<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/>', out: '<path d="M15 4h4v16h-4"/><path d="M10 8l-4 4 4 4M6 12h10"/>', alert: '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18v.5"/>',
  check: '<path d="M4 12l5 5L20 6"/>', bell: '<path d="M6 16V11a6 6 0 0112 0v5l2 2H4z"/><path d="M10 20a2 2 0 004 0"/>', menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
};
const ic = (n, c = '') => `<svg class="ic ${c}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[n] || ''}</svg>`;
const empty = (icon, text, colspan) => { const e = `<div class="empty">${ic(icon, 'big-ic')}<p>${text}</p></div>`; return colspan ? `<tr><td colspan="${colspan}">${e}</td></tr>` : e; };
const NAV = [['/', 'home', 'Dashboard'], ['/items', 'list', 'Items'], ['/items/new', 'plus', 'Add'], ['/upload', 'upload', 'CSV'], ['/letters', 'mail', 'Letters'], ['/deadlines', 'clock', 'Deadlines'], ['/scores', 'chart', 'Scores'], ['/tips', 'card', 'Utilization'], ['/profile', 'user', 'Profile']];
function page(req, title, body) {
  const cur = req.path;
  const nav = req.session.user ? `<header class="top"><a href="/" class="brand">CREDIT<span>//</span>BOOST</a>
    <input type="checkbox" id="navt" class="navt"><label for="navt" class="navbtn" aria-label="Menu">${ic('menu')}</label>
    <nav>${NAV.map(([h, i, t]) => `<a href="${h}" class="${cur === h ? 'on' : ''}">${ic(i)}<span>${t}</span></a>`).join('')}
    <form method="post" action="/logout" class="inline">${csrf(req)}<button class="ghost sm">${ic('out')}<span>Log out</span></button></form></nav></header>` : '';
  const toasts = [USE_PG ? '' : '⚠ Storage is temporary (no DATABASE_URL set) — data is lost on restart.', req.flash || ''].filter(Boolean);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><meta name="theme-color" content="#05060f"><title>${esc(title)} · Credit Boost</title><link rel="stylesheet" href="/style.css?v=3"></head>
<body><div class="grid-bg"></div>${nav}<main class="fade">${body}</main>
<div class="toasts" role="status" aria-live="polite">${toasts.map(t => `<div class="toast ${/error|invalid|rejected|required|could not|ssn/i.test(t) ? 'bad' : ''}">${ic(/error|invalid|rejected|required|could not|ssn/i.test(t) ? 'alert' : 'check')}<span>${esc(t)}</span></div>`).join('')}</div>
<footer>Private tool for Kai Green · Educational, not legal advice · Disputes can only remove information that is inaccurate, incomplete, or unverifiable.</footer>
<script src="/app.js?v=3"></script></body></html>`;
}
const csrf = req => `<input type="hidden" name="_csrf" value="${esc(req.session.csrf)}">`;

// ---------- app ----------
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(compression());
app.use(helmet({ contentSecurityPolicy: { directives: { 'script-src': ["'self'"], 'img-src': ["'self'", 'data:'], 'connect-src': ["'self'"] } } }));
app.use(express.static('public', { maxAge: '1h' }));
app.use(express.urlencoded({ extended: false, limit: '200kb' }));
app.get('/healthz', (req, res) => { res.set('Cache-Control', 'no-store'); res.type('text').send('ok'); });
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
  if (!ok) { return res.status(401).send(page(req, 'Login', '<div class="login card"><h1>Invalid credentials</h1><p><a href="/login">Try again</a></p></div>')); }
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
  const ds = (await q("SELECT * FROM disputes WHERE status='open' AND kind <> 'goodwill'")).rows;
  const today = new Date();
  const overdue = ds.filter(d => (timing(d).left ?? 0) < 0).length;
  const rems = await reminders();
  const sc = (await q('SELECT DISTINCT ON (bureau) bureau, score FROM scores ORDER BY bureau, score_date DESC, id DESC')).rows;
  const flagged = items.filter(i => i.flags.some(f => f.c === 'err')).length;
  const old = items.filter(i => i.flags.some(f => f.c === 'old')).length;
  const cards = dedupeCards(items.filter(i => /credit card/i.test(i.type || '') && Number(i.credit_limit) > 0));
  const bal = cards.reduce((s, c) => s + Number(c.balance || 0), 0), lim = cards.reduce((s, c) => s + Number(c.credit_limit || 0), 0);
  const util = lim ? (bal / lim * 100) : null;
  res.send(page(req, 'Dashboard', `<h1 class="neon">Command Center</h1>
  <div class="stats">
   <a class="stat" href="/items"><b>${items.length}</b><span>Items tracked</span></a>
   <a class="stat mag" href="/items?f=err"><b>${flagged}</b><span>Possible errors</span></a>
   <a class="stat" href="/items?f=old"><b>${old}</b><span>Past §605 limit</span></a>
   <a class="stat ${overdue ? 'mag' : ''}" href="/deadlines"><b>${ds.length}</b><span>Open disputes · ${overdue} overdue</span></a>
   <a class="stat" href="/tips"><b>${util == null ? '—' : util.toFixed(1) + '%'}</b><span>Card utilization</span></a>
   <a class="stat" href="/scores"><b>${sc.length ? sc.map(x => x.score).join(' / ') : '—'}</b><span>Latest scores${sc.length ? ' (' + sc.map(x => x.bureau[0] + x.bureau[1]).join('/') + ')' : ''}</span></a>
  </div>
  ${remindersHtml(rems)}
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
   <p class="filters"><a href="/items">All</a><a href="/items?f=err">Possible errors</a><a href="/items?f=old">Past reporting limit</a></p>
   <div class="card scroll"><table><thead><tr><th>Bureau</th><th>Creditor</th><th>Type</th><th>Status</th><th>Opened</th><th>DOFD</th><th>Balance</th><th>Limit</th><th>Flags</th><th></th></tr></thead>
   <tbody>${rows || empty('list', 'No items yet. <a href="/items/new">Add one</a> or <a href="/upload">upload a CSV</a>.', 10)}</tbody></table></div>
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
   <label>Payment due (day of month)<input type="number" name="due_day" min="1" max="31" value="${it.due_day ?? ''}"></label>
   <label>Statement closes (day of month)<input type="number" name="close_day" min="1" max="31" value="${it.close_day ?? ''}"></label>
   <label>Settlement / payoff status<select name="settle_status">${SETTLE.map(x => `<option value="${esc(x)}" ${x === (it.settle_status || '') ? 'selected' : ''}>${esc(x || '(none)')}</option>`).join('')}</select></label>
   <label>Agreed / offered amount<input name="settle_amount" inputmode="decimal" value="${it.settle_amount ?? ''}"></label>
   <label class="full">Settlement notes (who, date, reference — get agreements in writing before paying)<input name="settle_notes" maxlength="500" value="${esc(it.settle_notes)}"></label>
   <p class="muted full">Never enter a Social Security number. Anything SSN-shaped is rejected.</p>
   <button class="full">Save item</button></form>`;
}
const ITEM_COLS = ['bureau', 'creditor', 'acct_last4', 'type', 'status', 'date_opened', 'dofd', 'balance', 'credit_limit', 'notes', 'inaccurate', 'inaccuracy_reason', 'due_day', 'close_day', 'settle_status', 'settle_amount', 'settle_notes'];
const ITEM_INSERT = `INSERT INTO items (${ITEM_COLS.join(',')}) VALUES (${ITEM_COLS.map((_, i) => '$' + (i + 1)).join(',')})`;
const ITEM_UPDATE = `UPDATE items SET ${ITEM_COLS.map((c, i) => c + '=$' + (i + 1)).join(',')} WHERE id=$${ITEM_COLS.length + 1}`;
const SETTLE = ['', 'negotiating', 'pay-for-delete requested', 'settlement agreed (in writing)', 'settled - paid', 'paid in full'];
const dayNum = v => { const n = parseInt(v); return n >= 1 && n <= 31 ? n : null; };
function readItem(b) {
  const fields = ['creditor', 'status', 'notes', 'inaccuracy_reason', 'acct', 'settle_notes'];
  if (fields.some(f => hasSSN(b[f]))) return { error: 'SSN-like number detected. Social Security numbers are never accepted — remove it and try again.' };
  const bureau = BUREAUS.find(x => x.toLowerCase() === String(b.bureau || '').trim().toLowerCase());
  const creditor = clean(b.creditor, 120);
  if (!bureau || !creditor) return { error: 'Bureau and creditor are required.' };
  return { v: [bureau, creditor, last4(b.acct), clean(b.type, 40), clean(b.status, 80), dt(b.date_opened), dt(b.dofd),
    num(b.balance), num(b.credit_limit), clean(b.notes, 2000), b.inaccurate === 'on' || /^(y|yes|true|1)$/i.test(b.inaccurate || ''), clean(b.inaccuracy_reason, 300),
    dayNum(b.due_day), dayNum(b.close_day), SETTLE.includes(b.settle_status) && b.settle_status ? b.settle_status : null, num(b.settle_amount), clean(b.settle_notes, 500)] };
}
app.get('/items/new', (req, res) => res.send(page(req, 'Add item', `<h1 class="neon">Add Item</h1>${itemForm(req, {}, '/items')}`)));
app.post('/items', async (req, res) => {
  const r = readItem(req.body); if (r.error) { flash(req, r.error); return res.redirect('/items/new'); }
  await q(ITEM_INSERT, r.v);
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
  await q(ITEM_UPDATE, [...r.v, id]);
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
      balance: r.balance, credit_limit: r.limit || r.credit_limit, notes: r.notes, inaccurate: r.inaccurate, inaccuracy_reason: r.inaccuracy_reason,
      due_day: r.due_day || r.payment_due_day, close_day: r.close_day || r.statement_close_day };
    b.acct = last4(b.acct) || '';
    const x = readItem(b);
    if (x.error) { bad++; continue; }
    await q(ITEM_INSERT, x.v);
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
  if (kind === 'mov') {
    const b = opts.bureau || it.bureau;
    return { to: b, subject: `Method of verification request — ${it.creditor}`, text:
`${me}

${today}

${BUREAU_ADDR[b]}

RE: Request for description of reinvestigation procedure — FCRA Section 611(a)(6)(B)(iii) and 611(a)(7) (15 U.S.C. § 1681i(a)(7))

To Whom It May Concern:

On ${opts.orig ? fmtD(opts.orig) : '[date of original dispute]'} I disputed the following item in my ${b} credit file. You reported that the information was verified.

  Creditor/Furnisher: ${it.creditor}
  Account: ${acct}

Under Section 611(a)(7) of the FCRA, I request a description of the procedure used to determine the accuracy and completeness of this information, including the business name, address, and telephone number of any furnisher you contacted. The law requires you to provide this description within 15 days of receiving this request.

${reason}

I continue to believe this information is inaccurate or incomplete. Please also add a statement of dispute to my file if the item remains.

Sincerely,

${p.full_name || '[Signature]'}` };
  }
  if (kind === 'idtheft') {
    const b = opts.bureau || it.bureau;
    return { to: b, subject: `Identity theft block request — ${it.creditor}`, text:
`${me}

${today}

${BUREAU_ADDR[b]}

RE: Request to block information resulting from identity theft — FCRA Section 605B (15 U.S.C. § 1681c-2)

To Whom It May Concern:

I am a victim of identity theft. The following information in my ${b} file results from that identity theft and does not relate to any transaction I made or authorized:

  Creditor/Furnisher: ${it.creditor}
  Account: ${acct}
  Reported balance: ${money(it.balance)}

${reason}

Enclosed are (1) proof of my identity, (2) a copy of my identity theft report (FTC IdentityTheft.gov report and/or police report), and (3) this identification of the information to be blocked. Under Section 605B, please block this information within four business days of receiving this request and notify the furnisher that it may be the result of identity theft.

Sincerely,

${p.full_name || '[Signature]'}

Enclosures: proof of identity; identity theft report` };
  }
  if (kind === 'pfd') return { to: it.creditor, subject: `Settlement offer — ${it.creditor}`, text:
`${me}

${today}

${it.creditor}
[Creditor or collector's mailing address]

RE: Offer to resolve account ${acct}${it.balance != null ? ` (reported balance ${money(it.balance)})` : ''}

To Whom It May Concern:

I am writing to propose a resolution of the account referenced above. This letter is not an acknowledgment that I owe this debt and does not restart or extend any limitations period.

I am prepared to pay ${opts.amount != null ? money(opts.amount) : '$[amount]'} as full and final settlement of this account, on the following conditions, agreed in writing before any payment:

  1. You accept this amount as payment in full and will not sell or transfer any remaining balance;
  2. You will request that the credit bureaus to which you report delete this account from my credit files (or, if you will not, that you report it as "paid in full" / "settled" with a zero balance);
  3. You will provide the signed agreement on your letterhead before I pay.

I understand you are not required to accept this offer or to request deletion, and that accurately reported information may lawfully remain on my credit report. Payment will be made only after I receive your written agreement.

${opts.reason || ''}

Please respond in writing to the address above.

Sincerely,

${p.full_name || '[Signature]'}` };
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
   <label>Letter type<select name="kind" id="kind"><option value="dispute">Bureau dispute (FCRA §611)</option><option value="goodwill">Goodwill (creditor)</option><option value="validation">Debt validation (FDCPA §809)</option><option value="mov">Method of verification (FCRA §611(a)(7))</option><option value="pfd">Pay-for-delete / settlement offer</option><option value="idtheft">Identity theft block (FCRA §605B)</option></select></label>
   <label>Bureau (disputes)<select name="bureau"><option value="">Item's bureau</option>${BUREAUS.map(b => `<option>${b}</option>`).join('')}</select></label>
   <label>Offer amount (pay-for-delete)<input name="amount" inputmode="decimal" placeholder="e.g. 250"></label>
   <label>Original dispute date (MOV)<input type="date" name="orig"></label>
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
  const kind = ['dispute', 'goodwill', 'validation', 'mov', 'pfd', 'idtheft'].includes(req.query.kind) ? req.query.kind : 'dispute';
  const bureau = BUREAUS.includes(req.query.bureau) ? req.query.bureau : null;
  const reason = clean(req.query.reason, 1500);
  const L = buildLetter(kind, it, p, { bureau, reason, amount: num(req.query.amount), orig: dt(req.query.orig) });
  if (req.query.download) {
    res.set('Content-Type', 'text/plain; charset=utf-8');
    res.set('Content-Disposition', `attachment; filename="${kind}-${String(it.creditor).replace(/[^a-z0-9]+/gi, '_')}.txt"`);
    return res.send(L.text);
  }
  const qs = new URLSearchParams({ item: it.id, kind, bureau: bureau || '', reason: reason || '', amount: req.query.amount || '', orig: req.query.orig || '', download: 1 }).toString();
  res.send(page(req, L.subject, `<div class="noprint"><h1 class="neon">${esc(L.subject)}</h1>
   <p><button class="print-btn">Print / Save PDF</button> <a class="btn" href="/letters/view?${esc(qs)}">Download .txt</a>
   <a class="btn ghost" href="/deadlines?item=${it.id}&kind=${{ mov: 'dispute', idtheft: 'dispute', pfd: 'validation' }[kind] || kind}&to=${encodeURIComponent(L.to)}">Log as sent →</a></p></div>
   <article class="letter">${esc(L.text)}</article>`));
});

// Deadlines
app.get('/deadlines', async (req, res) => {
  const ds = (await q("SELECT d.*, i.creditor, i.bureau FROM disputes d LEFT JOIN items i ON i.id=d.item_id ORDER BY (d.status='open') DESC, d.date_sent")).rows;
  const items = (await q('SELECT id, creditor, bureau, acct_last4 FROM items ORDER BY creditor')).rows;
  const rows = ds.map(d => {
    const x = timing(d), open = d.status === 'open';
    let due = '<span class="muted">No legal deadline</span>', st;
    if (d.kind === 'dispute') {
      due = `<b>${fmtD(x.due)}</b> <span class="muted">(${x.days}d from ${d.mail_days ? 'receipt ' + fmtD(x.recv) : 'sent'})</span>`;
      st = !open ? esc(d.status) : x.left < 0 ? `<span class="flag err">OVERDUE ${-x.left}d</span>` : `<span class="flag ${x.left <= 5 ? 'warn' : 'ok'}">${x.left}d left</span>`;
    } else if (d.kind === 'validation') {
      due = d.first_notice ? `<span class="muted">1st notice ${fmtD(d.first_notice)} → 30-day window ends</span> <b>${fmtD(x.windowEnd)}</b> ${x.inWindow ? '<span class="flag ok">sent in window</span>' : '<span class="flag err">sent after window</span>'}` : '<span class="muted">Log first-notice date to check the 30-day window</span>';
      st = open ? '<span class="flag ok">awaiting verification</span>' : esc(d.status);
    } else st = open ? '<span class="flag ok">awaiting reply</span>' : esc(d.status);
    let follow = '';
    if (d.kind === 'dispute' && d.item_id && (d.status === 'verified' || d.status === 'no response' || (open && x.left < 0))) {
      const bq = BUREAUS.includes(d.recipient) ? '&bureau=' + d.recipient : '';
      follow = `<div class="follow">${d.status === 'verified' ? `<a href="/letters/view?item=${d.item_id}&kind=mov${bq}&orig=${fmtD(d.date_sent)}">MOV letter</a>` : ''}
        ${d.mov_sent ? `<span class="muted">MOV sent ${fmtD(d.mov_sent)} (reply due ${fmtD(addDays(new Date(d.mov_sent), 15))})</span>` : d.status === 'verified' ? `<form method="post" action="/deadlines/${d.id}/mov" class="inline">${csrf(req)}<button class="ghost sm">Mark MOV sent today</button></form>` : ''}
        <a href="https://www.consumerfinance.gov/complaint/" target="_blank" rel="noopener noreferrer">File CFPB complaint ↗</a></div>`;
    }
    return `<tr class="${!open ? 'done' : x.left < 0 ? 'overdue' : x.left <= 5 ? 'soon' : ''}"><td>${esc(d.kind)}</td><td>${esc(d.recipient)}</td><td>${esc(d.creditor || '—')}</td><td>${fmtD(d.date_sent)}</td>
     <td>${due}</td><td>${st}${d.outcome_date && !open ? ` <span class="muted">${fmtD(d.outcome_date)}</span>` : ''}${follow}</td>
     <td class="actions"><form method="post" action="/deadlines/${d.id}" class="inline">${csrf(req)}<select name="status">${OUTCOMES.map(s => `<option ${s === d.status ? 'selected' : ''}>${s}</option>`).join('')}</select><button class="sm">Save outcome</button></form>
     <form method="post" action="/deadlines/${d.id}/delete" class="inline confirm">${csrf(req)}<button class="ghost sm">✕</button></form></td></tr>`;
  }).join('');
  const sel = parseInt(req.query.item) || 0;
  res.send(page(req, 'Deadlines', `<h1 class="neon">Deadline &amp; Outcome Tracker</h1>
   <form method="post" action="/deadlines" class="card form-grid">${csrf(req)}
    <label>Item<select name="item_id"><option value="">(none)</option>${items.map(i => `<option value="${i.id}" ${i.id === sel ? 'selected' : ''}>${esc(i.creditor)} (${esc(i.bureau)})</option>`).join('')}</select></label>
    <label>Type<select name="kind">${['dispute', 'goodwill', 'validation'].map(k => `<option ${k === req.query.kind ? 'selected' : ''}>${k}</option>`).join('')}</select></label>
    <label>Sent to<input name="recipient" required maxlength="120" value="${esc(req.query.to || '')}"></label>
    <label>Date sent<input type="date" name="date_sent" required value="${new Date().toISOString().slice(0, 10)}"></label>
    <label>Mail days until received (disputes; 0 = count from sent)<input type="number" name="mail_days" min="0" max="30" value="0"></label>
    <label>Collector's first notice date (validation)<input type="date" name="first_notice"></label>
    <label class="check full"><input type="checkbox" name="after_free_report"> This dispute followed my free annual credit report (45-day window)</label>
    <button class="full">Log letter</button></form>
   <div class="card scroll"><table><thead><tr><th>Type</th><th>To</th><th>Item</th><th>Sent</th><th>Deadline / window</th><th>Status / outcome</th><th></th></tr></thead>
   <tbody>${rows || empty('clock', 'Nothing logged yet. Generate a letter, mail it, then log it here.', 7)}</tbody></table></div>
   <p class="muted">FCRA §611 gives bureaus 30 days from <i>receipt</i> (45 if the dispute follows a free annual report) — enter mail days (certified mail is typically 3–5) to count from receipt. If an item comes back "verified", you can request the method of verification (§611(a)(7); reply due within 15 days) and/or file a complaint with the CFPB. A validation request under FDCPA §809(b) is strongest within 30 days of the collector's first notice. Goodwill letters carry no legal deadline.</p>`));
});
app.post('/deadlines', async (req, res) => {
  const b = req.body; const d = dt(b.date_sent);
  if (!d || !clean(b.recipient)) { flash(req, 'Recipient and date are required.'); return res.redirect('/deadlines'); }
  const kind = ['dispute', 'goodwill', 'validation'].includes(b.kind) ? b.kind : 'dispute';
  const md = Math.min(30, Math.max(0, parseInt(b.mail_days) || 0));
  await q('INSERT INTO disputes (item_id, kind, recipient, date_sent, after_free_report, mail_days, first_notice) VALUES ($1,$2,$3,$4,$5,$6,$7)',
    [parseInt(b.item_id) || null, kind, clean(b.recipient, 120), d, b.after_free_report === 'on' && kind === 'dispute', kind === 'dispute' ? md : 0, kind === 'validation' ? dt(b.first_notice) : null]);
  flash(req, 'Logged.'); res.redirect('/deadlines');
});
app.post('/deadlines/:id/mov', async (req, res) => {
  await q('UPDATE disputes SET mov_sent=$1 WHERE id=$2', [new Date().toISOString().slice(0, 10), parseInt(req.params.id) || 0]);
  flash(req, 'Method-of-verification request logged — reply due in 15 days.'); res.redirect('/deadlines');
});
app.post('/deadlines/:id', async (req, res) => {
  const s = OUTCOMES.includes(req.body.status) ? req.body.status : 'open';
  await q('UPDATE disputes SET status=$1, outcome_date=$2 WHERE id=$3', [s, s === 'open' ? null : new Date().toISOString().slice(0, 10), parseInt(req.params.id) || 0]);
  flash(req, 'Outcome saved.'); res.redirect('/deadlines');
});
app.post('/deadlines/:id/delete', async (req, res) => { await q('DELETE FROM disputes WHERE id=$1', [parseInt(req.params.id) || 0]); res.redirect('/deadlines'); });

// Scores
const SCORE_COL = { Equifax: '#ff2bd6', Experian: '#00f0ff', TransUnion: '#3dffa8' };
function scoreChart(rows) {
  if (!rows.length) return empty('chart', 'Log a score to start the chart.');
  const W = 760, H = 300, P = 44;
  const ts = rows.map(r => new Date(r.score_date).getTime());
  let t0 = Math.min(...ts), t1 = Math.max(...ts); if (t0 === t1) { t0 -= 15 * 864e5; t1 += 15 * 864e5; }
  const sc = rows.map(r => r.score);
  const y0 = Math.max(300, Math.floor((Math.min(...sc) - 30) / 50) * 50), y1 = Math.min(850, Math.ceil((Math.max(...sc) + 30) / 50) * 50);
  const X = t => P + (t - t0) / (t1 - t0) * (W - P * 2), Y = v => H - P + 10 - (v - y0) / (y1 - y0) * (H - P * 1.5);
  let g = '';
  for (let v = y0; v <= y1; v += 50) g += `<line x1="${P}" x2="${W - P}" y1="${Y(v)}" y2="${Y(v)}" stroke="#1d2550"/><text x="${P - 8}" y="${Y(v) + 4}" text-anchor="end" fill="#7d86b8" font-size="11">${v}</text>`;
  for (const v of [580, 670, 740]) if (v > y0 && v < y1) g += `<line x1="${P}" x2="${W - P}" y1="${Y(v)}" y2="${Y(v)}" stroke="#ffcc00" stroke-dasharray="4 4" opacity=".35"/>`;
  g += `<text x="${P}" y="${H - 6}" fill="#7d86b8" font-size="11">${fmtD(t0)}</text><text x="${W - P}" y="${H - 6}" text-anchor="end" fill="#7d86b8" font-size="11">${fmtD(t1)}</text>`;
  for (const b of BUREAUS) {
    const pts = rows.filter(r => r.bureau === b).sort((a, c) => new Date(a.score_date) - new Date(c.score_date));
    if (!pts.length) continue;
    const pl = pts.map(r => `${X(new Date(r.score_date).getTime()).toFixed(1)},${Y(r.score).toFixed(1)}`).join(' ');
    g += `<polyline points="${pl}" fill="none" stroke="${SCORE_COL[b]}" stroke-width="3" filter="url(#glow)"/>`;
    g += pts.map(r => `<circle cx="${X(new Date(r.score_date).getTime()).toFixed(1)}" cy="${Y(r.score).toFixed(1)}" r="4" fill="${SCORE_COL[b]}"><title>${b} ${r.score} on ${fmtD(r.score_date)}</title></circle>`).join('');
  }
  const legend = BUREAUS.map(b => `<span style="color:${SCORE_COL[b]}">● ${b}</span>`).join(' &nbsp; ');
  return `<svg viewBox="0 0 ${W} ${H}" class="chart" role="img" aria-label="Credit score history"><defs><filter id="glow"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>${g}</svg><p>${legend} <span class="muted">· dashed lines: 580 / 670 / 740 (fair / good / very good, FICO)</span></p>`;
}
app.get('/scores', async (req, res) => {
  const rows = (await q('SELECT * FROM scores ORDER BY score_date, id')).rows;
  const first = {}, last = {};
  for (const r of rows) { first[r.bureau] ??= r; last[r.bureau] = r; }
  const summary = BUREAUS.filter(b => last[b]).map(b => { const ch = last[b].score - first[b].score; return `<div class="stat"><b>${last[b].score}</b><span>${b} · ${ch >= 0 ? '+' : ''}${ch} since ${fmtD(first[b].score_date)}</span></div>`; }).join('');
  res.send(page(req, 'Scores', `<h1 class="neon">Score Tracker</h1>
   ${summary ? `<div class="stats">${summary}</div>` : ''}
   <div class="card glow">${scoreChart(rows)}</div>
   <form method="post" action="/scores" class="card form-grid">${csrf(req)}
    <label>Bureau<select name="bureau">${BUREAUS.map(b => `<option>${b}</option>`).join('')}</select></label>
    <label>Score (300–850)<input type="number" name="score" min="300" max="850" required></label>
    <label>Date<input type="date" name="score_date" required value="${new Date().toISOString().slice(0, 10)}"></label>
    <label>Model / source<input name="model" maxlength="60" placeholder="FICO 8, VantageScore 3.0..."></label>
    <button class="full">Log score</button></form>
   <div class="card scroll"><table><thead><tr><th>Date</th><th>Bureau</th><th>Score</th><th>Model</th><th></th></tr></thead><tbody>
   ${rows.slice().reverse().map(r => `<tr><td>${fmtD(r.score_date)}</td><td>${esc(r.bureau)}</td><td><b>${r.score}</b></td><td>${esc(r.model || '')}</td><td><form method="post" action="/scores/${r.id}/delete" class="inline confirm">${csrf(req)}<button class="ghost sm">✕</button></form></td></tr>`).join('') || empty('chart', 'No scores yet. Log your first one above.', 5)}
   </tbody></table></div><p class="muted">Different models (FICO vs VantageScore) and sources give different numbers — compare like with like.</p>`));
});
app.post('/scores', async (req, res) => {
  const b = req.body, sc = parseInt(b.score), d = dt(b.score_date), bureau = BUREAUS.find(x => x === b.bureau);
  if (!bureau || !d || !(sc >= 300 && sc <= 850)) { flash(req, 'Bureau, date and a score between 300 and 850 are required.'); return res.redirect('/scores'); }
  await q('INSERT INTO scores (bureau, score, model, score_date) VALUES ($1,$2,$3,$4)', [bureau, sc, clean(b.model, 60), d]);
  flash(req, 'Score logged.'); res.redirect('/scores');
});
app.post('/scores/:id/delete', async (req, res) => { await q('DELETE FROM scores WHERE id=$1', [parseInt(req.params.id) || 0]); res.redirect('/scores'); });

// Tips + utilization
app.get('/tips', async (req, res) => {
  const cards = dedupeCards((await q("SELECT creditor, acct_last4, balance, credit_limit FROM items WHERE type='Credit Card' ORDER BY creditor")).rows);
  const budget = num(req.query.budget) || 0, plan = payoffPlan(cards, budget);
  const planHtml = plan.list.length ? `<div class="card glow"><h2>Payoff plan (highest utilization first)</h2>
   <form method="get" action="/tips" class="inline">Extra cash available this month $<input name="budget" inputmode="decimal" value="${budget || ''}" class="sm-in"> <button class="sm">Plan</button></form>
   <div class="scroll"><table><thead><tr><th>#</th><th>Card</th><th>Balance</th><th>Limit</th><th>Util</th><th>To 30%</th><th>To 10%</th>${budget ? '<th>Pay now</th>' : ''}</tr></thead><tbody>
   ${plan.list.map((c, i) => `<tr><td>${i + 1}</td><td>${esc(c.name)}</td><td>${money(c.b)}</td><td>${money(c.l)}</td><td class="${c.u < 10 ? 'good' : c.u < 30 ? 'mid' : 'high'}">${c.u.toFixed(1)}%</td><td>${money(c.to30)}</td><td>${money(c.to10)}</td>${budget ? `<td><b>${money(c.pay)}</b></td>` : ''}</tr>`).join('')}
   </tbody></table></div>
   <p>Overall ${plan.util.toFixed(1)}%${budget ? ` → <b>${plan.after.toFixed(1)}%</b> after paying ${money(plan.P)}${plan.leftover > 0 ? ` (${money(plan.leftover)} left over — all cards under 10%)` : ''}` : ''}. Order: the card with the highest utilization % gets money first until every card is under 30%, then under 10%. Pay before each statement closing date so the lower balance is what gets reported. (If you're paying down to save interest instead, target the highest APR first.)</p></div>` : '';
  const seed = JSON.stringify(cards.map(c => ({ n: c.creditor + (c.acct_last4 ? ' ••' + c.acct_last4 : ''), b: Number(c.balance || 0), l: Number(c.credit_limit || 0) })));
  res.send(page(req, 'Tips', `<h1 class="neon">Score Tips &amp; Utilization</h1>
  ${planHtml}
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
