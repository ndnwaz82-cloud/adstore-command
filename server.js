// AdStore Command — single-file bundle for phone-friendly deploy.
// Built from ~/workspace/adstore-product/ by build-phone-bundle.js.
// Do NOT edit by hand; rebuild from source.
require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const cookie = require('cookie');
const { DatabaseSync } = require('node:sqlite');

// ================= db.js =================
// SQLite storage (Node built-in node:sqlite — no native addons needed).
// EVERY table that holds customer content has a user_id column.
// All queries MUST filter by user_id = req.user.id so buyers never see
// each other's data.

const DB_PATH = process.env.DB_PATH
  ? path.resolve(process.env.DB_PATH)
  : path.join(__dirname, '..', 'data', 'adstore.db');

let db = null;

function getDb() {
  if (!db) {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    db = new DatabaseSync(DB_PATH);
    db.exec('PRAGMA journal_mode = WAL;');
    initSchema(db);
  }
  return db;
}

function initSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      stripe_customer_id TEXT,
      stripe_session_id TEXT,
      paid_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS pending_purchases (
      session_id TEXT PRIMARY KEY,
      email TEXT,
      paid_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS campaigns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      platform TEXT NOT NULL DEFAULT 'Other',
      status TEXT NOT NULL DEFAULT 'active',
      budget REAL NOT NULL DEFAULT 0,
      spend REAL NOT NULL DEFAULT 0,
      revenue REAL NOT NULL DEFAULT 0,
      conversions INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      company TEXT NOT NULL DEFAULT '',
      email TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS invoices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL,
      number TEXT NOT NULL,
      amount REAL NOT NULL,
      status TEXT NOT NULL DEFAULT 'sent',
      due_date TEXT,
      notes TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      invoice_id INTEGER REFERENCES invoices(id) ON DELETE SET NULL,
      amount REAL NOT NULL,
      method TEXT NOT NULL DEFAULT 'Other',
      note TEXT NOT NULL DEFAULT '',
      received_at TEXT NOT NULL DEFAULT (date('now'))
    );
    CREATE TABLE IF NOT EXISTS expenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      description TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'Other',
      amount REAL NOT NULL,
      spent_at TEXT NOT NULL DEFAULT (date('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_campaigns_user ON campaigns(user_id);
    CREATE INDEX IF NOT EXISTS idx_clients_user ON clients(user_id);
    CREATE INDEX IF NOT EXISTS idx_invoices_user ON invoices(user_id);
    CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id);
    CREATE INDEX IF NOT EXISTS idx_expenses_user ON expenses(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
  `);
}

// Overview metrics for one user. Definitions (shown on the dashboard):
//   grossRevenue = total payments actually received
//   adSpend      = total campaign spend
//   net          = grossRevenue - adSpend
//   marginPct    = net / grossRevenue * 100 (0 when revenue is 0)
//   conversions  = sum of campaign conversions
function getOverview(userId) {
  const d = getDb();
  const sum = (sql) => d.prepare(sql).get(userId)?.total ?? 0;
  const grossRevenue = sum('SELECT COALESCE(SUM(amount),0) AS total FROM payments WHERE user_id = ?');
  const adSpend = sum('SELECT COALESCE(SUM(spend),0) AS total FROM campaigns WHERE user_id = ?');
  const conversions = d.prepare('SELECT COALESCE(SUM(conversions),0) AS total FROM campaigns WHERE user_id = ?').get(userId).total;
  const totalExpenses = sum('SELECT COALESCE(SUM(amount),0) AS total FROM expenses WHERE user_id = ?');
  const outstanding = sum("SELECT COALESCE(SUM(amount),0) AS total FROM invoices WHERE user_id = ? AND status IN ('sent','overdue')");
  const activeClients = d.prepare("SELECT COUNT(*) AS c FROM clients WHERE user_id = ? AND status = 'active'").get(userId).c;
  const totalClients = d.prepare('SELECT COUNT(*) AS c FROM clients WHERE user_id = ?').get(userId).c;
  const activeCampaigns = d.prepare("SELECT COUNT(*) AS c FROM campaigns WHERE user_id = ? AND status = 'active'").get(userId).c;
  const net = grossRevenue - adSpend;
  return {
    grossRevenue, adSpend, net,
    marginPct: grossRevenue > 0 ? (net / grossRevenue) * 100 : 0,
    conversions, totalExpenses, outstanding,
    activeClients, totalClients, activeCampaigns,
  };
}


// ================= auth.js =================
// Auth: email+password login with DB-backed sessions.
// Passwords are hashed with bcrypt. Session tokens are random 256-bit
// values stored in the sessions table and sent as an httpOnly cookie.

const COOKIE_NAME = 'adstore_session';
const SESSION_DAYS = 30;

async function hashPassword(pw) {
  return bcrypt.hash(pw, 10);
}

async function verifyPassword(pw, hash) {
  return bcrypt.compare(pw, hash);
}

function createSession(userId) {
  const db = getDb();
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + SESSION_DAYS * 864e5);
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)')
    .run(token, userId, expires.toISOString().slice(0, 19).replace('T', ' '));
  return { token, expires };
}

function destroySession(token) {
  if (token) getDb().prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

function getCookieToken(req) {
  const parsed = cookie.parse(req.headers.cookie || '');
  return parsed[COOKIE_NAME] || null;
}

function setSessionCookie(req, res, token, expires) {
  const isProd = process.env.NODE_ENV === 'production';
  const serialized = cookie.serialize(COOKIE_NAME, token, {
    httpOnly: true,
    path: '/',
    sameSite: 'lax',
    secure: isProd,
    expires,
  });
  res.setHeader('Set-Cookie', serialized);
}

function clearSessionCookie(res) {
  const isProd = process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', cookie.serialize(COOKIE_NAME, '', {
    httpOnly: true, path: '/', sameSite: 'lax', secure: isProd, expires: new Date(0),
  }));
}

// Attaches req.user = { id, email, paidAt } | null
function sessionMiddleware(req, res, next) {
  req.user = null;
  try {
    const token = getCookieToken(req);
    if (token) {
      const row = getDb().prepare(`
        SELECT u.id AS id, u.email AS email, u.paid_at AS paidAt
        FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > datetime('now')
      `).get(token);
      if (row) req.user = { id: row.id, email: row.email, paidAt: row.paidAt };
    }
  } catch (e) { /* fail closed: req.user stays null */ }
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) {
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Not signed in' });
    return res.redirect('/login');
  }
  next();
}


// ================= views/landing.js =================
// Landing page templates for AdStore Command's public sales site.
// Pure functions that return HTML strings. All interpolated user content
// must go through esc().
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

const PRICE = 79;

function layout({ title, body, extraHead = '' }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="AdStore Command — the one-time-fee command center for running your ad agency: campaigns, clients, invoicing, expenses. Pay once, own it forever.">
<style>/* style.css (inlined for single-file deploy) */
/* Shared base styles. Feature CSS lives in public/app.css (dashboard)
   and public/landing.css (sales site) — do not put feature styles here. */
:root {
  --bg: #0f1420;
  --bg-soft: #161d2e;
  --card: #1b2338;
  --border: #2a3450;
  --text: #eef2ff;
  --muted: #9aa6c4;
  --accent: #4f7cff;
  --accent-hover: #3d68f0;
  --green: #34d399;
  --red: #f87171;
  --radius: 12px;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
}
a { color: var(--accent); }
.muted { color: var(--muted); }
.small { font-size: 0.85rem; }
.error {
  background: rgba(248,113,113,.12); border: 1px solid var(--red);
  color: var(--red); padding: 0.6rem 0.9rem; border-radius: 8px;
}
.btn {
  display: inline-block; border: 0; cursor: pointer; border-radius: 8px;
  padding: 0.7rem 1.4rem; font-size: 1rem; font-weight: 600; text-decoration: none;
}
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: var(--accent-hover); }
.btn-ghost { background: transparent; color: var(--text); border: 1px solid var(--border); }
input, select, textarea {
  width: 100%; padding: 0.65rem 0.8rem; margin: 0.25rem 0 0.9rem;
  background: var(--bg-soft); border: 1px solid var(--border); color: var(--text);
  border-radius: 8px; font-size: 1rem;
}
label { display: block; font-size: 0.9rem; color: var(--muted); }
.auth-body { display: flex; min-height: 100vh; align-items: center; justify-content: center; padding: 1rem; }
.auth-card {
  background: var(--card); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 2rem; width: 100%; max-width: 400px;
}
.auth-card h1 { margin: 0 0 0.25rem; font-size: 1.4rem; }
.card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1.25rem;
}
table { width: 100%; border-collapse: collapse; font-size: 0.95rem; }
th, td { text-align: left; padding: 0.6rem 0.5rem; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
.empty { text-align: center; color: var(--muted); padding: 2.5rem 1rem; }
.empty p { margin: 0.4rem 0 1rem; }
</style>
<style>/* landing.css (inlined for single-file deploy) */
/* AdStore Command sales site. Dark theme matching shared vars in style.css.
   Base link/button/form styles come from /style.css; everything here is
   landing-specific. */

.l-wrap {
  max-width: 1080px;
  margin: 0 auto;
  padding: 0 1.25rem;
}

/* ---- sticky nav ---- */
.l-nav {
  position: sticky;
  top: 0;
  z-index: 50;
  background: rgba(15, 20, 32, 0.92);
  backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--border);
}
.l-nav-inner {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  padding-top: 0.8rem;
  padding-bottom: 0.8rem;
}
.l-logo {
  font-weight: 800;
  font-size: 1.15rem;
  color: var(--text);
  text-decoration: none;
  letter-spacing: 0.01em;
  white-space: nowrap;
}
.l-nav-links {
  display: flex;
  gap: 1.25rem;
  margin-left: auto;
}
.l-nav-links a {
  color: var(--muted);
  text-decoration: none;
  font-size: 0.95rem;
}
.l-nav-links a:hover { color: var(--text); }
.l-nav-cta {
  display: flex;
  align-items: center;
  gap: 0.9rem;
}
.l-signin {
  color: var(--muted);
  text-decoration: none;
  font-size: 0.95rem;
}
.l-signin:hover { color: var(--text); }

/* ---- hero ---- */
.l-hero {
  text-align: center;
  padding: 4.5rem 0 3rem;
  background: radial-gradient(ellipse 70% 45% at 50% 0%, rgba(79, 124, 255, 0.14), transparent);
}
.l-eyebrow {
  color: var(--accent);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 0.8rem;
  margin: 0 0 1rem;
}
.l-hero h1 {
  font-size: 2.9rem;
  line-height: 1.12;
  margin: 0 auto 1rem;
  max-width: 16em;
}
.l-sub {
  color: var(--muted);
  font-size: 1.15rem;
  max-width: 34em;
  margin: 0 auto 1.8rem;
}
.l-hero-cta { margin-bottom: 2.5rem; }
.l-cta-big {
  font-size: 1.1rem;
  padding: 0.9rem 2rem;
}
.l-hero-cta .muted { margin-top: 0.7rem; }

/* ---- stylized dashboard mock (illustration, not a screenshot) ---- */
.mock {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  max-width: 820px;
  margin: 0 auto;
  text-align: left;
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
  overflow: hidden;
}
.mock-bar {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  padding: 0.7rem 1rem;
  border-bottom: 1px solid var(--border);
}
.mock-dot {
  width: 11px;
  height: 11px;
  border-radius: 50%;
  background: var(--border);
}
.mock-bar-title {
  margin-left: 0.5rem;
  color: var(--muted);
  font-size: 0.85rem;
}
.mock-body { padding: 1.1rem; }
.mock-cards {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 0.75rem;
  margin-bottom: 0.75rem;
}
.mock-card {
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.7rem 0.85rem;
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}
.mock-k {
  color: var(--muted);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.mock-v { font-size: 1.35rem; font-weight: 700; }
.mock-green { color: var(--green); }
.mock-cols {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.75rem;
  margin-bottom: 0.75rem;
}
.mock-panel {
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.7rem 0.85rem;
}
.mock-row {
  display: flex;
  justify-content: space-between;
  padding: 0.35rem 0;
  font-size: 0.9rem;
  border-top: 1px solid var(--border);
}
.mock-row:first-of-type { border-top: 0; }
.mock-row b { font-weight: 600; }
.mock-chart {
  display: flex;
  align-items: flex-end;
  gap: 8px;
  height: 90px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 14px;
}
.mock-chart span {
  flex: 1;
  border-radius: 4px 4px 0 0;
  background: linear-gradient(to top, var(--accent), #7fa1ff);
  opacity: 0.85;
}
.mock-bar1 { height: 35%; }
.mock-bar2 { height: 55%; }
.mock-bar3 { height: 42%; }
.mock-bar4 { height: 75%; }
.mock-bar5 { height: 95%; }
.mock-caption {
  margin: 0;
  padding: 0.6rem 1.1rem;
  color: var(--muted);
  font-size: 0.78rem;
  border-top: 1px solid var(--border);
}

/* ---- sections ---- */
.l-section { padding: 4rem 0; }
.l-alt { background: var(--bg-soft); border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); }
.l-section h2 {
  font-size: 2rem;
  margin: 0 0 0.6rem;
  text-align: center;
}
.l-lead {
  text-align: center;
  max-width: 42em;
  margin: 0 auto 2.2rem;
}
.l-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
}
.l-feature h3 { margin: 0 0 0.5rem; font-size: 1.08rem; }
.l-feature p { margin: 0; font-size: 0.95rem; }

/* ---- how it works ---- */
.l-steps {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
  margin-top: 2rem;
}
.l-step {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.6rem 1.4rem;
  text-align: center;
}
.l-step-num {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 2.6rem;
  height: 2.6rem;
  border-radius: 50%;
  background: var(--accent);
  color: #fff;
  font-weight: 800;
  font-size: 1.2rem;
  margin-bottom: 0.9rem;
}
.l-step h3 { margin: 0 0 0.4rem; }
.l-step p { margin: 0; }

/* ---- pricing ---- */
.l-price-card {
  max-width: 520px;
  margin: 2rem auto 0;
  text-align: center;
  padding: 2.2rem;
}
.l-price-name { font-weight: 700; font-size: 1.1rem; margin: 0 0 0.4rem; }
.l-price { font-size: 3.2rem; font-weight: 800; margin: 0 0 1.4rem; }
.l-price .muted { font-size: 1.1rem; font-weight: 400; }
.l-includes {
  list-style: none;
  margin: 0 0 1.8rem;
  padding: 0;
  text-align: left;
}
.l-includes li {
  padding: 0.45rem 0 0.45rem 1.9rem;
  position: relative;
  border-top: 1px solid var(--border);
}
.l-includes li:first-child { border-top: 0; }
.l-includes li::before {
  content: "✓";
  color: var(--green);
  font-weight: 800;
  position: absolute;
  left: 0.4rem;
}

/* ---- faq ---- */
.l-faq { max-width: 680px; margin: 2rem auto 0; }
.l-faq-item {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 0.75rem;
  padding: 0.4rem 1.2rem;
}
.l-faq-item summary {
  cursor: pointer;
  font-weight: 700;
  padding: 0.8rem 0;
  font-size: 1.02rem;
}
.l-faq-item p { margin: 0 0 1rem; }

/* ---- footer ---- */
.l-footer {
  border-top: 1px solid var(--border);
  padding: 1.6rem 0;
}
.l-footer-inner {
  display: flex;
  align-items: center;
  gap: 1.2rem;
  flex-wrap: wrap;
}
.l-footer-inner .muted { margin-left: auto; }
.l-footer-inner a.muted { text-decoration: none; }
.l-footer-inner a.muted:hover { color: var(--text); }

/* ---- responsive ---- */
@media (max-width: 860px) {
  .l-grid { grid-template-columns: 1fr 1fr; }
  .l-hero h1 { font-size: 2.2rem; }
  .l-nav-links { display: none; }
  .mock-cards { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 600px) {
  .l-grid, .l-steps { grid-template-columns: 1fr; }
  .mock-cols { grid-template-columns: 1fr; }
  .l-hero h1 { font-size: 1.8rem; }
  .l-nav-cta .btn { padding: 0.6rem 1rem; font-size: 0.9rem; }
}
</style>
${extraHead}
</head>
<body>
${body}
</body>
</html>`;
}

function nav() {
  return `<header class="l-nav">
  <div class="l-wrap l-nav-inner">
    <a class="l-logo" href="/">AdStore Command</a>
    <nav class="l-nav-links">
      <a href="/#features">Features</a>
      <a href="/#pricing">Pricing</a>
      <a href="/#faq">FAQ</a>
    </nav>
    <div class="l-nav-cta">
      <a class="l-signin" href="/login">Sign in</a>
      <a class="btn btn-primary" href="/#pricing">Get it for $${PRICE}</a>
    </div>
  </div>
</header>`;
}

// Stylized CSS-only mock of the dashboard — clearly labelled as an
// illustration. Never presented as a screenshot or real data.
function dashboardMock() {
  return `<div class="mock" aria-label="Illustration of the AdStore Command dashboard">
  <div class="mock-bar">
    <span class="mock-dot"></span><span class="mock-dot"></span><span class="mock-dot"></span>
    <span class="mock-bar-title">AdStore Command — Overview</span>
  </div>
  <div class="mock-body">
    <div class="mock-cards">
      <div class="mock-card"><span class="mock-k">Gross revenue</span><span class="mock-v">$12,400</span></div>
      <div class="mock-card"><span class="mock-k">Ad spend</span><span class="mock-v">$3,150</span></div>
      <div class="mock-card"><span class="mock-k">Net</span><span class="mock-v mock-green">$9,250</span></div>
      <div class="mock-card"><span class="mock-k">Margin</span><span class="mock-v">74.6%</span></div>
    </div>
    <div class="mock-cols">
      <div class="mock-panel">
        <span class="mock-k">Campaigns</span>
        <div class="mock-row"><span>Summer launch</span><b class="mock-green">$4,200</b></div>
        <div class="mock-row"><span>Retargeting</span><b class="mock-green">$2,900</b></div>
        <div class="mock-row"><span>Lead gen</span><b>$1,750</b></div>
      </div>
      <div class="mock-panel">
        <span class="mock-k">Invoices</span>
        <div class="mock-row"><span>INV-0101</span><b class="mock-green">Paid</b></div>
        <div class="mock-row"><span>INV-0102</span><b>Sent</b></div>
        <div class="mock-row"><span>INV-0103</span><b class="mock-green">Paid</b></div>
      </div>
    </div>
    <div class="mock-chart"><span class="mock-bar1"></span><span class="mock-bar2"></span><span class="mock-bar3"></span><span class="mock-bar4"></span><span class="mock-bar5"></span></div>
  </div>
  <p class="mock-caption">Illustration — stylized mock-up, not a screenshot or real data.</p>
</div>`;
}

function hero() {
  return `<section class="l-hero">
  <div class="l-wrap">
    <p class="l-eyebrow">For independent ad agencies</p>
    <h1>Run your entire agency from one command center.</h1>
    <p class="l-sub">AdStore Command tracks your campaigns, clients, invoices and expenses in one private dashboard — so you always know what's working and what's actually getting paid.</p>
    <div class="l-hero-cta">
      <a class="btn btn-primary l-cta-big" href="/billing/checkout">Get AdStore Command — $${PRICE}</a>
      <p class="muted small">One-time payment. Yours forever. No subscription.</p>
    </div>
    ${dashboardMock()}
  </div>
</section>`;
}

const FEATURES = [
  ['Command overview', 'Revenue, spend, margin and conversions at a glance. One screen that tells you exactly how the agency is doing this month.'],
  ['Campaign tracking', 'Log every campaign with platform, budget, spend, revenue and conversions — and see real margins per campaign.'],
  ['Client management', 'Keep every client, company and contact organized with active/inactive status, all in one place.'],
  ['Invoicing & payments', 'Send invoices, track sent vs. overdue vs. paid, and record payments so nothing slips through the cracks.'],
  ['Expense tracking', 'Categorize every business expense to see your true costs — not just ad spend.'],
  ['Private — your data is yours', 'Self-hosted and self-contained. No trackers, no data resale, no analytics phoning home. Your business numbers stay yours.'],
];

function features() {
  const cards = FEATURES.map(([t, d]) => `<div class="card l-feature"><h3>${esc(t)}</h3><p class="muted">${esc(d)}</p></div>`).join('\n');
  return `<section class="l-section" id="features">
  <div class="l-wrap">
    <h2>Everything you need to run the business side</h2>
    <p class="muted l-lead">This is the dashboard you operate yourself — it organizes the work you're already doing. It does not run ads or generate revenue on its own.</p>
    <div class="l-grid">${cards}</div>
  </div>
</section>`;
}

function howItWorks() {
  return `<section class="l-section l-alt" id="how">
  <div class="l-wrap">
    <h2>How it works</h2>
    <div class="l-steps">
      <div class="l-step"><span class="l-step-num">1</span><h3>Pay $${PRICE} once</h3><p class="muted">Secure checkout, 30-day refund promise.</p></div>
      <div class="l-step"><span class="l-step-num">2</span><h3>Create your account</h3><p class="muted">Your email and password — you're signed straight in.</p></div>
      <div class="l-step"><span class="l-step-num">3</span><h3>Run your agency</h3><p class="muted">Add clients, campaigns, invoices and expenses. Your data, your rules.</p></div>
    </div>
  </div>
</section>`;
}

function pricing() {
  return `<section class="l-section" id="pricing">
  <div class="l-wrap">
    <h2>Simple pricing</h2>
    <div class="l-price-card card">
      <p class="l-price-name">AdStore Command</p>
      <p class="l-price">$${PRICE}<span class="muted"> one-time</span></p>
      <ul class="l-includes">
        <li>Lifetime access — pay once, use it forever</li>
        <li>Command overview: revenue, spend, margin, conversions</li>
        <li>Campaign, client, invoice &amp; expense tracking</li>
        <li>Private, self-hosted — your data stays yours</li>
        <li>No subscription, no per-client fees, no upsells</li>
        <li>30-day money-back promise</li>
      </ul>
      <a class="btn btn-primary l-cta-big" href="/billing/checkout">Get it for $${PRICE}</a>
      <p class="muted small">Secure payment. No subscription.</p>
    </div>
  </div>
</section>`;
}

const FAQ = [
  ['Is it really one-time?',
    `Yes. You pay $${PRICE} once and get lifetime access to AdStore Command. There is no subscription, no renewal, and no per-client fee.`],
  ['Do you see my data?',
    'No. AdStore Command runs on your own hosting, against your own database. We have no backdoor, no analytics pipeline, and no interest in your numbers — they stay yours.'],
  ['What if I need help?',
    'Every purchase includes a 30-day money-back promise and support while you get set up. If something isn\u2019t working, reach out and we\u2019ll make it right.'],
  ['Can I get a refund?',
    `Yes — within 30 days of purchase, no questions asked. After you buy, you create your account right away; if it\u2019s not for you, we\u2019ll refund the $${PRICE}.`],
  ['I paid but closed the tab before creating my account — what now?',
    'No problem. Visit the claim page, enter the email you paid with, and you\u2019ll get a link to create your account.'],
];

function faq() {
  const items = FAQ.map(([q, a], i) => `<details class="l-faq-item"${i === 0 ? ' open' : ''}>
      <summary>${esc(q)}</summary>
      <p class="muted">${i === 4 ? `No problem. Visit <a href="/billing/claim">the claim page</a>, enter the email you paid with, and you\u2019ll get a link to create your account.` : esc(a)}</p>
    </details>`).join('\n');
  return `<section class="l-section l-alt" id="faq">
  <div class="l-wrap">
    <h2>Frequently asked questions</h2>
    <div class="l-faq">${items}</div>
  </div>
</section>`;
}

function footer() {
  return `<footer class="l-footer">
  <div class="l-wrap l-footer-inner">
    <span class="l-logo">AdStore Command</span>
    <span class="muted small">Pay once. Run your agency. Keep your data.</span>
    <a class="muted small" href="/login">Sign in</a>
  </div>
</footer>`;
}

function landingPage() {
  return layout({
    title: 'AdStore Command — Run your ad agency from one dashboard',
    body: nav() + hero() + features() + howItWorks() + pricing() + faq() + footer(),
  });
}

// Generic full-page billing layout: full HTML doc, shared base styles.
function billingPage({ title, heading, sub, body, error }) {
  return layout({
    title,
    body: `<div class="auth-body"><main class="auth-card">
      <h1>${esc(heading)}</h1>
      ${sub ? `<p class="muted">${esc(sub)}</p>` : ''}
      ${error ? `<p class="error">${esc(error)}</p>` : ''}
      ${body}
    </main></div>`,
  });
}


// ================= views/app.js =================
// Templates for the logged-in AdStore Command dashboard (/app/*).
// All functions return HTML strings. Every piece of user content goes
// through esc(). Money is always USD with 2 decimals via money().
// IMPORTANT: never render sample/demo data — empty tables show empty
// states, and zero numbers show $0.00.

const escApp = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

const moneyFmt = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' });
const money = (n) => moneyFmt.format(Number(n) || 0);
const pct = (n) => `${(Number(n) || 0).toFixed(1)}%`;

const NAV_LINKS = [
  ['overview', 'Overview', '/app/overview'],
  ['campaigns', 'Campaigns', '/app/campaigns'],
  ['clients', 'Clients', '/app/clients'],
  ['finance', 'Finance', '/app/finance'],
];

function appLayout(title, user, active, content) {
  const links = NAV_LINKS.map(([key, label, href]) =>
    `<a href="${href}" class="${active === key ? 'active' : ''}">${label}</a>`).join('');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — AdStore Command</title>
<style>/* style.css (inlined for single-file deploy) */
/* Shared base styles. Feature CSS lives in public/app.css (dashboard)
   and public/landing.css (sales site) — do not put feature styles here. */
:root {
  --bg: #0f1420;
  --bg-soft: #161d2e;
  --card: #1b2338;
  --border: #2a3450;
  --text: #eef2ff;
  --muted: #9aa6c4;
  --accent: #4f7cff;
  --accent-hover: #3d68f0;
  --green: #34d399;
  --red: #f87171;
  --radius: 12px;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
}
a { color: var(--accent); }
.muted { color: var(--muted); }
.small { font-size: 0.85rem; }
.error {
  background: rgba(248,113,113,.12); border: 1px solid var(--red);
  color: var(--red); padding: 0.6rem 0.9rem; border-radius: 8px;
}
.btn {
  display: inline-block; border: 0; cursor: pointer; border-radius: 8px;
  padding: 0.7rem 1.4rem; font-size: 1rem; font-weight: 600; text-decoration: none;
}
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: var(--accent-hover); }
.btn-ghost { background: transparent; color: var(--text); border: 1px solid var(--border); }
input, select, textarea {
  width: 100%; padding: 0.65rem 0.8rem; margin: 0.25rem 0 0.9rem;
  background: var(--bg-soft); border: 1px solid var(--border); color: var(--text);
  border-radius: 8px; font-size: 1rem;
}
label { display: block; font-size: 0.9rem; color: var(--muted); }
.auth-body { display: flex; min-height: 100vh; align-items: center; justify-content: center; padding: 1rem; }
.auth-card {
  background: var(--card); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 2rem; width: 100%; max-width: 400px;
}
.auth-card h1 { margin: 0 0 0.25rem; font-size: 1.4rem; }
.card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1.25rem;
}
table { width: 100%; border-collapse: collapse; font-size: 0.95rem; }
th, td { text-align: left; padding: 0.6rem 0.5rem; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
.empty { text-align: center; color: var(--muted); padding: 2.5rem 1rem; }
.empty p { margin: 0.4rem 0 1rem; }
</style>
<style>/* app.css (inlined for single-file deploy) */
/* Dashboard styles for /app/*. Pairs with /style.css (shared base).
   Dark theme tokens come from style.css :root. */

/* ---------- layout ---------- */
.app-nav {
  position: sticky; top: 0; z-index: 50;
  background: rgba(15, 20, 32, 0.95);
  border-bottom: 1px solid var(--border);
  backdrop-filter: blur(6px);
}
.nav-inner {
  max-width: 1100px; margin: 0 auto; padding: 0.7rem 1rem;
  display: flex; align-items: center; gap: 1.25rem;
}
.nav-brand {
  font-weight: 700; font-size: 1.05rem; color: var(--text);
  text-decoration: none; white-space: nowrap;
}
.nav-links { display: flex; gap: 0.25rem; flex: 1; }
.nav-links a {
  color: var(--muted); text-decoration: none; font-size: 0.95rem;
  padding: 0.45rem 0.8rem; border-radius: 8px;
}
.nav-links a:hover { color: var(--text); background: var(--bg-soft); }
.nav-links a.active { color: var(--text); background: var(--bg-soft); font-weight: 600; }
.nav-user { display: flex; align-items: center; gap: 0.75rem; margin-left: auto; }
.nav-logout { margin: 0; }
.nav-email { max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.app-main { max-width: 1100px; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
.page-title { margin: 0 0 1.25rem; font-size: 1.6rem; }

/* ---------- stat cards ---------- */
.stat-grid {
  display: grid; gap: 1rem;
  grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
}
.stat-label { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.35rem; }
.stat-value { font-size: 1.6rem; font-weight: 700; }
.stat-sub { margin-top: 0.25rem; }
.definitions { margin-top: 1.25rem; }

/* ---------- sections & tables ---------- */
.section-head {
  display: flex; align-items: flex-start; justify-content: space-between;
  gap: 1rem; margin: 0 0 1rem;
}
.section-head h2 { margin: 0; font-size: 1.25rem; }
.section-sub { margin: 0.25rem 0 0; }
.finance-section { margin-bottom: 2.5rem; }
.finance-section:last-child { margin-bottom: 0; }

.table-wrap { overflow-x: auto; padding: 0; }
.table-wrap table { min-width: 640px; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
td.actions { white-space: nowrap; text-align: right; }
td.actions .btn { margin-left: 0.35rem; }

/* ---------- badges ---------- */
.badge {
  display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px;
  font-size: 0.8rem; font-weight: 600; text-transform: capitalize;
  border: 1px solid var(--border); color: var(--muted);
}
.badge-active, .badge-paid, .badge-sent { color: var(--green); border-color: rgba(52, 211, 153, 0.4); }
.badge-paused { color: #fbbf24; border-color: rgba(251, 191, 36, 0.4); }
.badge-overdue { color: var(--red); border-color: rgba(248, 113, 113, 0.4); }
.badge-archived, .badge-draft { color: var(--muted); }

/* ---------- buttons ---------- */
.btn-sm { padding: 0.4rem 0.85rem; font-size: 0.85rem; }
.btn-danger { color: var(--red); }
.btn-danger:hover { border-color: var(--red); }

/* ---------- empty states ---------- */
.empty-state { text-align: center; padding: 2.5rem 1.5rem; margin-bottom: 1.5rem; }
.empty-state h2 { margin: 0 0 0.5rem; }
.empty-actions { display: flex; gap: 0.75rem; justify-content: center; margin-top: 1.25rem; flex-wrap: wrap; }

/* ---------- dialogs ---------- */
dialog.app-dialog {
  background: var(--card); color: var(--text);
  border: 1px solid var(--border); border-radius: var(--radius);
  padding: 1.5rem; width: min(480px, 92vw);
}
dialog.app-dialog::backdrop { background: rgba(0, 0, 0, 0.6); }
dialog.app-dialog h3 { margin: 0 0 1rem; }
dialog.app-dialog .error { margin-bottom: 1rem; }
.dialog-actions { display: flex; justify-content: flex-end; gap: 0.75rem; margin-top: 0.5rem; }

/* ---------- responsive ---------- */
@media (max-width: 640px) {
  .nav-inner { flex-wrap: wrap; gap: 0.6rem; }
  .nav-links { order: 3; width: 100%; overflow-x: auto; }
  .nav-email { display: none; }
  .section-head { flex-direction: column; align-items: stretch; }
  .section-head .btn { align-self: flex-start; }
  .stat-value { font-size: 1.35rem; }
}
</style>
</head>
<body>
<header class="app-nav">
  <div class="nav-inner">
    <a class="nav-brand" href="/app/overview">AdStore Command</a>
    <nav class="nav-links">${links}</nav>
    <div class="nav-user">
      <span class="muted small nav-email">${esc(user.email)}</span>
      <form method="POST" action="/logout" class="nav-logout">
        <button type="submit" class="btn btn-ghost btn-sm">Sign out</button>
      </form>
    </div>
  </div>
</header>
<main class="app-main">
${content}
</main>
</body>
</html>`;
}

function badge(status) {
  const s = String(status || '');
  return `<span class="badge badge-${esc(s)}">${esc(s)}</span>`;
}

function sectionHead(title, sub, addBtnId, addLabel) {
  return `<div class="section-head">
  <div><h2>${esc(title)}</h2>${sub ? `<p class="muted small section-sub">${esc(sub)}</p>` : ''}</div>
  ${addBtnId ? `<button class="btn btn-primary btn-sm" id="${addBtnId}">${esc(addLabel)}</button>` : ''}
</div>`;
}

function dataTable(headers, rowsHtml, emptyHtml) {
  if (!rowsHtml) {
    return `<div class="empty card">${emptyHtml}</div>`;
  }
  return `<div class="table-wrap card"><table>
<thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead>
<tbody>${rowsHtml}</tbody>
</table></div>`;
}

function rowActions() {
  return `<td class="actions">
    <button type="button" class="btn btn-ghost btn-sm" data-edit>Edit</button>
    <button type="button" class="btn btn-ghost btn-sm btn-danger" data-del>Delete</button>
  </td>`;
}

// ---- form field builders ----
function textField(name, label, opts = {}) {
  const { required = false, type = 'text', value = '', min, max, step, list, placeholder = '' } = opts;
  const attrs = [
    `type="${type}"`, `name="${esc(name)}"`,
    required ? 'required' : '',
    value !== '' ? `value="${esc(value)}"` : '',
    min !== undefined ? `min="${min}"` : '',
    max !== undefined ? `max="${max}"` : '',
    step !== undefined ? `step="${step}"` : '',
    list ? `list="${esc(list)}"` : '',
    placeholder ? `placeholder="${esc(placeholder)}"` : '',
  ].filter(Boolean).join(' ');
  return `<label>${esc(label)}<input ${attrs}></label>`;
}

function selectField(name, label, options, selected = '') {
  const opts = options.map(([v, t]) =>
    `<option value="${esc(v)}"${String(v) === String(selected) ? ' selected' : ''}>${esc(t)}</option>`).join('');
  return `<label>${esc(label)}<select name="${esc(name)}">${opts}</select></label>`;
}

function textareaField(name, label, value = '') {
  return `<label>${esc(label)}<textarea name="${esc(name)}" rows="2">${esc(value)}</textarea></label>`;
}

function dialog(prefix, titleText, fieldsHtml) {
  return `<dialog id="${prefix}-dialog" class="app-dialog">
  <h3 id="${prefix}-title">${esc(titleText)}</h3>
  <div id="${prefix}-err" class="error" hidden></div>
  <form id="${prefix}-form" novalidate>
    <input type="hidden" id="${prefix}-id">
    ${fieldsHtml}
    <div class="dialog-actions">
      <button type="button" class="btn btn-ghost" id="${prefix}-cancel">Cancel</button>
      <button type="submit" class="btn btn-primary">Save</button>
    </div>
  </form>
</dialog>`;
}

// Generic add/edit/delete wiring for one entity. The page must contain:
//   - a table whose <tr>s carry data-id and data-row (esc()'d JSON)
//   - buttons with data-edit / data-del inside those rows
//   - a dialog + form built by dialog() with the same prefix
//   - an "add" button with id `${prefix}-add`
// Dialog form fields must be named after the API/DB columns so the edit
// filler and the submit serializer line up.
function crudScript(base, prefix, singular) {
  return `<script>
(function () {
  var D = document.getElementById('${prefix}-dialog');
  var F = document.getElementById('${prefix}-form');
  var idF = document.getElementById('${prefix}-id');
  var err = document.getElementById('${prefix}-err');
  var title = document.getElementById('${prefix}-title');
  var addBtn = document.getElementById('${prefix}-add');
  var cancelBtn = document.getElementById('${prefix}-cancel');
  function showErr(m) { err.textContent = m; err.hidden = false; }
  function apiCall(path, method, body) {
    return fetch('/app/api' + path, {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (!r.ok) throw new Error(data.error || ('Request failed (' + r.status + ')'));
        return data;
      });
    });
  }
  function openAdd() {
    idF.value = ''; F.reset(); err.hidden = true;
    if (title) title.textContent = 'Add ${singular}';
    D.showModal();
  }
  function openEdit(btn) {
    var tr = btn.closest('tr');
    var row;
    try { row = JSON.parse(tr.getAttribute('data-row')); }
    catch (e) { showErr('Could not load this row.'); return; }
    idF.value = row.id; F.reset(); err.hidden = true;
    Array.prototype.forEach.call(F.elements, function (el) {
      if (el.name && row[el.name] !== undefined && row[el.name] !== null) el.value = row[el.name];
    });
    if (title) title.textContent = 'Edit ${singular}';
    D.showModal();
  }
  function delRow(btn) {
    var tr = btn.closest('tr');
    if (!confirm('Delete this ${singular}? This cannot be undone.')) return;
    apiCall('${base}/' + tr.getAttribute('data-id'), 'DELETE').then(function () {
      var tbody = tr.parentElement;
      tr.remove();
      if (tbody && tbody.rows.length === 0) location.reload();
    }).catch(showErr);
  }
  F.addEventListener('submit', function (e) {
    e.preventDefault();
    var data = {};
    new FormData(F).forEach(function (v, k) { data[k] = v; });
    var id = idF.value;
    var p = id
      ? apiCall('${base}/' + id, 'PUT', data)
      : apiCall('${base}', 'POST', data);
    p.then(function () { D.close(); location.reload(); }).catch(showErr);
  });
  if (addBtn) addBtn.addEventListener('click', openAdd);
  if (cancelBtn) cancelBtn.addEventListener('click', function () { D.close(); });
  Array.prototype.forEach.call(document.querySelectorAll('[data-edit]'), function (b) {
    if (b.closest('#${prefix}-table')) b.addEventListener('click', function () { openEdit(b); });
  });
  Array.prototype.forEach.call(document.querySelectorAll('[data-del]'), function (b) {
    if (b.closest('#${prefix}-table')) b.addEventListener('click', function () { delRow(b); });
  });
})();
</script>`;
}

function tableWithId(prefix, headers, rowsHtml, emptyHtml) {
  if (!rowsHtml) return `<div class="empty card">${emptyHtml}</div>`;
  return `<div class="table-wrap card"><table id="${prefix}-table">
<thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead>
<tbody>${rowsHtml}</tbody>
</table></div>`;
}

// ============================ OVERVIEW ============================

function statCard(label, valueHtml, sub) {
  return `<div class="stat-card card">
    <div class="stat-label">${esc(label)}</div>
    <div class="stat-value">${valueHtml}</div>
    ${sub ? `<div class="stat-sub muted small">${esc(sub)}</div>` : ''}
  </div>`;
}

function overviewPage(user, ov) {
  const allZero =
    ov.grossRevenue === 0 && ov.adSpend === 0 && ov.net === 0 &&
    ov.conversions === 0 && ov.totalExpenses === 0 && ov.outstanding === 0 &&
    ov.activeClients === 0 && ov.activeCampaigns === 0 && ov.totalClients === 0;

  const cards = [
    statCard('Gross Revenue', money(ov.grossRevenue), 'Payments actually received'),
    statCard('Ad Spend', money(ov.adSpend), 'Total campaign spend'),
    statCard('Net', money(ov.net), 'Revenue minus ad spend'),
    statCard('Margin', pct(ov.marginPct), 'Net ÷ gross revenue'),
    statCard('Conversions', esc(String(ov.conversions || 0))),
    statCard('Active Clients', `${esc(String(ov.activeClients))} <span class="muted">of ${esc(String(ov.totalClients))}</span>`),
    statCard('Active Campaigns', esc(String(ov.activeCampaigns))),
    statCard('Outstanding Invoices', money(ov.outstanding), 'Sent or overdue, not yet paid'),
    statCard('Total Expenses', money(ov.totalExpenses)),
  ].join('\n');

  const emptyState = allZero ? `<div class="empty-state card">
    <h2>Nothing here yet</h2>
    <p class="muted">Your dashboard starts at zero — no demo data, no fake numbers.<br>
    Add your first campaign to see stats here.</p>
    <div class="empty-actions">
      <a class="btn btn-primary" href="/app/campaigns">Add a campaign</a>
      <a class="btn btn-ghost" href="/app/finance">Log a payment</a>
    </div>
  </div>` : '';

  const body = `
<h1 class="page-title">Overview</h1>
${emptyState}
<div class="stat-grid">${cards}</div>
<p class="muted small definitions">Gross revenue = payments received. Ad spend = total campaign spend.
Net = gross revenue − ad spend. Margin = net ÷ gross revenue. Outstanding = invoices with status sent or overdue that are not yet paid.</p>`;

  return appLayout('Overview', user, 'overview', body);
}

// ============================ CAMPAIGNS ============================

const CAMPAIGN_STATUS_OPTS = [['active', 'Active'], ['paused', 'Paused'], ['archived', 'Archived']];
const PLATFORMS = ['Google Ads', 'Meta', 'TikTok', 'LinkedIn', 'X / Twitter', 'Other'];

function campaignsPage(user, rows) {
  const rowsHtml = rows.map((r) => {
    const data = esc(JSON.stringify(r));
    return `<tr data-id="${r.id}" data-row="${data}">
      <td>${esc(r.name)}</td>
      <td>${esc(r.platform)}</td>
      <td>${badge(r.status)}</td>
      <td class="num">${money(r.budget)}</td>
      <td class="num">${money(r.spend)}</td>
      <td class="num">${money(r.revenue)}</td>
      <td class="num">${esc(String(r.conversions ?? 0))}</td>
      ${rowActions()}
    </tr>`;
  }).join('');

  const fields =
    textField('name', 'Name', { required: true, placeholder: 'Spring launch' }) +
    `<label>Platform<input type="text" name="platform" list="platform-list" value="Other"></label>
     <datalist id="platform-list">${PLATFORMS.map((p) => `<option value="${esc(p)}">`).join('')}</datalist>` +
    selectField('status', 'Status', CAMPAIGN_STATUS_OPTS, 'active') +
    textField('budget', 'Budget (USD)', { type: 'number', min: 0, step: '0.01', value: '0' }) +
    textField('spend', 'Spend (USD)', { type: 'number', min: 0, step: '0.01', value: '0' }) +
    textField('revenue', 'Revenue (USD)', { type: 'number', min: 0, step: '0.01', value: '0' }) +
    textField('conversions', 'Conversions', { type: 'number', min: 0, step: '1', value: '0' });

  const body = `
${sectionHead('Campaigns', 'Track spend, revenue, and conversions per campaign.', 'campaign-add', 'Add campaign')}
${tableWithId('campaign', ['Name', 'Platform', 'Status', 'Budget', 'Spend', 'Revenue', 'Conversions', ''],
  rowsHtml,
  '<h3>No campaigns yet</h3><p>Click “Add campaign” above to create your first one.</p>')}
${dialog('campaign', 'Add campaign', fields)}
${crudScript('/campaigns', 'campaign', 'campaign')}`;

  return appLayout('Campaigns', user, 'campaigns', body);
}

// ============================ CLIENTS ============================

const CLIENT_STATUS_OPTS = [['active', 'Active'], ['paused', 'Paused'], ['archived', 'Archived']];

function clientsPage(user, rows) {
  const rowsHtml = rows.map((r) => {
    const data = esc(JSON.stringify(r));
    return `<tr data-id="${r.id}" data-row="${data}">
      <td>${esc(r.name)}</td>
      <td>${esc(r.company) || '<span class="muted">—</span>'}</td>
      <td>${esc(r.email) || '<span class="muted">—</span>'}</td>
      <td>${badge(r.status)}</td>
      ${rowActions()}
    </tr>`;
  }).join('');

  const fields =
    textField('name', 'Name', { required: true, placeholder: 'Jane Smith' }) +
    textField('company', 'Company', { placeholder: 'Acme Inc.' }) +
    textField('email', 'Email', { type: 'email', placeholder: 'jane@acme.com' }) +
    selectField('status', 'Status', CLIENT_STATUS_OPTS, 'active');

  const body = `
${sectionHead('Clients', 'People and businesses you run ads for.', 'client-add', 'Add client')}
${tableWithId('client', ['Name', 'Company', 'Email', 'Status', ''],
  rowsHtml,
  '<h3>No clients yet</h3><p>Click “Add client” above to create your first one.</p>')}
${dialog('client', 'Add client', fields)}
${crudScript('/clients', 'client', 'client')}`;

  return appLayout('Clients', user, 'clients', body);
}

// ============================ FINANCE ============================

const INVOICE_STATUS_OPTS = [['draft', 'Draft'], ['sent', 'Sent'], ['paid', 'Paid'], ['overdue', 'Overdue']];

function invoicesSection(invoices, clients) {
  const rowsHtml = invoices.map((inv) => {
    const data = esc(JSON.stringify(inv));
    return `<tr data-id="${inv.id}" data-row="${data}">
      <td>${esc(inv.number)}</td>
      <td>${inv.client_name ? esc(inv.client_name) : '<span class="muted">—</span>'}</td>
      <td class="num">${money(inv.amount)}</td>
      <td>${badge(inv.status)}</td>
      <td>${inv.due_date ? esc(inv.due_date) : '<span class="muted">—</span>'}</td>
      ${rowActions()}
    </tr>`;
  }).join('');

  const clientOptions = [['', '— No client —']]
    .concat(clients.map((c) => [String(c.id), `${c.name}${c.company ? ' (' + c.company + ')' : ''}`]));
  const fields =
    textField('number', 'Invoice number', { required: true, placeholder: 'INV-001' }) +
    selectField('client_id', 'Client', clientOptions, '') +
    textField('amount', 'Amount (USD)', { required: true, type: 'number', min: 0, step: '0.01', value: '0' }) +
    selectField('status', 'Status', INVOICE_STATUS_OPTS, 'sent') +
    textField('due_date', 'Due date', { type: 'date' }) +
    textareaField('notes', 'Notes');

  return `
${sectionHead('Invoices', 'Bill clients; mark paid when money arrives.', 'invoice-add', 'Add invoice')}
${tableWithId('invoice', ['Number', 'Client', 'Amount', 'Status', 'Due date', ''],
  rowsHtml,
  '<h3>No invoices yet</h3><p>Click “Add invoice” above to bill your first client.</p>')}
${dialog('invoice', 'Add invoice', fields)}
${crudScript('/invoices', 'invoice', 'invoice')}`;
}

function paymentsSection(payments, invoices, today) {
  const rowsHtml = payments.map((p) => {
    const data = esc(JSON.stringify(p));
    return `<tr data-id="${p.id}" data-row="${data}">
      <td class="num">${money(p.amount)}</td>
      <td>${p.invoice_number ? esc(p.invoice_number) : '<span class="muted">—</span>'}</td>
      <td>${esc(p.method)}</td>
      <td>${esc(p.received_at)}</td>
      <td>${esc(p.note) || '<span class="muted">—</span>'}</td>
      <td><button type="button" class="btn btn-ghost btn-sm btn-danger" data-del>Delete</button></td>
    </tr>`;
  }).join('');

  const invoiceOptions = [['', '— No invoice —']]
    .concat(invoices.map((i) => [String(i.id), `${i.number} — ${money(i.amount)}`]));
  const fields =
    textField('amount', 'Amount (USD)', { required: true, type: 'number', min: 0, step: '0.01', value: '0' }) +
    selectField('invoice_id', 'Linked invoice', invoiceOptions, '') +
    textField('method', 'Method', { placeholder: 'Bank transfer', value: 'Other' }) +
    textField('received_at', 'Date received', { type: 'date', value: today }) +
    textField('note', 'Note', { placeholder: 'Optional' });

  // Payments: add + delete only (no edit — money records stay immutable).
  return `
${sectionHead('Payments received', 'Money that actually landed. This drives gross revenue.', 'payment-add', 'Log payment')}
${tableWithId('payment', ['Amount', 'Invoice', 'Method', 'Date', 'Note', ''],
  rowsHtml,
  '<h3>No payments logged</h3><p>Click “Log payment” above when a client pays you.</p>')}
${dialog('payment', 'Log payment', fields)}
${paymentScript()}`;
}

function paymentScript() {
  return `<script>
(function () {
  var D = document.getElementById('payment-dialog');
  var F = document.getElementById('payment-form');
  var err = document.getElementById('payment-err');
  var addBtn = document.getElementById('payment-add');
  var cancelBtn = document.getElementById('payment-cancel');
  function showErr(m) { err.textContent = m; err.hidden = false; }
  function apiCall(path, method, body) {
    return fetch('/app/api' + path, {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (!r.ok) throw new Error(data.error || ('Request failed (' + r.status + ')'));
        return data;
      });
    });
  }
  if (addBtn) addBtn.addEventListener('click', function () {
    F.reset(); err.hidden = true; D.showModal();
  });
  if (cancelBtn) cancelBtn.addEventListener('click', function () { D.close(); });
  F.addEventListener('submit', function (e) {
    e.preventDefault();
    var data = {};
    new FormData(F).forEach(function (v, k) { data[k] = v; });
    apiCall('/payments', 'POST', data).then(function () {
      D.close(); location.reload();
    }).catch(showErr);
  });
  Array.prototype.forEach.call(document.querySelectorAll('#payment-table [data-del]'), function (b) {
    b.addEventListener('click', function () {
      var tr = b.closest('tr');
      if (!confirm('Delete this payment? This cannot be undone.')) return;
      apiCall('/payments/' + tr.getAttribute('data-id'), 'DELETE').then(function () {
        var tbody = tr.parentElement;
        tr.remove();
        if (tbody && tbody.rows.length === 0) location.reload();
      }).catch(function (e) { alert(e.message); });
    });
  });
})();
</script>`;
}

function expensesSection(expenses, today) {
  const rowsHtml = expenses.map((e) => {
    const data = esc(JSON.stringify(e));
    return `<tr data-id="${e.id}" data-row="${data}">
      <td>${esc(e.description)}</td>
      <td>${esc(e.category)}</td>
      <td class="num">${money(e.amount)}</td>
      <td>${esc(e.spent_at)}</td>
      <td><button type="button" class="btn btn-ghost btn-sm btn-danger" data-del>Delete</button></td>
    </tr>`;
  }).join('');

  const fields =
    textField('description', 'Description', { required: true, placeholder: 'Stock photos' }) +
    textField('category', 'Category', { placeholder: 'Software', value: 'Other' }) +
    textField('amount', 'Amount (USD)', { required: true, type: 'number', min: 0, step: '0.01', value: '0' }) +
    textField('spent_at', 'Date', { type: 'date', value: today });

  // Expenses: add + delete only.
  return `
${sectionHead('Expenses', 'Business costs outside of ad spend.', 'expense-add', 'Add expense')}
${tableWithId('expense', ['Description', 'Category', 'Amount', 'Date', ''],
  rowsHtml,
  '<h3>No expenses yet</h3><p>Click “Add expense” above to record your first one.</p>')}
${dialog('expense', 'Add expense', fields)}
${expenseScript()}`;
}

function expenseScript() {
  return `<script>
(function () {
  var D = document.getElementById('expense-dialog');
  var F = document.getElementById('expense-form');
  var err = document.getElementById('expense-err');
  var addBtn = document.getElementById('expense-add');
  var cancelBtn = document.getElementById('expense-cancel');
  function showErr(m) { err.textContent = m; err.hidden = false; }
  function apiCall(path, method, body) {
    return fetch('/app/api' + path, {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (!r.ok) throw new Error(data.error || ('Request failed (' + r.status + ')'));
        return data;
      });
    });
  }
  if (addBtn) addBtn.addEventListener('click', function () {
    F.reset(); err.hidden = true; D.showModal();
  });
  if (cancelBtn) cancelBtn.addEventListener('click', function () { D.close(); });
  F.addEventListener('submit', function (e) {
    e.preventDefault();
    var data = {};
    new FormData(F).forEach(function (v, k) { data[k] = v; });
    apiCall('/expenses', 'POST', data).then(function () {
      D.close(); location.reload();
    }).catch(showErr);
  });
  Array.prototype.forEach.call(document.querySelectorAll('#expense-table [data-del]'), function (b) {
    b.addEventListener('click', function () {
      var tr = b.closest('tr');
      if (!confirm('Delete this expense? This cannot be undone.')) return;
      apiCall('/expenses/' + tr.getAttribute('data-id'), 'DELETE').then(function () {
        var tbody = tr.parentElement;
        tr.remove();
        if (tbody && tbody.rows.length === 0) location.reload();
      }).catch(function (e) { alert(e.message); });
    });
  });
})();
</script>`;
}

function financePage(user, data) {
  const { invoices, payments, expenses, clients, today } = data;
  const body = `
<h1 class="page-title">Finance</h1>
<section class="finance-section">${invoicesSection(invoices, clients)}</section>
<section class="finance-section">${paymentsSection(payments, invoices, today)}</section>
<section class="finance-section">${expensesSection(expenses, today)}</section>`;
  return appLayout('Finance', user, 'finance', body);
}


// ================= routes/billing.js =================
// Stripe billing for AdStore Command: $79 one-time checkout.
// Mounted at /billing by src/server.js BEFORE the landing billingRouter.
// IMPORTANT: the webhook route is FIRST and uses express.raw() — no
// express.json() may run before it or the Stripe signature check breaks.

const billingRouter = express.Router();

const PRICE_CENTS = parseInt(process.env.PRICE_CENTS || '7900', 10) || 7900;
const APP_URL = (process.env.APP_URL || 'http://localhost:3000').replace(/\/$/, '');

const isPlaceholder = (v) => !v || String(v).includes('PASTE_YOUR');
const stripeConfigured = () => !isPlaceholder(process.env.STRIPE_SECRET_KEY);
const webhookConfigured = () => !isPlaceholder(process.env.STRIPE_WEBHOOK_SECRET);

function stripeClient() {
  // Lazily constructed so placeholder keys never get used.
  return require('stripe')(process.env.STRIPE_SECRET_KEY);
}

// ---------------------------------------------------------------- webhook
// FIRST route in this file. Raw body required for signature verification.
billingRouter.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!stripeConfigured() || !webhookConfigured()) {
    // Fail closed: never record anything without a verified signature.
    return res.status(400).send('webhook not configured');
  }
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripeClient().webhooks.constructEvent(
      req.body, sig, process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    return res.status(400).send(`webhook signature verification failed: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email = session.customer_details?.email || session.customer_email || null;
    try {
      getDb().prepare(
        'INSERT OR IGNORE INTO pending_purchases (session_id, email, paid_at) VALUES (?,?,?)'
      ).run(session.id, email, new Date().toISOString().slice(0, 19).replace('T', ' '));
    } catch (dbErr) {
      // Don't leak internals; Stripe will retry the webhook anyway.
      return res.status(500).send('webhook processing error');
    }
  }
  return res.status(200).send('ok');
});

// Body parsers for all routes below (AFTER the raw webhook route).
billingRouter.use(express.urlencoded({ extended: false }));
billingRouter.use(express.json());

// --------------------------------------------------------------- checkout
billingRouter.get('/checkout', async (req, res) => {
  if (!stripeConfigured()) {
    return res.send(billingPage({
      title: 'Checkout — AdStore Command',
      heading: "Payments aren't connected yet",
      sub: 'The store owner still needs to connect Stripe before this page can take payment. If you were sent here to buy, please check back shortly.',
      body: `<p><a class="btn btn-ghost" href="/#pricing">Back to pricing</a></p>`,
    }));
  }
  try {
    const session = await stripeClient().checkout.sessions.create({
      mode: 'payment',
      line_items: [{
        price_data: {
          currency: 'usd',
          unit_amount: PRICE_CENTS,
          product_data: { name: 'AdStore Command — lifetime access' },
        },
        quantity: 1,
      }],
      success_url: `${APP_URL}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${APP_URL}/#pricing`,
    });
    return res.redirect(303, session.url);
  } catch (err) {
    return res.status(500).send(billingPage({
      title: 'Checkout — AdStore Command',
      heading: 'Checkout failed',
      sub: 'Something went wrong creating your payment session. Please try again in a moment.',
      body: `<p><a class="btn btn-ghost" href="/#pricing">Back to pricing</a></p>`,
    }));
  }
});

// ---------------------------------------------------------------- success
billingRouter.get('/success', async (req, res) => {
  const sessionId = String(req.query.session_id || '');
  if (!sessionId || !stripeConfigured()) {
    return res.status(400).send(billingPage({
      title: 'Create your account — AdStore Command',
      heading: 'Payment could not be verified',
      sub: 'We couldn\u2019t verify a completed payment for that link. If you paid and closed the tab, you can still claim your access.',
      body: `<p><a class="btn btn-primary" href="/billing/claim">Claim your purchase</a></p>
             <p><a class="muted small" href="/#pricing">Back to pricing</a></p>`,
    }));
  }
  let session;
  try {
    session = await stripeClient().checkout.sessions.retrieve(sessionId);
  } catch (err) {
    return res.status(400).send(billingPage({
      title: 'Create your account — AdStore Command',
      heading: 'Payment could not be verified',
      sub: 'That payment link doesn\u2019t look valid. If you paid and closed the tab, you can still claim your access.',
      body: `<p><a class="btn btn-primary" href="/billing/claim">Claim your purchase</a></p>`,
    }));
  }
  if (session.payment_status !== 'paid') {
    return res.status(402).send(billingPage({
      title: 'Create your account — AdStore Command',
      heading: 'Payment not completed',
      sub: 'Your payment hasn\u2019t gone through yet. If you already paid, check your email or claim your purchase below.',
      body: `<p><a class="btn btn-primary" href="/billing/claim">Claim your purchase</a></p>
             <p><a class="muted small" href="/billing/checkout">Try checkout again</a></p>`,
    }));
  }
  const email = session.customer_details?.email || session.customer_email || '';
  res.send(billingPage({
    title: 'Create your account — AdStore Command',
    heading: 'Payment received — create your account',
    sub: 'You\u2019re one step away. Choose a password and you\u2019ll be signed straight into your dashboard.',
    body: `<form method="POST" action="/billing/activate">
      <input type="hidden" name="session_id" value="${esc(sessionId)}">
      <label>Email<input type="email" name="email" required autocomplete="email" value="${esc(email)}"></label>
      <label>Password (8+ characters)<input type="password" name="password" required minlength="8" autocomplete="new-password"></label>
      <label>Confirm password<input type="password" name="confirm" required minlength="8" autocomplete="new-password"></label>
      <button type="submit" class="btn btn-primary">Create account &amp; open my dashboard</button>
    </form>`,
  }));
});

// ---------------------------------------------------------------- activate
billingRouter.post('/activate', async (req, res) => {
  const sessionId = String(req.body.session_id || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const confirm = String(req.body.confirm || '');

  const fail = (msg) => res.status(400).send(billingPage({
    title: 'Create your account — AdStore Command',
    heading: 'Couldn\u2019t create your account',
    sub: msg,
    body: `<p><a class="btn btn-primary" href="/billing/claim">Claim your purchase</a></p>
           <p><a class="muted small" href="/login">Already have an account? Sign in</a></p>`,
  }));

  if (!sessionId || !stripeConfigured()) return fail('That payment link isn\u2019t valid.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail('Please enter a valid email address.');
  if (password.length < 8) return fail('Password must be at least 8 characters.');
  if (password !== confirm) return fail('The two passwords don\u2019t match.');

  // Re-verify with Stripe: the session must exist and be paid.
  let session;
  try {
    session = await stripeClient().checkout.sessions.retrieve(sessionId);
  } catch (err) {
    return fail('We couldn\u2019t verify that payment with Stripe. Try the claim page.');
  }
  if (session.payment_status !== 'paid') return fail('That payment hasn\u2019t completed yet.');

  const db = getDb();
  const claimed = db.prepare('SELECT id FROM users WHERE stripe_session_id = ?').get(sessionId);
  if (claimed) {
    // Already claimed — account exists, just send them to sign in.
    return res.redirect('/login');
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    return fail('That email is already registered. Sign in instead.');
  }

  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const info = db.prepare(
    'INSERT INTO users (email, password_hash, stripe_customer_id, stripe_session_id, paid_at) VALUES (?,?,?,?,?)'
  ).run(
    email,
    await hashPassword(password),
    typeof session.customer === 'string' ? session.customer : null,
    sessionId,
    now
  );
  const { token, expires } = createSession(Number(info.lastInsertRowid));
  setSessionCookie(req, res, token, expires);
  res.redirect('/app');
});

// ------------------------------------------------------------------- claim
// Buyer paid but closed the tab before creating their account.
billingRouter.get('/claim', (req, res) => {
  res.send(billingPage({
    title: 'Claim your purchase — AdStore Command',
    heading: 'Claim your purchase',
    sub: 'Paid but never created your account? Enter the email you paid with and we\u2019ll find your purchase.',
    body: `<form method="POST" action="/billing/claim">
      <label>Email you paid with<input type="email" name="email" required autocomplete="email"></label>
      <button type="submit" class="btn btn-primary">Find my purchase</button>
    </form>`,
  }));
});

billingRouter.post('/claim', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const rows = email
    ? getDb().prepare(`
        SELECT pp.session_id AS sessionId, pp.paid_at AS paidAt
        FROM pending_purchases pp
        LEFT JOIN users u ON u.stripe_session_id = pp.session_id
        WHERE LOWER(pp.email) = LOWER(?) AND u.id IS NULL
        ORDER BY pp.paid_at DESC
      `).all(email)
    : [];
  if (!rows.length) {
    return res.status(404).send(billingPage({
      title: 'Claim your purchase — AdStore Command',
      heading: 'No unclaimed purchase found',
      sub: `We couldn\u2019t find a completed payment for ${esc(email || 'that address')} that hasn\u2019t been claimed yet. Double-check the email you paid with — or buy below.`,
      body: `<form method="POST" action="/billing/claim">
        <label>Email you paid with<input type="email" name="email" required autocomplete="email" value="${esc(email)}"></label>
        <button type="submit" class="btn btn-primary">Find my purchase</button>
      </form>
      <p><a class="muted small" href="/#pricing">Get AdStore Command — $79 one-time</a></p>`,
    }));
  }
  const buttons = rows.map((r) => `<p><a class="btn btn-primary" href="/billing/success?session_id=${esc(r.sessionId)}">Create my account (paid ${esc(r.paidAt)})</a></p>`).join('');
  res.send(billingPage({
    title: 'Claim your purchase — AdStore Command',
    heading: 'Found your purchase',
    sub: 'Click below to finish creating your account and open your dashboard.',
    body: buttons,
  }));
});

// ================= routes/landing.js =================
// Public sales site: GET / -> the AdStore Command landing page.

const landingRouter = express.Router();

landingRouter.get('/', (req, res) => {
  res.send(landingPage());
});

// ================= routes/app.js =================
// AdStore Command dashboard router, mounted at /app in src/server.js.
// Pages are server-rendered (see src/views/app.js); CRUD happens through
// the JSON API under /app/api/.
//
// SECURITY: every database query filters by user_id = req.user.id.
// Never trust a client-supplied user id.

const appRouter = express.Router();
appRouter.use(express.json());
appRouter.use(requireAuth);

const CAMPAIGN_STATUSES = ['active', 'paused', 'archived'];
const CLIENT_STATUSES = ['active', 'paused', 'archived'];
const INVOICE_STATUSES = ['draft', 'sent', 'paid', 'overdue'];
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const today = () => new Date().toISOString().slice(0, 10);

// ---------- validation helpers ----------
const ok = (data) => ({ ok: true, data });
const fail = (error) => ({ ok: false, error });

// Finite number >= min (default 0). Form data arrives as strings; '' -> 0.
function num(v, opts = {}) {
  const { min = 0, integer = false } = opts;
  const n = Number(v);
  if (!Number.isFinite(n) || n < min) return null;
  if (integer && !Number.isInteger(n)) return null;
  return n;
}

function numDef(v, def = 0, opts = {}) {
  if (v === undefined || v === null || v === '') return def;
  return num(v, opts);
}

function str(v, opts = {}) {
  const { required = false, max = 500 } = opts;
  const s = String(v ?? '').trim();
  if (required && !s) return null;
  return s.slice(0, max);
}

// Optional date: '' / missing -> fallback; otherwise must be YYYY-MM-DD.
function dateOpt(v, fallback = null) {
  if (v === undefined || v === null || String(v).trim() === '') return fallback;
  const s = String(v).trim();
  return DATE_RE.test(s) ? s : 'INVALID';
}

function enumVal(v, allow, fallback) {
  const s = String(v ?? fallback);
  return allow.includes(s) ? s : 'INVALID';
}

// Optional FK id: '' / missing -> null; otherwise must reference a row
// owned by this user.
function refOpt(v, table, userId) {
  if (v === undefined || v === null || String(v).trim() === '') return null;
  const id = Number(v);
  if (!Number.isInteger(id) || id <= 0) return 'INVALID';
  const row = getDb().prepare(`SELECT id FROM ${table} WHERE id = ? AND user_id = ?`).get(id, userId);
  return row ? id : 'INVALID';
}

function owned(table, id, userId) {
  const n = Number(id);
  if (!Number.isInteger(n) || n <= 0) return null;
  return getDb().prepare(`SELECT * FROM ${table} WHERE id = ? AND user_id = ?`).get(n, userId) || null;
}

// ---------- body parsers (per entity) ----------
function parseCampaign(b) {
  const name = str(b.name, { required: true });
  if (name === null) return fail('Campaign name is required.');
  const budget = numDef(b.budget);
  if (budget === null) return fail('Budget must be a number ≥ 0.');
  const spend = numDef(b.spend);
  if (spend === null) return fail('Spend must be a number ≥ 0.');
  const revenue = numDef(b.revenue);
  if (revenue === null) return fail('Revenue must be a number ≥ 0.');
  const conversions = numDef(b.conversions, 0, { integer: true });
  if (conversions === null) return fail('Conversions must be a whole number ≥ 0.');
  const status = enumVal(b.status, CAMPAIGN_STATUSES, 'active');
  if (status === 'INVALID') return fail('Invalid campaign status.');
  return ok({
    name,
    platform: str(b.platform) || 'Other',
    status, budget, spend, revenue, conversions,
  });
}

function parseClient(b) {
  const name = str(b.name, { required: true });
  if (name === null) return fail('Client name is required.');
  const status = enumVal(b.status, CLIENT_STATUSES, 'active');
  if (status === 'INVALID') return fail('Invalid client status.');
  return ok({
    name,
    company: str(b.company),
    email: str(b.email),
    status,
  });
}

function parseInvoice(b, userId) {
  const number = str(b.number, { required: true, max: 100 });
  if (number === null) return fail('Invoice number is required.');
  const amount = num(b.amount);
  if (amount === null) return fail('Amount must be a number ≥ 0.');
  const status = enumVal(b.status, INVOICE_STATUSES, 'sent');
  if (status === 'INVALID') return fail('Invalid invoice status.');
  const client_id = refOpt(b.client_id, 'clients', userId);
  if (client_id === 'INVALID') return fail('Selected client does not exist.');
  const due_date = dateOpt(b.due_date);
  if (due_date === 'INVALID') return fail('Due date must be YYYY-MM-DD.');
  return ok({
    number, amount, status, client_id,
    due_date,
    notes: str(b.notes, { max: 2000 }),
  });
}

function parsePayment(b, userId) {
  const amount = num(b.amount);
  if (amount === null) return fail('Amount must be a number ≥ 0.');
  const invoice_id = refOpt(b.invoice_id, 'invoices', userId);
  if (invoice_id === 'INVALID') return fail('Selected invoice does not exist.');
  const received_at = dateOpt(b.received_at, today());
  if (received_at === 'INVALID') return fail('Date must be YYYY-MM-DD.');
  return ok({
    amount, invoice_id,
    method: str(b.method) || 'Other',
    note: str(b.note, { max: 1000 }),
    received_at,
  });
}

function parseExpense(b) {
  const description = str(b.description, { required: true });
  if (description === null) return fail('Description is required.');
  const amount = num(b.amount);
  if (amount === null) return fail('Amount must be a number ≥ 0.');
  const spent_at = dateOpt(b.spent_at, today());
  if (spent_at === 'INVALID') return fail('Date must be YYYY-MM-DD.');
  return ok({
    description,
    category: str(b.category) || 'Other',
    amount, spent_at,
  });
}

// ---------- generic CRUD wiring ----------
// table: DB table name (internal constant only, never from the client).
// parse: (body, userId) => { ok, data } | { ok: false, error }.
function crud(path, table, parse) {
  appRouter.get(`/api/${path}`, (req, res) => {
    const rows = getDb()
      .prepare(`SELECT * FROM ${table} WHERE user_id = ? ORDER BY id DESC`)
      .all(req.user.id);
    res.json(rows);
  });

  appRouter.post(`/api/${path}`, (req, res) => {
    const p = parse(req.body || {}, req.user.id);
    if (!p.ok) return res.status(400).json({ error: p.error });
    const cols = Object.keys(p.data);
    const info = getDb().prepare(
      `INSERT INTO ${table} (user_id, ${cols.join(', ')}) VALUES (?, ${cols.map(() => '?').join(', ')})`
    ).run(req.user.id, ...cols.map((c) => p.data[c]));
    const row = getDb()
      .prepare(`SELECT * FROM ${table} WHERE id = ? AND user_id = ?`)
      .get(info.lastInsertRowid, req.user.id);
    res.status(201).json(row);
  });

  appRouter.put(`/api/${path}/:id`, (req, res) => {
    if (!owned(table, req.params.id, req.user.id)) {
      return res.status(404).json({ error: 'Not found.' });
    }
    const p = parse(req.body || {}, req.user.id);
    if (!p.ok) return res.status(400).json({ error: p.error });
    const cols = Object.keys(p.data);
    getDb().prepare(
      `UPDATE ${table} SET ${cols.map((c) => `${c} = ?`).join(', ')} WHERE id = ? AND user_id = ?`
    ).run(...cols.map((c) => p.data[c]), req.params.id, req.user.id);
    const row = getDb()
      .prepare(`SELECT * FROM ${table} WHERE id = ? AND user_id = ?`)
      .get(req.params.id, req.user.id);
    res.json(row);
  });

  appRouter.delete(`/api/${path}/:id`, (req, res) => {
    if (!owned(table, req.params.id, req.user.id)) {
      return res.status(404).json({ error: 'Not found.' });
    }
    // Invoices keep client_id -> NULL when their client is deleted
    // (schema also declares ON DELETE SET NULL; do it explicitly so it
    // holds even if foreign keys are not enforced).
    if (table === 'clients') {
      getDb().prepare('UPDATE invoices SET client_id = NULL WHERE client_id = ? AND user_id = ?')
        .run(req.params.id, req.user.id);
    }
    getDb().prepare(`DELETE FROM ${table} WHERE id = ? AND user_id = ?`)
      .run(req.params.id, req.user.id);
    res.json({ deleted: true });
  });
}

crud('campaigns', 'campaigns', parseCampaign);
crud('clients', 'clients', parseClient);
crud('invoices', 'invoices', parseInvoice);
crud('payments', 'payments', parsePayment);
crud('expenses', 'expenses', parseExpense);

// ---------- pages ----------
appRouter.get('/', (req, res) => res.redirect('/app/overview'));

appRouter.get('/overview', (req, res) => {
  res.send(overviewPage(req.user, getOverview(req.user.id)));
});

appRouter.get('/campaigns', (req, res) => {
  const rows = getDb()
    .prepare('SELECT * FROM campaigns WHERE user_id = ? ORDER BY id DESC')
    .all(req.user.id);
  res.send(campaignsPage(req.user, rows));
});

appRouter.get('/clients', (req, res) => {
  const rows = getDb()
    .prepare('SELECT * FROM clients WHERE user_id = ? ORDER BY id DESC')
    .all(req.user.id);
  res.send(clientsPage(req.user, rows));
});

appRouter.get('/finance', (req, res) => {
  const db = getDb();
  const invoices = db.prepare(`
    SELECT i.*, c.name AS client_name
    FROM invoices i LEFT JOIN clients c ON c.id = i.client_id
    WHERE i.user_id = ? ORDER BY i.id DESC`).all(req.user.id);
  const payments = db.prepare(`
    SELECT p.*, i.number AS invoice_number
    FROM payments p LEFT JOIN invoices i ON i.id = p.invoice_id
    WHERE p.user_id = ? ORDER BY p.received_at DESC, p.id DESC`).all(req.user.id);
  const expenses = db.prepare(
    'SELECT * FROM expenses WHERE user_id = ? ORDER BY spent_at DESC, id DESC'
  ).all(req.user.id);
  const clients = db.prepare(
    'SELECT id, name, company FROM clients WHERE user_id = ? ORDER BY name'
  ).all(req.user.id);
  res.send(financePage(req.user, { invoices, payments, expenses, clients, today: today() }));
});

// ---------- JSON: overview ----------
appRouter.get('/api/overview', (req, res) => {
  res.json(getOverview(req.user.id));
});

// ================= server.js =================
// AdStore Command — standalone server (NOT Base44).
// Routers are owned by feature:
//   src/routes/landing.js  -> public sales site (GET /)
//   src/routes/billing.js  -> Stripe $79 one-time checkout + webhook
//   src/routes/app.js      -> logged-in dashboard (/app/*)
// Auth pages (/login, /logout) live here since they are shared.
require('dotenv').config();


const app = express();
const PORT = process.env.PORT || 3000;

getDb(); // create schema on boot
app.use(sessionMiddleware);
// static CSS inlined above; no public/ dir needed

// Billing FIRST: its webhook route uses express.raw() and must see the
// raw body before any JSON parser touches it.
app.use('/billing', billingRouter);
app.use('/', landingRouter);
app.use('/app', appRouter);

// ---- shared auth pages ----
const escServer = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

function loginPage(error) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — AdStore Command</title>
<style>/* style.css (inlined for single-file deploy) */
/* Shared base styles. Feature CSS lives in public/app.css (dashboard)
   and public/landing.css (sales site) — do not put feature styles here. */
:root {
  --bg: #0f1420;
  --bg-soft: #161d2e;
  --card: #1b2338;
  --border: #2a3450;
  --text: #eef2ff;
  --muted: #9aa6c4;
  --accent: #4f7cff;
  --accent-hover: #3d68f0;
  --green: #34d399;
  --red: #f87171;
  --radius: 12px;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
}
a { color: var(--accent); }
.muted { color: var(--muted); }
.small { font-size: 0.85rem; }
.error {
  background: rgba(248,113,113,.12); border: 1px solid var(--red);
  color: var(--red); padding: 0.6rem 0.9rem; border-radius: 8px;
}
.btn {
  display: inline-block; border: 0; cursor: pointer; border-radius: 8px;
  padding: 0.7rem 1.4rem; font-size: 1rem; font-weight: 600; text-decoration: none;
}
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: var(--accent-hover); }
.btn-ghost { background: transparent; color: var(--text); border: 1px solid var(--border); }
input, select, textarea {
  width: 100%; padding: 0.65rem 0.8rem; margin: 0.25rem 0 0.9rem;
  background: var(--bg-soft); border: 1px solid var(--border); color: var(--text);
  border-radius: 8px; font-size: 1rem;
}
label { display: block; font-size: 0.9rem; color: var(--muted); }
.auth-body { display: flex; min-height: 100vh; align-items: center; justify-content: center; padding: 1rem; }
.auth-card {
  background: var(--card); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 2rem; width: 100%; max-width: 400px;
}
.auth-card h1 { margin: 0 0 0.25rem; font-size: 1.4rem; }
.card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1.25rem;
}
table { width: 100%; border-collapse: collapse; font-size: 0.95rem; }
th, td { text-align: left; padding: 0.6rem 0.5rem; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
.empty { text-align: center; color: var(--muted); padding: 2.5rem 1rem; }
.empty p { margin: 0.4rem 0 1rem; }
</style></head>
<body class="auth-body"><main class="auth-card">
<h1>AdStore Command</h1><p class="muted">Sign in to your dashboard</p>
${error ? `<p class="error">${esc(error)}</p>` : ''}
<form method="POST" action="/login">
<label>Email<input type="email" name="email" required autocomplete="email"></label>
<label>Password<input type="password" name="password" required autocomplete="current-password"></label>
<button type="submit" class="btn btn-primary">Sign in</button>
</form>
<p class="muted small">Don't have access yet? <a href="/#pricing">Get AdStore Command — $79 one-time</a></p>
</main></body></html>`;
}

app.get('/login', (req, res) => {
  if (req.user) return res.redirect('/app');
  res.send(loginPage(null));
});

app.post('/login', express.urlencoded({ extended: false }), async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = getDb().prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return res.status(401).send(loginPage('Wrong email or password.'));
  }
  const { token, expires } = createSession(user.id);
  setSessionCookie(req, res, token, expires);
  res.redirect('/app');
});

app.post('/logout', requireAuth, (req, res) => {
  destroySession(getCookieToken(req));
  clearSessionCookie(res);
  res.redirect('/');
});

app.use((req, res) => res.status(404).send('Not found'));

app.listen(PORT, () => console.log(`AdStore Command listening on port ${PORT}`));
