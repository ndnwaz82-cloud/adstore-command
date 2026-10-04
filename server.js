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


// ================= src/pwa.js =================
// PWA assets for AdStore Command — GENERATED by gen-pwa-source.py. Do not hand-edit;
// re-run the generator after changing pwa/ assets.
// No require()/module.exports here: the single-file bundler concatenates this
// into the shared top-level scope, so registerPwaRoutes is visible to server.js.
const PWA_MANIFEST_JSON = `{
  "name": "AdStore Command",
  "short_name": "AdStore",
  "description": "AdStore Command \u2014 the one-time-fee command center for running your ad agency.",
  "id": "/",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "orientation": "portrait",
  "theme_color": "#1b2f6b",
  "background_color": "#0f1420",
  "icons": [
    {
      "src": "/icon-192.png",
      "sizes": "192x192",
      "type": "image/png",
      "purpose": "any"
    },
    {
      "src": "/icon-512.png",
      "sizes": "512x512",
      "type": "image/png",
      "purpose": "any"
    }
  ]
}`;
const PWA_SW = `const PWA_CACHE = 'pwa-v1';
self.addEventListener('install', (event) => {
  self.skipWaiting();
});
self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  event.respondWith(
    fetch(event.request).then((resp) => {
      const copy = resp.clone();
      caches.open(PWA_CACHE).then((cache) => cache.put(event.request, copy));
      return resp;
    }).catch(() => caches.match(event.request))
  );
});
`;
const PWA_ICON_192 = 'iVBORw0KGgoAAAANSUhEUgAAAMAAAADACAIAAADdvvtQAABUU0lEQVR4nO29e8ytzXUf9FvzPO97bt/5/F1iO7FTp60DxLk7zs1OHGO3hSRNRBQahSCTNqSKoqDmAiIkadNAwx9AhAJCBEqqSEitkKAltLQSlSpakBA0KoQmpRIqTkyudmL7u53z3vZ+5scfa62ZNfNc9t7vOZ/tRIxfn2/vZ88zs2bNmnWbNWsEJxQBqJ/G4d54/tx4/tx4/oZhfJDSeUqjiBDIoGQCgAgFABJEQisEMwkCICDarojA/4U2wq530p90lfU3+9kfUpAIEamv+csKEoFs/WcQEvrQ5gkIBiKLwhrakWZA9p2GHgIQiH4iFQfIYcACkdKECEgIMkEKhAXJUqACIEhoxwvmFkFJJGnz+pKAJFghL3gjkKcd8820e7zbv7q7fml384k8XZdq9IEcLHK4ilVTzI537r357v23jufPy3BHICKgTTYBUPw/oGJxDkXBSwbovw/HQgLtSVHdvZPFYE0QgmUqkv2gUAoR1oJAfI5LI+ko1FVIFovSQkFAIrJAaJRdoE2AQLJNtg8gvKjv1voBtly7VrxDxBaez8BGEYhQyTjnPF3vrj9+fflb15cfJSercAQNHTttScZ7Dz7n7jN/cDx/CAg5CVhYSFcW54B1EpvHE5ggUhfbIkg+2/UD1j9XGLIgkW0drI86G4Pouytl4UXCFlAk6NyyKJkN3NiUzbpQoMyi1DcIDhBBmYJ5rTVM1pKlAALBABlA7nevXj768OXjX2PetbAsl+0+7OV7D952/9nPPTt7A7knJ5F0POWtlzL4Al/yJ9m/wn9dG4OE+qWR2MXauxHpnMGwgbLSfl6vg5VJLS+mjoDWWunlb4Ofje4Y1kDXuP6UoGus0S44gZAhYZhuXn306v999fjXvZFVhGzQgQAcxnsPn/uiu/ffSk4O95OTTilxxUt4qKVMVWR1a3gp76aVJxHpc3RjvcFS0tKvi4yT88q5lbmu/a3TTqnZ01Dz42Jf4ddSVvpJQlJEEpFdUQOZMEDS9eVvvfaJX56miw0aWoNfAN6596Y3vPDONN7L005kY0ktvXxk1U9q2WD4x5fbDy4qMQSQjHpmYr3qVeUn1+5FdefjtbTaZvhc6VgauW76q9D0wnSep8vXPv6LV5cfmakBfVPdQ95/8LaHL3yJM8zTMF6Nq1ui+rD8PqVa80pjqt2mwaaOchBnElFwdMXVDf+WDnVkBlnAYdGRiopJrBkqC60VyJKZZ81g5taAAARFhoT06sf/z4tHv7oo38elofLBwz/08PkvyZxkmXrooK/CWvkzyRZ3h6wDHKHtYmm2uq8dZo39zBf3rMGOS3UKdfmaQ7W5pjIvtevGIF+yLfShYVLAaohbhVyw39vybb1aWQAISQHBLJJsKVW2g2AFCs3qJqcJ+eGL74Ski9c+1BoZs56M9zzzOc+++GWZezbmQ0WuOyw6704duTaboDQclhCkNSvspRkhUBrDpXI08bdokHR0vEhSDdOgz/iMNulKrTaeIHNflGuwBYcBB6Kel67R8CYBIonCHOBunS7mhCJmHqz5OLjuQ+hgkPZl7aGfflEqL+6H2HqSs9c+8YsXrykfyvGd+Jl37n7Gc29+98Tc/RCZgk0daCTEQsPbnEWXEzqysC+yoArMW6gLjz1SFofU9bTdg4S55Ip6uy0whA3S1yuLokJEcmXQdZ1gRojtOBp4JTyuhH1osEqdiaistA5ZGPhlaTKJvPw7f//68qOx+aLAC8BhuPeGN77Lp6YCSgjVV+E/UFAZkGjfB7WHVg9o6x9BPVaLvqT6Jrxw9ofwYaNYsyIbxtGBWWlf26icRFnNEnSriOx+cDTMWPpBOL09YVJWrFRcRaUPJAKWyfzsi186DPciKTcW4MMXvkiGe+TUahLlb81c/D1QZGNeXv9+/c+gSMaICbR6AAjbfnj9AbNFIpREMXLW3ae8ol+SWca7D1/84ojL5PV49/5b7jx4S843LappWw71g71whAvDYVVwj63fzLWIJJFTXl9pVESbWrXAnnYRoEBe4E8KQ6sapahIAUeyj2NKcuxtgimQZBqcFLYW593hEWHe3bn3mffuv7UwIbXCmGR85rnP47JKH4dUWdsJ5FD3DYXY9oyVl0wJkdBraYdHNLHRdKShjZa6mrGsvSU9KXS/YpE4Ymu3G1cEtds6Lb/eCmfzVyRzuv/cP311+RFyD9vLA+4+8weG8+eYT3D53G4SjxAlLIbOU+QVcQXEv3lJgefJrL4E1tK92NVfgGEJZYvKWVrnGbOOpeztF9jKSGulteaaKkfiO49nz95/5m36VgIoMtx/+IfI3ZGq7EllEdFP0uAx6vDai/0TUlxKdoJSNl/ETIgfI2K7djaQnVcWZ1roZbWVqhGvN3irIhnTvYd/UGQEmADcvffm8exZ38R/onLQxU7yyMHkFRa3soxXtzaFSGpELs1YlMVyBN0cgmS1pgUGFflCQKM7Tp/a2Qtc/KJ0UyOlnmLhNJw/e+fuG6E60J0Hb31aiv98Ggu5HPRMzIsOPSpAp0NJDfjpLeDgvFuQ824OVZ9Ku/TnczJ/skaLLB680wezuPa21crXyaAjeOfBW64uf3tMw93x/LmMaVsEdiAuMmyrw+U6cySuNaj7w2H7cPmV+DYAckGBE1GXqAR2vgL2CqhwE3Zl3Uuo0oz4gMdoCYYZVo02gjlBdwSf4FLZMhRuqU4I83R+94VxuDue33khDXdO5XLkgqt2IX70SHC68KvbjEpC7x1+jzcZTZXZXNNRB4vS73b+gQ10lY4i/MXtckLZmJdj+MIqeMOd8c5zaTx/zndZV+rBFsep83okMa01e4seffbRDueExVq8But2ENvPTyIiqqNl5v3mjPFFDe3kfo/DZI6uvkOFAjk7f34cz55ljxQsLTKDo+r2MyZ0CvuR24anKTUnfc11gipNRGyrr4VlUc85BGKzcNf0pbnmM2d4y8bA0tcip1xxrBjOs/o8fm20U9P15R8WDNCNIgCG8zeM6eyeaomx9bDL21OJiBQLiVyyK5cBbTsXhvMPRyKioLXTNLpetDW63iAr63WlU8lqmUKyMMHiGrajV+dzs/Z1rXT23wbYfddJ0nECtydNBNfjChiH+gbTcHdMw512tcZI5O1GN9xdBdYFFlUOlxwPa4SkUoqZaII+XBWz+VjjAT0MJGx3mhqNcjxL71qOysoa/W0vm6qeb79Y9K+l8A9d515T0gyYFETBiTNCDOPdUWSIUM4PBJG5xLMGw7ZhgIWddDrZ4vGiQEaltTlDjm/Np7lDVSrAd2QZAJASWrkRnkuWamsya/5KOb5lUzmT7fM4/CNFj8xI8CAq4k8L9dtSd0IXay62HcZGyDC2L2CJCWvrKrZqoLtImit6IiUCcVFyzakwx6ltO42DbH5bKozgsfH8dLJA5nTWlsKDyyhkjYt0ngtYFJja3vM+UhDcx5f5jMjabwGwtdYKy0muxZ4ouVp1amyFYkcQZbFWnmHRY1LItvfwziRr03ug4FIhz+pvaBW1n45JiKAwjxiq5JXLv51eHCvElmPjq7Ox5LlZbNzaEeFxs+Wvp2QTLNCzq+sSOXYUN25t0RYHhVfOS3TcLGOFNvpTQx39nMdVaJZWUOvv4uyntTi+puKJP22oh6e231drF8OpLSw12uyEb1DqsV3I5WNOHp9z7y7GcYO3bCBw3Y0/Z299hSBV5nVkXFAc9Je+nRhzsCoDFh2Mn94lrqq1Kr6jcqpf6kmIEaDI7ou/ivfvYWS6Ow7/6B/Lxz5+iIZelyIiCAdn7SEAyKgROrMfyvIE4AcoY6UFz35knl1bpc4BQBmZcD8Ibbucxbfh+NaSLL0zb6EBQyoTqpWycL4lHHFyTA9wzXp15ccXWg5FG2bGOFx85w/t3vFm3EN6E579vp84+/Xf5MNnNI4aAiHcwGHfznLryzAQRQ0JMx3e05P2dkBTkFgUMY7e07KeGNWbOlXHr8Pwujr/1o0GgcXMr2nJWkvKtPdvnwLMyhPBrc7srXV3OE/DEkh2VkBD0C8v+UqWRztOZ7yeVDDGA4qJCJrNrXh/PaDC8N9mIiIZpJabjEcq4Qdl04Ffk61HEWHeEMbbLjt4zGSn5t+29KvhKYuG29OiwNb5jeAyAcIhcUdJiX2zT0A6fSPbT5YBHUVSd/RvueLaPB0n55+SbvTJlv1PrZysDREiIHCV8RjIRAb2oNCPsR/XyOtcRFLxA92mM+LoGMZbRU79ni/VmyAzHXSzkECGDHhEvApMwA6yFxFSqDEDhZFLcqbeMPiZIqMnJZ/uLIjpQEdS9Pz938NM4ZNQnoTpqpuBj4iXiExekzdmz3frtqoEtE6XRcrrs4ZHSL41ETTsx09l8kSBPK9/ixbwBFrAYnenwrDcchDclQmJm2e+DdFanqaVUTO8PR7wmmB/hmvhTihgXmYjbkUtz6XS3FMZVFdGdy27X3mlXnRDsv/Jl0Srza+1tvi8e+UWJF1eqT7yQ/1ud1fQ3R1YPmiVIwwns+6QQe3MUkmkZIqsLQRPQJYsF1fptZs07fL1KJl5GOan4cVX8kKulnY4WMFM19pBGigjFVDe+Ae+PnZwm1JCIH6flicX1CpW6iKcneFaKKTsr/LZG3IaJGchcP2qJODO3TmbKYlg1pItvE5FRMaidpnS5YkgFab5ku0KAaG5KdVfiXYdNDRfstSwX61HjlzayjPX4FFvrVYLwEjgQPPGA5tAX7Uy5L7T+pzLaTWkYImZZ/f2b3oH0o7DJAlyJnj4dvn4y8Ov/waGwdqI43IYquJFYjaJxy+GgzXV/TO2A/EEMaqXmU90G/HGhqs3aZ45hfVDlS9KtXW0R42tdAH0vdR59OQ2/btHs5HO836A8Dop2A1fE9z4ZEv7vAPJf00yXe+ef/sr3/7TfBPwBuAh5Fngc3H/v/k793/kJ/H8s9jva6Ic/9BvU7eAHRzOXEOSpYdNBVEdKNRipgYjl0AFrm+RnqTVbx/glfBvrCwi0PDFoqEvQVNepxrA3A52O6LI05EHCvQywBuJtkSwuxo/+iu4EbxM3CXuTPLy2fBrv8lBwGazJSJNPBCzCalY6YTUnDzGxxYxdhAF8qbP/vp2D7m2Hoaz0M5atNGaz3ChvqjUmzGspmtU04LdSlvqxCwdlFQYtyk12/cCeKeWOafZ3uIwXYnISYQmTqmJqZgVulWa0HPOrcW+dvSiBicVlWI+F9scKMk8xV3tZhZSHp4UjtwEUwtOojadnlYHX6JmEcka+OdREkvKmMdZ17M5cSzH+/EkA5YFboV66BricbS1sHD8l6WpLZrQAGJIIHCzk8sriOSHD7YzRx9IXtHOWg3L8ZU5h/vgxucoSZBXDtcljSjKtgFVjuNq05IgbNzq6witVC8t65a8/JZIs0wLb3ZRJh0ZSatRofsVQtELDQ5oQhpSlwWSS6hqzzDaJgzNXE0Ov/Fk+cSWCIcEUm52+fIxReRtnz299yvTxdXwt//uLY6fGVpkLXPGeoMqaJdXrJWx9EHkakkZe/B2UrAcq50mOrGVZ6SqrPSnnMSWrc8Eq82zqDyTbR7TYtuIiXiLljtKSuV6nNiXQO/RaHitbQ+Wr8utGqNQ8PMTiUxvaRiYM3Y3eO1azs751s/cv/MLb9777v273zV91sPhPh58n4x/9W/KGx5imp3y2bRBXFqpunPcGZjSoC0OUd4MNJxiBLKrUZ2+7hZn0cuAuukh9LACO31cE8nKzNlurVLcWuvXsH/PlruzM2zsCwXqMzCBFFLuCcogGBZcGW2Qs4F8ZNZLhVYjZEsOuOWly57C4idjTZFDp2xcPAuT9TwkCJCJmx0fP5LxbPeWz9x/2Zfmr/va/Zd/0f7NDzGAV5CXrqbhfP+2t4w5Q9g0u9B7U1z6+8+L7y5jwRWyVO+j8YHbpzHqHEvSs0Y8K2OpMAUFS8KUrKK7NLI4ZRRAUiH5pRerv1Wzvi9pNSVuP+CL+j8HtFHctsvx8RizBpd5Y7IUHQkiMiRk4voa11f57Iyf87b9V3z57mvfvfv8z9u/+AwTcIP06l4SZRQMCZISFwOZD8Gmx/BuFRAhC2u5KY0SfVIH/dGVEyz6WemYavm6tFYida1bY4ks9AjoWQS7bOCWgLb2iK4mMtwDtPJO2SRS3c0ObMvNTb6+4tnZ9NbP3r/rXfv3fM3+iz5//+J9COQG8tpOEjkOGBIGVckgAhk2DqEfMYQmpP0pFJLjpuhchuB1KO167fStrfck8rTWSAwOBSFoeatvb9p3AOszceG9CGd06uv5imknV5eE7D7rrbsv/Yqbd79n98VfkF98Rgi5nvDytYyQYeAgSKnqsBrDQSw7sD+ZpUU4PCLxKLJ4HQN6VjyyJ7/YFKLKsuKsDT8/yXJkQhM0fghCTnJxgWk/vfDC9Tu/cvfV77v50i/Lb3qBAuxu8NKlJJEBPBNqvstKOwJSCGbkXMd1atlI0LEwuFbYdfpAV3nMJlbl1OX5evDDjprLsOOJxDVf5cxrBbPXSLTu6zUnWwytjxUWxtjI1g6nhR3WJnB+Z//5X3Hz7j9y/eVfvX/rAyZAL+MagbvnGEABBmAP2d+IpzJTf2BSJOhe7HI08OEyH/KT7y5ozRGI+8Qnw/c02FIhXLLafE3jHgpdyWilX4bDtRmQcrVZX785UipOoPAX00LdVeAX0ZaLwUBO+e1fuPvS92SR8X/9e+f7awp4lpAESZASUmJC2t3kd33xzds/R/YZgzYhASfaywSqr2Tb9Dlctt/qfl2vnMe4woJx+8ksEj6s5d7qVKQNGMtQE9b4B4w3lVfCopQIAEvlbWnZdS+hd1IkDf/X3x/+j/8JWT1XUo/VEdTA4psdh+H6Z3/mZhy4d2OfICWDKYsQSe8fkFNOxbzupcZEB4fG66bq1L7sGGtqqeGgnWnMx74lWTKWF8bQ6eJq0M9Y3QJdNjpr8CUterRZXLDeSfEcYDzD+R0UM77e8kGmETc7PHhw+e/+5NWXfZE82nNM5quiIAMDzD9LkJhKSoQm0cAcVZINmzqx65N63DUlK91xjL6cTwLpzMriFK1WFjdLgDYIslTwB8GX3B+kle6/lff0Je6GNUheQZS0v9m+j7Y+mWBlVLZEhqurKQ2X//ZPXH/Nu+SVHc8SKBkZ2W4tRlYnVsoZyFl8U++A5BIkobOx7ZpPNOvjE5m2ty+v9wnowIee7ETRqVFE/UPfci1bpM6CiDRgt0eSq7/wFy7f+1Xp5WucDSp0WVyy8GuZSBCSBjnWkmfZjLq1nrQ0HNXok205k6u78Sc1eyrvErl9COyR7+qyN1l5IvYOSIcTi5NOFKICGbDfk7j6c//O5dd+lbx0LefJL0ordZR2bNf6SRbck9NQeL14RAhg7Pn776+yJpu2y+vo8dIyEPtdBi5/7M9fft178NINz4as/h7AQ4zFNvwECapBq/53sjvnkBV5i82RsrH/BJygBeL/L0eXJNhPJC9/5McvPvBevHyFlCSDWSw7aM4CSqbeT4ksOZtOrmkbj+9Kt8Ce9gCqx0dWxcGn3GW+XRbU56dbJPw93YYF08TMi3/rJy7+2a/Dy1cYRot+1/uYMwiIZUf3y3WJTGEGlpKpPyFAtxqE2A0vdntVVz6NqUc0DElV0yc4S+R7mrPip7g8fi38nVaWZI0kTuQ+X/zrf/7ife/FyzdIIzVYiZRsF8wKU3Znobot1EDO7o4+1PPTmL4DorLmBB79DEtwBpygcxaNrzzQJVNDtY9ow1+OlcU9vBKey6zBLiHMgU5DIpPC2HtmJlXnjm5ExF4UsMAMFnqcPUkJ08QpX/7Qj1984H14+RrDANWNSU1NTOrl8tRsqkzIRIIIlXzcsXSAoEug8CHkL06WBJw0IWKVKjwGQUCMIslfWDppMi9lexmzkOEKh6xKmXLmZsHvFOqXyWPR8honYn2DmJ1hc7u5x6DYDlMcC5ZyEi3joIDhqTOqO4c2bWtFEqYJ03T1Q3/24o+8H69cYxwcAG2UdvwEts8miSCRJSezJyUjV5o+RBzsnLSLdby1gsNuM0L6qk30NKE5EtsXGq/FAiZClx1wbLuX5QGU9tnT9VJH3s4257YAs/7pCvqkIg7dSA/yy3gWazb8SsfduhLkCfv94x/8c5fvfz9evsY4mjZjpwAAGDPSeM6ckah+QAizuYHyqeLpYOWA5EK5UTEoElPK135NjsQkMvhvdPVCf13hECxdspcvUpZ45ApLqeui5FrgFm2/xupnDK9r00ab1/lBvMU+V0XnqJJ91LNfKmazH4Mvw0xKPRd/5scu3v9+Md7j60f/zRqPJ96JCJBByUksehHIEFOi18oSik4oLek3KgQ21M0R8ODcZiKlUkCdncA8HOZmAJAgBJcmppBRDaPRYR9Uh2cXkaOsD5csxQm3fEhl3uK6nF17A3IooDi1cCbkfd5Pl//an734wAfwyg1LikwRVXBACoRZkEjfKbUI5kyKkCApGcKlfebeP4kF1eKEAVpDVZgcaEpGsUi9CRBhas6n2Az5JFURqUanh8yhAC19oExh+AW8GuIf3j2gQ5RU8AWG0mCgZqFfc6GPciC75ZZtD9V8dfNOC6hOnau60aK2l8CJ+3zxnT92+f4P4JUrjGPFJ52GoEk9BRQh7LNAD7wAAFWNZs4t/j3uzEWBKj0riS50J7YbZp0sqZNuLZaO/Gvhsq1cKvmBAlcxKUaLSKktBj2DAfQWiX41QsRqCPq0VZLDZ2+nCEEbTKM+A+hVVyOj0qxPedXEtrXIcrahk4w6BwXmshZ9nppFskL3Krny7uLbfvzy694vj68gieEggFGjyjuL1hb4gRQPi7LM74CAGRl10QpJPUqUIgweO0SPdxh8rOUUTVrKpkKbQTp0VcFAOc3pBNDw2NEjGQBqXke/wKAOxYmjqL1V5AcpEMSfb49IS2Gorzj+XHdLlds11X0JlqltuGBotshsm5xab/n0BgAkwVK+wYpct4fr6HK7/jaoZ8dpf/EdP3b5Je+X3RXOB1CE2SfddfDKPmObRM60ULhccB4WVAImwTBbHlKluJR0tlIG2w+Qc2IKam5hwEZdNPdBu4DbTPXm+W5sXdoR/NBHo/OGLsGwWRNZog2q+axMVUqD9ZCrYAAz/C6OTsW2aqy9VhKXInCjbkT0FFRvJPJ2V28zaTWDMti1vU0a9exuLv+VH7/4ij8qr1xiHMv9LYXJgpSkaphSTEIiQJnMJYSUkUXjWCGCKTcHiCk9SM0obDYCNw4D7CHPS1J4bkgVrcNVBQgkHuuRHDHaYsUXcV05+0X81VeYRQorKjIowGfk5RG/TXcTAPgt0mJx5hRKXgRPpS2k2XNe5jpathVhEcFiO2URi7HKeujQQmlFBPu8v3n8wR+5evcfxSuXPJciVLTdlIVDEkeqmHtZs0oDfoKNqmIju1cQzBoTPRF74KgrtpdxsIIZF4hag9FfZ3xR/5FGuzgynCOoFScGXXekMfukjGd+0dMCJ9AIF/Z1jMHM4hXSelPHAL78E1y/iGOxGxRlBCfuby4++CNX7/kGeXTBcdSFrElzCIgkMjPnslGOpBA2ROtB0ExM2fSkSbJe0Xgs/k8tBOd06cG+lYn44KkrrdgFDvqWDRgZpn7Ix10iXCTLvOm88lVB0sji7ggE2zr+ZYEzR1A3AJuX5UEFymouaaMKXO5wc3P5nT96+d5vwKtXGAZL0ECAIbbRMg2oDAMyJYGWAwmqQaoSr6dPXFk0e342usIzTl4n4d/FqQmLvJGYUaan1FHP0X3bnVP+Ic/u/Fp8a97B/JUU/uZF2s+nYu2YIg7GWpmNQgTMuLm5+JM/cvG+b5BHVxgGSkISkWxKGIVZJOvGOoTANNFZpziVwDZRVT2Px301M9B8BzhvU88KN2U7HRtodEOvvlhmHGTeFmGtFd2wH5ZWQplWJjXKmo6Ku/opNL5WuqktvHCtzHlJt+w2VuFaCZVV+FxfXv2pH738wDfylWsZB8UzbYkOyBmgJNVlFA0i5ks0CweEfjaz0V3STKoCD2h2dDpQjyGFJywRP7kIh9GRm/3IQASoM0C61Y92YnKoqUjq7EOZNdsCKHYU5tSRHSpzXvKEbCzUVwXl6vLqT/3wxR/7JrxyLaO4IUsOw5AE034aBkhmph74gmtzAmDK0KuLk6tKynoshY46G5NM3RqJa3JLf1gJNz1m1BsVys2QNTtHmV12dFN9SwuMYa4VIbAZs4y8s2XdpeBifpHKZmniedaTJohrvq6FH1tW4oW6GiSuLi6/64cff/2/gFduZEwqhiRnDMOQ8OC//ZmrP/YvTm/8LNlnc98k936ZWi3iyaRhPhfxuDE13QSqhmdMU87ZtKFugB3c83V45MmCpQVckkYtSMTx0IJ38lnW/tdgkvJvGc62aYPODjlUOmwwrwk+emRMCPQ5oqRmVVdPScGjpASCV5dX3/XDF9/4LXjlGkOyi7cyOKRhGJ75uZ8c/8H/fPH1/5JG8/iyUt+Gqo8Kkoja7WKmtPZEETOn9UPWb9X1u1gWcUjBEL+uzNzKNLEm+Zn9mtr+VvxjwgMK9gohxQPpW69rjQ72vkcaGOqGY6MGpjUuHk/IABCo++6UUq2VuupTSgQuH1/+q//GxTd9C1+7xphsUwHEIMPd8f5/+e+Nf+/n84NnkDMIMmtCbXOyWPwh1bltoWQ6skyqzzA7yZOY1A2ux71uU4IA1IMeC1hYZVJUF9U8O0h0Y5e9pIX3D+3Kbo5JD/huArqYcmtRYrJS0jElQi7wlXSYgloClahnWBrUy0eX3/VDF9/0rXhtJ8MIeAbQJOnueP/n/v2z//Hn+cxzmKZ6kotZ9HiyPjEaEmY/wKUUphZtdmajdz3ljAymhJQknXzQLW5tAVUBm5eU3NsQNQRPUTGvP/Z6wYHQnLWyzBTt/LAgeKUrTOVFKRpAK82P6LEq5tK/3tYOw9TujhCXC2LRMsA+fnT13T/4+Fu/TV65wZDMhtL40/Pxwc/91Pnf+Wt89jnsrkUESYlAmOAULaBQ7BVASvYr7cC9dirRnG9lCNKQbC9+yZuwOnftLJPrOmOo1HxV+1Gcioo/d/RcllGuxtAkB7WPBHX81l85D6PMmS1FB1WsbnSX/VpCpHoNTWgEJb0FI2dvUGA7dmUDMSICTT4Ck2cFCyXEdgF95Uirg6I85vHjm+/+/os/8e14+ZppgBoaJAdJ52f3/9JPnf3tv4pnn0ee7M1JkMuuOwjz79iW9wQPpxTd+mSCBrhCk+Cqc3gCJiBnt/jZoRpGc4VlNkV89Ur783zdb6wrAcoZDCKrjjaGX8ubISmrxOdtY5x9qaGAK/qssw1liFErBQpOo32x2GsfCGZv+hmlDgWpVRoKgtuULvOOrCFjV05N+bVH13/6+y+//Tv4yjXGVKaSg6S7Zw9+9qfP/of/Wp59HvsQFUlBhm11Vcr1jXI/PetBiU5nQjAajkQGc87M6kOqG5QV5kruXSnLeF6iT33D1um4WxKBCCljjewsGI43iNHfXmjMN9Vk6l9HDO1gpVoAoHGOyJAKDTIvkA2X8BJAUmsYmbkX02YEq26aaoiJv1jibdpXaG5WXdUU6K44eHFx8z0/cPHt38FXriQlQpAhmUyS7o0Pfvanz//Wf8Vnn+M0Gd9T0AlompayGn2N0VQnahZQFwv+r2tsyjvYTlMSvb05LNdO0/HKzX52W6Tgrwy3BpTOKtbbq2w9iWBsZ9c/H9SC6vwtcMFSYR4ARi7ovweOT/Z9zcATnwhdP+FXxZ3U5VloUVwx7Eg2ACyudksCkF99df+9P3j5we/gJ3YYBvMWghxE7o0P/uJ/dP43/gqefQ7T3rQ9PWYBEapYEslg6sJ0TB8Jg7Ne7WFy30YuJAdTiKC7aivyAQiEtTGdlWx7yd+jJfA3k7W2mfr6lgI8N+XrkY1tPl9oPMejeH4aRwfvtCYOpa8818YtJkvtr9ce7b73+y8++C/zlRsMYsF9BBPS/fH+f/4fn/31v8xnn8M0tVAKLBbVdTHdMVWk1J2u4gEjBJJMGYIAk9dR06x6fRtF7gmKRNXp+LdgpNfelbGmvDTvAcf3Z9QqSx6ET1YJ7Mt4Tn0qQEq42UmeUGZNbHfTzu+CvLm5+Z7vv/jOD+aXr03RUiknSR6O9/+L//TOz/9lPvucas2lRMJFzqDiQEmVQNlQklBdIB5Ll02TtiayYILndo8hdbLwaY4CKVU6rDxRITl2+Z3XprkTVMdTA4tevXio4FNQdCgZItjvsLueXnwzHzyroiZJDBEnU5Lr6/03/PGL7/ogXtWdCtdgE2Xgg5/+D8/+u7+CF1+U/T6yQVcAkUGnHhSrz2sKsodJK0MRd3pPRrsu4UScZYoa1CtHDKUFoA6ZZkK6+ULvD8NRHo3VsnVbD4LQuTX/KArcp4oDLRVCEnbX+eHzl9/2vTdf8tW890AGwaBb38SZIFlSQgySH97FxT7dEQxCSBqTJEmSKXn6yrePv/CW9MprPBvtLqauq5yZCSbhVOLQQuB3pDrjQCiGuimsNOl/XHaOxZ/b2Sx6j99hI1WEu4pzbFkmoJAXWDIoR2c3ql5fNg/plCSzhzwxyz3hRzBmz4GKv3mzoYIg73Hn/uMf+A+uv+AduCCQMQADoX6/lDBmJGIgksj1jqOHKiRlpkQSSrr47m/hF77jwZ/+AV5dUs+6lyKAsouyEVZ15yhKTFOvp9zMKjIkWovZTUOC8FvEQltCv/BlCZlKMlkagq3CtIPmEPIrYlPa8orTko0cKCqXs6Bu9QBZ7ImOrbh3WOS4l1O3dopJpT5dSu0rAjBvtlZISS4vrt/7zdfveId84kLy3uBiNvWZWXcSoE8cRaJcCXAXkaTfvrl+9z+z+5ZvlEeP5xtyQrPkdIcLWfO2OD1lR1MGbC/Hx6PUVv8KWnMJj5jj0HLBlCXkmNEesivMQSns/45CvupvNrNtTLQKRoNDjYzNVhmgn7vRy4EtZcaVtH21naQSmdAOfQUbZmHwpm3qyZ1iwRvTI1Pavf0LsCOGM3qyWPprLRtJSnspgwN1M73SyiC84u5LvngY0gLnD1EQYsTguEisP1uwuh9OrwZW4edZt10jcAW9xZde9zicfyVHgrDhPaWUSNvjl3HHb3orzJha70/pS5y/Mp6FRR9aLgMmFgTQUXDHiaWfj1mCpGA+haUJv06KkkREcGbuXudZUo4A0RimUMisEcvO/02fzWTSQWXheL6Y602IQUSShuea15JGDyIiTJXFN1NMXyhl9BRkcO16PthOSWmgR53/EqskH/wtLsoprxyMB1oukQLyLCdMueKvzjoXXjyyGC2XtdJybCw1KIFiInZ829P/CMskByKDY3tqzvLr6oqyT8ZIsrmn1eueZhE6dZh+Zs1dS37vlO68TmJ0paOSeOaueowayg4dqTpS2I+96vxGd1AcIMdk4EyFe20oT2tFiXWQPC5Q7IllTr9PdPXTrFQ77gkWSmytj47r4gTgbM2UD5+HZA5GDYEXmmAx/QIG4cLyIDCZkCzuMBFLGQ3xWyLFNyuqtm6rh8iS6Ts1qZxk6FfpEooKQW5rTrcoAjAvXbpbVjxmrOX3VWGR1cbaxdwufjoChbsKBJgIQS5evmQqsExbSVcIzevja1aZRvB1gyCyB42KaJiHxAMKAiTaMUt1j8sB3bTYLlgQeadKgMVSRdj8t7nc+X1YzMNSvqhq7bxHsjvu9COQKeKp3cp2+QDJ5B7MSEsRcQCYs1rgQjInf5tqrbhfRixuVQ8HQw88l0A01YoGTPXRgcG1yqLMze+nV47aC7Ot96ff+6ewhNGU1WJKhiCTqdxT4QkONJiHHniaCCTnLquqqEc9iSrhIqIKFETdzaxsRifZWA5VBYtbiepScI/2yaVYo0+RjERkPCaH+e8/QSYANDmkRZESg9GQbXiqAjSJDJpsWTxBIT0qLENTOGfzYK8iKSi+HmJE0AMjyColpRAx7AkzJQlIzRV92/vCTK162vPIpasOYiey9JPMas400OWf6iuutj4JUysdzRtZw1NYzYVv0E01Vf2y3jcudtBYUx/EIx869UlET/qRQbKwWFD1FvBiN2vyu6T1Cu3ATHSEkEHVIVxPamMY9Fx0XhnjUfgsx939lW6yuhncbpmj2xJN6/ZSF51VFb+mZqymB5kWf+oaJ489qbQMOJt407VeYmngzDlrpISGA2ZXPOykjYAZTKJGVspORnYaR980BrbHtMtTnsTTZ8BM8kROyFmmECGvDMjNuH5Jar/w4NzC+aVsZcD9dAsa19H4jL1yCZN9gNZGyz0H2qja/bRYs2zOBbCOavzUsg1npOOFmur0y1Px7WrESTXgkY3r6Eyr7Eh2FYExiazeHUHGfu/b3bFTPUqg7RGVNM3BQ7BkEIncSmoEU1SZmTC50SgHMbnM+BdRtzGPh4tgvPU1nAdafnq0siAzj+t9BQbxX+iOQWo6S1F7KIOSXOek5dVILmWUCKai+WrQO4sjume6gGTa9paa1cyAUN08xXnsRzE0x1GrJ3vNDFGCPYyHKJU2ai+z8BMKX/+IxCcvFsNFzNLRbWNno1BSGoYzbdbayJmpJKx1RUT5UNKdLAH0bHIxnYicMWHjpJadU1ZLvvAb8fOpFhirvQhU93IvjjfhAnM94n1jpIcq3BqHVj7tCUjctF5Q645fQO3rBCApaS6Hokf7oT7PTei+YNqZKDWf1LM7+NG8DGQkLB/0hL5TDDsP+lf1hqls5hEwx7QxoKiu2X+y11k2HG5V+ATUYyj9FBDQonqEmZLuTxH2HUoiEZw4eDafJZM5T43WCCaLCCOozuiJLPlWACBTPAPL5B6aDEzIu5xzFstVFw2IYOtZ0LOYuiVlK0NrF/vUT8J34NtuvAnCo8b8ZFc1Hlk+BQS0QT1ohl2tdEpQcutziWR0krcz5zztdyAkJya1lbOmuLE8DXpoRWN0RISZtINdAqgyYhUm5IlU8x9VedfIDRKSKXq4m34kQ9wcg5GOKt3O5TzLgiHBh3fKkikwtNh+AoElip7ag/5nfGIh+JRLGHBcm72964XlP+b9Z3x3c2DuU9bky+LbW6bOitOQ+oQHkawaMJV6pNxqMUEoQ0oBkyqnLORET/cEWKqVVZ5U1UdPAtXjSB48ZXXXErfNyxwDciQB0aHvH2ojLX98inemxn+x9KFUXgJY2tdlsE1Ne6HwFm3KTpmjOPudfGg2VkLOvo0p8S2AsAQFPi8Ec5JEZIjYXrsZ2Mmj3HVHTKh3GQjcMZ1RrOs6QmegIpKB7Gnt4FuoyB48Zkwu286XeLBqGWvhVdQEmGt2ZU8WwU+IoC/GFuaUVN6pJO5TqLu8hKg5aichBRiZo29wDYIDJ/9QOUeEtTTYDVsKn47VLAEDBCnh6gJ5wnjuaoLqF9mPQ/u+FD2yxY1uiGCfZb/nMw+QUrjiT+AsnfDwN1qAoc6c6ruSSFU4RFTtYXKZojRt+ZBFAGrWlexU1QWcEkBCJibCeUzAct3NLdSlUUYWCSoekQ53JJYJbQji8KGpIMfqi4u5pBxTHoTsy0zEL70P0oB62YqHNDQlSs+ZRlfgiOu7e2WD4vwUXcckTcsUXD7ef+47b77mj+c3voVJMECGxARIRgLUeBkhCXrdGZJwyBwkDSJjkstH4//yv539tb8pux3PzjQJQwCSdiV7SiB8112JKgOCnGAiDLrwzAcobiWZNwgsjCGrutPuh9mWKciELJb3uU59d2q3CCvvEXG7PnnodHamXNb8UfpHtzew/lZHCnVE7QYI7Fi1WDzQYnOrWwIbIN4uvrGWlHDx6PrrvvXig/9mPhsAYACS/zsCIyzD/wCcA4P/6fMzr/PN77n/z7//3p/5UTy+wDjUVGBxFK4DqfYjpDn3REWKmDgT1D+AmghAeRWIDE7gxDZKu8GLZBqlZimEaB8s9ZkY6lhZAFDdjHYMm3Uz9dYnuZ7wcHD3um6m3qZFyyjxdK1EEdxcT5/1hy/+xA/mCbi+wJAwQE9gM4kMWT8gQUZyp1SVZBAMGaPIKBjAAXg1X/5z75Tv+ZN3fvKn5IXn5xFfmcx6eYAdVlCN2HP5FENL9R5x8MScQxZKLXbcgVxzJBIgbSOMSrVSklz5fwH3JZagVALBq2k+1AxyAJ+UCJ5umee/jX/xOQDFgwZXEmr6Hnire7g1corg5nL3eV+Z79/F7gaDyScmMQdMShBBEpFEGSADUkJKTCIpISWIHlNKSc7wsbx7//vw4gvY7xfjUUzRaQ7WZLWqXCqVkFaNaU/IwB7Qa3Ldv6zhqis8HIAkvUpGoxxp9ARCsghFskgeJCfJCVNCFkyERo+otM2Owuz2xG0LuZ3GgutTuVa55olejqfrel+CaZotvoMgdkXij9O9N+gGlKmMpG5I0gclGRxc/3WGYfFfYmY4BdgNcv+BPHyA3/040lkn2UWTGtNtUr0tzSSYXgEn5ikWN4LM6CunHxRt2YgPtFu7ay+DCGhbGXWP1P5L05DhCqvvxWqzDqVpsqy9GKYsKjqgcSNTtkNkPqqgxVfUL5R6ktVf1//STBOmLjuHKUoqi9sgjQ2wytb3RvCG2dpLvmZnY+ZJs4MytNkSP7rkSqN4HTBZbiMKONnWN+zivwkC7oncWfIBYWWqxH+16QRMpnnWZlNTcvXvlRFkWZ04bVKpnlJPhGUgZSDbzrqLNJgJCsBPWJuTgqbX5yKKI0eXY0in1J9t9a5XXZl0lz/W3ti9UIP4TxG088obr7c/1ethALWCq96v6AwciICIpckV5GT1lXomRbpSVgLAqcx2GXPAn4kwM7gsmt2IWZAm0H0/SldGoMH9YEcOVTup6aNKBzCXYELxGykJZl/KBSKplJTNUWA8S/R8Z2a7DV/WVPFT3F6tPl2XLcsZxQoLDPa2pbKiQIhW8pqrouxeGiDmGcwiTGQ2urETpknVWL1hVOgJFUU4QU/dSZJy+gt70LLA932LMHhWXImGB5iy+pBR2IKlorJQEfO/ZPMDraKN8CSsydo3nsYahmQA6QfAZsGuf4KITFAPplQrDIFisiwdazxYlraP+p8iyvy/TU27rYdkuDnlJCi6VW2Mu+max9KlTg3dfxKNbRUgugpFyAnG8bNpLaYYJPp2RsKOM5bA4tuwaEMmH3Q9kGd+TjjR+26EuRxBEY/JzeBeoVpNY64dSRbnUV5PYgCk/yTFDxyvt4JYQKPY0NqZqteMHl3mBvk81rQZxUo7UQc6gXpqZ0ucs5xLYl1PGyU7RgZtuth8SiyqppTFB5ciVF9y8p2m5BsRyUKaZeqGHbQ6lZBT2R8o+rIpJmapS3CD2w6VUP17OvElibOVZmr9HGyJh9fEgmV42kkRQE46rF4rXUQiib5n4gwLNuYjdKC1CON5tbUTFuLBbvOfRmc/p5VjBOcp0jA7V/cVR7gV7WE3qqVk3ST3/CYa1i7QKyOprmqliQTsynYYmqWvoiuDLn3sAqaqIBdpboozBZKTVpNiOomb8SVjWFQwjX4md+G4lWAOZpOZgW8FlajgzgSsb7qZSyn71nxxozQTv0YHq3px6XatwopaXDzRtylP252lWwFuuhAypYoH1axM6dHr1sFk57ZEwGHCJCKJWXlRxh7Yi66ONhJCLLOczo3d81mkVQhZkMKZUhWiyoQ8/S4pmMCcXAylcOmfU4d5orXPXIbk9rAN0OLN4tGbor2p89BPjgRyCcQayslTY+beKieLG5dd+TSJSEzOIapKRUQLQwA/LKNoFBVkmR7vAHE1RGyDIO+5J8u2Ogp7A8O1FYLsLQCmA8FDd2wGc/1clKHCpqYIN90ccZWTdVHY/JuwkkZp8oNBLv4tD7SuG0iSrIunKMsxtu4JChMkXgg9L8UEYUemWsanzkgWu9kumtCe/sXSFWh0DsChUFI2DYmkJDspofdZF1VaWYjKiL0qrj4RQMWCUEwo5HC5anEYWthGxaqqR8X+kqLCZ5j0Y6BBlM8Wc0KbKjPmC9GXDlx5L2ag62JUu0CyuT1dRzwSyeIz0ten7yJ7CvINd9aqukI/WHgr+6t/Md2CdMqLWdOdwJNp5TKXsJuwE9TUcIVWj21lURaSXBuVAMje/IDZTqEisDfJFOwhk/IjSjnBpxM0UZCY7AiO7an6TT8WeAKApgMRhYaCeWHOwqQnN1wZ83D6GnaoWMzeZpwtsVvACwtTEjKreRvhhXkUpkhU0tFfNnhPLKsdjYErnlRqcNaRPa21k5tzRRYkKhROCYm0ExGmdTAVvOn+t8Y11UOeArFcKgQn0bu3lkeoWgXNGW2+ILfsVG22sxOG5eIpR8g5T+zBKRpR5pvyTQnzNAqJ5JEzSj11K77jEEGzsYgz0PbdylbqqbPWUo+fpRW5Ne/Q17fCObZLVOK2ZOQ2AL0XIHmynGJkOIlY0CdN46OYcuq+3TLFtEmbUsqQ5qKMKl7VzFcpxqHwBlOtCqr9KUymJrfRatyTs8xejXUqLxteFEwNi9KNmnB7QMFlUfWSD9AEX3s2/uDEs50aFYCdPHpSLeoJCQiLdHMkW4RHpZpaUlxoRMllYQxG6LceeTiY6rMaiWyajhRnsUE0+XVK9r0avQJqyibJEI0GMp4mVaMs8kSc1U6uoUu26EQCe89tGEKCRDX6yQVHpp/BcBVGnQetguFeIakEWmievsPa43+7RPrg7MOTFpIj62UoT6+csr/iPrESEpMwWYp/phJq7uGsIhBKcg+cEQht97FouASYwmZqLyNsVWfQ0x3YD9FF6lTEwhEA4/5aSW3vqayYRTHkn52D+n9KCwgaSXCiwuiNJsikJaBPlzK+HhCd5FY3ywKoqsUEmahKqEYGqvZqc6lu2aI9uHVtbZUlPhJ75Szu426LJ0wRj44WV4XcGCvP7cJFKhDt4Cz3pQQGOuupFfi2KeNqd+TXlZSU5pxYaUY/AdtbllD3U1cIjOrc/VRDYoUC5ozJAgWNOemdNL4jSfq5l+SruVyG1XiT7YbJxbERQmV1Wf2EmtNF3BlOlyO6e+FBI84kTUsBQXIKV6KEIkVT9ZDWaqCZshV1lABmUSwrQVq6GT+7AgVq0TXsXXwy6CuJjBtOxk9+ERQ/EN1lR8lJAA4CWKJCU5YTAEJ8N7RKFo1LT7Lb7ImWrsC3tlXVLfOnzuPE2mqIpTfBI4TdgeLBi4uFRmo26waBlP+2c+1RWZ5jT8w+dG19lUSe+jnUaCKtlbknuqyJ5SfHba2vMPMCmasry+9OwN7Xq+1+S5M4R2ciu2qsHCg5gAlCcCAmBvnYQQDbopo8aKtahK6t+5YqXeNxTlT+D+SMnVmL1ZscutHdMwuTTXXbsexnOFVWPUhbr5ahaYlkRi5JiWP9YFpuHro4MCkdeiqoMI6/UI0cUx9KEmWAaQLBzqwQiHm29OqaOawR3KZ3xp0duPqiarQq0RkyAbbW1XnocYLlsKG49iSAxn6JEJaY3hjJXklByNRmZBIhMbHMqwEmDp/CTGNCoNlcVK3ZHcZGNNlkpTOKymPsfjn1V/Vqi426WY10tJcBqvvCw9YGSVI97hHVZUJnk9jwkcW1ZBpWgCSxELBjgij8V5eR1R4XG5Uin9k913Nvxq8l2x5gogcUN3CYUOioVwS+UEzFQFQ0JwtcN4yWGGfA4g8LAUHUnywQO9wm4nfYEhTseq0U3bdcbqjwdQ74bqhWSaE7hSHVCdYKJlRdKeoRKSzh8cMSDygafMfYXWeurTIQ9zL7Pv5hLbnkmw5mZtK17Fu2njHEAfKxERg1LU7PJEDx6xrLuIT1NRtWj5B6o6bNNo09F6JpRtYojta6Zh2k7lLBIpNNbzUXjVTEig3Yv2YNPBWACdjTdxyWinmiyx0U7YqLNpWJsPaz4TbbxstaJwiLw/yNqV5RYc0GNSjw4wZXRoRH+v14kG605EyAER5nLUoAQeC0M21sNtupDNfnFHhzexgXjUyFHncFmGUkRS+wFoxF4Xh5W1RXUVonJsgULjShbnu5cquO6Uwkt4aT58oQ0OxyYsjcR99eVyzZ19KZQ++0G0TZQjdK8iSveXOoEkiYsOx6UQZ17+oWCgo/R0sKRyL1WG26SgDpZJwAdsm3IdFgzo2PT9P8FuAYgkJU/4jwG1eBex7D6Fz46x63oX5j8YfSapAAJt1d8m0KwK4YsSgL0139HwoEKdA1/PyM6kDKpeYGi9bLhU1LWPW+V1UYqvkAnYhZN8VAi/Mqu7VtL8oxowRsqWEuuYSBvI5lJEEQHks6DZirss/SVWSIpoetZ0i8jOIOKoej/IfGb7WxsrtjPEmQsliwjekolJXoRs/6l6Rz6JUu2Dyzg1Qe3wOf2I7YikztXLTKjUjskUwH7/1uhJ3i4qT5D3OhOm0iLh13vviWnE4VfZlkC1ed7+xVjIpYZirEES3RR6SnYJt404tb1930yVKdOD4JQ1slOJtxUWdG0T5TXbgEIStHm2uzrvBUD4bUvY9Zen9233q9UE8axJIApOTuGFVeNECi8tT5IKVHlkSHslGh7PSSJdVyW7ebijt9Y3KfU5i8QLsx+CE6chQB5ASPWusLAaLJorxgmNym5PDvvM/uA5ZIikft5zuaKeIZ/1BVFIHEW5tdDC27eYTLYlLl4qzH5eImaRlGbadxp012VFR5p8kh5wG2w8rKGRqB4ko2IJygB4nhLAWqOWuIKv1Yj4S1Pr/xIt5mNeOvLMyS5WRFV1JJrtmM2hPTGMbpvDXKu1kxH4EkcJpFcS2qSlE8HSRcIujBDpBKc+l+LR+MgArdzKiHQOck6HHYjLDlifR8PG7X1PVbtH4fp7eg91tPqY6dhbvoN0e6tA0QvkqE6l1UZxJqFHqZvYqfRvaFlRCHzPYqlW52tGFhvUdOLJIsOrZrz5UJqZ9JGigi+iwUJAo1eLNz9rNMH+oAWxJVqq0KbIo0rI6dO0YE9Lw1jervDtAxfi//RuF80PUctapeIyxavn5oxxhdlHVuCUyQPcsWZmBaAMFUzcQqYAziXD4yT/W0TeMXA8AFbaWQCJ3TiFQ+Uco8rbZUxiTJWKUUu8W0LRUaUcvy/Zdqwc71oV7K0F7sYagscrb+a3DBrOh+dembvTvRDByhx73WSxGrIRaONgcOFKlno9hUHa34Wxc25eKCSUVbdq+dnRQuL6hc6oRA4adFuikp6iMCZY8snpOoRYSm0a+M0ORz4QHriCjhSVLzvBrzWbNv2pdXMah8N5KRzK+HBE6Zgth6MZQLv4j+GvjKDzoHwzqnjnqsjAeBD2gP4pIuL6yPspOxDXzcoFFSKDA4LThOdG0t+soa9hEwWImrRYYO2s5L+IaT40lNi5mDyKlE2sFGKzWyHwvfUPLJYhOiqqLYHdytJ84RnXywaDjQwphd0hW4C1EV0FBRGPcA1IbtaI0N9bnpAAxxY0kbbiWSStp6jNbeJzVTvTje4iIXnXKB8WLlGK3z2GTPnLYqoD6tRjwNwWV3wRyUksul9/2X/UfffzAAyr53XRJh1d261NMRlXY99M0dKIa1AGTxjm4OO1LtJnbMtRvq6vRbUs+WX3XGQGEz0TYoCkGUSIQ52uaA1DS//WoptYNQW4w09P2CsrNcB8b6KrqPoTvTFexy7rxvWg9WwXoJFhDt0CAHgpNkdRw0WrCoTZZvGs7WqLdLZeFSEVWSKHly5q0TSECSkEzMmUUHEpeJyoeM/hx7nfYhaHiVNp/39AOYLeONqHLGI5hAAVLLUVBWMTX3dWP3VX2u6NE0D58+T2wWX4J7qiN6sgCpsagqP/XS4BbIoPlEVFiR2T1/2fX4DGTLuNHPFNVCTePwsV8yx6BthiuK29pSHgY5WEkezDsMaXjpn6SrjyMNplwrJNZ7Hn/nl2BRIh1ltNpW+ZpUbPmfzh4zkowf/QfgRBEaBpQBiKQhXX1ifOmfYBBwDxQO5DNTHei6q6LjyoHrELDTZ9hh+J1f0mRZtERxCkEzGRFVyb0C4kKqWYl2aAVsVHmJE0/thXSbzagnO1uph3ybjj0nSqrsv0FtV+J5XDOE2LDWUk3/utXsbuCM8f74kV+486G/gXt3kEZQwAFM/biRRAYxF0vJfToU1Rd3HqSr1+7+w//MIxHqiWIAYMbZ/fNf+e/PPvLLuHcfpk0LmOzckJ0eSoYiauLFFFJ+DqAAA+7fP/+t//38Q38d4wPYDWQgdM2Y9Lz7D/9iun6MO/cr/CYYUv2zuRYz/aw7h0pG3L9790M/f/aRX8jDg3jBkjPNpZlx+vQlDY/tD2+rajGbKSgryiwrFEHk1RkXkRff9LX0bMqE3UTDkkpS+/c26GoUGNne8m60IOwGOv+spO26mILiLYhwysDNF3739du/mXee7+KtbF8CklyKV1cLTb0UTsMn/vHdX/xPzj7+yzh7UO+YCFABCfl6uvP85Tu/f/fW92C4L8n5irFjYc4akBhFbxHlINLuYvyNv3vvl34m3TzCcMblmRxk92j/pi+7euf3Tc9/HtPoCvCsqnKDTMe3h86Rcv3K2a/+rbv/6C8lIuvmgftF49sRt4GFWR7RygnM79NZTFUxVJFXM8K2sQLNUo4EVBFUnUhiboCAu8VS+ihoKbxu0xHApVaFyLJ7PN1/I++/WXfKbC9NV7RtSmQnyAzzXzqd7i/Sa7+WuMfZM2Be7EYFDKabPN3kZ96CO88VhMCMKRBZj5tV37aIK0oEgauX0qPfTGf3MIwKow1f4kgASWl3QRnzw8/m2X0/gBom0LxOSq3KvzSCVnTJ4PJjw+OP4vw+Jbl1JYIcO6KE8FtUalBQ9WkOFzd3OMnSTllL35GG2uwPIi+86WuLr3G+KqIK21FfVxhp5wDddGPEbH4FIsg3kneljil/xnFbNUXgW2yed364A/fKeKWGBVqj6t6cbsApQK/yJeZE9R3lFu+UAcN54YE0xlyxUEwYSErcY3/jx1FZlgMqzhvQFD9+HvcM6Q6Y/Vip1q6wiEfVJm8gSJ4w6tAf21vAc0la43KqTn2xv2YEIIKxSEG4ud8VmX1Y4xvwSTquRHyx/0pCzjied73lpa4xFxzMLVdVMUjCs8b5IwBM56hTWTbYrCHpeg82tbhyGTHQjNC37MicIWm8kyF+DUeVQ+2I4rNyWp7gvk6f74TL/J0g2aTgtbgMzTsuQO8iMp4ohF18Z4PfGJ0+Lbvxnv66rcfZyxmZYLI8Az0t+VVYcE5BiMStCG9VD+eEPQPbsklNNVaVpOhB63e7RT2nfsqcFFt1+RGapC50FIZQo6wQug1MntZOSXqZQo++UsUlE8ynV6ax0lym6B0vZASvGSYdCJtdVA5sVGgLTk11aYUG2vAdA6Kwp4Jtv9AB4kHf5gyYzV0smcRY1NyA85Uv1rG2nF3gBru0QiaCbMYCdfe7aamEuoZvqOIjiK35BaFsuUJtsvE72XrTy3OXeIMKnUVOyoJ3G0AJqSUomExmVZGXpb6i8WwaWFeu3BV4WLEP2ZUlcXQFfEQU+JB9zEp8SQOts1rcRqCIgSYd71A0DkEhUi7k0XdCZClLXbeFjvHtUtNt2/hYTj/2tconltPGZcTllfghm5C3mcztBoUUbTQONUYeo8rx8pc7pLcQlomqAC8OJgKxNNLitSvE6A4U7ZzFYRPfipSRg5RzQqm/+tMAqiayT5AUfDCdZ858RrTYBgggSSSlbEu61060MhLtlt5ydG2ON8Nqifdax9lC8d14mG7nFr3pgP2utbTqFWC7alzYr4QeuqqwTgjMIOLYGqQt3DI2hirloRulra4CF/D22kQxjrQe8L4WkCW5qA81EIkl+H5WH+YBKnNv6mgHfO3UbpYiNdAkyFYPggVnqK9iS7+ppZ19wK6/xReYZfJFDgijBpkFKYN6U5XFNGFx39mLFJXDH0AEY9ydKMFa0b3i2dbqMKoWGUa23OfSj5rwmW0938pYbKtTsw706rbPBvfZKFEVKbg35rPcoh/rUY25bD0uAm+P7HZV/Rx7jQy0aMH9LQAmiFpwWpFn77WDUTFnrKG11Y/BFvuJgCDcleE9JQAWGV8jVxvLOWzdhX+1lPVkd8dpmH6oQfE71GFjYEuUG2VRm2kqOGtcNCdvV3RPQoqbg+zoXFDsBOefM1PUbYWZ1O76Kh8C6puv3jw6ZuC9SNADNOigZJ9EpUirEltYC6qo+qmaFjNqHvs3fUE0W3sz7WxjdlyQCir3XKhgrZUva8dvih5yHIWx/fDkRYCqwsIYsltZiizTleeKyK0zHBSCq8L7uIQ5y9WCtoDjVtcadc6f9zHR0Zxa5GvuKVAjfVnOw6T5ATC77edblOgBj4v+GGo7raNqKAbrxKR7VeO0qtLvwog89IXOt7BJZJUazGhVNmdScnE6McNknk+O2PM1JKnDrNt6iqCSdBqIeaKldr8hEgP6Kolwph8cSRDHVGOAbW3QZW0xjOKplOj+r8lT9KvZNWXPErmgZAXOgWx0k7AC7a12zqYiEWqrrmkBtHOKvt7nokMWQGEhhVSRxZoJmQXPbMVCmssBuhKtu2siMve7zLuvqlkZ2G1V1qdYjlSkblEKDWV6DmlFtJNOG99/AMhoQEpnlNB1daekxvHtbw12w3C9Lch/9/U/40xr7MrfAzyMYgOHUZctH0dolDpAKXeirZa5fPXVqV7nVSOqVyrbDd7XaeJvVxJ7yz/1U+TwFjPKVdrm/rfFQUXPsB+ICCJRW2UkirLfYeaxCNjsicZCQHK5yjpoZu1lSXon7BJ4J3PvsfZkY3DkdLv9Kxpc5fB099FxJe7wtREdT78klzXlw1bN2a8sQc7uBZcScGH77Tb5Jss21JqlxrWUhSQQV3cASAndKh82WisaGNBrMM0wn0DKi0fmaO+jRhHEZVcRVMJMA/UU27tUxgrKNqi53aBRh4LfU7AeXXSkLdYVD+mxtAYbmJOA98b1ANc+Oh4e6i9uVh9Zil6tDjfzCzYJiivU2wsgSr01l0fJTX/rkmh596kHC7uZjnpdZZVRJ3cQ07qxhqNpXLlCDj5uBIJOXSsBOwUNXHcBJALu/rCPgpnGX2oL7aIEdo0weRDWSriBZOgGeYwdtmvyNllsHXXod5bCYLlEt75RIZvnC73NXPjR8t/gneLSNotl16BAMsZEzZOr10OmGjAVe/Gk27SmkoutGN58y5znc+0hEUBKtn3WHK5zdLfilUWNzUDKQm/EZ6ySftRiZbZ2pFTpCNeYk6T54WYEBWNOeQhrICHNdyjbV4oyLtLsWrE1VMrY3AhzzayDulSuTwiU2+no7RSPnS1j/wd+z4I3R2YJXRN5nPIuyVm9igIKyiIpinfnR70KZkIXC+/dpuTN0/9d3Hd5bqEB3fQHknOw6xrvZNVK8dNBnqyi1I4EMZ+wWGpIQm6DuVqFWKBu/IbSpPzusZftrzHOzPUxAKzbX3WBWQL8BnjPb0KUHXBX3p0mNDKnya8i5DTmaZfGMx+hD2VJPZujbKZZS5uKkD3/qHRfmxKj1sJvKuk0G0CrfveeaofCj/zFzoiNtH96ST6QRcNYPKSJYVD+Vvmy3PstVZNFMByajmX2iPW5EFc+BUzzTVOgxamXPO1G5iuRB+EFnY/IABieHyiKPo1ZDsOIS1PC+qhPLGN8TPTR7Uke4chfAaksSgtTPUq/uG1HXbfdXpKWwoEYZEeMaD6+LLp8Nr7OKiuQaGfnKGwTmPLVOE0XwIsmZZtQqdqB10+++XOgdRHxa3DnHH55bO7XT+H5bShmHTaB+22PbHh7J+s4N0dYzQTESKdzbfs6OwDPYheFud56gbXvntCIQPJ0Oe53r7Vv5vZr/BCVuJWe6Ocsg1eITSAKWgKV8kjK/25dGuEUgaTDP8t34Y6TFon9yclS0xWCttv1yfM1acEeqeydFb4u1SzoQv4VmdnPMHlHZSyr1uRSmQuQqJAUrrE+s0uDm/aPxmn3Wp6uZLjjnuSoozFoc9LCbcuqKKNiIet6ZKqzIApojE+lXcdZDyBbqIzU0cG6Mu1fWb0Flin/Vx1SFyNZNzwjyvTzVAgc8KCvmhi03nbp2G2wnMHieY+Izq35GVIbZacMBbPcO2isPFkwKnOJny8EZt2WO37h7dgVaqFDQU00UOO/o7rdZgmizVJ9vRBoxJWEuXMlXRsXJKScb/a7V8fM3W736p3hzUR7KB0Mg4nyyAnGooayDxSoAW0EJUbdaygug/cZAINPM9EGn4WedbpVe32PqMbgwdKCuW9TO1l1Crm7qAr8MkkwYtJpy56MJDmWdfrdR8cyT31r+jCDyZOgFf81nM5dO6SPKDXwuD5bGhSd8GZiFnhJu4dKH3Fy5BPl1OgMMfVTc3VTw4bVOSICoei5tf3ulZxvRgC764/dufvmgs5AN8mZkCooi9LN12wHkpRdQWAWbCgNwipRuSNBihcnl+h0j0pmiyw9RGkmbuUu/QJFIeSAoBaPoqeLs5u51mQhWveRCJid9JvXlY4J5VUonKCO15OeFhcCNRrdWEXyLcWy+q0TKaPr5E6dCyEhTCzMsHTbsJODQo+E1D3++lisF8D0AN5cfQy6F7bbvTxNj9Nwf5abxxd6dREFhDmrF6Dzj1G6gMv5yEMjQPIr34B+VjzTecBUCyAreWiuCc9/WF8w6u1yuXajieDpMZ2pghuwX02WMnRSJNFPmzk8HrwDvbNTkCCT0lXZimI3SwtRMc6Lm9NRhaybleT4MXHjjLnqHtlchLH9OuymWwhaZ5vxUHsj7fePd7uXoFcdkPn68rfvP/NPTdgFJJYlIO2UVOTpf6TmgZOA5KIEdJD1sBIgcjIJVwJVqrwKA2aRJgGVUTBp4vjGAiRz3SdZlm+OX3uRU6UC1ioOQiEV+iVemnI8hmFYz4V1C4hJKkhxJVWW2sQNIzZVFJBeCCo1Zmd3LHNvHNvme22TYGlB+Vz7ed9ckam4FZHh5uojahvZwcLrq4+e3/uslO6SewoShkIoRdq79G8UyDAwR3CgpKOKVKDFcJmd1KtHU/rFqSXDTRtdbU0kRPhoQoC9uuAw108GTpDKhUjVjS8uoqvrlwstqSStcqiLd2uEeBE29ba7hnU0TTN+NZEVRyQYLD0Imqf92jtQ2PZkOBYRDNP06Prqo/rYfP9kvnr8/4pdyVr9MNK2WBHTLOVubDIDfVVy2JAYPpe2JKJgbdxSZrELae32smn28xYkXVdzXM9Vj/a9fqTCAJjz8IJGSqUnj6iR2g1A6K0heSrkMhc2TWIq0VD0SbOk9VAvtLCGVtpfzO8iukYJXD7+9eKaqdLn5vrj11cfFRn8DBSLSI7zeBwADoQUYDbgRNR7xY+Mx5158TieQ8yjfm22vnXswpYoF4qJuUB/US+JxLoQItfeTqIwZCUU5KzHZGdpkyRoFhHPtJv3LFdd1iRTRNwsmlNDbg+9uHxYylFcwFb566ssQuItFBKkyNnu+ndvrj9WWNoYG7569OHx7BkZ7pKWITflqr2JH9AHOvT1a9LdK8es91o/6rGYKQGLxeJ3JdFVghR0ikIH4mlgXPyotGhAQLmFi9JNjWVQdiTAf27oIAwBs6ktLgKPSIPUlLlNs8VwYnjRv9JF6AwGUYma2SEQZaTeWadc2HU9EGdaqbxqlmYT6ZSni4tHH65wt55Zydw/fu1DQiakpEmPfRhpeS5l1kjQCVHod40MDkm3rups3Us5dR/kR5AaDVQS14CgMAP983QRfb8+jioCZblOL+4j3xJp8Fmep7DSohQuvcQQDYtaKZYRbTjJHRCJqVBn0xQDRFEtcEEnMdyxMH4LKZHiPBfi4tH/k/N1HGubDQMy7V67eO1DYprQGg/ppFJDBytc6mA5rXbtrlEbAkDb3MtJwf8YBtVAIlHNKg8J0MoqYL20EtNRwnddX2ub86odUgqJ96qlD0VlT6ZJ6VlDSgpsYows62FrK3SCxQkbQibI5aNf3d28XADvwGjGdefuG+8//FyTiZ3nxWVwSMWSZiR1QvHdIqBxPBz/ej75xfnu82b7vpAMceFtbWEhbqkX6muNawvL/Rpa2qbWRhrE4fKvqSbxhMDNXoY3i9joNrMJJhkvH3/48uI3OupZA14Ant/5jPvPvF0spUkI9ClWU0g46jE9aOela3xrvVYb1wFYrdnLiq06EQz2btLFNo9ZBoGxzG4jWAdPIjzdHa4dRYZFtVEi0ZiIDhNRWqtdrJ/sWct6TpEEpMvHH766/O3FednQTjiePfvgmT+c0j1IbpfdxsppgW/iBrcxcuSivUXZJsfblarhnAaKs6s1ai55O14HmDfK4oQypfM8XV08/pWb65fW0LgxfgGY0tm9B59zfveNAJin7lf7tH5oLeDrk4yRT2WZCbXltTGnoSdGl65YdkL29EIgiaTd7qWLRx/O09XGItxeQPba+Z0X795/6zA88FBD7eCYhVLCtz/dqEe6wM2jBcdxTa9ZH2G7eyWY8BiBu9F1uvW7bvskQZr2F9eXv3V9/bva6gZajuXAgnR25zPu3PvMcXwAQ8RBqfQk5XWSO8vjfR0ExzyXiyrgn24LqQgvi+bO+fL68neurz7K5aRhfTmSgKSQ5/nZc+d3XhzGB5LO/Q7iBeu3vOhM9Skhrqrwq6t8qWyQTlKu8KRsv9jcSx1tHU1/SqVwr6OXQT3eTOZpupn2j/Y3n9jtXnHSOWoNn6QD1haTjMP4II3PDMODYbwjMqZ03oYNlYGV+IrG1JxHXJzAfsUTzxkvbAwf2zBdkSOzKPeozJUTAauLYRM8P/pi/KyvOQteLg36/ncbJH4kTVt6jMb21kWbsYRnfSnnPbnjdD1NF/vdo/3+gtyVisevpf8PFEsZ6Guuhn0AAAAASUVORK5CYII=';
const PWA_ICON_512 = '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';
const PWA_ICON_APPLE = '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';

function registerPwaRoutes(app) {
  app.get('/manifest.json', (req, res) => {
    res.set('Content-Type', 'application/manifest+json').send(PWA_MANIFEST_JSON);
  });
  app.get('/sw.js', (req, res) => {
    res.set('Content-Type', 'application/javascript').send(PWA_SW);
  });
  const servePng = (b64data) => (req, res) => {
    res.set('Content-Type', 'image/png')
       .set('Cache-Control', 'public, max-age=86400')
       .send(Buffer.from(b64data, 'base64'));
  };
  app.get('/icon-192.png', servePng(PWA_ICON_192));
  app.get('/icon-512.png', servePng(PWA_ICON_512));
  app.get('/apple-touch-icon.png', servePng(PWA_ICON_APPLE));
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
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#1b2f6b">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<script>if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js');}</script>
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
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#1b2f6b">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<script>if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js');}</script>
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
registerPwaRoutes(app); // PWA: /manifest.json, /sw.js, /icon-*.png, /apple-touch-icon.png

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
</style>
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#1b2f6b">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<script>if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js');}</script>
</head>
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
