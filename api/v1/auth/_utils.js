const crypto = require('crypto');

const SECRET = process.env.JWT_SECRET || 'stockagent-jerry-secret-2026';
const KV_URL   = process.env.KV_REST_API_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN;

// ── Simple JWT (no deps) ───────────────────────────────────
function b64url(str) {
  return Buffer.from(str).toString('base64url');
}
function signJWT(payload, expiresInSec = 86400) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body   = b64url(JSON.stringify({ ...payload, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000)+expiresInSec }));
  const sig    = crypto.createHmac('sha256', SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}
function verifyJWT(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', SECRET).update(`${header}.${body}`).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp < Math.floor(Date.now()/1000)) return null;
    return payload;
  } catch { return null; }
}

// ── Password hashing ───────────────────────────────────────
function hashPwd(pwd) {
  return crypto.createHmac('sha256', SECRET).update(pwd).digest('hex');
}
function checkPwd(pwd, hash) {
  return hashPwd(pwd) === hash;
}

// ── KV store (Vercel KV REST) ──────────────────────────────
async function kvGet(key) {
  if (!KV_URL || !KV_TOKEN) return null;
  try {
    const r = await fetch(`${KV_URL}/get/${encodeURIComponent(key)}`, { headers: { Authorization: `Bearer ${KV_TOKEN}` } });
    const j = await r.json();
    return j.result ? JSON.parse(j.result) : null;
  } catch { return null; }
}
async function kvSet(key, value, ttl) {
  if (!KV_URL || !KV_TOKEN) return false;
  try {
    const body = { value: JSON.stringify(value) };
    if (ttl) body.ex = ttl;
    await fetch(`${KV_URL}/set/${encodeURIComponent(key)}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${KV_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return true;
  } catch { return false; }
}

// ── CORS headers ───────────────────────────────────────────
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Trace-ID');
}

module.exports = { signJWT, verifyJWT, hashPwd, checkPwd, kvGet, kvSet, cors };
