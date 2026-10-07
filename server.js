// DJY Hub Key Server
// Node.js + Express. Stores keys in keys.json. UserId-locked.
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const ADMIN_PW = process.env.ADMIN_PW || "CHANGE_ME_NOW";
const KEYS_FILE = path.join(__dirname, "keys.json");

// Storage
function loadKeys() {
  try {
    if (!fs.existsSync(KEYS_FILE)) return {};
    return JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
  } catch {
    return {};
  }
}

function saveKeys(data) {
  fs.writeFileSync(KEYS_FILE, JSON.stringify(data, null, 2));
}

if (!fs.existsSync(KEYS_FILE)) saveKeys({});

// Key generation
function generateKey() {
  const hex = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `DJY-${hex()}-${hex()}-${hex()}`;
}

// Rate limiting (in-memory)
const rateMap = new Map();
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 5;

function rateLimited(ip) {
  const now = Date.now();
  const arr = (rateMap.get(ip) || []).filter((time) => now - time < RATE_WINDOW_MS);
  if (arr.length >= RATE_MAX) {
    rateMap.set(ip, arr);
    return true;
  }
  arr.push(now);
  rateMap.set(ip, arr);
  return false;
}

function getIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}

// Key verification
app.post("/verify", (req, res) => {
  const ip = getIp(req);
  if (rateLimited(ip)) {
    return res.json({ ok: false, reason: "rate_limited" });
  }

  const { key, userId, username } = req.body || {};
  if (!key || !userId) {
    return res.json({ ok: false, reason: "missing_params" });
  }

  const normKey = String(key).trim().toUpperCase();
  const keys = loadKeys();
  const entry = keys[normKey];

  if (!entry) return res.json({ ok: false, reason: "invalid" });
  if (entry.banned) return res.json({ ok: false, reason: "banned" });

  const uid = String(userId);

  if (!entry.boundUserId) {
    entry.boundUserId = uid;
    entry.boundUsername = username || "unknown";
    entry.claimedAt = new Date().toISOString();
    entry.claimedFromIp = ip;
    saveKeys(keys);
    return res.json({ ok: true, message: "key claimed" });
  }

  if (String(entry.boundUserId) === uid) {
    entry.lastSeenAt = new Date().toISOString();
    saveKeys(keys);
    return res.json({ ok: true, message: "welcome back" });
  }

  return res.json({ ok: false, reason: "already_claimed" });
});

// Admin panel
function esc(value) {
  return String(value).replace(/[&<>"']/g, (character) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[character])
  );
}

app.get("/admin", (req, res) => {
  if (req.query.pw !== ADMIN_PW) {
    return res.status(401).send("<h1>401 Unauthorized</h1>");
  }

  const keys = loadKeys();
  const rows = Object.entries(keys)
    .map(([key, value]) => {
      const bound = value.boundUserId
        ? `${esc(value.boundUsername)} (${esc(value.boundUserId)})<br><small>${esc(value.claimedAt || "")}</small>`
        : "<em>unclaimed</em>";
      const status = value.banned ? "🔴 banned" : value.boundUserId ? "🟢 active" : "⚪ new";
      return `
      <tr>
        <td><code>${esc(key)}</code></td>
        <td>${status}</td>
        <td>${bound}</td>
        <td>
          <form method="POST" action="/admin/reset?pw=${encodeURIComponent(ADMIN_PW)}" style="display:inline">
            <input type="hidden" name="key" value="${esc(key)}">
            <button ${value.boundUserId ? "" : "disabled"}>Reset</button>
          </form>
          <form method="POST" action="/admin/ban?pw=${encodeURIComponent(ADMIN_PW)}" style="display:inline">
            <input type="hidden" name="key" value="${esc(key)}">
            <button>${value.banned ? "Unban" : "Ban"}</button>
          </form>
          <form method="POST" action="/admin/delete?pw=${encodeURIComponent(ADMIN_PW)}" style="display:inline" onsubmit="return confirm('Delete ${esc(key)}?')">
            <input type="hidden" name="key" value="${esc(key)}">
            <button>Delete</button>
          </form>
        </td>
      </tr>`;
    })
    .join("");

  res.send(`<!doctype html><html><head><meta charset="utf-8">
<title>DJY Key Admin</title>
<style>
body{background:#101016;color:#f0f0f5;font-family:system-ui;padding:30px;max-width:1100px;margin:auto}
h1{color:#aa64ff}
table{border-collapse:collapse;width:100%;margin-top:20px}
th,td{padding:10px;border-bottom:1px solid #2a2a3c;text-align:left;font-size:14px}
th{color:#ff5a8c;text-transform:uppercase;font-size:11px;letter-spacing:1px}
button{background:#aa64ff;color:#fff;border:0;padding:6px 12px;border-radius:6px;cursor:pointer;font-weight:600}
button:hover{background:#c088ff}
button:disabled{background:#3c3c4b;cursor:not-allowed}
input{background:#1a1a24;border:1px solid #2a2a3c;color:#f0f0f5;padding:8px;border-radius:6px;font-family:monospace}
code{background:#1a1a24;padding:3px 8px;border-radius:4px;color:#aa64ff;font-weight:600}
form.inline{display:inline}
</style></head><body>
<h1>DJY Hub — Key Admin</h1>
<form method="POST" action="/admin/generate?pw=${encodeURIComponent(ADMIN_PW)}">
  <input name="count" type="number" value="1" min="1" max="50" style="width:60px">
  <button>Generate Keys</button>
</form>
<table>
<thead><tr><th>Key</th><th>Status</th><th>Bound User</th><th>Actions</th></tr></thead>
<tbody>${rows || '<tr><td colspan="4"><em>No keys yet.</em></td></tr>'}</tbody>
</table>
</body></html>`);
});

app.post("/admin/generate", express.urlencoded({ extended: true }), (req, res) => {
  if (req.query.pw !== ADMIN_PW) return res.status(401).send("unauthorized");
  const count = Math.min(parseInt(req.body.count, 10) || 1, 50);
  const keys = loadKeys();
  for (let index = 0; index < count; index++) {
    let key = generateKey();
    while (keys[key]) key = generateKey();
    keys[key] = { createdAt: new Date().toISOString() };
  }
  saveKeys(keys);
  res.redirect(`/admin?pw=${encodeURIComponent(ADMIN_PW)}`);
});

app.post("/admin/reset", express.urlencoded({ extended: true }), (req, res) => {
  if (req.query.pw !== ADMIN_PW) return res.status(401).send("unauthorized");
  const keys = loadKeys();
  const key = String(req.body.key || "").toUpperCase();
  if (keys[key]) {
    delete keys[key].boundUserId;
    delete keys[key].boundUsername;
    delete keys[key].claimedAt;
    delete keys[key].claimedFromIp;
    saveKeys(keys);
  }
  res.redirect(`/admin?pw=${encodeURIComponent(ADMIN_PW)}`);
});

app.post("/admin/ban", express.urlencoded({ extended: true }), (req, res) => {
  if (req.query.pw !== ADMIN_PW) return res.status(401).send("unauthorized");
  const keys = loadKeys();
  const key = String(req.body.key || "").toUpperCase();
  if (keys[key]) {
    keys[key].banned = !keys[key].banned;
    saveKeys(keys);
  }
  res.redirect(`/admin?pw=${encodeURIComponent(ADMIN_PW)}`);
});

app.post("/admin/delete", express.urlencoded({ extended: true }), (req, res) => {
  if (req.query.pw !== ADMIN_PW) return res.status(401).send("unauthorized");
  const keys = loadKeys();
  const key = String(req.body.key || "").toUpperCase();
  delete keys[key];
  saveKeys(keys);
  res.redirect(`/admin?pw=${encodeURIComponent(ADMIN_PW)}`);
});

app.get("/", (req, res) => res.send("DJY Key Server — running"));

app.listen(PORT, () => console.log(`DJY Key Server on port ${PORT}`));