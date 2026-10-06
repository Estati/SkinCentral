const enc = new TextEncoder();

/* ---------- settings (change the numbers if you want) ---------- */
const LIMITS = {
  icon: 512 * 1024,        // icon max size
  shot: 2 * 1024 * 1024,   // each screenshot max
  pack: 5 * 1024 * 1024,   // each pack file max
  total: 20 * 1024 * 1024, // whole upload max
  maxPending: 3,           // pending packs one person can have at once
  anonTotal: 10 * 1024 * 1024, // anon upload whole thing max
  anonPerDay: 2,           // anon uploads per visitor per day
  anonMaxPending: 10,      // anon packs waiting for review site wide
  avatar: 256 * 1024,      // profile picture max size
  nameMax: 24,             // display name length
  bioMax: 200,             // bio length
  profileEditsPerHour: 20, // profile saves per person per hour
};
const PLATFORMS = {
  xbox360: "Xbox 360",
  ps3: "PS3",
  wiiu: "Wii U",
  vita: "PS Vita",
  switch: "Switch",
};
const BLOCKED_EXT = /\.(exe|dll|bat|cmd|com|msi|scr|js|mjs|vbs|ps1|apk|ipa|jar|sh|html?|svgz?|php|py)$/i;

/* ---------- small helpers ---------- */
function toB64url(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

function cookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function notFound() {
  return new Response("Not found", { status: 404 });
}

function clean(s, max) {
  return String(s || "")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

function slugify(s) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "pack";
}

function safeName(name) {
  let n = String(name || "file").split(/[\\/]/).pop().replace(/[^A-Za-z0-9._-]+/g, "_");
  if (n.length > 80) n = n.slice(-80);
  n = n.replace(/^\.+/, "");
  return n || "file";
}

function niceSize(b) {
  if (b < 1024) return b + " B";
  if (b < 1024 * 1024) return Math.round(b / 1024) + " KB";
  return (b / 1048576).toFixed(1) + " MB";
}

function isFile(v) {
  return v && typeof v === "object" && typeof v.arrayBuffer === "function" && v.size > 0;
}

function sameOrigin(request, env) {
  return request.headers.get("Origin") === env.SITE_URL;
}

// checks the first bytes to make sure its really a png, jpg or webp
async function sniffImage(file) {
  const b = new Uint8Array(await file.slice(0, 12).arrayBuffer());
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  if (
    b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
    b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50
  ) return "image/webp";
  return null;
}

/* ---------- login sessions ---------- */
function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function signSession(env, data) {
  const payload = toB64url(enc.encode(JSON.stringify(data)));
  const sig = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(env.SESSION_SECRET),
    enc.encode(payload)
  );
  return payload + "." + toB64url(sig);
}

async function readSession(env, request) {
  try {
    const raw = getCookie(request, "session");
    if (!raw) return null;
    const [payload, sig] = raw.split(".");
    if (!payload || !sig) return null;
    const ok = await crypto.subtle.verify(
      "HMAC",
      await hmacKey(env.SESSION_SECRET),
      fromB64url(sig),
      enc.encode(payload)
    );
    if (!ok) return null;
    const data = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
    if (data.exp < Date.now() / 1000) return null;
    // only site accounts (ids like u1a2b3c4d5e6f) count now. old discord cookies (digit ids) stop working
    if (!/^u[0-9a-f]{12}$/.test(String(data.id))) return null;
    // look the user up every time so a ban or a role change works right away
    let u;
    try {
      u = await env.DB.prepare(
        "SELECT username, role, banned, display_name, has_avatar, avatar_v, pw_at FROM users WHERE id = ?"
      ).bind(data.id).first();
    } catch {
      // profile columns not added to the database yet
      u = await env.DB.prepare(
        "SELECT username, role, banned FROM users WHERE id = ?"
      ).bind(data.id).first();
    }
    if (!u || u.banned) return null;
    // password was changed or reset after this cookie was made -> logged out
    if ((data.iat || 0) < (u.pw_at || 0)) return null;
    data.name = u.username;
    data.displayName = u.display_name || null;
    data.hasAvatar = !!u.has_avatar;
    data.avatarV = u.avatar_v || 0;
    data.role = u.role;
    data.mod = u.role === "mod" || u.role === "admin" || u.role === "owner";
    return data;
  } catch {
    return null;
  }
}

function logout() {
  const res = json({ ok: true });
  res.headers.append("Set-Cookie", cookie("session", "", 0));
  return res;
}

async function me(request, env) {
  const s = await readSession(env, request);
  return json(
    s
      ? { loggedIn: true, user: { id: s.id, name: s.name, displayName: s.displayName || null, hasAvatar: !!s.hasAvatar, avatarV: s.avatarV || 0 }, isMod: s.mod, role: s.role || (s.mod ? "mod" : "user") }
      : { loggedIn: false }
  );
}

/* ---------- accounts (username + password) ---------- */
const PBKDF2_ROUNDS = 100000; // cloudflare's max. the number is saved inside each hash so it can change later
// names nobody can sign up with (underscores are ignored, so skin_central is blocked too)
const RESERVED_NAMES = new Set([
  "skincentral", "admin", "administrator", "owner", "moderator", "mod", "mods",
  "staff", "support", "system", "anonymous", "anon", "discord", "mojang", "microsoft",
]);
// fake hash so unknown usernames take as long to check as real ones
const DUMMY_HASH = "pbkdf2-sha256$100000$" + "A".repeat(22) + "$" + "A".repeat(43);

// password + secret pepper -> scrambled hash (pbkdf2). the pepper must never change
async function hashPassword(env, password, salt, rounds) {
  const peppered = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(env.PASSWORD_PEPPER),
    enc.encode(password)
  );
  const key = await crypto.subtle.importKey("raw", peppered, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: rounds },
    key,
    256
  );
  return toB64url(bits);
}

// compares two strings without stopping at the first difference
function sameText(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function checkPassword(env, password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2-sha256") return false;
  const rounds = Number(parts[1]);
  if (!(rounds >= 1000 && rounds <= 100000)) return false;
  const got = await hashPassword(env, password, fromB64url(parts[2]), rounds);
  return sameText(got, parts[3]);
}

// reads a small json body, null if its too big or broken
async function readJson(request) {
  const len = Number(request.headers.get("Content-Length") || 0);
  if (len > 4096) return null;
  try {
    const text = await request.text();
    if (text.length > 4096) return null;
    const data = JSON.parse(text);
    return data && typeof data === "object" ? data : null;
  } catch {
    return null;
  }
}

// rate limit helpers, they use the login_attempts table
async function countAttempts(env, key, since) {
  const r = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM login_attempts WHERE key = ? AND created_at > ?"
  ).bind(key, since).first();
  return r ? r.n : 0;
}

async function addAttempt(env, key, now) {
  await env.DB.prepare("INSERT INTO login_attempts (key, created_at) VALUES (?, ?)").bind(key, now).run();
  // now and then sweep out rows older than a day
  if (Math.random() < 0.05) {
    await env.DB.prepare("DELETE FROM login_attempts WHERE created_at < ?").bind(now - 86400).run().catch(() => {});
  }
}

// makes the session cookie, same cookie the discord login uses
async function startSession(env, u) {
  const mod = u.role === "mod" || u.role === "admin" || u.role === "owner";
  const maxAge = mod ? 60 * 60 * 24 : 60 * 60 * 24 * 7;
  const token = await signSession(env, {
    id: u.id,
    name: u.username,
    avatar: null,
    mod,
    role: u.role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + maxAge,
  });
  const res = json({ ok: true });
  res.headers.append("Set-Cookie", cookie("session", token, maxAge));
  return res;
}

async function signup(request, env) {
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  if (!env.PASSWORD_PEPPER) return json({ error: "Accounts are not set up yet. Tell the owner." }, 500);
  const body = await readJson(request);
  if (!body) return json({ error: "That did not look right. Try again." }, 400);

  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) {
    return json({ error: "Usernames are 3 to 20 letters, numbers or underscores." }, 400);
  }
  const lc = username.toLowerCase();
  if (RESERVED_NAMES.has(lc.replace(/_/g, ""))) return json({ error: "That username is reserved." }, 400);
  if (password.length < 10) return json({ error: "Your password needs at least 10 characters." }, 400);
  if (password.length > 128) return json({ error: "That password is too long (128 max)." }, 400);
  if (password.toLowerCase() === lc) return json({ error: "Your password can not be your username." }, 400);

  // 3 new accounts per connection per hour
  const now = Math.floor(Date.now() / 1000);
  const tag = await visitorTag(request, env);
  if ((await countAttempts(env, "signup:" + tag, now - 3600)) >= 3) {
    return json({ error: "Too many accounts made from your connection. Try again in an hour." }, 429);
  }
  if (!(await checkHuman(request, env))) {
    return json({ error: "The human check failed. Please try again." }, 400);
  }

  if (await isBreached(password)) {
    return json({ error: "That password showed up in a known data leak. Please pick a different one." }, 400);
  }

  const taken = await env.DB.prepare("SELECT id FROM users WHERE username_lc = ?").bind(lc).first();
  if (taken) return json({ error: "That username is taken." }, 409);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(env, password, salt, PBKDF2_ROUNDS);
  const passHash = `pbkdf2-sha256$${PBKDF2_ROUNDS}$${toB64url(salt)}$${hash}`;
  const id = "u" + [...crypto.getRandomValues(new Uint8Array(6))].map((b) => b.toString(16).padStart(2, "0")).join("");

  try {
    await env.DB.prepare(
      "INSERT INTO users (id, username, username_lc, pass_hash, role, banned, created_at) VALUES (?, ?, ?, ?, 'user', 0, ?)"
    ).bind(id, username, lc, passHash, now).run();
  } catch (e) {
    // two people grabbing the same name at the same moment
    if (/UNIQUE/i.test(String(e))) return json({ error: "That username is taken." }, 409);
    throw e;
  }
  await addAttempt(env, "signup:" + tag, now);
  return startSession(env, { id, username, role: "user" });
}

async function loginPassword(request, env) {
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  if (!env.PASSWORD_PEPPER) return json({ error: "Accounts are not set up yet. Tell the owner." }, 500);
  const body = await readJson(request);
  if (!body) return json({ error: "That did not look right. Try again." }, 400);

  const username = String(body.username || "").trim().slice(0, 40);
  const password = String(body.password || "").slice(0, 200);
  const lc = username.toLowerCase();
  if (!lc || !password) return json({ error: "Enter a username and password." }, 400);

  // 10 wrong tries per connection or per username, then wait 15 minutes
  const now = Math.floor(Date.now() / 1000);
  const tag = await visitorTag(request, env);
  const ipKey = "login:ip:" + tag;
  const userKey = "login:user:" + lc;
  if (
    (await countAttempts(env, ipKey, now - 900)) >= 10 ||
    (await countAttempts(env, userKey, now - 900)) >= 10
  ) {
    return json({ error: "Too many wrong tries. Wait 15 minutes and try again." }, 429);
  }

  const u = await env.DB.prepare(
    "SELECT id, username, pass_hash, role, banned FROM users WHERE username_lc = ?"
  ).bind(lc).first();
  // always hash, even for names that dont exist, so the timing looks the same
  const ok = await checkPassword(env, password, u ? u.pass_hash : DUMMY_HASH);
  if (!u || !ok) {
    await addAttempt(env, ipKey, now);
    await addAttempt(env, userKey, now);
    return json({ error: "Wrong username or password." }, 401);
  }
  if (u.banned) return json({ error: "This account has been banned." }, 403);

  // right password clears that usernames counter (the connection counter stays)
  await env.DB.prepare("DELETE FROM login_attempts WHERE key = ?").bind(userKey).run().catch(() => {});
  return startSession(env, u);
}

/* ---------- password tools: breach check, change your own, admin reset ---------- */
// asks haveibeenpwned if a password is in a known leak. only the first 5 characters of a
// scrambled copy leave the worker, never the password. if the service is down we just allow it
async function isBreached(password) {
  try {
    const buf = await crypto.subtle.digest("SHA-1", enc.encode(password));
    const hex = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
    const res = await fetch("https://api.pwnedpasswords.com/range/" + hex.slice(0, 5), {
      headers: { "Add-Padding": "true" },
      signal: AbortSignal.timeout(2500),
    });
    if (!res.ok) return false;
    const rest = hex.slice(5);
    for (const line of (await res.text()).split("\n")) {
      const [suffix, count] = line.trim().split(":");
      if (suffix === rest && Number(count) > 0) return true;
    }
  } catch {}
  return false;
}

// makes a fresh salt + hash string ready to store in users.pass_hash
async function newPassHash(env, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(env, password, salt, PBKDF2_ROUNDS);
  return `pbkdf2-sha256$${PBKDF2_ROUNDS}$${toB64url(salt)}$${hash}`;
}

// POST /api/password {current, next}  -> changes your own password, logs your other devices out
async function changePassword(request, env) {
  const s = await readSession(env, request);
  if (!s) return json({ error: "Please log in first." }, 401);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  const body = await readJson(request);
  if (!body) return json({ error: "That did not look right. Try again." }, 400);
  const current = String(body.current || "").slice(0, 200);
  const next = String(body.next || "");

  // 5 wrong current passwords, then wait 15 minutes
  const now = Math.floor(Date.now() / 1000);
  const key = "pwchange:" + s.id;
  if ((await countAttempts(env, key, now - 900)) >= 5) {
    return json({ error: "Too many wrong tries. Wait 15 minutes and try again." }, 429);
  }
  if (next.length < 10) return json({ error: "Your new password needs at least 10 characters." }, 400);
  if (next.length > 128) return json({ error: "That password is too long (128 max)." }, 400);
  if (next.toLowerCase() === s.name.toLowerCase()) return json({ error: "Your password can not be your username." }, 400);

  const row = await env.DB.prepare("SELECT pass_hash FROM users WHERE id = ?").bind(s.id).first();
  if (!row || !(await checkPassword(env, current, row.pass_hash))) {
    await addAttempt(env, key, now);
    return json({ error: "Your current password is wrong." }, 401);
  }
  if (next === current) return json({ error: "Your new password is the same as the old one." }, 400);
  if (await isBreached(next)) {
    return json({ error: "That password showed up in a known data leak. Please pick a different one." }, 400);
  }

  await env.DB.prepare("UPDATE users SET pass_hash = ?, pw_at = ? WHERE id = ?")
    .bind(await newPassHash(env, next), now, s.id).run();
  // fresh cookie for this device, every older cookie stops working
  return startSession(env, { id: s.id, username: s.name, role: s.role });
}

// random temporary password like "k7mq-x3np-r9wd-h4tc" (no lookalike letters)
function tempPassword() {
  const chars = "abcdefghjkmnpqrstuvwxyz23456789"; // 31 characters
  let out = "";
  while (out.length < 16) {
    for (const b of crypto.getRandomValues(new Uint8Array(32))) {
      if (b < 248 && out.length < 16) out += chars[b % 31]; // skip 248+ so no letter is more likely
    }
  }
  return out.match(/.{4}/g).join("-");
}

// POST /api/admin/user-reset {id}  -> new temporary password, shown once to the admin
// same rules as the other account tools: not yourself, not the owner, only the owner can reset an admin
async function resetPassword(request, env) {
  const s = await readSession(env, request);
  if (!isAdmin(s)) return json({ error: "Admins only." }, 403);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  const body = await readJson(request);
  if (!body) return json({ error: "Bad request." }, 400);
  const t = await targetUser(env, s, body.id);
  if (t.err) return t.err;
  const temp = tempPassword();
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare("UPDATE users SET pass_hash = ?, pw_at = ? WHERE id = ?")
    .bind(await newPassHash(env, temp), now, t.u.id).run();
  // clear their login lock so they can try the new password right away
  await env.DB.prepare("DELETE FROM login_attempts WHERE key = ?").bind("login:user:" + t.u.username.toLowerCase()).run().catch(() => {});
  await logAction(env, s, "reset a password", t.u.username, "");
  return json({ ok: true, username: t.u.username, password: temp });
}

/* ---------- splash texts (the tilted yellow text under the logo) ---------- */
const SPLASH_MAX = 30;   // characters per splash
const SPLASH_COUNT = 60; // how many splashes

// anyone can read them. custom:false means none saved, the page uses its built-in list
async function getSplashes(env) {
  try {
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'splashes'").first();
    if (row) {
      const v = JSON.parse(row.value);
      if (Array.isArray(v) && v.length) return json({ splashes: v.map(String), custom: true });
    }
  } catch {}
  return json({ splashes: [], custom: false });
}

// POST /api/admin/splashes {splashes: [..]}  (an empty list goes back to the built-in ones)
async function saveSplashes(request, env) {
  const s = await readSession(env, request);
  if (!isAdmin(s)) return json({ error: "Admins only." }, 403);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  const body = await readJson(request);
  if (!body || !Array.isArray(body.splashes)) return json({ error: "Bad request." }, 400);
  const list = [];
  for (const x of body.splashes) {
    const t = clean(x, SPLASH_MAX);
    if (t && !list.includes(t)) list.push(t);
  }
  if (list.length > SPLASH_COUNT) return json({ error: `Keep it to ${SPLASH_COUNT} splashes at most.` }, 400);
  if (!list.length) {
    await env.DB.prepare("DELETE FROM settings WHERE key = 'splashes'").run();
    await logAction(env, s, "reset splash texts", "splashes", "back to built-in");
    return json({ ok: true, count: 0 });
  }
  await env.DB.prepare(
    `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('splashes', ?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`
  ).bind(JSON.stringify(list), Math.floor(Date.now() / 1000), s.id).run();
  await logAction(env, s, "edited splash texts", "splashes", list.length + " saved");
  return json({ ok: true, count: list.length });
}

/* ---------- one time owner setup (/admin/setup) ----------
   only works while no owner exists AND you know the SETUP_KEY secret */
async function ownerExists(env) {
  const r = await env.DB.prepare("SELECT id FROM users WHERE role = 'owner' LIMIT 1").first();
  return !!r;
}

function setupPage(msg, status = 200) {
  const note = msg ? `<p class="err">${msg}</p>` : "";
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Owner setup | Skin Central</title>
<style>
@font-face{font-family:Mojang;src:url(/fonts/Mojang-Regular.ttf)}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;
  background:#4a3426 url(/images/dirt.png);background-size:128px;font-family:Mojang,monospace;font-size:16px;color:#222}
form{background:#c6c6c6;border:3px solid;border-color:#fff #555 #555 #fff;outline:3px solid #000;padding:24px;max-width:480px;width:100%}
h1{font-size:24px;margin:0 0 12px}
p{margin:0 0 12px}
label{display:block;margin:16px 0 8px}
input{width:100%;font:inherit;color:#fff;background:#000;padding:8px 12px;border:3px solid #6d6d6d}
button{margin-top:24px;width:100%;font:inherit;color:#fff;background:#6d6d6d;padding:10px;border:3px solid;border-color:#bbb #333 #333 #bbb;cursor:pointer}
.err{color:#a00000}
</style></head><body>
<form method="post" action="/admin/setup" autocomplete="off">
<h1>Owner setup</h1>
<p>This creates the one and only owner account, named SkinCentral. It stops working once the owner exists.</p>
${note}
<label for="pw">Owner password (12+ characters)</label>
<input id="pw" name="password" type="password" maxlength="128" autocomplete="new-password" required>
<label for="pw2">Repeat password</label>
<input id="pw2" name="password2" type="password" maxlength="128" autocomplete="new-password" required>
<label for="key">Setup key</label>
<input id="key" name="key" type="password" maxlength="200" autocomplete="off" required>
<button type="submit">Create owner account</button>
</form></body></html>`;
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    },
  });
}

async function setupShow(env) {
  if (!env.SETUP_KEY || (await ownerExists(env))) return notFound();
  return setupPage("");
}

async function setupSubmit(request, env) {
  if (!env.SETUP_KEY || !env.PASSWORD_PEPPER || (await ownerExists(env))) return notFound();
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  const len = Number(request.headers.get("Content-Length") || 0);
  if (len > 4096) return setupPage("That was too big.", 413);

  let form;
  try {
    form = await request.formData();
  } catch {
    return setupPage("That did not look right. Try again.", 400);
  }
  const password = String(form.get("password") || "");
  const password2 = String(form.get("password2") || "");
  const key = String(form.get("key") || "");

  // 5 wrong setup keys per connection per 15 minutes
  const now = Math.floor(Date.now() / 1000);
  const tag = await visitorTag(request, env);
  const limitKey = "setup:" + tag;
  if ((await countAttempts(env, limitKey, now - 900)) >= 5) {
    return setupPage("Too many wrong tries. Wait 15 minutes.", 429);
  }

  // compare the key without leaking how much of it matched (both sides get scrambled first)
  const hk = await hmacKey(env.SESSION_SECRET);
  const a = toB64url(await crypto.subtle.sign("HMAC", hk, enc.encode("setup:" + key)));
  const b = toB64url(await crypto.subtle.sign("HMAC", hk, enc.encode("setup:" + env.SETUP_KEY)));
  if (!sameText(a, b)) {
    await addAttempt(env, limitKey, now);
    return setupPage("That setup key is not right.", 403);
  }

  if (password.length < 12) return setupPage("The password needs at least 12 characters.", 400);
  if (password.length > 128) return setupPage("That password is too long (128 max).", 400);
  if (password !== password2) return setupPage("The two passwords do not match.", 400);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(env, password, salt, PBKDF2_ROUNDS);
  const passHash = `pbkdf2-sha256$${PBKDF2_ROUNDS}$${toB64url(salt)}$${hash}`;
  const id = "u" + [...crypto.getRandomValues(new Uint8Array(6))].map((x) => x.toString(16).padStart(2, "0")).join("");

  // the WHERE NOT EXISTS part makes sure two people cant both become owner at once
  let res;
  try {
    res = await env.DB.prepare(
      `INSERT INTO users (id, username, username_lc, pass_hash, role, banned, created_at)
       SELECT ?, 'SkinCentral', 'skincentral', ?, 'owner', 0, ?
       WHERE NOT EXISTS (SELECT 1 FROM users WHERE role = 'owner')`
    ).bind(id, passHash, now).run();
  } catch (e) {
    if (/UNIQUE/i.test(String(e))) return setupPage("A user named SkinCentral already exists. Ask me how to fix that.", 409);
    throw e;
  }
  if (!res.meta || res.meta.changes !== 1) return notFound();

  // log the new owner in and send them to the home page
  const maxAge = 60 * 60 * 24;
  const token = await signSession(env, {
    id, name: "SkinCentral", avatar: null, mod: true, role: "owner",
    exp: now + maxAge,
  });
  const headers = new Headers({ Location: env.SITE_URL + "/" });
  headers.append("Set-Cookie", cookie("session", token, maxAge));
  return new Response(null, { status: 303, headers });
}

/* ---------- owner + admin tools: users, roles, bans ---------- */
// admins have the same powers as the owner, except they cant touch the owner or other admins
function isAdmin(s) {
  return !!s && (s.role === "owner" || s.role === "admin");
}

// writes a line in the mod log table (shown in the owner panel later)
async function logAction(env, s, action, target, detail) {
  await env.DB.prepare(
    "INSERT INTO mod_log (actor_id, actor_name, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(s.id, clean(s.name, 60), action, clean(target, 80), clean(detail, 200), Math.floor(Date.now() / 1000)).run().catch(() => {});
}

// GET /api/admin/users?q=name  -> up to 50 accounts, newest first
async function adminUsers(request, env, url) {
  const s = await readSession(env, request);
  if (!isAdmin(s)) return json({ error: "Admins only." }, 403);
  const q = clean(url.searchParams.get("q"), 20).toLowerCase();
  let res;
  if (q) {
    // escape % and _ so they search as normal letters
    const like = "%" + q.replace(/[\\%_]/g, (c) => "\\" + c) + "%";
    res = await env.DB.prepare(
      "SELECT id, username, role, banned, created_at FROM users WHERE username_lc LIKE ? ESCAPE '\\' ORDER BY created_at DESC LIMIT 51"
    ).bind(like).all();
  } else {
    res = await env.DB.prepare(
      "SELECT id, username, role, banned, created_at FROM users ORDER BY created_at DESC LIMIT 51"
    ).all();
  }
  const rows = res.results || [];
  return json({
    users: rows.slice(0, 50).map((u) => ({
      id: u.id,
      username: u.username,
      role: u.role,
      banned: !!u.banned,
      created: u.created_at,
    })),
    more: rows.length > 50,
  });
}

// looks up the account an owner action is aimed at, null + error response if its not allowed
async function targetUser(env, s, id) {
  const u = await env.DB.prepare("SELECT id, username, role, banned FROM users WHERE id = ?")
    .bind(String(id || "")).first();
  if (!u) return { err: json({ error: "That account does not exist." }, 404) };
  if (u.id === s.id) return { err: json({ error: "You can not change your own account here." }, 400) };
  if (u.role === "owner") return { err: json({ error: "The owner account can not be changed." }, 400) };
  if (u.role === "admin" && s.role !== "owner") {
    return { err: json({ error: "Only the owner can change an admin." }, 403) };
  }
  return { u };
}

// POST /api/admin/user-role  {id, role: "mod" or "user"}
async function setUserRole(request, env) {
  const s = await readSession(env, request);
  if (!isAdmin(s)) return json({ error: "Admins only." }, 403);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  const body = await readJson(request);
  if (!body) return json({ error: "Bad request." }, 400);
  const role = ["user", "mod", "admin"].includes(body.role) ? body.role : null;
  if (!role) return json({ error: "Pick user, moderator or admin." }, 400);
  if (role === "admin" && s.role !== "owner") return json({ error: "Only the owner can make admins." }, 403);
  const t = await targetUser(env, s, body.id);
  if (t.err) return t.err;
  if (t.u.banned && role !== "user") return json({ error: "Unban that account first." }, 400);
  await env.DB.prepare("UPDATE users SET role = ? WHERE id = ?").bind(role, t.u.id).run();
  const what = { user: "set to user", mod: "set to moderator", admin: "set to admin" };
  await logAction(env, s, what[role], t.u.username, "was " + t.u.role);
  return json({ ok: true, role });
}

// POST /api/admin/user-ban  {id, banned: true/false}
async function setUserBan(request, env) {
  const s = await readSession(env, request);
  if (!isAdmin(s)) return json({ error: "Admins only." }, 403);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  const body = await readJson(request);
  if (!body) return json({ error: "Bad request." }, 400);
  const banned = body.banned === true;
  const t = await targetUser(env, s, body.id);
  if (t.err) return t.err;
  // a banned moderator also loses the role so unbanning doesnt hand it back
  await env.DB.prepare("UPDATE users SET banned = ?, role = CASE WHEN ? = 1 THEN 'user' ELSE role END WHERE id = ?")
    .bind(banned ? 1 : 0, banned ? 1 : 0, t.u.id).run();
  await logAction(env, s, banned ? "banned" : "unbanned", t.u.username, "");
  return json({ ok: true, banned });
}

// POST /api/admin/user-delete {id, confirm: username}  (owner only)
// the account, its likes, comments and profile picture are deleted for good.
// their packs stay up but turn anonymous ("Deleted user") so nothing disappears from the gallery
async function deleteAccount(request, env) {
  const s = await readSession(env, request);
  if (!s || s.role !== "owner") return json({ error: "Only the owner can delete accounts." }, 403);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  const body = await readJson(request);
  if (!body) return json({ error: "Bad request." }, 400);
  const t = await targetUser(env, s, body.id);
  if (t.err) return t.err;
  // typing the username is the "are you really sure" step
  if (String(body.confirm || "").trim().toLowerCase() !== t.u.username.toLowerCase()) {
    return json({ error: "The username you typed does not match." }, 400);
  }
  const id = t.u.id;
  // picture first, if this fails nothing else was touched yet
  await env.FILES.delete("avatars/" + t.u.username.toLowerCase());
  await env.DB.batch([
    env.DB.prepare("DELETE FROM likes WHERE user_id = ?").bind(id),
    env.DB.prepare("DELETE FROM comments WHERE user_id = ?").bind(id),
    env.DB.prepare("UPDATE packs SET creator_id = 'anon', creator_name = 'Deleted user' WHERE creator_id = ?").bind(id),
    env.DB.prepare("DELETE FROM login_attempts WHERE key IN (?, ?)").bind("login:user:" + t.u.username.toLowerCase(), "profile:" + id),
    env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id),
  ]);
  await logAction(env, s, "deleted an account", t.u.username, "was " + t.u.role);
  return json({ ok: true });
}

// GET /api/admin/log  -> the last 100 owner/admin actions
async function adminLog(request, env) {
  const s = await readSession(env, request);
  if (!isAdmin(s)) return json({ error: "Admins only." }, 403);
  const { results } = await env.DB.prepare(
    "SELECT actor_name, action, target, detail, created_at FROM mod_log ORDER BY id DESC LIMIT 100"
  ).all();
  return json({
    log: (results || []).map((r) => ({
      actor: r.actor_name,
      action: r.action,
      target: r.target,
      detail: r.detail || "",
      created: r.created_at,
    })),
  });
}

// GET /api/admin/stats  -> site numbers for the owner panel
async function adminStats(request, env) {
  const s = await readSession(env, request);
  if (!isAdmin(s)) return json({ error: "Admins only." }, 403);
  // a missing table just counts as 0 instead of breaking the whole box
  const one = async (sql) => {
    try {
      const r = await env.DB.prepare(sql).first();
      return r ? r.n || 0 : 0;
    } catch {
      return 0;
    }
  };
  const [users, approved, pending, denied, downloads, likes, comments, reports] = await Promise.all([
    one("SELECT COUNT(*) AS n FROM users"),
    one("SELECT COUNT(*) AS n FROM packs WHERE status = 'approved'"),
    one("SELECT COUNT(*) AS n FROM packs WHERE status = 'pending'"),
    one("SELECT COUNT(*) AS n FROM packs WHERE status = 'denied'"),
    one("SELECT COALESCE(SUM(downloads), 0) AS n FROM packs"),
    one("SELECT COUNT(*) AS n FROM likes"),
    one("SELECT COUNT(*) AS n FROM comments"),
    one("SELECT COUNT(*) AS n FROM reports WHERE status = 'open'"),
  ]);
  return json({ users, approved, pending, denied, downloads, likes, comments, reports });
}

/* ---------- owner + admin tools: pack owners ---------- */
// finds a site account by username, null if there isnt one
async function findAccount(env, name) {
  const lc = clean(name, 20).toLowerCase();
  if (!lc) return null;
  return env.DB.prepare("SELECT id, username, banned FROM users WHERE username_lc = ?").bind(lc).first();
}

// POST /api/admin/pack-owner {id: pack id, to: username}  (also works for anonymous packs)
async function setPackOwner(request, env) {
  const s = await readSession(env, request);
  if (!isAdmin(s)) return json({ error: "Admins only." }, 403);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  const body = await readJson(request);
  if (!body) return json({ error: "Bad request." }, 400);
  const pack = await env.DB.prepare("SELECT id, name, creator_name FROM packs WHERE id = ?")
    .bind(String(body.id || "").slice(0, 40)).first();
  if (!pack) return json({ error: "That pack does not exist." }, 404);
  const to = await findAccount(env, body.to);
  if (!to) return json({ error: "There is no account with that username." }, 404);
  if (to.banned) return json({ error: "That account is banned." }, 400);
  await env.DB.prepare("UPDATE packs SET creator_id = ?, creator_name = ? WHERE id = ?")
    .bind(to.id, to.username, pack.id).run();
  await logAction(env, s, "changed a pack owner", pack.name, `${pack.creator_name || "anonymous"} -> ${to.username}`);
  return json({ ok: true });
}

/* ---------- packs ---------- */
// turns a database row into the same shape as packs.json
function packView(r) {
  const files = JSON.parse(r.files || "[]");
  const images = JSON.parse(r.images || "[]");
  return {
    id: r.id,
    slug: r.slug,
    name: r.name,
    creator: r.creator_name,
    creatorId: r.creator_id && r.creator_id !== "anon" ? r.creator_id : null,
    // site accounts get a profile link and picture (creator_name is their username)
    creatorUsername: /^u[0-9a-f]{12}$/.test(String(r.creator_id || "")) ? r.creator_name : null,
    creatorAvatar: /^u[0-9a-f]{12}$/.test(String(r.creator_id || "")) && r.creator_has_avatar
      ? `/files/avatar/${String(r.creator_name).toLowerCase()}?v=${r.creator_avatar_v || 0}`
      : null,
    date: new Date(r.created_at * 1000).toISOString().slice(0, 10),
    tags: JSON.parse(r.tags || "[]"),
    description: r.description,
    type: r.type === "texture" ? "texture" : "skin",   // old packs have no type, they are skins
    downloads: r.downloads || 0,
    likes: r.like_count || 0,
    icon: `/files/${r.id}/icon`,
    images: images.map((n) => `/files/${r.id}/${n}`),
    files: files.map((f) => ({
      platform: f.platform,
      href: `/files/${r.id}/${f.pkey}/${f.filename}`,
      size: niceSize(f.size),
    })),
  };
}

async function listPacks(env) {
  let results;
  try {
    ({ results } = await env.DB.prepare(
      `SELECT p.*, (SELECT COUNT(*) FROM likes l WHERE l.pack_id = p.id) AS like_count,
              u.has_avatar AS creator_has_avatar, u.avatar_v AS creator_avatar_v
       FROM packs p LEFT JOIN users u ON u.id = p.creator_id
       WHERE p.status = 'approved' ORDER BY p.created_at DESC LIMIT 500`
    ).all());
  } catch {
    // profile columns missing, go without pictures
    try {
      ({ results } = await env.DB.prepare(
        `SELECT p.*, (SELECT COUNT(*) FROM likes l WHERE l.pack_id = p.id) AS like_count
         FROM packs p WHERE p.status = 'approved' ORDER BY p.created_at DESC LIMIT 500`
      ).all());
    } catch {
      // likes table missing, just skip the counts
      ({ results } = await env.DB.prepare(
        "SELECT * FROM packs WHERE status = 'approved' ORDER BY created_at DESC LIMIT 500"
      ).all());
    }
  }
  return json(results.map(packView));
}

async function myPacks(request, env) {
  const s = await readSession(env, request);
  if (!s) return json({ error: "Please log in first." }, 401);
  const { results } = await env.DB.prepare(
    "SELECT id, name, description, tags, images, files, status, deny_reason, created_at FROM packs WHERE creator_id = ? ORDER BY created_at DESC LIMIT 50"
  ).bind(s.id).all();
  return json(results.map((r) => {
    let tags = [], images = [], files = [];
    try { tags = JSON.parse(r.tags || "[]"); } catch {}
    try { images = JSON.parse(r.images || "[]"); } catch {}
    try { files = JSON.parse(r.files || "[]"); } catch {}
    return { ...r, tags, images, files };
  }));
}

// edit your own pack. mods can edit ANY pack, theirs go live right away and the status stays
// - text only (name, description, tags): approved packs stay live
// - new icon, screenshot or pack file: approved pack goes back to pending
// - denied pack always goes back to pending
async function editMine(request, env, ctx) {
  const s = await readSession(env, request);
  if (!s) return json({ error: "Please log in first." }, 401);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  const len = Number(request.headers.get("Content-Length") || 0);
  if (len > LIMITS.total + 1024 * 1024) return json({ error: "That upload is too big." }, 413);
  let form;
  try {
    form = await request.formData();
  } catch {
    return json({ error: "Bad request." }, 400);
  }
  const id = String(form.get("id") || "");
  if (!/^[a-f0-9]{12}$/.test(id)) return json({ error: "Bad pack id." }, 400);
  const name = clean(form.get("name"), 40);
  const description = clean(form.get("description"), 500);
  if (name.length < 3) return json({ error: "Pack name must be at least 3 characters." }, 400);
  const tags = [];
  for (const t of clean(form.get("tags"), 200).split(",")) {
    const tag = clean(t, 20);
    if (tag && !tags.some((x) => x.toLowerCase() === tag.toLowerCase())) tags.push(tag);
  }
  tags.length = Math.min(tags.length, 5);

  // normal people can only edit their own packs, mods can edit any pack
  const row = s.mod
    ? await env.DB.prepare(
        "SELECT id, creator_id, status, images, files FROM packs WHERE id = ?"
      ).bind(id).first()
    : await env.DB.prepare(
        "SELECT id, creator_id, status, images, files FROM packs WHERE id = ? AND creator_id = ?"
      ).bind(id, s.id).first();
  if (!row) return json({ error: "Pack not found." }, 404);

  let newImages = [], newFiles = [];
  try { newImages = JSON.parse(row.images || "[]"); } catch {}
  try { newFiles = JSON.parse(row.files || "[]"); } catch {}

  // whats in R2 for this pack right now (key -> size), for the total size check
  const sizes = new Map();
  let cursor;
  do {
    const page = await env.FILES.list({ prefix: id + "/", cursor });
    for (const o of page.objects) sizes.set(o.key, o.size);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  const existing = new Set(sizes.keys());

  const puts = [];     // new files to store
  const removes = [];  // old files to delete after everything worked
  let mediaChanged = false;

  const icon = form.get("icon");
  if (isFile(icon)) {
    if (icon.size > LIMITS.icon) return json({ error: "The icon is too big (max 512 KB)." }, 400);
    const type = await sniffImage(icon);
    if (!type) return json({ error: "The icon must be a PNG, JPG or WebP image." }, 400);
    puts.push({ key: `${id}/icon`, file: icon, type });
    sizes.set(`${id}/icon`, icon.size);
    mediaChanged = true;
  }

  for (let i = 1; i <= 4; i++) {
    const n = "shot" + i;
    const key = `${id}/${n}`;
    const f = form.get(n);
    if (isFile(f)) {
      if (f.size > LIMITS.shot) return json({ error: `Screenshot ${i} is too big (max 2 MB).` }, 400);
      const type = await sniffImage(f);
      if (!type) return json({ error: `Screenshot ${i} must be a PNG, JPG or WebP image.` }, 400);
      puts.push({ key, file: f, type });
      sizes.set(key, f.size);
      if (!newImages.includes(n)) newImages.push(n);
      mediaChanged = true;
    } else if (form.get("remove_" + n) === "1" && newImages.includes(n)) {
      newImages = newImages.filter((x) => x !== n);
      removes.push(key);
      sizes.delete(key);
      mediaChanged = true;
    }
  }
  newImages.sort();

  for (const pkey of Object.keys(PLATFORMS)) {
    const f = form.get("file_" + pkey);
    const old = newFiles.find((x) => x.pkey === pkey);
    if (isFile(f)) {
      if (f.size > LIMITS.pack) {
        return json({ error: `The ${PLATFORMS[pkey]} file is too big (max 5 MB).` }, 400);
      }
      const filename = safeName(f.name);
      if (BLOCKED_EXT.test(filename)) {
        return json({ error: `The ${PLATFORMS[pkey]} file type isn't allowed.` }, 400);
      }
      const key = `${id}/${pkey}/${filename}`;
      if (old) {
        const oldKey = `${id}/${pkey}/${old.filename}`;
        if (oldKey !== key) {
          removes.push(oldKey);
          sizes.delete(oldKey);
        }
        newFiles = newFiles.filter((x) => x.pkey !== pkey);
      }
      puts.push({ key, file: f, type: "application/octet-stream" });
      sizes.set(key, f.size);
      newFiles.push({ platform: PLATFORMS[pkey], pkey, filename, size: f.size });
      mediaChanged = true;
    } else if (form.get("remove_file_" + pkey) === "1" && old) {
      const oldKey = `${id}/${pkey}/${old.filename}`;
      removes.push(oldKey);
      sizes.delete(oldKey);
      newFiles = newFiles.filter((x) => x.pkey !== pkey);
      mediaChanged = true;
    }
  }
  if (!newFiles.length) return json({ error: "A pack needs at least one pack file." }, 400);

  let total = 0;
  for (const v of sizes.values()) total += v;
  if (total > LIMITS.total) {
    return json({ error: `That pack would be too big overall (max ${Math.round(LIMITS.total / 1048576)} MB).` }, 400);
  }

  const wasDenied = row.status === "denied";
  const backToPending = !s.mod && row.status !== "pending" && (wasDenied || mediaChanged);
  if (backToPending) {
    const pending = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM packs WHERE creator_id = ? AND status = 'pending'"
    ).bind(s.id).first();
    if (pending.n >= LIMITS.maxPending) {
      return json({
        error: `You already have ${LIMITS.maxPending} packs waiting for review. Please wait for a moderator.`,
      }, 429);
    }
    // take the pack off the site BEFORE storing new files so unreviewed stuff is never public
    await env.DB.prepare(
      `UPDATE packs SET status = 'pending', deny_reason = NULL, reviewed_by = NULL, reviewed_at = NULL
       WHERE id = ? AND creator_id = ?`
    ).bind(id, row.creator_id).run();
  }

  const done = [];
  try {
    for (const u of puts) {
      await env.FILES.put(u.key, await u.file.arrayBuffer(), {
        httpMetadata: { contentType: u.type },
      });
      done.push(u.key);
    }
    await env.DB.prepare(
      "UPDATE packs SET name = ?, description = ?, tags = ?, images = ?, files = ? WHERE id = ? AND creator_id = ?"
    ).bind(
      name, description, JSON.stringify(tags), JSON.stringify(newImages), JSON.stringify(newFiles), id, row.creator_id
    ).run();
  } catch (e) {
    await Promise.allSettled(done.filter((k) => !existing.has(k)).map((k) => env.FILES.delete(k)));
    return json({ error: "Saving failed. Please try again." }, 500);
  }
  if (removes.length) await Promise.allSettled(removes.map((k) => env.FILES.delete(k)));

  if (backToPending && env.MOD_WEBHOOK_URL) {
    ctx.waitUntil(
      fetch(env.MOD_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: `<@&${env.MOD_ROLE_ID}> ${wasDenied ? "A denied pack was edited" : "A pack's icon, screenshots or files were changed"} and it is waiting for review again.`,
          allowed_mentions: { roles: [env.MOD_ROLE_ID] },
          embeds: [{
            title: name,
            description: description.slice(0, 300) || "(no description)",
            url: env.SITE_URL + "/#/admin",
            color: 0x8f8f8f,
            fields: [
              { name: "By", value: clean(s.name, 60) || "unknown" },
              { name: "Platforms", value: newFiles.map((f) => f.platform).join(", ") },
            ],
          }],
        }),
      }).catch(() => {})
    );
  }

  return json({ ok: true, name, description, tags, status: backToPending ? "pending" : row.status });
}

// delete your own pack, mods can delete any pack
// R2 files go first, then the database row
async function deleteMine(request, env) {
  const s = await readSession(env, request);
  if (!s) return json({ error: "Please log in first." }, 401);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Bad request." }, 400);
  }
  const id = String(body.id || "");
  if (!/^[a-f0-9]{12}$/.test(id)) return json({ error: "Bad pack id." }, 400);
  // normal people can only delete their own packs, mods can delete any pack
  const row = s.mod
    ? await env.DB.prepare("SELECT id FROM packs WHERE id = ?").bind(id).first()
    : await env.DB.prepare("SELECT id FROM packs WHERE id = ? AND creator_id = ?").bind(id, s.id).first();
  if (!row) return json({ error: "Pack not found." }, 404);
  // every file of a pack is under "<id>/" in R2
  let cursor;
  do {
    const page = await env.FILES.list({ prefix: id + "/", cursor });
    if (page.objects.length) await env.FILES.delete(page.objects.map((o) => o.key));
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  // likes and comments go with it
  await env.DB.prepare("DELETE FROM likes WHERE pack_id = ?").bind(id).run().catch(() => {});
  await env.DB.prepare("DELETE FROM comments WHERE pack_id = ?").bind(id).run().catch(() => {});
  await env.DB.prepare("DELETE FROM packs WHERE id = ?").bind(id).run();
  return json({ ok: true });
}

// asks turnstile if the visitor passed the human check
async function checkHuman(request, env) {
  if (!env.TURNSTILE_SECRET) return false;
  const token = request.headers.get("X-Turnstile-Token") || "";
  if (!token || token.length > 2048) return false;
  const params = new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: token });
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) params.set("remoteip", ip);
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: params,
    });
    const out = await res.json();
    return out.success === true;
  } catch {
    return false;
  }
}

// scrambled (hashed) tag for a visitors ip, the real ip never gets stored
async function visitorTag(request, env) {
  let ip = request.headers.get("CF-Connecting-IP") || "unknown";
  // ipv6 only uses the first half so changing the end of the address doesnt skip the limit
  if (ip.includes(":")) ip = ip.split(":").slice(0, 4).join(":");
  const sig = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(env.SESSION_SECRET),
    enc.encode("visitor:" + ip)
  );
  return toB64url(sig).slice(0, 24);
}

async function submit(request, env, ctx) {
  // anon uploads use /api/submit?anon=1, no login but a human check and tighter limits
  const anon = new URL(request.url).searchParams.get("anon") === "1";
  let s;
  if (anon) {
    s = { id: "anon", name: "Anonymous" };
  } else {
    s = await readSession(env, request);
    if (!s) return json({ error: "Please log in first." }, 401);
  }
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);

  const totalMax = anon ? LIMITS.anonTotal : LIMITS.total;
  const len = Number(request.headers.get("Content-Length") || 0);
  if (len > totalMax + 1024 * 1024) {
    return json({ error: "That upload is too big." }, 413);
  }

  let visitor = null;
  if (anon) {
    if (!(await checkHuman(request, env))) {
      return json({ error: "The human check failed. Please reload the page and try again." }, 400);
    }
    visitor = await visitorTag(request, env);
    const now = Math.floor(Date.now() / 1000);
    const today = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM packs WHERE ip_hash = ? AND created_at > ?"
    ).bind(visitor, now - 86400).first();
    if (today.n >= LIMITS.anonPerDay) {
      return json({
        error: `Anonymous uploads are limited to ${LIMITS.anonPerDay} per day. Try again tomorrow, or log in.`,
      }, 429);
    }
    const queue = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM packs WHERE creator_id = 'anon' AND status = 'pending'"
    ).first();
    if (queue.n >= LIMITS.anonMaxPending) {
      return json({
        error: "Too many anonymous packs are waiting for review right now. Please try again later, or log in.",
      }, 429);
    }
  } else {
    const pending = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM packs WHERE creator_id = ? AND status = 'pending'"
    ).bind(s.id).first();
    if (pending.n >= LIMITS.maxPending) {
      return json({
        error: `You already have ${LIMITS.maxPending} packs waiting for review. Please wait for a moderator.`,
      }, 429);
    }
  }

  let form;
  try {
    form = await request.formData();
  } catch {
    return json({ error: "Could not read the upload." }, 400);
  }

  const name = clean(form.get("name"), 40);
  const description = clean(form.get("description"), 500);
  if (name.length < 3) return json({ error: "Pack name must be at least 3 characters." }, 400);
  // skin pack or texture pack, anything else counts as skin
  const packType = form.get("type") === "texture" ? "texture" : "skin";

  const tags = [];
  for (const t of clean(form.get("tags"), 200).split(",")) {
    const tag = clean(t, 20);
    if (tag && !tags.some((x) => x.toLowerCase() === tag.toLowerCase())) tags.push(tag);
  }
  tags.length = Math.min(tags.length, 5);

  const id = [...crypto.getRandomValues(new Uint8Array(6))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const slug = slugify(name) + "-" + id.slice(0, 4);

  const uploads = [];
  let total = 0;

  const icon = form.get("icon");
  if (!isFile(icon)) return json({ error: "Please add an icon image." }, 400);
  if (icon.size > LIMITS.icon) return json({ error: "The icon is too big (max 512 KB)." }, 400);
  const iconType = await sniffImage(icon);
  if (!iconType) return json({ error: "The icon must be a PNG, JPG or WebP image." }, 400);
  uploads.push({ key: `${id}/icon`, file: icon, type: iconType });
  total += icon.size;

  const images = [];
  for (let i = 1; i <= 4; i++) {
    const f = form.get("shot" + i);
    if (!isFile(f)) continue;
    if (f.size > LIMITS.shot) return json({ error: `Screenshot ${i} is too big (max 2 MB).` }, 400);
    const type = await sniffImage(f);
    if (!type) return json({ error: `Screenshot ${i} must be a PNG, JPG or WebP image.` }, 400);
    uploads.push({ key: `${id}/shot${i}`, file: f, type });
    images.push("shot" + i);
    total += f.size;
  }

  const files = [];
  for (const pkey of Object.keys(PLATFORMS)) {
    const f = form.get("file_" + pkey);
    if (!isFile(f)) continue;
    if (f.size > LIMITS.pack) {
      return json({ error: `The ${PLATFORMS[pkey]} file is too big (max 5 MB).` }, 400);
    }
    const filename = safeName(f.name);
    if (BLOCKED_EXT.test(filename)) {
      return json({ error: `The ${PLATFORMS[pkey]} file type isn't allowed.` }, 400);
    }
    uploads.push({ key: `${id}/${pkey}/${filename}`, file: f, type: "application/octet-stream" });
    files.push({ platform: PLATFORMS[pkey], pkey, filename, size: f.size });
    total += f.size;
  }
  if (!files.length) return json({ error: "Please add at least one pack file." }, 400);
  if (total > totalMax) return json({ error: `That upload is too big overall (max ${Math.round(totalMax / 1048576)} MB).` }, 400);

  const done = [];
  try {
    for (const u of uploads) {
      await env.FILES.put(u.key, await u.file.arrayBuffer(), {
        httpMetadata: { contentType: u.type },
      });
      done.push(u.key);
    }
    await env.DB.prepare(
      `INSERT INTO packs
       (id, slug, name, description, tags, creator_id, creator_name, status, icon_key, images, files, created_at, ip_hash, type)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 'icon', ?, ?, ?, ?, ?)`
    ).bind(
      id, slug, name, description, JSON.stringify(tags), s.id, clean(s.name, 60),
      JSON.stringify(images), JSON.stringify(files), Math.floor(Date.now() / 1000), visitor, packType
    ).run();
  } catch (e) {
    await Promise.allSettled(done.map((k) => env.FILES.delete(k)));
    return json({ error: "Upload failed. Please try again." }, 500);
  }

  if (env.MOD_WEBHOOK_URL) {
    ctx.waitUntil(
      fetch(env.MOD_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: `<@&${env.MOD_ROLE_ID}> A new ${packType === "texture" ? "texture pack" : "skin pack"} is waiting for review.`,
          allowed_mentions: { roles: [env.MOD_ROLE_ID] },
          embeds: [{
            title: name,
            description: description.slice(0, 300) || "(no description)",
            url: env.SITE_URL + "/#/admin",
            color: 0x8f8f8f,
            fields: [
              { name: "By", value: anon ? "Anonymous (no login)" : (clean(s.name, 60) || "unknown") },
              { name: "Type", value: packType === "texture" ? "Texture pack" : "Skin pack" },
              { name: "Platforms", value: files.map((f) => f.platform).join(", ") },
            ],
          }],
        }),
      }).catch(() => {})
    );
  }

  return json({ ok: true, message: "Submitted! A moderator will review your pack soon." });
}

/* ---------- moderation ---------- */
async function adminList(request, env, url) {
  const s = await readSession(env, request);
  if (!s || !s.mod) return json({ error: "Moderators only." }, 403);
  const status = url.searchParams.get("status") || "pending";
  if (!["pending", "approved", "denied"].includes(status)) {
    return json({ error: "Bad status." }, 400);
  }
  const { results } = await env.DB.prepare(
    "SELECT * FROM packs WHERE status = ? ORDER BY created_at DESC LIMIT 100"
  ).bind(status).all();
  return json(
    results.map((r) => ({
      ...packView(r),
      status: r.status,
      creatorId: r.creator_id,
      anonymous: r.creator_id === "anon",
      visitorTag: r.ip_hash ? r.ip_hash.slice(0, 8) : null,
      denyReason: r.deny_reason,
      imageNames: JSON.parse(r.images || "[]"),
      fileInfo: JSON.parse(r.files || "[]"),
    }))
  );
}

async function review(request, env) {
  const s = await readSession(env, request);
  if (!s || !s.mod) return json({ error: "Moderators only." }, 403);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Bad request." }, 400);
  }
  const id = String(body.id || "");
  if (!/^[a-f0-9]{12}$/.test(id)) return json({ error: "Bad pack id." }, 400);
  if (body.action !== "approve" && body.action !== "deny") {
    return json({ error: "Bad action." }, 400);
  }
  const status = body.action === "approve" ? "approved" : "denied";
  const reason = status === "denied" ? clean(body.reason, 200) : null;
  const r = await env.DB.prepare(
    "UPDATE packs SET status = ?, reviewed_by = ?, reviewed_at = ?, deny_reason = ? WHERE id = ?"
  ).bind(
    status, `${clean(s.name, 60)} (${s.id})`, Math.floor(Date.now() / 1000), reason, id
  ).run();
  if (!r.meta.changes) return json({ error: "Pack not found." }, 404);
  return json({ ok: true, status });
}

/* ---------- reports ---------- */
async function report(request, env, ctx) {
  const s = await readSession(env, request);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Bad request." }, 400);
  }
  const slug = clean(body.slug, 80);
  const reason = clean(body.reason, 300);
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(slug)) return json({ error: "Bad pack." }, 400);
  if (reason.length < 5) {
    return json({ error: "Please say what is wrong (at least 5 characters)." }, 400);
  }

  const now = Math.floor(Date.now() / 1000);
  let reporterId = "anon", reporterName = "Anonymous visitor", anonKey = null;
  if (s) {
    reporterId = s.id;
    reporterName = clean(s.name, 60);
    const recent = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM reports WHERE reporter_id = ? AND created_at > ?"
    ).bind(s.id, now - 86400).first();
    if (recent.n >= 5) {
      return json({ error: "You have sent several reports today. Please try again tomorrow." }, 429);
    }
  } else {
    // not logged in: human check + 5 per connection per day
    anonKey = "report:" + (await visitorTag(request, env));
    if ((await countAttempts(env, anonKey, now - 86400)) >= 5) {
      return json({ error: "You have sent several reports today. Please try again tomorrow." }, 429);
    }
    if (!(await checkHuman(request, env))) {
      return json({ error: "The human check failed. Please try again." }, 400);
    }
  }

  const pack = await env.DB.prepare("SELECT id, name FROM packs WHERE slug = ?").bind(slug).first();
  const packName = pack ? pack.name : clean(body.name, 60) || slug;
  await env.DB.prepare(
    `INSERT INTO reports (pack_slug, pack_id, pack_name, reporter_id, reporter_name, reason, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(slug, pack ? pack.id : null, packName, reporterId, reporterName, reason, now).run();
  if (anonKey) await addAttempt(env, anonKey, now);

  if (env.MOD_WEBHOOK_URL) {
    ctx.waitUntil(
      fetch(env.MOD_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: `<@&${env.MOD_ROLE_ID}> A pack was reported.`,
          allowed_mentions: { roles: [env.MOD_ROLE_ID] },
          embeds: [{
            title: packName,
            description: reason,
            url: env.SITE_URL + "/#/admin",
            color: 0xaa0000,
            fields: [{ name: "Reported by", value: reporterName || "unknown" }],
          }],
        }),
      }).catch(() => {})
    );
  }
  return json({ ok: true, message: "Thanks, your report was sent to the moderators." });
}

async function adminReports(request, env) {
  const s = await readSession(env, request);
  if (!s || !s.mod) return json({ error: "Moderators only." }, 403);
  const { results } = await env.DB.prepare(
    "SELECT * FROM reports WHERE status = 'open' ORDER BY created_at DESC LIMIT 100"
  ).all();
  return json(
    results.map((r) => ({
      id: r.id,
      packId: r.pack_id,
      packSlug: r.pack_slug,
      packName: r.pack_name,
      reporter: r.reporter_name,
      reporterId: r.reporter_id,
      reason: r.reason,
      date: new Date(r.created_at * 1000).toISOString().slice(0, 10),
    }))
  );
}

async function closeReport(request, env) {
  const s = await readSession(env, request);
  if (!s || !s.mod) return json({ error: "Moderators only." }, 403);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Bad request." }, 400);
  }
  const id = Number(body.id);
  if (!Number.isInteger(id) || id < 1) return json({ error: "Bad report id." }, 400);
  await env.DB.prepare("UPDATE reports SET status = 'closed' WHERE id = ?").bind(id).run();
  return json({ ok: true });
}

/* ---------- moderation: all packs + edit details ---------- */
async function adminAll(request, env) {
  const s = await readSession(env, request);
  if (!s || !s.mod) return json({ error: "Moderators only." }, 403);
  const { results } = await env.DB.prepare(
    "SELECT * FROM packs ORDER BY created_at DESC LIMIT 200"
  ).all();
  return json(
    results.map((r) => ({
      ...packView(r),
      status: r.status,
      creatorId: r.creator_id,
      anonymous: r.creator_id === "anon",
      visitorTag: r.ip_hash ? r.ip_hash.slice(0, 8) : null,
      denyReason: r.deny_reason,
      imageNames: JSON.parse(r.images || "[]"),
      fileInfo: JSON.parse(r.files || "[]"),
    }))
  );
}

/* ---------- file downloads (from R2) ---------- */
async function serveFile(request, env, url, ctx) {
  // paths look like /files/<id>/icon or /files/<id>/<platform>/<filename>
  const parts = url.pathname.split("/");
  const id = parts[2] || "";
  const a = parts[3] || "";
  const b = parts[4] || "";
  if (!/^[a-f0-9]{12}$/.test(id)) return notFound();

  let key, isImage;
  if (parts.length === 4 && /^(icon|shot[1-4])$/.test(a)) {
    key = `${id}/${a}`;
    isImage = true;
  } else if (parts.length === 5 && /^[a-z0-9]{3,10}$/.test(a) && /^[A-Za-z0-9._-]{1,80}$/.test(b)) {
    key = `${id}/${a}/${b}`;
    isImage = false;
  } else {
    return notFound();
  }

  const row = await env.DB.prepare(
    "SELECT status, creator_id FROM packs WHERE id = ?"
  ).bind(id).first();
  if (!row) return notFound();

  // pending or denied packs can only be seen by mods and the uploader
  let allowed = row.status === "approved";
  if (!allowed) {
    const s = await readSession(env, request);
    allowed = !!s && (s.mod || s.id === row.creator_id);
  }
  if (!allowed) return notFound();

  const obj = await env.FILES.get(key);
  if (!obj) return notFound();

  const headers = new Headers({
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; sandbox",
    "Cache-Control": row.status === "approved" ? "public, max-age=300" : "private, no-store",
  });
  if (isImage) {
    const t = obj.httpMetadata && obj.httpMetadata.contentType;
    headers.set(
      "Content-Type",
      ["image/png", "image/jpeg", "image/webp"].includes(t) ? t : "application/octet-stream"
    );
  } else {
    headers.set("Content-Type", "application/octet-stream");
    headers.set("Content-Disposition", `attachment; filename="${b}"`);
  }
  // plain download count: every pack file download on an approved pack adds 1
  // (images dont count, and neither do resumed/partial downloads)
  if (!isImage && row.status === "approved" && !request.headers.get("Range")) {
    ctx.waitUntil(
      env.DB.prepare("UPDATE packs SET downloads = downloads + 1 WHERE id = ?").bind(id).run().catch(() => {})
    );
  }
  return new Response(obj.body, { headers });
}

/* ---------- profiles (display name, bio, picture) ---------- */
// GET /api/user?name=<username> -> public profile info
async function publicProfile(env, url) {
  const lc = String(url.searchParams.get("name") || "").toLowerCase();
  if (!/^[a-z0-9_]{3,20}$/.test(lc)) return json({ error: "No one has that name." }, 404);
  let u;
  try {
    u = await env.DB.prepare(
      "SELECT username, display_name, bio, has_avatar, avatar_v, role, banned, created_at FROM users WHERE username_lc = ?"
    ).bind(lc).first();
  } catch {
    u = await env.DB.prepare(
      "SELECT username, role, banned, created_at FROM users WHERE username_lc = ?"
    ).bind(lc).first();
  }
  if (!u || u.banned) return json({ error: "No one has that name." }, 404);
  return json({
    username: u.username,
    displayName: u.display_name || null,
    bio: u.bio || "",
    hasAvatar: !!u.has_avatar,
    avatarV: u.avatar_v || 0,
    role: u.role,
    joined: new Date(u.created_at * 1000).toISOString().slice(0, 10),
  });
}

// GET /files/avatar/<username> -> the profile picture (?v=N is only there so browsers refresh it)
async function serveAvatar(env, url) {
  const parts = url.pathname.split("/");
  const lc = parts[3] || "";
  if (parts.length !== 4 || !/^[a-z0-9_]{3,20}$/.test(lc)) return notFound();
  const obj = await env.FILES.get("avatars/" + lc);
  if (!obj) return notFound();
  const t = obj.httpMetadata && obj.httpMetadata.contentType;
  return new Response(obj.body, {
    headers: {
      "Content-Type": ["image/png", "image/jpeg", "image/webp"].includes(t) ? t : "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'none'; sandbox",
      "Cache-Control": url.searchParams.has("v") ? "public, max-age=31536000, immutable" : "public, max-age=300",
    },
  });
}

// POST /api/profile (multipart: displayName, bio, avatar file, removeAvatar=1)
async function saveProfile(request, env) {
  const s = await readSession(env, request);
  if (!s) return json({ error: "Please log in first." }, 401);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  const len = Number(request.headers.get("Content-Length") || 0);
  if (len > LIMITS.avatar + 64 * 1024) return json({ error: "That upload is too big." }, 413);

  const now = Math.floor(Date.now() / 1000);
  if ((await countAttempts(env, "profile:" + s.id, now - 3600)) >= LIMITS.profileEditsPerHour) {
    return json({ error: "You changed your profile too many times. Try again later." }, 429);
  }

  let form;
  try { form = await request.formData(); } catch { return json({ error: "Bad request." }, 400); }
  const nameIn = form.get("displayName");
  const bioIn = form.get("bio");
  const displayName = typeof nameIn === "string" ? clean(nameIn, LIMITS.nameMax) : "";
  const bio = typeof bioIn === "string" ? clean(bioIn, LIMITS.bioMax) : "";

  if (displayName) {
    if (!/[\p{L}\p{N}]/u.test(displayName)) {
      return json({ error: "Your display name needs at least one letter or number." }, 400);
    }
    // letters and numbers only, so "Skin_Central" and "skin central" count as the same name
    const flat = displayName.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (flat && RESERVED_NAMES.has(flat) && s.role !== "owner") {
      return json({ error: "You cannot use that display name." }, 400);
    }
    // nobody can look like somebody else's username
    if (flat && flat !== s.name.toLowerCase().replace(/[^a-z0-9]/g, "")) {
      const clash = await env.DB.prepare(
        "SELECT id FROM users WHERE REPLACE(username_lc, '_', '') = ? AND id != ?"
      ).bind(flat, s.id).first();
      if (clash) return json({ error: "That name belongs to another account." }, 400);
    }
  }

  const lc = s.name.toLowerCase();
  const file = form.get("avatar");
  let change = null; // "set" or "removed"
  if (isFile(file)) {
    if (file.size > LIMITS.avatar) {
      return json({ error: `Profile pictures can be ${niceSize(LIMITS.avatar)} at most.` }, 400);
    }
    const type = await sniffImage(file);
    if (!type) return json({ error: "Profile pictures must be PNG, JPG or WebP." }, 400);
    await env.FILES.put("avatars/" + lc, await file.arrayBuffer(), { httpMetadata: { contentType: type } });
    change = "set";
  } else if (form.get("removeAvatar") === "1") {
    await env.FILES.delete("avatars/" + lc);
    change = "removed";
  }

  let sql = "UPDATE users SET display_name = ?, bio = ?";
  if (change === "set") sql += ", has_avatar = 1, avatar_v = avatar_v + 1";
  if (change === "removed") sql += ", has_avatar = 0, avatar_v = avatar_v + 1";
  await env.DB.prepare(sql + " WHERE id = ?").bind(displayName || null, bio || null, s.id).run();
  await addAttempt(env, "profile:" + s.id, now);
  return json({ ok: true });
}

/* ---------- likes + comments ---------- */
// only approved packs can get likes and comments
async function approvedPack(env, id) {
  if (!/^[a-f0-9]{12}$/.test(id)) return null;
  return env.DB.prepare("SELECT id FROM packs WHERE id = ? AND status = 'approved'").bind(id).first();
}

// like count, if im logged in whether i liked it, and the comments for one pack (anyone can read these)
async function packSocial(request, env, url) {
  const id = url.searchParams.get("id") || "";
  if (!(await approvedPack(env, id))) return notFound();
  const s = await readSession(env, request);
  const likes = await env.DB.prepare("SELECT COUNT(*) AS n FROM likes WHERE pack_id = ?").bind(id).first();
  let liked = false;
  if (s) {
    liked = !!(await env.DB.prepare(
      "SELECT 1 AS x FROM likes WHERE pack_id = ? AND user_id = ?"
    ).bind(id, s.id).first());
  }
  const { results } = await env.DB.prepare(
    "SELECT id, user_id, user_name, body, created_at FROM comments WHERE pack_id = ? ORDER BY created_at DESC LIMIT 100"
  ).bind(id).all();
  return json({
    likes: likes.n,
    liked,
    comments: results.map((c) => ({
      id: c.id,
      name: c.user_name,
      userId: c.user_id,
      body: c.body,
      date: new Date(c.created_at * 1000).toISOString().slice(0, 10),
      // you can delete your own comments, mods can delete any
      canDelete: !!s && (s.mod || s.id === c.user_id),
    })),
  });
}

// reads the json body for the like/comment routes and checks login + origin
async function socialInput(request, env) {
  const s = await readSession(env, request);
  if (!s) return { err: json({ error: "Log in first." }, 401) };
  if (!sameOrigin(request, env)) return { err: json({ error: "Bad origin." }, 403) };
  let body;
  try {
    body = await request.json();
  } catch {
    return { err: json({ error: "Bad request." }, 400) };
  }
  return { s, body };
}

// like or unlike (one like per account per pack)
async function setLike(request, env) {
  const { s, body, err } = await socialInput(request, env);
  if (err) return err;
  const id = String(body.id || "");
  if (!(await approvedPack(env, id))) return json({ error: "Pack not found." }, 404);
  if (body.like) {
    await env.DB.prepare(
      "INSERT OR IGNORE INTO likes (pack_id, user_id, created_at) VALUES (?, ?, ?)"
    ).bind(id, s.id, Math.floor(Date.now() / 1000)).run();
  } else {
    await env.DB.prepare("DELETE FROM likes WHERE pack_id = ? AND user_id = ?").bind(id, s.id).run();
  }
  const likes = await env.DB.prepare("SELECT COUNT(*) AS n FROM likes WHERE pack_id = ?").bind(id).first();
  return json({ ok: true, likes: likes.n, liked: !!body.like });
}

// post a comment (300 characters max, 5 per hour per person)
async function addComment(request, env) {
  const { s, body, err } = await socialInput(request, env);
  if (err) return err;
  const id = String(body.id || "");
  const text = clean(body.body, 300);
  if (!text) return json({ error: "Write something first." }, 400);
  if (!(await approvedPack(env, id))) return json({ error: "Pack not found." }, 404);
  const now = Math.floor(Date.now() / 1000);
  const recent = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM comments WHERE user_id = ? AND created_at > ?"
  ).bind(s.id, now - 3600).first();
  if (recent.n >= 5) return json({ error: "Slow down, you can post 5 comments per hour." }, 429);
  const cid = [...crypto.getRandomValues(new Uint8Array(6))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  await env.DB.prepare(
    "INSERT INTO comments (id, pack_id, user_id, user_name, body, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(cid, id, s.id, clean(s.name, 60) || "unknown", text, now).run();
  return json({ ok: true });
}

// delete a comment, your own or any if youre a mod
async function deleteComment(request, env) {
  const { s, body, err } = await socialInput(request, env);
  if (err) return err;
  const cid = String(body.id || "");
  if (!/^[a-f0-9]{12}$/.test(cid)) return json({ error: "Bad comment id." }, 400);
  const row = await env.DB.prepare("SELECT id, user_id FROM comments WHERE id = ?").bind(cid).first();
  if (!row) return json({ error: "Comment not found." }, 404);
  if (!s.mod && row.user_id !== s.id) return json({ error: "That is not your comment." }, 403);
  await env.DB.prepare("DELETE FROM comments WHERE id = ?").bind(cid).run();
  return json({ ok: true });
}

/* ---------- announcements (the bell box) ---------- */
// what shows if nobody edited it yet (or the settings table isnt there)
const DEFAULT_NEWS = {
  title: "Welcome back!",
  intro: "Here's what's new:",
  items: [
    "Packs now have likes, comments and download counts.",
    "You can edit or delete your own packs from your account.",
    "Moderators can edit and delete any pack.",
    "You can upload without logging in.",
    "The new Tools page has PCK Studio and the tutorials.",
  ],
  image: false,
};
const NEWS_IMAGE_KEY = "site/news-image"; // the banner image lives in R2 under this key
const NEWS_IMAGE_MAX = 1024 * 1024;       // 1 MB

// reads the saved announcements + when they last changed (0 = never edited)
async function newsRow(env) {
  try {
    const row = await env.DB.prepare("SELECT value, updated_at FROM settings WHERE key = 'news'").first();
    if (row) {
      const v = JSON.parse(row.value);
      if (v && Array.isArray(v.items)) return { v, updated: row.updated_at };
    }
  } catch {}
  return { v: DEFAULT_NEWS, updated: 0 };
}

// saves the announcements, returns the new "last changed" time
async function writeNews(env, v, userId) {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('news', ?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`
  ).bind(JSON.stringify(v), now, userId).run();
  return now;
}

// anyone can read the announcements
async function getNews(env) {
  const { v, updated } = await newsRow(env);
  return json({ title: v.title, intro: v.intro, items: v.items, image: !!v.image, updated });
}

// anyone can see the banner image
async function newsImage(env) {
  const obj = await env.FILES.get(NEWS_IMAGE_KEY);
  if (!obj) return notFound();
  return new Response(obj.body, {
    headers: {
      "Content-Type": obj.httpMetadata?.contentType || "image/png",
      "Cache-Control": "public, max-age=3600", // the page adds ?v=<time> so a new image shows up right away
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'none'; sandbox",
    },
  });
}

// save the announcement text (mods for now, owner only once the owner account exists)
async function saveNews(request, env) {
  const s = await readSession(env, request);
  if (!isAdmin(s)) return json({ error: "Admins only." }, 403);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Bad request." }, 400);
  }
  const title = clean(body.title, 40);
  const intro = clean(body.intro, 80);
  if (!title) return json({ error: "The title cant be empty." }, 400);
  const items = (Array.isArray(body.items) ? body.items : [])
    .map((t) => clean(t, 120))
    .filter(Boolean)
    .slice(0, 12);
  const cur = await newsRow(env); // keep whatever banner image is already set
  const updated = await writeNews(env, { title, intro, items, image: !!cur.v.image }, s.id);
  return json({ ok: true, title, intro, items, image: !!cur.v.image, updated });
}

// change or remove the banner image (multipart: "file", or remove=1)
async function saveNewsImage(request, env) {
  const s = await readSession(env, request);
  if (!isAdmin(s)) return json({ error: "Admins only." }, 403);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
  if (Number(request.headers.get("Content-Length") || 0) > NEWS_IMAGE_MAX + 64 * 1024) {
    return json({ error: "That image is too big (max 1 MB)." }, 413);
  }
  let form;
  try {
    form = await request.formData();
  } catch {
    return json({ error: "Bad request." }, 400);
  }
  const cur = await newsRow(env);
  const v = { title: cur.v.title, intro: cur.v.intro, items: cur.v.items, image: false };
  if (form.get("remove") === "1") {
    await env.FILES.delete(NEWS_IMAGE_KEY);
  } else {
    const f = form.get("file");
    if (!isFile(f)) return json({ error: "Choose an image first." }, 400);
    if (f.size > NEWS_IMAGE_MAX) return json({ error: "That image is too big (max 1 MB)." }, 400);
    const type = await sniffImage(f);
    if (!type) return json({ error: "The image must be a PNG, JPG or WebP." }, 400);
    await env.FILES.put(NEWS_IMAGE_KEY, await f.arrayBuffer(), { httpMetadata: { contentType: type } });
    v.image = true;
  }
  const updated = await writeNews(env, v, s.id);
  return json({ ok: true, image: v.image, updated });
}

/* ---------- router ---------- */
/* ---------- cleanup: denied packs ----------
   denied packs nobody touched for 30 days lose their R2 files (the row and the deny reason stay).
   runs by itself now and then, no cron needed. if the creator edits it later they add files again */
async function purgeDenied(env) {
  try {
    const cutoff = Math.floor(Date.now() / 1000) - 30 * 86400;
    const { results } = await env.DB.prepare(
      "SELECT id FROM packs WHERE status = 'denied' AND reviewed_at < ? AND files IS NOT NULL AND files != '[]' LIMIT 5"
    ).bind(cutoff).all();
    for (const r of results || []) {
      let cursor;
      do {
        const page = await env.FILES.list({ prefix: r.id + "/", cursor });
        if (page.objects.length) await env.FILES.delete(page.objects.map((o) => o.key));
        cursor = page.truncated ? page.cursor : undefined;
      } while (cursor);
      await env.DB.prepare("UPDATE packs SET files = '[]', images = '[]' WHERE id = ?").bind(r.id).run();
    }
  } catch {}
}

async function route(request, env, ctx) {
  const url = new URL(request.url);
  const p = url.pathname;
  const m = request.method;

  if (p === "/auth/logout" && m === "POST") {
    if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);
    return logout();
  }
  if (p === "/api/me") return me(request, env);
  if (p === "/api/signup" && m === "POST") return signup(request, env);
  if (p === "/api/login" && m === "POST") return loginPassword(request, env);
  if (p === "/api/admin/users" && m === "GET") return adminUsers(request, env, url);
  if (p === "/api/admin/user-role" && m === "POST") return setUserRole(request, env);
  if (p === "/api/admin/user-ban" && m === "POST") return setUserBan(request, env);
  if (p === "/api/admin/pack-owner" && m === "POST") return setPackOwner(request, env);
  if (p === "/api/admin/log" && m === "GET") return adminLog(request, env);
  if (p === "/api/admin/stats" && m === "GET") return adminStats(request, env);
  if (p === "/api/admin/user-reset" && m === "POST") return resetPassword(request, env);
  if (p === "/api/admin/user-delete" && m === "POST") return deleteAccount(request, env);
  if (p === "/api/admin/splashes" && m === "POST") return saveSplashes(request, env);
  if (p === "/api/splashes" && m === "GET") return getSplashes(env);
  if (p === "/api/password" && m === "POST") return changePassword(request, env);
  if (p === "/admin/setup" && m === "GET") return setupShow(env);
  if (p === "/admin/setup" && m === "POST") return setupSubmit(request, env);
  if (p === "/api/packs" && m === "GET") {
    if (Math.random() < 0.02) ctx.waitUntil(purgeDenied(env));
    return listPacks(env);
  }
  if (p === "/api/my" && m === "GET") return myPacks(request, env);
  if (p === "/api/social" && m === "GET") return packSocial(request, env, url);
  if (p === "/api/news" && m === "GET") return getNews(env);
  if (p === "/api/news/image" && m === "GET") return newsImage(env);
  if (p === "/api/admin/news" && m === "POST") return saveNews(request, env);
  if (p === "/api/admin/news-image" && m === "POST") return saveNewsImage(request, env);
  if (p === "/api/like" && m === "POST") return setLike(request, env);
  if (p === "/api/comment" && m === "POST") return addComment(request, env);
  if (p === "/api/comment/delete" && m === "POST") return deleteComment(request, env);
  if (p === "/api/my/delete" && m === "POST") return deleteMine(request, env);
  if (p === "/api/my/edit" && m === "POST") return editMine(request, env, ctx);
  if (p === "/api/submit" && m === "POST") return submit(request, env, ctx);
  if (p === "/api/admin/list" && m === "GET") return adminList(request, env, url);
  if (p === "/api/admin/review" && m === "POST") return review(request, env);
    if (p === "/api/report" && m === "POST") return report(request, env, ctx);
  if (p === "/api/admin/reports" && m === "GET") return adminReports(request, env);
  if (p === "/api/admin/report-close" && m === "POST") return closeReport(request, env);
    if (p === "/api/admin/all" && m === "GET") return adminAll(request, env);
  if (p === "/api/user" && m === "GET") return publicProfile(env, url);
  if (p === "/api/profile" && m === "POST") return saveProfile(request, env);
  if (p.startsWith("/files/avatar/") && m === "GET") return serveAvatar(env, url);
  if (p.startsWith("/files/") && m === "GET") return serveFile(request, env, url, ctx);

  if (
    p.startsWith("/api/") || p.startsWith("/auth/") ||
    p.startsWith("/admin/") || p.startsWith("/files/")
  ) {
    return notFound();
  }
  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env, ctx);
    } catch (e) {
      return json({ error: "Server error." }, 500);
    }
  },
};
