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
    return data;
  } catch {
    return null;
  }
}

function login(env) {
  const state = crypto.randomUUID();
  const params = new URLSearchParams({
    client_id: env.DISCORD_CLIENT_ID,
    redirect_uri: env.SITE_URL + "/auth/callback",
    response_type: "code",
    scope: "identify guilds.members.read",
    state,
  });
  const headers = new Headers({
    Location: "https://discord.com/oauth2/authorize?" + params,
  });
  headers.append("Set-Cookie", cookie("oauth_state", state, 600));
  return new Response(null, { status: 302, headers });
}

async function callback(request, env, url) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state || state !== getCookie(request, "oauth_state")) {
    return new Response("Login failed (bad state). Please try again.", { status: 400 });
  }

  const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: env.SITE_URL + "/auth/callback",
    }),
  });
  if (!tokenRes.ok) return new Response("Discord login failed.", { status: 502 });
  const { access_token } = await tokenRes.json();
  const auth = { Authorization: "Bearer " + access_token };

  const userRes = await fetch("https://discord.com/api/users/@me", { headers: auth });
  if (!userRes.ok) return new Response("Could not read your Discord profile.", { status: 502 });
  const user = await userRes.json();

  let roles = [];
  const memRes = await fetch(
    `https://discord.com/api/users/@me/guilds/${env.GUILD_ID}/member`,
    { headers: auth }
  );
  if (memRes.ok) {
    const member = await memRes.json();
    roles = member.roles || [];
  }

  const isMod = roles.includes(env.MOD_ROLE_ID);
  // mods get a 1 day login so a removed role stops working fast
  const maxAge = isMod ? 60 * 60 * 24 : 60 * 60 * 24 * 7;
  const session = await signSession(env, {
    id: user.id,
    name: user.global_name || user.username,
    avatar: user.avatar,
    mod: isMod,
    exp: Math.floor(Date.now() / 1000) + maxAge,
  });

  const headers = new Headers({ Location: env.SITE_URL + "/" });
  headers.append("Set-Cookie", cookie("session", session, maxAge));
  headers.append("Set-Cookie", cookie("oauth_state", "", 0));
  return new Response(null, { status: 302, headers });
}

function logout(env) {
  const headers = new Headers({ Location: env.SITE_URL + "/" });
  headers.append("Set-Cookie", cookie("session", "", 0));
  return new Response(null, { status: 302, headers });
}

async function me(request, env) {
  const s = await readSession(env, request);
  return json(
    s
      ? { loggedIn: true, user: { id: s.id, name: s.name, avatar: s.avatar }, isMod: s.mod }
      : { loggedIn: false }
  );
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
    date: new Date(r.created_at * 1000).toISOString().slice(0, 10),
    tags: JSON.parse(r.tags || "[]"),
    description: r.description,
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
      `SELECT p.*, (SELECT COUNT(*) FROM likes l WHERE l.pack_id = p.id) AS like_count
       FROM packs p WHERE p.status = 'approved' ORDER BY p.created_at DESC LIMIT 500`
    ).all());
  } catch {
    // likes table missing, just skip the counts
    ({ results } = await env.DB.prepare(
      "SELECT * FROM packs WHERE status = 'approved' ORDER BY created_at DESC LIMIT 500"
    ).all());
  }
  return json(results.map(packView));
}

async function myPacks(request, env) {
  const s = await readSession(env, request);
  if (!s) return json({ error: "Please log in with Discord first." }, 401);
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
  if (!s) return json({ error: "Please log in with Discord first." }, 401);
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
  if (!s) return json({ error: "Please log in with Discord first." }, 401);
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
    if (!s) return json({ error: "Please log in with Discord first." }, 401);
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
        error: `Anonymous uploads are limited to ${LIMITS.anonPerDay} per day. Try again tomorrow, or log in with Discord.`,
      }, 429);
    }
    const queue = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM packs WHERE creator_id = 'anon' AND status = 'pending'"
    ).first();
    if (queue.n >= LIMITS.anonMaxPending) {
      return json({
        error: "Too many anonymous packs are waiting for review right now. Please try again later, or log in with Discord.",
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
       (id, slug, name, description, tags, creator_id, creator_name, status, icon_key, images, files, created_at, ip_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 'icon', ?, ?, ?, ?)`
    ).bind(
      id, slug, name, description, JSON.stringify(tags), s.id, clean(s.name, 60),
      JSON.stringify(images), JSON.stringify(files), Math.floor(Date.now() / 1000), visitor
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
          content: `<@&${env.MOD_ROLE_ID}> A new pack is waiting for review.`,
          allowed_mentions: { roles: [env.MOD_ROLE_ID] },
          embeds: [{
            title: name,
            description: description.slice(0, 300) || "(no description)",
            url: env.SITE_URL + "/#/admin",
            color: 0x8f8f8f,
            fields: [
              { name: "By", value: anon ? "Anonymous (no login)" : (clean(s.name, 60) || "unknown") },
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
  if (!s) return json({ error: "Please log in with Discord to send a report." }, 401);
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
  const recent = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM reports WHERE reporter_id = ? AND created_at > ?"
  ).bind(s.id, now - 86400).first();
  if (recent.n >= 5) {
    return json({ error: "You have sent several reports today. Please try again tomorrow." }, 429);
  }

  const pack = await env.DB.prepare("SELECT id, name FROM packs WHERE slug = ?").bind(slug).first();
  const packName = pack ? pack.name : clean(body.name, 60) || slug;
  await env.DB.prepare(
    `INSERT INTO reports (pack_slug, pack_id, pack_name, reporter_id, reporter_name, reason, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(slug, pack ? pack.id : null, packName, s.id, clean(s.name, 60), reason, now).run();

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
            fields: [{ name: "Reported by", value: clean(s.name, 60) || "unknown" }],
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

async function editPack(request, env) {
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
  const name = clean(body.name, 40);
  const description = clean(body.description, 500);
  if (name.length < 3) return json({ error: "Pack name must be at least 3 characters." }, 400);
  const tags = [];
  for (const t of clean(body.tags, 200).split(",")) {
    const tag = clean(t, 20);
    if (tag && !tags.some((x) => x.toLowerCase() === tag.toLowerCase())) tags.push(tag);
  }
  tags.length = Math.min(tags.length, 5);
  const r = await env.DB.prepare(
    "UPDATE packs SET name = ?, description = ?, tags = ? WHERE id = ?"
  ).bind(name, description, JSON.stringify(tags), id).run();
  if (!r.meta.changes) return json({ error: "Pack not found." }, 404);
  return json({ ok: true });
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
  if (!s) return { err: json({ error: "Log in with Discord first." }, 401) };
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
};

// anyone can read the announcements
async function getNews(env) {
  try {
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'news'").first();
    if (row) {
      const v = JSON.parse(row.value);
      if (v && Array.isArray(v.items)) return json(v);
    }
  } catch {}
  return json(DEFAULT_NEWS);
}

// save the announcements (mods for now, owner only once the owner account exists)
async function saveNews(request, env) {
  const s = await readSession(env, request);
  if (!s || !s.mod) return json({ error: "Moderators only." }, 403);
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
  const value = JSON.stringify({ title, intro, items });
  await env.DB.prepare(
    `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('news', ?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`
  ).bind(value, Math.floor(Date.now() / 1000), s.id).run();
  return json({ ok: true, title, intro, items });
}

/* ---------- router ---------- */
async function route(request, env, ctx) {
  const url = new URL(request.url);
  const p = url.pathname;
  const m = request.method;

  if (p === "/auth/login") return login(env);
  if (p === "/auth/callback") return callback(request, env, url);
  if (p === "/auth/logout") return logout(env);
  if (p === "/api/me") return me(request, env);
  if (p === "/api/packs" && m === "GET") return listPacks(env);
  if (p === "/api/my" && m === "GET") return myPacks(request, env);
  if (p === "/api/social" && m === "GET") return packSocial(request, env, url);
  if (p === "/api/news" && m === "GET") return getNews(env);
  if (p === "/api/admin/news" && m === "POST") return saveNews(request, env);
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
  if (p === "/api/admin/edit" && m === "POST") return editPack(request, env);
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
