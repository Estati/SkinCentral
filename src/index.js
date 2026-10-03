const enc = new TextEncoder();

/* ---------- SETTINGS (edit these numbers freely) ---------- */
const LIMITS = {
  icon: 512 * 1024,        // icon image, max size
  shot: 2 * 1024 * 1024,   // each screenshot, max size
  pack: 5 * 1024 * 1024,   // each pack file, max size
  total: 20 * 1024 * 1024, // whole submission, max size
  maxPending: 3,           // how many packs one person can have waiting at once
};
const PLATFORMS = {
  xbox360: "Xbox 360",
  ps3: "PS3",
  wiiu: "Wii U",
  vita: "PS Vita",
  ps4: "PS4",
  xboxone: "Xbox One",
  switch: "Switch",
};
const BLOCKED_EXT = /\.(exe|dll|bat|cmd|com|msi|scr|js|mjs|vbs|ps1|apk|ipa|jar|sh|html?|svgz?|php|py)$/i;

/* ---------- SMALL HELPERS ---------- */
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

// Looks at the first bytes of a file to check it is really a PNG, JPG or WebP.
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

/* ---------- LOGIN SESSIONS ---------- */
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
  // Moderators get a shorter login (1 day) so a removed role stops working quickly.
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

/* ---------- PACKS ---------- */
// Turns a database row into the same shape packs.json uses.
function packView(r) {
  const files = JSON.parse(r.files || "[]");
  const images = JSON.parse(r.images || "[]");
  return {
    id: r.id,
    slug: r.slug,
    name: r.name,
    creator: r.creator_name,
    date: new Date(r.created_at * 1000).toISOString().slice(0, 10),
    tags: JSON.parse(r.tags || "[]"),
    description: r.description,
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
  const { results } = await env.DB.prepare(
    "SELECT * FROM packs WHERE status = 'approved' ORDER BY created_at DESC LIMIT 500"
  ).all();
  return json(results.map(packView));
}

async function myPacks(request, env) {
  const s = await readSession(env, request);
  if (!s) return json({ error: "Please log in with Discord first." }, 401);
  const { results } = await env.DB.prepare(
    "SELECT id, name, status, deny_reason, created_at FROM packs WHERE creator_id = ? ORDER BY created_at DESC LIMIT 50"
  ).bind(s.id).all();
  return json(results);
}

async function submit(request, env, ctx) {
  const s = await readSession(env, request);
  if (!s) return json({ error: "Please log in with Discord first." }, 401);
  if (!sameOrigin(request, env)) return json({ error: "Bad origin." }, 403);

  const len = Number(request.headers.get("Content-Length") || 0);
  if (len > LIMITS.total + 1024 * 1024) {
    return json({ error: "That upload is too big." }, 413);
  }

  const pending = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM packs WHERE creator_id = ? AND status = 'pending'"
  ).bind(s.id).first();
  if (pending.n >= LIMITS.maxPending) {
    return json({
      error: `You already have ${LIMITS.maxPending} packs waiting for review. Please wait for a moderator.`,
    }, 429);
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
  if (total > LIMITS.total) return json({ error: "That upload is too big overall (max 20 MB)." }, 400);

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
       (id, slug, name, description, tags, creator_id, creator_name, status, icon_key, images, files, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 'icon', ?, ?, ?)`
    ).bind(
      id, slug, name, description, JSON.stringify(tags), s.id, clean(s.name, 60),
      JSON.stringify(images), JSON.stringify(files), Math.floor(Date.now() / 1000)
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
              { name: "By", value: clean(s.name, 60) || "unknown" },
              { name: "Platforms", value: files.map((f) => f.platform).join(", ") },
            ],
          }],
        }),
      }).catch(() => {})
    );
  }

  return json({ ok: true, message: "Submitted! A moderator will review your pack soon." });
}

/* ---------- MODERATION ---------- */
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
      denyReason: r.deny_reason,
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

/* ---------- REPORTS ---------- */
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

/* ---------- FILE DOWNLOADS (from R2) ---------- */
async function serveFile(request, env, url) {
  // Paths look like /files/<id>/icon  or  /files/<id>/<platform>/<filename>
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

  // Pending or denied packs can only be seen by moderators and the person who uploaded them.
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
  return new Response(obj.body, { headers });
}

/* ---------- ROUTER ---------- */
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
  if (p === "/api/submit" && m === "POST") return submit(request, env, ctx);
  if (p === "/api/admin/list" && m === "GET") return adminList(request, env, url);
  if (p === "/api/admin/review" && m === "POST") return review(request, env);
    if (p === "/api/report" && m === "POST") return report(request, env, ctx);
  if (p === "/api/admin/reports" && m === "GET") return adminReports(request, env);
  if (p === "/api/admin/report-close" && m === "POST") return closeReport(request, env);
  if (p.startsWith("/files/") && m === "GET") return serveFile(request, env, url);

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
