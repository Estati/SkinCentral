const enc = new TextEncoder();

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

  const maxAge = 60 * 60 * 24 * 7;
  const session = await signSession(env, {
    id: user.id,
    name: user.global_name || user.username,
    avatar: user.avatar,
    mod: roles.includes(env.MOD_ROLE_ID),
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
  const body = s
    ? { loggedIn: true, user: { id: s.id, name: s.name, avatar: s.avatar }, isMod: s.mod }
    : { loggedIn: false };
  return new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    if (p === "/auth/login") return login(env);
    if (p === "/auth/callback") return callback(request, env, url);
    if (p === "/auth/logout") return logout(env);
    if (p === "/api/me") return me(request, env);
    if (p.startsWith("/api/") || p.startsWith("/auth/") || p.startsWith("/admin/")) {
      return new Response("Not found", { status: 404 });
    }
    return env.ASSETS.fetch(request);
  },
};
