// Arpent — access gate in front of the static site.
// Login (username + password) + Cloudflare Turnstile (captcha), signed session cookie (HMAC-SHA256).
//
// DEPLOY-SAFE: if the required variables are not set, the site stays public (fail open).
// The gate activates automatically once ALL of these are set in the Worker's
// Settings → Variables and Secrets:
//   SITE_USER            plain var   — the username (e.g. "arpent")
//   SITE_PASS            SECRET      — the password
//   TURNSTILE_SITE_KEY   plain var   — public site key of your Turnstile widget
//   TURNSTILE_SECRET     SECRET      — secret key of your Turnstile widget
//   SESSION_SECRET       SECRET      — any long random string (signs the session cookie)

const COOKIE = "arp_session";
const TTL = 60 * 60 * 12; // 12 hours

export default {
  async fetch(request, env) {
    const configured = env.SITE_PASS && env.TURNSTILE_SECRET && env.TURNSTILE_SITE_KEY && env.SESSION_SECRET;
    if (!configured) return env.ASSETS.fetch(request); // gate inactive until secrets are set

    const url = new URL(request.url);
    const USER = (env.SITE_USER || "arpent").toString();

    if (url.pathname === "/__logout") {
      return redirect("/", clearCookie());
    }

    if (url.pathname === "/__auth" && request.method === "POST") {
      let f;
      try { f = await request.formData(); } catch (e) { f = new FormData(); }
      const u = (f.get("username") || "").toString();
      const p = (f.get("password") || "").toString();
      const tk = (f.get("cf-turnstile-response") || "").toString();
      const human = await verifyTurnstile(tk, env.TURNSTILE_SECRET, request.headers.get("CF-Connecting-IP"));
      if (human && timingEqual(u, USER) && timingEqual(p, env.SITE_PASS.toString())) {
        const val = await sign(USER, env.SESSION_SECRET.toString());
        return redirect(safeNext(url.searchParams.get("next")), setCookie(val));
      }
      const msg = human ? "Identifiant ou mot de passe invalide." : "Captcha non validé — réessaie.";
      return page(loginPage(env.TURNSTILE_SITE_KEY.toString(), msg, url.searchParams.get("next")), 401);
    }

    const tok = readCookie(request, COOKIE);
    if (tok && await verify(tok, env.SESSION_SECRET.toString())) {
      return env.ASSETS.fetch(request);
    }
    return page(loginPage(env.TURNSTILE_SITE_KEY.toString(), "", url.pathname + url.search), 401);
  }
};

async function verifyTurnstile(token, secret, ip) {
  if (!token) return false;
  const body = new URLSearchParams();
  body.set("secret", secret);
  body.set("response", token);
  if (ip) body.set("remoteip", ip);
  try {
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
    const j = await r.json();
    return !!j.success;
  } catch (e) { return false; }
}

async function keyFor(secret) {
  return crypto.subtle.importKey("raw", enc(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function sign(user, secret) {
  const exp = Math.floor(Date.now() / 1000) + TTL;
  const payload = user + "|" + exp;
  const key = await keyFor(secret);
  const sig = await crypto.subtle.sign("HMAC", key, enc(payload));
  return b64u(enc(payload)) + "." + b64u(new Uint8Array(sig));
}
async function verify(tok, secret) {
  const i = tok.indexOf(".");
  if (i < 0) return false;
  let payloadBytes, sigBytes;
  try { payloadBytes = ub64u(tok.slice(0, i)); sigBytes = ub64u(tok.slice(i + 1)); } catch (e) { return false; }
  const key = await keyFor(secret);
  const ok = await crypto.subtle.verify("HMAC", key, sigBytes, payloadBytes);
  if (!ok) return false;
  const payload = new TextDecoder().decode(payloadBytes);
  const exp = parseInt(payload.split("|")[1] || "0", 10);
  return exp > Math.floor(Date.now() / 1000);
}

function enc(s) { return new TextEncoder().encode(s); }
function b64u(bytes) { let s = ""; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function ub64u(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const bin = atob(s); const a = new Uint8Array(bin.length); for (let k = 0; k < bin.length; k++) a[k] = bin.charCodeAt(k); return a; }
function timingEqual(a, b) { if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false; let r = 0; for (let k = 0; k < a.length; k++) r |= a.charCodeAt(k) ^ b.charCodeAt(k); return r === 0; }

function setCookie(v) { return COOKIE + "=" + v + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=" + TTL; }
function clearCookie() { return COOKIE + "=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"; }
function readCookie(req, name) { const h = req.headers.get("Cookie") || ""; const m = h.match(new RegExp("(?:^|; )" + name + "=([^;]+)")); return m ? m[1] : null; }
function redirect(loc, cookie) { const h = { Location: loc }; if (cookie) h["Set-Cookie"] = cookie; return new Response(null, { status: 302, headers: h }); }
function page(body, status) { return new Response(body, { status: status || 200, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } }); }
function safeNext(n) { if (!n || !n.startsWith("/") || n.startsWith("//")) return "/"; return n; }

function loginPage(siteKey, msg, next) {
  const err = msg ? '<div class="err">' + msg + "</div>" : "";
  const nx = (next && next.startsWith("/") && !next.startsWith("//")) ? next.replace(/"/g, "&quot;") : "/";
  return `<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Arpent — accès</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>
:root{--bg:#0a0e14;--bg2:#0f1520;--card:#141b28;--line:#232c3d;--ink:#e9edf4;--mut:#9aa6bd;--dim:#657089;--gold:#d4af37;--acc:#4fd1c5;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,Roboto,sans-serif;background:radial-gradient(1000px 520px at 50% -10%,#16233b 0%,var(--bg) 55%) fixed;color:var(--ink);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}
.box{width:100%;max-width:380px;background:linear-gradient(180deg,var(--card),var(--bg2));border:1px solid var(--line);border-radius:16px;padding:30px 26px;}
.logo{font-size:.72rem;font-weight:800;letter-spacing:.42em;text-transform:uppercase;color:var(--gold);text-align:center;}
h1{font-size:1.25rem;font-weight:750;text-align:center;margin:10px 0 4px;}
.sub{font-size:.86rem;color:var(--mut);text-align:center;margin-bottom:20px;}
label{display:block;font-size:.72rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);margin:14px 0 5px;}
input{width:100%;background:var(--bg2);border:1px solid var(--line);border-radius:9px;color:var(--ink);font:inherit;font-size:.95rem;padding:10px 12px;}
input:focus{outline:none;border-color:var(--acc);}
.cf-turnstile{margin:18px 0 6px;display:flex;justify-content:center;}
button{width:100%;margin-top:14px;background:var(--acc);color:#06222a;border:none;border-radius:9px;font:inherit;font-size:.95rem;font-weight:750;padding:11px;cursor:pointer;}
button:hover{filter:brightness(1.05);}
.err{background:rgba(224,115,107,.12);border:1px solid rgba(224,115,107,.4);color:#e0736b;border-radius:9px;padding:9px 12px;font-size:.84rem;margin-bottom:14px;text-align:center;}
.foot{margin-top:16px;font-size:.72rem;color:var(--dim);text-align:center;}
</style></head><body>
<form class="box" method="POST" action="/__auth?next=${nx}">
<div class="logo">Arpent</div>
<h1>Accès réservé</h1>
<div class="sub">Read the real. Proof moves money.</div>
${err}
<label>Identifiant</label>
<input name="username" autocomplete="username" autofocus required>
<label>Mot de passe</label>
<input name="password" type="password" autocomplete="current-password" required>
<div class="cf-turnstile" data-sitekey="${siteKey}"></div>
<button type="submit">Entrer</button>
<div class="foot">arpentai.com · accès protégé</div>
</form>
</body></html>`;
}
