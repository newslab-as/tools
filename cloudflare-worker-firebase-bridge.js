// Cloudflare Worker — bridges Cloudflare Access (Google SSO) to Firebase Auth
// for tools.newslab.no.
//
// WHAT THIS DOES
// Cloudflare Access already verifies the visitor is signed in with a Google
// account before the request even reaches the origin. This Worker reads that
// verified identity, checks it's @newslab.no, and mints a Firebase "custom
// token" for that person — which the page then uses to sign into Firebase
// automatically, with no second "Sign in with Google" click.
//
// This file is NOT part of the tools repo's deploy (GitHub Pages doesn't run
// server code) — paste it directly into the Cloudflare dashboard's Worker
// editor, or deploy via `wrangler deploy` if you use the CLI.
//
// SETUP CHECKLIST (see chat for the full walkthrough)
// 1. Firebase console -> Project settings -> Service accounts -> Generate new
//    private key. Downloads a JSON file with "client_email" and "private_key".
// 2. Cloudflare dashboard -> Workers & Pages -> Create Worker -> paste this
//    file's contents -> Deploy.
// 3. Worker -> Settings -> Variables and Secrets:
//      ACCESS_TEAM_DOMAIN   (plain text)  e.g. "newslab" — your Zero Trust
//                           team domain, from <team>.cloudflareaccess.com
//      ACCESS_AUD           (plain text)  the Access application's AUD tag —
//                           Zero Trust -> Access -> Applications -> your
//                           tools.newslab.no app -> Overview tab
//      FIREBASE_CLIENT_EMAIL (encrypt)    "client_email" from step 1's JSON
//      FIREBASE_PRIVATE_KEY   (encrypt)   "private_key" from step 1's JSON,
//                           pasted exactly as-is including the
//                           -----BEGIN PRIVATE KEY----- / END lines
// 4. Worker -> Settings -> Triggers -> Routes -> add a route so this Worker
//    handles requests at:  tools.newslab.no/api/firebase-token
//    (Your existing Cloudflare Access policy on the whole subdomain already
//    covers this path, so no separate Access application is needed for it.)
// 5. Reload tools.newslab.no while already logged into Cloudflare Access —
//    the "Sign in to sync" modal should never appear; Firebase sync activates
//    silently.
//
// NOTE ON EXISTING ACCOUNTS: this mints Firebase UIDs derived from email
// (e.g. doug@newslab.no -> doug_newslab_no), which will differ from any UID
// assigned earlier via the manual Google popup sign-in. Anyone who already
// pinned personal tools under the old UID will see a fresh "Your tools" list
// once this ships — their old data isn't deleted, just no longer linked. Say
// the word if you want help migrating specific accounts' data across.

let cachedJWKS = null;
let cachedJWKSAt = 0;

export default {
  async fetch(request, env) {
    if (request.method !== "GET") return new Response("Method not allowed", { status: 405 });

    try {
      const jwt = getAccessJWT(request);
      if (!jwt) return json({ error: "no_access_session" }, 401);

      const payload = await verifyAccessJWT(jwt, env);
      const email = (payload.email || "").toLowerCase();
      if (!email.endsWith("@newslab.no")) return json({ error: "wrong_domain" }, 403);

      const uid = email.replace(/[^a-z0-9]/g, "_");
      const customToken = await mintFirebaseCustomToken(uid, email, env);
      return json({ token: customToken, email }, 200);
    } catch (err) {
      return json({ error: String((err && err.message) || err) }, 401);
    }
  }
};

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
  });
}

function getAccessJWT(request) {
  const header = request.headers.get("Cf-Access-Jwt-Assertion");
  if (header) return header;
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/CF_Authorization=([^;]+)/);
  return match ? match[1] : null;
}

function b64urlToBytes(b64url) {
  const pad = (4 - (b64url.length % 4)) % 4;
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function bytesToB64url(bytes) {
  let bin = "";
  bytes.forEach(b => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function textToB64url(str) {
  return bytesToB64url(new TextEncoder().encode(str));
}

async function getAccessJWKS(env) {
  const now = Date.now();
  if (cachedJWKS && now - cachedJWKSAt < 3600_000) return cachedJWKS;
  const res = await fetch(`https://${env.ACCESS_TEAM_DOMAIN}.cloudflareaccess.com/cdn-cgi/access/certs`);
  if (!res.ok) throw new Error("failed to fetch Access JWKS");
  cachedJWKS = await res.json();
  cachedJWKSAt = now;
  return cachedJWKS;
}

async function verifyAccessJWT(jwt, env) {
  const [headerB64, payloadB64, sigB64] = jwt.split(".");
  if (!headerB64 || !payloadB64 || !sigB64) throw new Error("malformed JWT");

  const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(headerB64)));
  const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(payloadB64)));

  const audList = [].concat(payload.aud || []);
  if (!audList.includes(env.ACCESS_AUD)) throw new Error("aud mismatch");
  if (payload.iss !== `https://${env.ACCESS_TEAM_DOMAIN}.cloudflareaccess.com`) throw new Error("iss mismatch");
  if (payload.exp && payload.exp * 1000 < Date.now()) throw new Error("token expired");

  const jwks = await getAccessJWKS(env);
  const jwk = jwks.keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error("no matching signing key");

  const key = await crypto.subtle.importKey(
    "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
  );
  const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64urlToBytes(sigB64), signedData);
  if (!valid) throw new Error("bad signature");

  return payload;
}

function pemToPkcs8(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function mintFirebaseCustomToken(uid, email, env) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: env.FIREBASE_CLIENT_EMAIL,
    sub: env.FIREBASE_CLIENT_EMAIL,
    aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    iat: now,
    exp: now + 3600,
    uid,
    claims: { email, email_verified: true }
  };
  const headerB64 = textToB64url(JSON.stringify(header));
  const payloadB64 = textToB64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  const pem = env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n");
  const keyData = pemToPkcs8(pem);
  const key = await crypto.subtle.importKey(
    "pkcs8", keyData, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(signingInput));
  const sigB64 = bytesToB64url(new Uint8Array(sig));

  return `${signingInput}.${sigB64}`;
}
