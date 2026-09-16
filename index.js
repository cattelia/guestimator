// Hardened access gate for the Live Picking Dashboard.
//
// This runs on every request before the dashboard is served. Security
// measures, and why each one is here:
//
// 1. CONSTANT-TIME COMPARISON — credentials are compared by hashing both
//    sides and comparing the hashes byte-by-byte, so a wrong guess takes the
//    same amount of time whether the first character is wrong or the last
//    one is. A plain `===` comparison leaks tiny timing differences that
//    can, in principle, be used to guess a password one character at a time.
//
// 2. DEFENSIVE PARSING — the Authorization header is length-capped and
//    wrapped in try/catch. Malformed input is rejected outright, never
//    allowed to throw an unhandled error or reach any code path that could
//    behave unexpectedly.
//
// 3. FAIL CLOSED — if credentials aren't configured, or anything about the
//    request is unexpected, the default is "deny," never "allow."
//
// 4. BRUTE-FORCE LOCKOUT (optional) — if you bind a KV namespace named
//    LOGIN_ATTEMPTS (see wrangler.jsonc), an IP address that fails 5 times
//    gets locked out for 15 minutes. If you don't set up the KV namespace,
//    this feature quietly does nothing — login still works, you just don't
//    get lockout protection.
//
// 5. SECURITY HEADERS — every response (including the real dashboard, once
//    authenticated) gets headers that block clickjacking, stop the browser
//    from caching the authenticated page, and prevent MIME-type sniffing.
//
// Nothing in this file evaluates or executes any string as code (no eval,
// no Function(), no dynamic imports) — the only "logic" a request can
// influence is which of two fixed outcomes (allow / deny) it gets.

const MAX_AUTH_HEADER_LENGTH = 2048;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_SECONDS = 15 * 60; // 15 minutes

function securityHeaders(extra = {}) {
  return {
    ...extra,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
  };
}

// Compare two strings without leaking timing information about *where*
// they differ. Always does the same amount of work regardless of input.
async function timingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const [aHash, bHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const aArr = new Uint8Array(aHash);
  const bArr = new Uint8Array(bHash);
  let diff = 0;
  for (let i = 0; i < aArr.length; i++) diff |= aArr[i] ^ bArr[i];
  return diff === 0;
}

// Parses "Basic <base64(user:pass)>" defensively. Returns null for
// anything malformed, oversized, or unexpected rather than throwing.
function parseBasicAuth(header) {
  if (!header || typeof header !== "string") return null;
  if (header.length > MAX_AUTH_HEADER_LENGTH) return null;
  if (!header.startsWith("Basic ")) return null;

  const encoded = header.slice(6).trim();
  let decoded;
  try {
    decoded = atob(encoded);
  } catch {
    return null; // not valid base64 -> reject, never throw
  }

  const sep = decoded.indexOf(":");
  if (sep === -1) return null;

  return { user: decoded.slice(0, sep), pass: decoded.slice(sep + 1) };
}

function unauthorized() {
  return new Response("Authentication required.", {
    status: 401,
    headers: securityHeaders({
      "WWW-Authenticate": 'Basic realm="Live Picking Dashboard", charset="UTF-8"',
      "Content-Type": "text/plain; charset=utf-8",
    }),
  });
}

function lockedOut() {
  return new Response("Too many failed attempts. Try again in 15 minutes.", {
    status: 429,
    headers: securityHeaders({
      "Retry-After": String(LOCKOUT_SECONDS),
      "Content-Type": "text/plain; charset=utf-8",
    }),
  });
}

async function isLockedOut(env, ip) {
  if (!env.LOGIN_ATTEMPTS) return false; // KV not set up -> feature skipped
  return (await env.LOGIN_ATTEMPTS.get(`lockout:${ip}`)) !== null;
}

async function recordFailedAttempt(env, ip) {
  if (!env.LOGIN_ATTEMPTS) return;
  const key = `fails:${ip}`;
  const current = parseInt((await env.LOGIN_ATTEMPTS.get(key)) || "0", 10);
  const next = current + 1;
  if (next >= MAX_FAILED_ATTEMPTS) {
    await env.LOGIN_ATTEMPTS.put(`lockout:${ip}`, "1", { expirationTtl: LOCKOUT_SECONDS });
    await env.LOGIN_ATTEMPTS.delete(key);
  } else {
    await env.LOGIN_ATTEMPTS.put(key, String(next), { expirationTtl: LOCKOUT_SECONDS });
  }
}

async function clearFailedAttempts(env, ip) {
  if (!env.LOGIN_ATTEMPTS) return;
  await env.LOGIN_ATTEMPTS.delete(`fails:${ip}`);
  await env.LOGIN_ATTEMPTS.delete(`lockout:${ip}`);
}

export default {
  async fetch(request, env) {
    const expectedUser = env.BASIC_AUTH_USER;
    const expectedPass = env.BASIC_AUTH_PASS;

    // Fail closed: if secrets aren't set, never serve the real page.
    if (!expectedUser || !expectedPass) {
      return new Response("Site is not configured yet.", {
        status: 503,
        headers: securityHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
      });
    }

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    if (await isLockedOut(env, ip)) {
      return lockedOut();
    }

    const creds = parseBasicAuth(request.headers.get("Authorization"));
    if (!creds) {
      return unauthorized();
    }

    const [userOk, passOk] = await Promise.all([
      timingSafeEqual(creds.user, expectedUser),
      timingSafeEqual(creds.pass, expectedPass),
    ]);

    if (!userOk || !passOk) {
      await recordFailedAttempt(env, ip);
      return unauthorized();
    }

    await clearFailedAttempts(env, ip);

    // Credentials correct -> serve the real dashboard from static assets.
    const assetResponse = await env.ASSETS.fetch(request);
    const response = new Response(assetResponse.body, assetResponse);
    for (const [key, value] of Object.entries(securityHeaders())) {
      response.headers.set(key, value);
    }
    return response;
  },
};
