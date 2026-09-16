// Cloudflare Pages Function — runs before every request to this site.
// It checks for a username/password (via the browser's built-in login prompt)
// before letting the request through to index.html or anything else.
//
// The actual username/password live in Cloudflare's dashboard as environment
// variables (Settings -> Environment variables), never in this file or in
// GitHub, so they aren't exposed even though this repo/file is visible.

export async function onRequest(context) {
  const { request, env } = context;

  const expectedUser = env.BASIC_AUTH_USER;
  const expectedPass = env.BASIC_AUTH_PASS;

  // Safety net: if the env vars haven't been set yet in Cloudflare,
  // block access entirely rather than accidentally serving the page open.
  if (!expectedUser || !expectedPass) {
    return new Response(
      "Site is not configured yet (missing BASIC_AUTH_USER / BASIC_AUTH_PASS).",
      { status: 503 }
    );
  }

  const authHeader = request.headers.get("Authorization");

  if (authHeader && authHeader.startsWith("Basic ")) {
    const encoded = authHeader.slice(6);
    const decoded = atob(encoded); // "username:password"
    const separatorIndex = decoded.indexOf(":");
    const user = decoded.slice(0, separatorIndex);
    const pass = decoded.slice(separatorIndex + 1);

    if (user === expectedUser && pass === expectedPass) {
      return context.next(); // credentials correct -> serve the real page
    }
  }

  // No credentials, or wrong ones -> ask the browser to prompt for login.
  return new Response("Authentication required.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Live Picking Dashboard", charset="UTF-8"',
    },
  });
}
