interface AssetBinding {
  fetch(request: Request): Promise<Response>;
}

export interface Env {
  ASSETS?: AssetBinding;
  ADMIN_USERNAME?: string;
  ADMIN_PASSWORD?: string;
  SESSION_SIGNING_KEY?: string;
  GOOGLE_SAFE_BROWSING_API_KEY?: string;
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    },
  });
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/api/health" && request.method === "GET") {
    return json({ status: "ok", service: "watch-dog" });
  }

  if (url.pathname.startsWith("/api/")) {
    return json({ error: "not_configured" }, 503);
  }

  if (env.ASSETS) return env.ASSETS.fetch(request);
  return new Response("Watch Dog asset binding is unavailable", {
    status: 503,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

export default { fetch: handleRequest };
