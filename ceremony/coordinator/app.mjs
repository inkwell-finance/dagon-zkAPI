import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { Readable } from "node:stream";
import { getConnInfo } from "@hono/node-server/conninfo";
import { Hono } from "hono";
import { QueueError } from "./queue.mjs";
import { RateLimiter } from "./ratelimit.mjs";

const CSP = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "worker-src 'self' blob:",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

/**
 * @param {object} args
 * @param {import("./coordinator.mjs").Coordinator} args.coordinator
 * @param {Map<string, object>} args.assets from loadAssets
 * @param {() => number} args.now
 * @param {boolean} [args.trustProxy] take the client address from the last X-Forwarded-For entry (set behind Railway)
 * @param {Record<string, {max: number, windowMs: number}>} [args.limits]
 */
export function buildApp({ coordinator, assets, now, trustProxy = false, limits, maxPingBytes = 4096 }) {
  const app = new Hono();
  const limiter = new RateLimiter({ now, limits });
  const ids = coordinator.circuitIds.join("|");
  const publicFile = new RegExp(`^(ceremony\\.json|transcript\\.json|closed\\.json|r1cs/(${ids})\\.r1cs|rounds/\\d{4}/(${ids})\\.zkey|rounds/\\d{4}/entry\\.json|final/FINAL\\.md|final/(${ids})_(final\\.zkey|verification_key\\.json))$`);

  app.use("*", async (c, next) => {
    await next();
    c.header("content-security-policy", CSP);
    c.header("x-content-type-options", "nosniff");
    c.header("referrer-policy", "no-referrer");
    c.header("cross-origin-opener-policy", "same-origin");
    c.header("permissions-policy", "camera=(), microphone=(), geolocation=()");
  });

  function clientKey(c) {
    let address = "unknown";
    if (trustProxy) address = c.req.header("x-forwarded-for")?.split(",").pop()?.trim() || address;
    else {
      try {
        address = getConnInfo(c).remote.address ?? address;
      } catch {
        // no socket (in-process requests): every caller shares one bucket
      }
    }
    return limiter.key(address);
  }

  const limited = (bucket) => async (c, next) => {
    const wait = limiter.check(bucket, clientKey(c));
    if (wait > 0) {
      c.header("retry-after", String(wait));
      return c.json({ error: "rate_limited", message: `Too many requests. Try again in ${wait} seconds.` }, 429);
    }
    await next();
  };

  const bearer = (c) => c.req.header("authorization")?.match(/^Bearer (\S{20,100})$/)?.[1];

  app.onError((error, c) => {
    if (error instanceof QueueError) return c.json({ error: error.code, message: error.message }, error.status);
    console.error(`[ceremony] ${error instanceof Error ? error.stack : String(error)}`);
    return c.json({ error: "internal", message: "Something went wrong on the server." }, 500);
  });

  app.get("/healthz", (c) => c.json({ ok: true, round: coordinator.latest.round }));

  app.get("/api/status", limited("status"), async (c) => {
    const status = await coordinator.status();
    return c.json({ ...status, assets: Object.fromEntries([...assets].map(([name, a]) => [name, a.sha256])), webReady: assets.has("index.html") && assets.has("app.js") }, 200, { "cache-control": "no-store" });
  });

  app.post("/api/queue", limited("join"), async (c) => {
    const declared = Number(c.req.header("content-length") ?? 0);
    if (declared > maxPingBytes) throw new QueueError("too_large", "Request body too large.", 413);
    const body = await c.req.json().catch(() => ({}));
    const ticket = await coordinator.join({ name: body?.name, key: clientKey(c) });
    return c.json({ ticket: ticket.token, ...coordinator.view(ticket) }, 201, { "cache-control": "no-store" });
  });

  app.get("/api/ticket", limited("poll"), (c) => c.json(coordinator.view(coordinator.ticket(bearer(c))), 200, { "cache-control": "no-store" }));

  app.delete("/api/ticket", limited("poll"), (c) => {
    coordinator.queue.release(coordinator.ticket(bearer(c)));
    return c.body(null, 204);
  });

  app.get("/api/round/:circuit", limited("download"), async (c) => {
    const ticket = coordinator.ticket(bearer(c));
    const { path, size, sha256, round } = await coordinator.openRound(ticket, c.req.param("circuit"));
    return new Response(Readable.toWeb(createReadStream(path)), {
      headers: { "content-type": "application/octet-stream", "content-length": String(size), "x-round": String(round), "x-sha256": sha256, "cache-control": "no-store" },
    });
  });

  app.put("/api/contribution", limited("upload"), async (c) => {
    const ticket = coordinator.ticket(bearer(c));
    const length = c.req.header("content-length");
    if (!length || !/^\d+$/.test(length)) throw new QueueError("length_required", "Content-Length is required.", 411);
    if (!c.req.raw.body) throw new QueueError("bad_upload", "The request has no body.", 400);
    return c.json(await coordinator.receive(ticket, c.req.raw.body, Number(length)), 202, { "cache-control": "no-store" });
  });

  app.get("/files/*", limited("files"), async (c) => {
    const name = c.req.path.slice("/files/".length);
    if (!publicFile.test(name)) return c.json({ error: "not_found" }, 404);
    const path = coordinator.store.path(name);
    const info = await stat(path).catch(() => undefined);
    if (!info?.isFile()) return c.json({ error: "not_found" }, 404);
    const immutable = name.startsWith("rounds/") && name.endsWith(".zkey");
    const type = name.endsWith(".json") ? "application/json" : name.endsWith(".md") ? "text/markdown; charset=utf-8" : "application/octet-stream";
    return new Response(Readable.toWeb(createReadStream(path)), {
      headers: { "content-type": type, "content-length": String(info.size), "cache-control": immutable ? "public, max-age=31536000, immutable" : "no-cache" },
    });
  });

  function serveAsset(name) {
    return (c) => {
      const asset = assets.get(name);
      if (!asset) return c.text("The page bundle is not built. Run `npm run build` in ceremony/.", 503);
      if (c.req.header("if-none-match") === `"${asset.sha256}"`) return new Response(null, { status: 304 });
      const gzip = /\bgzip\b/.test(c.req.header("accept-encoding") ?? "");
      const headers = { "content-type": asset.type, etag: `"${asset.sha256}"`, "cache-control": "no-cache", vary: "accept-encoding" };
      if (gzip) headers["content-encoding"] = "gzip";
      return new Response(gzip ? asset.gzip : asset.body, { headers });
    };
  }

  app.get("/", serveAsset("index.html"));
  for (const name of ["style.css", "favicon.svg", "app.js", "worker.js", "contribute.mjs"]) app.get(`/${name}`, serveAsset(name));

  app.notFound((c) => c.json({ error: "not_found" }, 404));
  return app;
}
