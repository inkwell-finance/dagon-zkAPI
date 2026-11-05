// HTTP client for the coordinator API. Used unchanged by the CLI (Node) and the web page (browser).

export class CeremonyError extends Error {
  constructor(code, message, status = 0) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

const GATEWAY_STATUSES = new Set([502, 503, 504]);

/**
 * Error for a non-2xx answer. A 502/503/504 without the coordinator's JSON error code comes from the hosting edge
 * (a lost upstream response): the request may still have reached the coordinator, so it is as uncertain as a dropped
 * connection and is classified the same way.
 */
export function httpError(status, body) {
  const code = typeof body?.error === "string" ? body.error : undefined;
  if (!code && GATEWAY_STATUSES.has(status)) return new CeremonyError("network", `The ceremony server's gateway answered HTTP ${status}.`, status);
  return new CeremonyError(code ?? "http_error", typeof body?.message === "string" ? body.message : `The server answered HTTP ${status}.`, status);
}

export class CeremonyClient {
  #base;
  #fetch;

  constructor({ server, fetch: fetcher = (...args) => globalThis.fetch(...args) }) {
    this.#base = new URL(server.endsWith("/") ? server : `${server}/`);
    this.#fetch = fetcher;
  }

  #url(path) {
    return new URL(path.replace(/^\//, ""), this.#base).href;
  }

  async #request(path, init = {}) {
    let response;
    try {
      response = await this.#fetch(this.#url(path), init);
    } catch (error) {
      throw new CeremonyError("network", `Could not reach the ceremony server (${error instanceof Error ? [error.message, error.cause?.code ?? error.cause?.message].filter(Boolean).join(": ") : error}).`);
    }
    if (response.ok) return response;
    throw httpError(response.status, await response.json().catch(() => undefined));
  }

  async #json(path, init) {
    const response = await this.#request(path, init);
    try {
      return await response.json();
    } catch (error) {
      if (error instanceof SyntaxError) throw new CeremonyError("bad_response", "The ceremony server returned invalid JSON.");
      throw new CeremonyError("network", "The response from the ceremony server was interrupted.");
    }
  }

  async status() {
    return this.#json("api/status");
  }

  async join(name) {
    return this.#json("api/queue", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name }) });
  }

  async poll(ticket) {
    return this.#json("api/ticket", { headers: { authorization: `Bearer ${ticket}` } });
  }

  async leave(ticket) {
    await this.#request("api/ticket", { method: "DELETE", headers: { authorization: `Bearer ${ticket}` } });
  }

  /** @returns {Promise<{bytes: Uint8Array, round: number, sha256: string}>} */
  async download(ticket, circuitId, onProgress) {
    const response = await this.#request(`api/round/${circuitId}`, { headers: { authorization: `Bearer ${ticket}` } });
    const total = Number(response.headers.get("content-length")) || 0;
    const reader = response.body.getReader();
    const chunks = [];
    let loaded = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      loaded += value.length;
      onProgress?.(loaded, total);
    }
    const bytes = new Uint8Array(loaded);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return { bytes, round: Number(response.headers.get("x-round")), sha256: response.headers.get("x-sha256") };
  }

  /** Uploads the bundle. The page replaces this with an XMLHttpRequest version to show upload progress. */
  async upload(ticket, blob) {
    return this.#json("api/contribution", { method: "PUT", headers: { authorization: `Bearer ${ticket}`, "content-type": "application/octet-stream", "content-length": String(blob.size) }, body: blob });
  }
}
