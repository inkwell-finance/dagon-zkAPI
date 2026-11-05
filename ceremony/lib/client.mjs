// HTTP client for the coordinator API. Used unchanged by the CLI (Node) and the web page (browser).

export class CeremonyError extends Error {
  constructor(code, message, status = 0) {
    super(message);
    this.code = code;
    this.status = status;
  }
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
    const body = await response.json().catch(() => ({}));
    throw new CeremonyError(body.error ?? "http_error", body.message ?? `The server answered HTTP ${response.status}.`, response.status);
  }

  async status() {
    return (await this.#request("api/status")).json();
  }

  async join(name) {
    return (
      await this.#request("api/queue", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name }) })
    ).json();
  }

  async poll(ticket) {
    return (await this.#request("api/ticket", { headers: { authorization: `Bearer ${ticket}` } })).json();
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
    const response = await this.#request("api/contribution", { method: "PUT", headers: { authorization: `Bearer ${ticket}`, "content-type": "application/octet-stream", "content-length": String(blob.size) }, body: blob });
    return response.json();
  }
}
