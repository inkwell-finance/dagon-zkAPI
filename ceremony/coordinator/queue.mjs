import { randomBytes } from "node:crypto";

// FIFO queue with one active contributor at a time. Nothing here uses a timer: every state change is evaluated lazily
// against the injected clock when a request touches the queue, so tests drive time directly.
//
// Ticket states: waiting -> active -> verifying -> done | rejected, or expired (heartbeat lost / slot ran out).

export class QueueError extends Error {
  constructor(code, message, status) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

const LIVE = new Set(["waiting", "active", "verifying"]);

export class SlotQueue {
  #tickets = new Map();
  #now;
  #opts;
  #recent = [];

  constructor({ now, slotMs, claimMs, waitHeartbeatMs, maxQueue, maxPerKey, finishedKeepMs }) {
    this.#now = now;
    this.#opts = { slotMs, claimMs, waitHeartbeatMs, maxQueue, maxPerKey, finishedKeepMs };
  }

  get slotMs() {
    return this.#opts.slotMs;
  }

  #live() {
    return [...this.#tickets.values()].filter((t) => LIVE.has(t.state));
  }

  join({ name, key }) {
    this.tick();
    const live = this.#live();
    if (live.length >= this.#opts.maxQueue) throw new QueueError("queue_full", "The queue is full right now. Please try again in a little while.", 503);
    if (live.filter((t) => t.key === key).length >= this.#opts.maxPerKey) {
      throw new QueueError("too_many_tickets", "You already have a place in the queue from this connection.", 429);
    }
    const now = this.#now();
    const ticket = {
      token: randomBytes(32).toString("base64url"),
      name,
      key,
      state: "waiting",
      joinedAt: now,
      lastSeen: now,
      activatedAt: 0,
      claimed: false,
      uploading: false,
      expiresAt: 0,
      finishedAt: 0,
      result: undefined,
      error: undefined,
    };
    this.#tickets.set(ticket.token, ticket);
    this.tick();
    return ticket;
  }

  /** Looks a ticket up and counts the request as a sign of life. */
  touch(token) {
    this.tick();
    const ticket = this.#tickets.get(token);
    if (!ticket) return undefined;
    ticket.lastSeen = this.#now();
    if (ticket.state === "active") ticket.claimed = true;
    return ticket;
  }

  tick() {
    const now = this.#now();
    for (const [token, t] of this.#tickets) {
      if (t.state === "waiting" && now - t.lastSeen > this.#opts.waitHeartbeatMs) this.#end(t, "expired", { message: "You were removed from the queue because the page stopped checking in." });
      else if (t.state === "active" && !t.uploading) {
        if (now >= t.expiresAt) this.#end(t, "expired", { message: "Your time slot ran out." });
        else if (!t.claimed && now - t.activatedAt > this.#opts.claimMs) this.#end(t, "expired", { message: "Your turn started but nothing connected for it." });
      }
      if (!LIVE.has(t.state) && now - t.finishedAt > this.#opts.finishedKeepMs) this.#tickets.delete(token);
    }
    if (!this.#live().some((t) => t.state !== "waiting")) {
      const next = this.#live().find((t) => t.state === "waiting");
      if (next) {
        next.state = "active";
        next.activatedAt = now;
        next.expiresAt = now + this.#opts.slotMs;
      }
    }
  }

  #end(ticket, state, error) {
    ticket.uploadController?.abort(new QueueError("slot_expired", "The upload ticket was released.", 410));
    ticket.state = state;
    ticket.finishedAt = this.#now();
    ticket.uploading = false;
    ticket.error = error;
  }

  /** Tickets ahead of this one, the active or verifying contributor included. */
  ahead(ticket) {
    if (ticket.state !== "waiting") return 0;
    let ahead = 0;
    for (const t of this.#live()) {
      if (t === ticket) break;
      ahead++;
    }
    return ahead;
  }

  length() {
    return this.#live().length;
  }

  /** Rough wait per person ahead: the average of recent contributions, or the slot length before there is any history. */
  typicalMs() {
    if (this.#recent.length === 0) return Math.min(this.#opts.slotMs, 5 * 60_000);
    return this.#recent.reduce((a, b) => a + b, 0) / this.#recent.length;
  }

  /** The contributor gave up (closed the page, pressed cancel): free the place at once instead of waiting for a timeout. */
  release(ticket) {
    if (ticket.state === "waiting" || ticket.state === "active") {
      this.#end(ticket, "expired", { message: "You left the queue." });
      this.tick();
    }
  }

  startUpload(ticket) {
    if (ticket.state !== "active" || this.holder() !== ticket || ticket.uploading) throw new QueueError("not_your_turn", "The upload no longer owns the slot.", 409);
    ticket.uploading = true;
    ticket.uploadStartedAt = this.#now();
    ticket.uploadController = new AbortController();
    return ticket.uploadController;
  }

  cancelUpload(ticket) {
    ticket.uploading = false;
  }

  startVerify(ticket) {
    if (ticket.state !== "active" || this.holder() !== ticket || !ticket.uploading || ticket.uploadController?.signal.aborted) throw new QueueError("not_your_turn", "The upload no longer owns the slot.", 409);
    ticket.state = "verifying";
    ticket.uploading = false;
  }

  finish(ticket, result) {
    this.#recent = [...this.#recent, this.#now() - ticket.activatedAt].slice(-10);
    ticket.result = result;
    this.#end(ticket, "done", undefined);
    this.tick();
  }

  reject(ticket, error) {
    this.#end(ticket, "rejected", error);
    this.tick();
  }

  /** The contributor currently holding the slot, if any, for the public status page. */
  holder() {
    return this.#live().find((t) => t.state !== "waiting");
  }
}
