// The contributor page. Everything protocol-shaped (queue, download, attestation, upload) is lib/flow.mjs, shared with the
// CLI; the contribution itself runs in worker.js. This file is only the user interface.
import { CeremonyClient, CeremonyError } from "../lib/client.mjs";
import { contributeToCeremony } from "../lib/flow.mjs";
import { prettyHash } from "../lib/hex.mjs";

const el = Object.fromEntries([...document.querySelectorAll("[id]")].map((node) => [node.id, node]));
const client = new CeremonyClient({ server: location.origin });
const sections = ["intro", "run", "done", "failed"];
const show = (name) => sections.forEach((s) => (el[s].hidden = s !== name));

for (const node of document.querySelectorAll(".origin")) node.textContent = location.origin;

// ---- capability check -----------------------------------------------------------------------------------------------
const missing = [];
if (!window.isSecureContext || !crypto?.subtle) missing.push("a secure (https) connection");
if (typeof Worker === "undefined") missing.push("Web Workers");
if (typeof WebAssembly === "undefined") missing.push("WebAssembly");
if (missing.length > 0) {
  el.unsupported.hidden = false;
  el.unsupported.textContent = `This browser cannot take part from this page: it lacks ${missing.join(", ")}. Use a recent Chrome, Firefox, Safari or Edge, or the command line (see the README).`;
}

// ---- extra entropy: pointer movement and key timing; mixed into what snarkjs uses, never replacing it ---------------
const samples = [];
let lastSample = 0;
addEventListener(
  "pointermove",
  (event) => {
    const t = performance.now();
    if (t - lastSample < 8 || samples.length >= 4096) return;
    lastSample = t;
    samples.push(`${event.clientX},${event.clientY},${t.toFixed(3)}`);
    el["entropy-note"].dataset.samples = String(samples.length);
  },
  { passive: true },
);
addEventListener("keydown", () => samples.length < 4096 && samples.push(`k${performance.now().toFixed(3)}`), { passive: true });
const entropyText = () => `${el.entropy.value}|${samples.join(";")}|${Date.now()}|${performance.now()}`;

// ---- the contribution worker ----------------------------------------------------------------------------------------
let worker;
const pending = new Map();
let nextJob = 0;

function startWorker() {
  const w = new Worker("/worker.js", { type: "module" });
  w.onmessage = ({ data }) => {
    const job = pending.get(data.id);
    if (!job) return;
    if (data.type === "progress") return job.onProgress(data.fraction);
    pending.delete(data.id);
    if (data.type === "done") job.resolve({ zkey: data.zkey, contributionHash: data.contributionHash });
    else job.reject(new Error(data.message));
  };
  w.onerror = (event) => {
    for (const job of pending.values()) job.reject(new Error(event.message || "The worker crashed (out of memory?)."));
    pending.clear();
    worker = undefined;
  };
  return w;
}

function contribute({ zkey, name, entropyText: text, onProgress }) {
  worker ??= startWorker();
  const { promise, resolve, reject } = Promise.withResolvers();
  const id = nextJob++;
  pending.set(id, { resolve, reject, onProgress });
  worker.postMessage({ id, zkey, name, entropyText: text }, [zkey.buffer]);
  return promise;
}

// ---- upload with progress -------------------------------------------------------------------------------------------
function upload(ticket, blob, onProgress) {
  const { promise, resolve, reject } = Promise.withResolvers();
  const xhr = new XMLHttpRequest();
  xhr.open("PUT", "/api/contribution");
  xhr.setRequestHeader("authorization", `Bearer ${ticket}`);
  xhr.setRequestHeader("content-type", "application/octet-stream");
  xhr.upload.onprogress = (event) => event.lengthComputable && onProgress(event.loaded, event.total);
  xhr.onerror = () => reject(new CeremonyError("network", "The upload was interrupted."));
  xhr.onload = () => {
    let body = {};
    try {
      body = JSON.parse(xhr.responseText);
    } catch {
      // not JSON: handled below by the status code
    }
    if (xhr.status >= 200 && xhr.status < 300) resolve(body);
    else reject(new CeremonyError(body.error ?? "http_error", body.message ?? `The server answered HTTP ${xhr.status}.`, xhr.status));
  };
  xhr.send(blob);
  return promise;
}

// ---- rendering ------------------------------------------------------------------------------------------------------
const STEPS = ["queue", "download", "mix", "upload", "verify"];
let deadline = 0;
let clockTimer;
let wakeLock;

function setStep(name) {
  const index = STEPS.indexOf(name);
  for (const li of el.steps.children) {
    const i = STEPS.indexOf(li.dataset.step);
    li.className = i < index ? "done" : i === index ? "active" : "";
  }
}

const minutes = (seconds) => Math.max(1, Math.round(seconds / 60));
const mib = (bytes) => (bytes / 2 ** 20).toFixed(1);

function render(event) {
  const { phase } = event;
  if (phase === "joining") {
    el["run-title"].textContent = "Joining the queue";
    setStep("queue");
    el.bar.removeAttribute("value");
  } else if (phase === "waiting") {
    setStep("queue");
    el["run-title"].textContent = event.ahead === 0 ? "You are next" : `You are number ${event.ahead + 1} in line`;
    el["run-detail"].textContent = event.ahead === 0 ? "Hang on: the contributor before you is finishing. Keep this tab open." : `About ${minutes(event.etaSeconds ?? 0)} minute(s) to go. You can leave this tab in the background, but do not close it.`;
    el.bar.removeAttribute("value");
  } else if (phase === "turn") {
    deadline = Date.now() + event.expiresInMs;
    el["run-title"].textContent = "It is your turn";
    el["run-detail"].textContent = "Downloading the current keys...";
    el.bar.value = 0;
  } else if (phase === "downloading") {
    setStep("download");
    el["run-title"].textContent = `Downloading keys ${event.index + 1} of ${event.total}`;
    el["run-detail"].textContent = event.size ? `${event.circuit}: ${mib(event.loaded)} of ${mib(event.size)} MiB` : event.circuit;
    el.bar.value = ((event.index + 0.1 * (event.size ? event.loaded / event.size : 0)) / event.total) * 0.85;
  } else if (phase === "contributing") {
    setStep("mix");
    el["run-title"].textContent = `Mixing in your randomness: ${event.index + 1} of ${event.total}`;
    el["run-detail"].textContent = `${event.circuit}: ${Math.round(event.fraction * 100)}%`;
    el.bar.value = ((event.index + 0.1 + 0.9 * event.fraction) / event.total) * 0.85;
  } else if (phase === "uploading") {
    setStep("upload");
    el["run-title"].textContent = "Sending the result back";
    el["run-detail"].textContent = event.sent === undefined ? `${mib(event.total)} MiB` : `${mib(event.sent)} of ${mib(event.total)} MiB`;
    el.bar.value = 0.85 + 0.1 * (event.sent === undefined ? 0 : event.sent / event.total);
  } else if (phase === "verifying") {
    setStep("verify");
    deadline = 0;
    el["run-title"].textContent = "The coordinator is checking your contribution";
    el["run-detail"].textContent = "It verifies every point with snarkjs; this can take a few minutes for the real circuits.";
    el["run-clock"].textContent = "";
    el.bar.removeAttribute("value");
  } else if (phase === "expired") {
    deadline = 0;
    setStep("queue");
    el["run-title"].textContent = "Your turn ran out of time";
    el["run-detail"].textContent = `${event.message} Rejoining the queue automatically...`;
    el["run-clock"].textContent = "";
    el.bar.removeAttribute("value");
  }
}

function tickClock() {
  if (deadline === 0) return;
  const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
  el["run-clock"].textContent = `Time left in your slot: ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
}

function shareText(round, attestation) {
  return `I just added my randomness to the Dagon zkAPI trusted setup (round ${round}).\nMy attestation hash: ${attestation}\nCheck the ceremony yourself: ${location.origin}/`;
}

function renderDone(result) {
  el["done-round"].textContent = String(result.round);
  el.attestation.textContent = result.attestation;
  const text = shareText(result.round, result.attestation);
  el.post.value = text;
  el["share-x"].href = `https://x.com/intent/post?text=${encodeURIComponent(text)}`;
  el["share-bsky"].href = `https://bsky.app/intent/compose?text=${encodeURIComponent(text)}`;
  el["share-mail"].href = `mailto:?subject=${encodeURIComponent("My Dagon zkAPI ceremony attestation")}&body=${encodeURIComponent(text)}`;
  el["circuit-hashes"].replaceChildren(
    ...result.contributions.map((c) => {
      const wrap = document.createElement("div");
      const title = document.createElement("h3");
      title.textContent = c.id;
      const pre = document.createElement("pre");
      pre.textContent = prettyHash(c.contributionHash);
      wrap.append(title, pre);
      return wrap;
    }),
  );
  show("done");
  refreshStatus();
}

async function copy(text, button) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    document.body.append(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  const before = button.textContent;
  button.textContent = "Copied";
  setTimeout(() => (button.textContent = before), 1500);
}

el.copy.onclick = () => copy(el.attestation.textContent, el.copy);
el["copy-post"].onclick = () => copy(el.post.value, el["copy-post"]);

// ---- the button -----------------------------------------------------------------------------------------------------
const warnLeaving = (event) => {
  event.preventDefault();
  event.returnValue = "";
};

async function acquireWakeLock() {
  try {
    wakeLock = await navigator.wakeLock?.request("screen");
  } catch {
    // not available, or the tab is hidden: the contribution still works, the screen may just sleep
  }
}
document.addEventListener("visibilitychange", () => document.visibilityState === "visible" && wakeLock !== undefined && !wakeLock.released && acquireWakeLock());

let controller;

async function start() {
  controller = new AbortController();
  show("run");
  setStep("queue");
  el.bar.removeAttribute("value");
  addEventListener("beforeunload", warnLeaving);
  clockTimer = setInterval(tickClock, 1000);
  await acquireWakeLock();
  try {
    const result = await contributeToCeremony({
      client,
      name: el.name.value,
      entropyText: entropyText(),
      contribute,
      upload,
      sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
      onEvent: render,
      attempts: 4,
      signal: controller.signal,
    });
    renderDone(result);
  } catch (error) {
    if (controller.signal.aborted) {
      show("intro");
      return;
    }
    el["failed-message"].textContent = error instanceof CeremonyError || error instanceof Error ? error.message : String(error);
    show("failed");
  } finally {
    removeEventListener("beforeunload", warnLeaving);
    clearInterval(clockTimer);
    await wakeLock?.release().catch(() => {});
    wakeLock = undefined;
  }
}

el.start.onclick = start;
el.cancel.onclick = () => controller?.abort();
el.retry.onclick = () => show("intro");

// ---- status and the public list -------------------------------------------------------------------------------------
async function refreshStatus() {
  try {
    const status = await client.status();
    el.eta.textContent = String(minutes(status.queue.typicalSeconds));
    if (status.closed || status.finalized) {
      el["status-line"].textContent = "The ceremony is closed. Thank you to everyone who took part.";
      el.start.disabled = true;
    } else {
      el["status-line"].textContent = status.queue.length === 0 ? "Nobody is waiting: you can start right now." : `${status.queue.length} contributor(s) in the queue right now.`;
      el.start.disabled = missing.length > 0;
    }
    el["roster-summary"].textContent = `${status.contributions} contribution(s) so far, currently at round ${status.round}${status.finalized ? ", finalized" : ""}.`;
    el.roster.replaceChildren(
      ...status.contributors
        .slice()
        .reverse()
        .map((c) => {
          const li = document.createElement("li");
          const name = document.createElement("b");
          name.textContent = c.kind === "beacon" ? "Final public beacon" : c.name;
          const hash = document.createElement("code");
          hash.textContent = c.attestation ? `${c.attestation.slice(0, 16)}...` : "";
          hash.title = c.attestation ?? "";
          li.append(name, hash);
          return li;
        }),
    );
    el.assets.textContent = Object.entries(status.assets)
      .filter(([name]) => /\.(js|css|html|mjs)$/.test(name))
      .map(([name, sha]) => `${name} sha256 ${sha.slice(0, 12)}...`)
      .join(", ");
  } catch (error) {
    el["status-line"].textContent = `Cannot reach the ceremony right now (${error.message}).`;
    el.start.disabled = true;
  }
}

refreshStatus();
setInterval(() => document.visibilityState === "visible" && el.run.hidden && refreshStatus(), 20_000);
