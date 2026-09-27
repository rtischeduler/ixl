const WISP_CACHE_KEY = "korona.singlefile.wisp.cache.v1";
const WISP_FAILURES_KEY = "korona.singlefile.wisp.failures.v1";

function normalizeWispUrl(rawUrl) {
  try {
    const url = new URL(rawUrl.trim());
    if (url.protocol !== "wss:" || url.username || url.password || url.search || url.hash) {
      return null;
    }
    if (!url.pathname.endsWith("/")) {
      url.pathname = `${url.pathname}/`;
    }
    return url.toString();
  } catch {
    return null;
  }
}

function decodeWispList(raw) {
  let text = raw.trim();
  for (let i = 0; i < 4; i += 1) {
    const layer = decodeMaskedWispLayer(text);
    if (layer === null) break;
    text = layer.trim();
  }
  const seen = new Set();
  const result = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const normalized = normalizeWispUrl(trimmed);
    if (normalized && !seen.has(normalized)) {
      seen.add(normalized);
      result.push(normalized);
    }
  }
  return result;
}

function decodeMaskedWispLayer(value) {
  const parts = value.trim().split(".");
  if (parts.length !== 3 || parts[0] !== "aw1" || !parts[1] || !/^[A-Za-z0-9_-]+$/.test(parts[2])) {
    return null;
  }
  try {
    const base64 = parts[2].replace(/-/g, "+").replace(/_/g, "/");
    const decoded = atob(`${base64}${"=".repeat((4 - (base64.length % 4)) % 4)}`);
    const bytes = Uint8Array.from(decoded, ch => ch.charCodeAt(0));
    const maskKey = new TextEncoder().encode(`arctic-list-mask:${parts[1]}:1`);
    const unmasked = Uint8Array.from(bytes, (byte, index) => byte ^ maskKey[index % maskKey.length]);
    return new TextDecoder("utf-8", { fatal: true }).decode(unmasked);
  } catch {
    return null;
  }
}

class WispEndpointResolver {
  endpoints;
  storage;
  now;
  probe;
  waveSize;
  probeTimeoutMs;
  rejected = new Set();
  cooldownRecoveryUsed = false;

  constructor(options) {
    this.endpoints = dedupeWispEndpoints(options.endpoints);
    this.storage = options.storage ?? getLocalStorage();
    this.now = options.now ?? (() => Date.now());
    this.probe = options.probe ?? probeWispEndpoint;
    this.waveSize = Math.max(1, Math.min(12, options.waveSize ?? 12));
    this.probeTimeoutMs = Math.max(500, Math.min(15000, options.probeTimeoutMs ?? 6000));
  }

  async resolve() {
    const cached = this.readCache();
    if (cached && this.isAvailable(cached)) {
      return { url: cached, latencyMs: 0, source: "cache" };
    }
    const candidates = this.availableCandidates();
    if (candidates.length === 0) {
      throw new Error("No Seal Wisp endpoints are currently available");
    }
    for (let i = 0; i < candidates.length; i += this.waveSize) {
      const winner = await this.race(candidates.slice(i, i + this.waveSize));
      if (winner) {
        return { ...winner, source: "race" };
      }
    }
    throw new Error("No Seal Wisp endpoint completed its handshake");
  }

  candidates() {
    return this.availableCandidates();
  }

  availableCandidates() {
    const available = this.endpoints.filter(endpoint => this.isAvailable(endpoint));
    if (available.length > 0 || this.cooldownRecoveryUsed || this.rejected.size > 0) {
      return available;
    }
    this.cooldownRecoveryUsed = true;
    return [...this.endpoints];
  }

  reject(endpoint) {
    const normalized = normalizeWispUrl(endpoint);
    if (!normalized || !this.endpoints.includes(normalized)) return;
    this.rejected.add(normalized);
    this.evictCache(normalized);
    this.markFailure(normalized);
  }

  confirm(endpoint) {
    const normalized = normalizeWispUrl(endpoint);
    if (!normalized || !this.endpoints.includes(normalized)) return;
    this.rejected.delete(normalized);
    this.clearFailure(normalized);
    try {
      this.storage?.setItem(WISP_CACHE_KEY, JSON.stringify({ url: normalized, storedAt: this.now() }));
    } catch {}
  }

  async race(endpoints) {
    const results = await Promise.all(
      endpoints.map(async endpoint => {
        try {
          return { url: endpoint, latencyMs: await this.probe(endpoint, this.probeTimeoutMs) };
        } catch {
          this.reject(endpoint);
          return null;
        }
      })
    );
    return results
      .filter(result => result !== null)
      .reduce((best, current) => (best === null || current.latencyMs < best.latencyMs ? current : best), null);
  }

  isAvailable(endpoint) {
    return !this.rejected.has(endpoint) && !this.isCoolingDown(endpoint);
  }

  readCache() {
    try {
      const raw = this.storage?.getItem(WISP_CACHE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      const url = typeof parsed.url === "string" ? normalizeWispUrl(parsed.url) : null;
      if (!url || !this.endpoints.includes(url) || typeof parsed.storedAt !== "number") {
        return null;
      }
      const age = this.now() - parsed.storedAt;
      return age >= 0 && age < 86400000 ? url : null;
    } catch {
      return null;
    }
  }

  evictCache(endpoint) {
    try {
      const cached = this.readCache();
      if (!cached || cached === endpoint) {
        this.storage?.removeItem(WISP_CACHE_KEY);
      }
    } catch {}
  }

  failures() {
    try {
      const raw = this.storage?.getItem(WISP_FAILURES_KEY);
      const parsed = raw ? JSON.parse(raw) : {};
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    } catch {
      return {};
    }
  }

  writeFailures(failures) {
    try {
      if (Object.keys(failures).length === 0) {
        this.storage?.removeItem(WISP_FAILURES_KEY);
      } else {
        this.storage?.setItem(WISP_FAILURES_KEY, JSON.stringify(failures));
      }
    } catch {}
  }

  markFailure(endpoint) {
    const failures = this.failures();
    const count = Math.min((failures[endpoint]?.failures ?? 0) + 1, 8);
    failures[endpoint] = { failures: count, retryAt: this.now() + Math.min(30000 * 4 ** (count - 1), 1800000) };
    this.writeFailures(failures);
  }

  clearFailure(endpoint) {
    const failures = this.failures();
    if (endpoint in failures) {
      delete failures[endpoint];
      this.writeFailures(failures);
    }
  }

  isCoolingDown(endpoint) {
    const failures = this.failures();
    const entry = failures[endpoint];
    if (!entry) return false;
    if (Number.isFinite(entry.retryAt) && entry.retryAt > this.now()) {
      return true;
    }
    delete failures[endpoint];
    this.writeFailures(failures);
    return false;
  }
}

function dedupeWispEndpoints(endpoints) {
  const seen = new Set();
  return endpoints.flatMap(endpoint => {
    const normalized = normalizeWispUrl(endpoint);
    if (!normalized || seen.has(normalized)) return [];
    seen.add(normalized);
    return [normalized];
  });
}

function getLocalStorage() {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function probeWispEndpoint(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const startedAt = performance.now();
    let socket;
    try {
      socket = new WebSocket(url);
    } catch (err) {
      reject(err);
      return;
    }
    let settled = false;
    const finish = callback => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timeoutId);
      socket.onopen = null;
      socket.onmessage = null;
      socket.onerror = null;
      socket.onclose = null;
      try {
        socket.close();
      } catch {}
      callback();
    };
    const timeoutId = window.setTimeout(
      () => finish(() => reject(new Error("Seal Wisp handshake timed out"))),
      timeoutMs
    );
    socket.binaryType = "arraybuffer";
    socket.onmessage = event => {
      const handleBuffer = buffer => {
        if (buffer.byteLength < 5) return;
        const view = new DataView(buffer);
        if (view.getUint8(0) === 3 && view.getUint32(1, true) === 0) {
          finish(() => resolve(performance.now() - startedAt));
        }
      };
      if (event.data instanceof ArrayBuffer) {
        handleBuffer(event.data);
      } else if (event.data instanceof Blob) {
        event.data
          .arrayBuffer()
          .then(handleBuffer, () => finish(() => reject(new Error("Seal Wisp handshake data failed"))));
      }
    };
    socket.onerror = () => finish(() => reject(new Error("Seal Wisp socket failed")));
    socket.onclose = () => finish(() => reject(new Error("Seal Wisp socket closed before handshake")));
  });
}

function parseLaunchParams(queryString, overrides) {
  if (queryString.length > 16384) return null;
  const params = new URLSearchParams(queryString);
  const target =
    typeof overrides?.target === "string" ? overrides.target : decodeBase64UrlString(params.get("target"));
  const wisps = Array.isArray(overrides?.wisps) ? overrides.wisps : decodeBase64UrlJson(params.get("wisps"));
  const apiOriginParam =
    typeof overrides?.apiOrigin === "string" ? overrides.apiOrigin : decodeBase64UrlString(params.get("api"));
  if (!target || !Array.isArray(wisps)) return null;
  try {
    const targetUrl = new URL(target);
    if (!["https:", "http:"].includes(targetUrl.protocol)) return null;
    let apiOrigin = "";
    if (apiOriginParam) {
      const apiUrl = new URL(apiOriginParam);
      if (apiUrl.protocol !== "https:") return null;
      apiOrigin = apiUrl.href.replace(/\/$/, "");
    }
    const wispList = decodeWispList(wisps.filter(entry => typeof entry === "string").join("\n"));
    if (wispList.length === 0 || wispList.length > 256) return null;
    return { target: targetUrl.href, wisps: wispList, apiOrigin };
  } catch {
    return null;
  }
}

function buildRuntimeMessage(status, payload = {}) {
  switch (status) {
    case "ready":
      return { type: "korona-runtime", status, source: typeof payload.source === "string" ? payload.source : "" };
    case "progress":
      return { type: "korona-runtime", status, count: typeof payload.count === "number" ? payload.count : 0 };
    case "first-content":
      return { type: "korona-runtime", status, url: typeof payload.url === "string" ? payload.url : "" };
    case "navigate":
      return { type: "korona-runtime", status, url: typeof payload.url === "string" ? payload.url : "" };
    case "wisp-failed":
      return {
        type: "korona-runtime",
        status,
        endpoint: typeof payload.endpoint === "string" ? payload.endpoint : ""
      };
    case "error":
      return {
        type: "korona-runtime",
        status,
        detail: typeof payload.detail === "string" ? payload.detail : "Runtime error"
      };
  }
}

function decodeBase64UrlString(value) {
  const decoded = decodeBase64UrlJson(value);
  return typeof decoded === "string" && decoded.length <= 4096 ? decoded : null;
}

function decodeBase64UrlJson(value) {
  if (!value || value.length > 12000 || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(`${base64}${"=".repeat((4 - (base64.length % 4)) % 4)}`));
  } catch {
    return null;
  }
}

function reportWispFailure(resolver, endpoint, emit) {
  resolver.reject(endpoint);
  emit("wisp-failed", { endpoint });
}

const MODULE_PRELOAD_REL = "modulepreload";
const preloadedModules = {};

function toAssetUrl(path) {
  return "/" + path;
}

function preloadModule(loadModule, deps) {
  let ready = Promise.resolve();
  if (deps && deps.length > 0) {
    const toSettledResults = promises =>
      Promise.all(
        promises.map(promise =>
          Promise.resolve(promise).then(
            value => ({ status: "fulfilled", value }),
            reason => ({ status: "rejected", reason })
          )
        )
      );
    document.getElementsByTagName("link");
    const nonceMeta = document.querySelector("meta[property=csp-nonce]");
    const nonce = nonceMeta?.nonce || nonceMeta?.getAttribute("nonce");
    ready = toSettledResults(
      deps.map(dep => {
        dep = toAssetUrl(dep);
        if (dep in preloadedModules) return;
        preloadedModules[dep] = true;
        const isCss = dep.endsWith(".css");
        const selector = isCss ? '[rel="stylesheet"]' : "";
        if (document.querySelector(`link[href="${dep}"]${selector}`)) return;
        const link = document.createElement("link");
        link.rel = isCss ? "stylesheet" : MODULE_PRELOAD_REL;
        if (!isCss) link.as = "script";
        link.crossOrigin = "";
        link.href = dep;
        if (nonce) link.setAttribute("nonce", nonce);
        document.head.appendChild(link);
        if (isCss) {
          return new Promise((resolve, reject) => {
            link.addEventListener("load", resolve);
            link.addEventListener("error", () => reject(new Error(`Unable to preload CSS for ${dep}`)));
          });
        }
      })
    );
  }
  return ready.then(results => {
    for (const result of results || []) {
      if (result.status === "rejected") handlePreloadError(result.reason);
    }
    return loadModule().catch(handlePreloadError);
  });
}

function handlePreloadError(err) {
  const event = new Event("vite:preloadError", { cancelable: true });
  event.payload = err;
  window.dispatchEvent(event);
  if (!event.defaultPrevented) throw err;
}

const DEFAULT_FORWARD_TIMEOUT_MS = 7000;
const MAX_FORWARD_TIMEOUT_MS = 15000;

async function createTransport(wispUrl, factory) {
  const transport = factory?.(wispUrl) ?? (await loadDefaultTransport(wispUrl));
  await transport.init();
  if (!transport.ready) {
    throw new Error("Korona runtime transport did not become ready.");
  }
  return transport;
}

async function warmUpTransport(transport, targetUrl, options = {}) {
  const qualifiedUrl = qualifyTargetUrl(targetUrl);
  const request = getTransportRequest(transport);
  const controller = new AbortController();
  const timeoutMs = clampTimeoutMs(options.timeoutMs);
  const response = await withTimeout(
    request(qualifiedUrl, "GET", null, [["accept", "*/*"], ["cache-control", "no-cache"]], controller.signal),
    timeoutMs,
    () => controller.abort()
  );
  if (!Number.isFinite(response.status) || response.status <= 0) {
    throw new Error("Korona runtime forwarding returned an invalid response.");
  }
  drainResponseBody(response.body);
  return transport;
}

async function loadDefaultTransport(wispUrl) {
  const { default: TransportClass } = await preloadModule(async () => {
    const { default: mod } = await import("./assets/index-DOyCiNlp.js");
    return { default: mod };
  }, []);
  return new TransportClass({ wisp: wispUrl });
}

function qualifyTargetUrl(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Korona runtime can only qualify web destinations.");
  }
  parsed.hash = "";
  return parsed;
}

function getTransportRequest(transport) {
  if (typeof transport.request !== "function") {
    throw new Error("Korona runtime transport cannot forward requests.");
  }
  return transport.request.bind(transport);
}

function clampTimeoutMs(timeoutMs) {
  return Number.isFinite(timeoutMs)
    ? Math.max(250, Math.min(MAX_FORWARD_TIMEOUT_MS, Math.floor(timeoutMs)))
    : DEFAULT_FORWARD_TIMEOUT_MS;
}

async function withTimeout(promise, timeoutMs, onTimeout) {
  let timeoutId = 0;
  const timeout = new Promise((_, reject) => {
    timeoutId = window.setTimeout(() => {
      onTimeout();
      reject(new Error("Korona runtime destination forwarding timed out."));
    }, timeoutMs);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    window.clearTimeout(timeoutId);
  }
}

function drainResponseBody(body) {
  if (typeof body?.getReader !== "function") return;
  const reader = body.getReader();
  reader.cancel?.().finally(() => reader.releaseLock?.());
}

class RelayForwardingError extends Error {
  endpoint;
  constructor(endpoint, cause) {
    super(cause instanceof Error ? cause.message : "Korona runtime forwarding failed.");
    this.endpoint = endpoint;
  }
}

function postRuntimeMessage(status, payload = {}) {
  if (window.parent !== window) {
    window.parent.postMessage(buildRuntimeMessage(status, payload), "*");
  }
}

function setStatusMessage(text) {
  const el = document.getElementById("runtime-message");
  if (el) el.textContent = text;
}

async function ensureServiceWorker() {
  const container = getServiceWorkerContainer();
  if (!container) {
    throw new Error("Service workers are unavailable in this browser.");
  }
  const baseUrl = getBaseUrl();
  const registration = await container.register(new URL("sw.js", baseUrl).href, {
    scope: baseUrl.href,
    updateViaCache: "none"
  });
  const active = registration.active;
  if (active?.state === "activated") return active;
  const worker = registration.installing ?? registration.waiting ?? active;
  if (!worker) {
    throw new Error("Korona runtime worker did not begin installing.");
  }
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      window.clearTimeout(timeoutId);
      worker.removeEventListener("statechange", onStateChange);
    };
    const timeoutId = window.setTimeout(() => {
      cleanup();
      reject(new Error("Korona runtime worker did not activate."));
    }, 15000);
    const onStateChange = () => {
      if (worker.state === "activated") {
        cleanup();
        resolve(worker);
      } else if (worker.state === "redundant") {
        cleanup();
        reject(new Error("Korona runtime worker became redundant."));
      }
    };
    worker.addEventListener("statechange", onStateChange);
  });
}

function getServiceWorkerContainer() {
  try {
    if (window.parent !== window && "serviceWorker" in window.parent.navigator) {
      return window.parent.navigator.serviceWorker;
    }
  } catch {}
  return "serviceWorker" in navigator ? navigator.serviceWorker : null;
}

function getBaseUrl() {
  return new URL("./", document.baseURI);
}

function resolveAssetUrl(path) {
  return new URL(path, getBaseUrl()).href;
}

function getFramePrefixPath() {
  return new URL("f/", getBaseUrl()).pathname;
}

function getEmbeddedLaunchConfig() {
  return globalThis.__KORONA_RUNTIME_LAUNCH__;
}

async function bootstrap() {
  const params = parseLaunchParams(location.search, getEmbeddedLaunchConfig());
  if (!params) {
    throw new Error("This Korona runtime launch was invalid.");
  }
  const frameEl = document.getElementById("runtime-frame");
  if (!frameEl) {
    throw new Error("Korona runtime frame was missing.");
  }
  setStatusMessage("Selecting a relay…");
  postRuntimeMessage("progress", { count: 1 });
  const resolver = new WispEndpointResolver({ endpoints: params.wisps });
  const { endpoint, transport } = await selectWorkingRelay(resolver, params.target);
  setStatusMessage("Starting secure browser runtime…");
  postRuntimeMessage("progress", { count: 2 });
  const serviceWorker = await ensureServiceWorker();
  const sealjet = globalThis.$sealjetController;
  if (!sealjet?.Controller) {
    throw new Error("Korona relay controller did not load.");
  }
  const controller = new sealjet.Controller({
    serviceworker: serviceWorker,
    transport,
    config: {
      prefix: getFramePrefixPath(),
      sealjetPath: resolveAssetUrl("sealjet/sealjet.js"),
      injectPath: resolveAssetUrl("sealjet/sealjet.inject.js"),
      wasmPath: resolveAssetUrl("sealjet/sealjet.wasm")
    }
  });
  await controller.wait();
  postRuntimeMessage("ready", { source: getBaseUrl().origin });
  postRuntimeMessage("progress", { count: 3 });
  const frame = controller.createFrame(frameEl);
  let timedOut = false;
  const failsafeId = window.setTimeout(() => {
    timedOut = true;
    setStatusMessage("Trying another relay…");
    reportWispFailure(resolver, endpoint, postRuntimeMessage);
  }, 45000);
  frameEl.addEventListener(
    "load",
    () => {
      if (timedOut) return;
      window.clearTimeout(failsafeId);
      resolver.confirm(endpoint);
      document.getElementById("runtime-stage")?.classList.add("ready");
      postRuntimeMessage("first-content", { url: params.target });
    },
    { once: true }
  );
  frame.go(params.target);
}

async function selectWorkingRelay(resolver, targetUrl) {
  let lastEndpoint = "";
  let lastError = new Error("Korona runtime could not select a relay.");
  const candidates = resolver.candidates();
  if (candidates.length === 0) {
    throw new Error("No Seal Wisp endpoints are currently available");
  }
  for (const endpoint of candidates) {
    try {
      const transport = await createTransport(endpoint);
      await warmUpTransport(transport, targetUrl);
      return { endpoint, transport };
    } catch (err) {
      resolver.reject(endpoint);
      lastEndpoint = endpoint;
      lastError = err;
    }
  }
  throw new RelayForwardingError(lastEndpoint, lastError);
}

bootstrap().catch(err => {
  if (err instanceof RelayForwardingError) {
    setStatusMessage(err.message);
    postRuntimeMessage("wisp-failed", { endpoint: err.endpoint });
    return;
  }
  const message = err instanceof Error ? err.message : "Korona runtime failed.";
  setStatusMessage(message);
  postRuntimeMessage("error", { detail: message });
});
