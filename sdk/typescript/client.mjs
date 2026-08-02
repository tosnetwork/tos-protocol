const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_SEARCH_BODY_BYTES = 64 * 1024;

export class RegistryClient {
  #base;
  #fetch;

  constructor(baseURL, fetchImplementation = globalThis.fetch) {
    let parsed;
    try { parsed = new URL(baseURL); } catch { throw new Error("invalid Registry client configuration"); }
    const local = parsed.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
    if ((!local && parsed.protocol !== "https:") || parsed.username || parsed.password ||
        parsed.search || parsed.hash || baseURL.length > 2048 || typeof fetchImplementation !== "function") {
      throw new Error("invalid Registry client configuration");
    }
    parsed.pathname = parsed.pathname.replace(/\/$/, "");
    this.#base = parsed;
    this.#fetch = fetchImplementation;
  }

  async search(request, options = {}) {
    const body = JSON.stringify(request);
    if (typeof body !== "string" || !request || Array.isArray(request) || typeof request !== "object" ||
        Buffer.byteLength(body) > MAX_SEARCH_BODY_BYTES) throw new Error("invalid Registry search");
    const response = await this.#request("search", { method: "POST", body,
      headers: { "content-type": "application/json" }, signal: options.signal });
    if (!Array.isArray(response.results) || response.results.length > 100) throw new Error("invalid Registry search response");
    for (const result of response.results) {
      if (!validEntry(result) || !Number.isFinite(result.score) || result.score < 0 || result.score > 100 ||
          typeof result.source !== "string" || result.source.length === 0) throw new Error("invalid Registry search response");
    }
    return response;
  }

  async list(request = {}, options = {}) {
    if (!request || Array.isArray(request) || typeof request !== "object" ||
        !optionalString(request.filter) || !optionalString(request.orderBy) || !optionalString(request.pageToken) ||
        (request.filter?.length ?? 0) > 4096 || (request.orderBy?.length ?? 0) > 256 ||
        (request.pageToken?.length ?? 0) > 4096 ||
        (request.pageSize !== undefined && (!Number.isInteger(request.pageSize) || request.pageSize < 0 || request.pageSize > 100))) {
      throw new Error("invalid Registry list");
    }
    const query = new URLSearchParams();
    for (const field of ["filter", "orderBy", "pageToken"]) if (request[field]) query.set(field, request[field]);
    if (request.pageSize) query.set("pageSize", String(request.pageSize));
    const response = await this.#request(`agents${query.size ? `?${query}` : ""}`, { signal: options.signal });
    if (!Array.isArray(response.items) || response.items.length > 100 || !Number.isInteger(response.total) ||
        response.total < response.items.length || response.items.some((entry) => !validEntry(entry))) {
      throw new Error("invalid Registry list response");
    }
    return response;
  }

  async #request(path, init) {
    const endpoint = new URL(this.#base);
    const separator = path.indexOf("?");
    const relativePath = separator < 0 ? path : path.slice(0, separator);
    endpoint.pathname = `${endpoint.pathname.replace(/\/$/, "")}/${relativePath}`;
    endpoint.search = separator < 0 ? "" : path.slice(separator + 1);
    let response;
    try { response = await this.#fetch(endpoint, { ...init, redirect: "error" }); }
    catch { throw new Error("Registry transport failed"); }
    if (!response.ok || response.headers.get("content-type") !== "application/json") throw new Error("Registry response rejected");
    let data;
    try { data = await readBounded(response.body, MAX_RESPONSE_BYTES); }
    catch { throw new Error("Registry response rejected"); }
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(data);
      rejectDuplicateKeys(text);
      const decoded = JSON.parse(text);
      if (!decoded || Array.isArray(decoded) || typeof decoded !== "object") throw new Error("object required");
      return decoded;
    } catch { throw new Error("invalid Registry response"); }
  }
}

async function readBounded(stream, maximum) {
  if (!stream) throw new Error("empty response");
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximum) throw new Error("response too large");
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result;
}

// Tokenizes JSON only far enough to track object key sets. JSON.parse remains
// the semantic parser; this pass closes JavaScript's duplicate-key ambiguity.
function rejectDuplicateKeys(text) {
  let index = 0;
  const space = () => { while (/\s/.test(text[index] ?? "")) index++; };
  const string = () => {
    const start = index++;
    while (index < text.length) {
      if (text[index] === "\\") { index += 2; continue; }
      if (text[index++] === '"') return JSON.parse(text.slice(start, index));
    }
    throw new Error("unterminated string");
  };
  const value = () => {
    space();
    if (text[index] === '{') return object();
    if (text[index] === '[') {
      index++; space();
      if (text[index] === ']') { index++; return; }
      for (;;) { value(); space(); if (text[index++] === ']') return; if (text[index - 1] !== ',') throw new Error("array"); }
    }
    if (text[index] === '"') { string(); return; }
    const match = /^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/.exec(text.slice(index));
    if (!match) throw new Error("value");
    index += match[0].length;
  };
  const object = () => {
    index++; space();
    const keys = new Set();
    if (text[index] === '}') { index++; return; }
    for (;;) {
      space(); if (text[index] !== '"') throw new Error("object key");
      const key = string(); if (keys.has(key)) throw new Error("duplicate key"); keys.add(key);
      space(); if (text[index++] !== ':') throw new Error("colon");
      value(); space(); const delimiter = text[index++];
      if (delimiter === '}') return;
      if (delimiter !== ',') throw new Error("object delimiter");
    }
  };
  value(); space();
  if (index !== text.length) throw new Error("trailing data");
}

function validEntry(entry) {
  return entry && typeof entry === "object" && !Array.isArray(entry) &&
    typeof entry.identifier === "string" && entry.identifier.length > 0 && entry.identifier.length <= 512 &&
    typeof entry.displayName === "string" && entry.displayName.length > 0 && entry.displayName.length <= 512 &&
    typeof entry.type === "string" && entry.type.length > 0 && entry.type.length <= 256 &&
    typeof entry.publisherId === "string" && entry.publisherId.length > 0 && entry.publisherId.length <= 512;
}

function optionalString(value) {
  return value === undefined || typeof value === "string";
}
