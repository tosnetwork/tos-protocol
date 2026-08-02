import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";
import { RegistryClient } from "./client.mjs";

const entry = { identifier: "worker-1", displayName: "Worker 1", type: "tos.ai.worker", publisherId: "operator-1" };

test("bounded independent-language Registry client", async (t) => {
  const server = http.createServer((request, response) => {
    response.setHeader("content-type", "application/json");
    if (request.url === "/search" && request.method === "POST") response.end(JSON.stringify({ results: [{ ...entry, score: 100, source: "local" }] }));
    else if (request.url.startsWith("/agents")) response.end(JSON.stringify({ items: [entry], total: 1, nextPageToken: "" }));
    else { response.statusCode = 404; response.end("{}"); }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const { port } = server.address();
  const client = new RegistryClient(`http://127.0.0.1:${port}`);
  assert.equal((await client.search({ query: "worker" })).results[0].identifier, "worker-1");
  assert.equal((await client.list({ filter: 'type="tos.ai.worker"', pageSize: 10 })).items[0].publisherId, "operator-1");
});

test("fails closed on redirects, oversized bodies, duplicates and invalid entries", async (t) => {
  const server = http.createServer((request, response) => {
    response.setHeader("content-type", "application/json");
    if (request.url === "/search") { response.statusCode = 302; response.setHeader("location", "/agents"); return response.end(); }
    response.end(JSON.stringify({ items: [{ ...entry, publisherId: "" }], total: 1 }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const { port } = server.address();
  const client = new RegistryClient(`http://127.0.0.1:${port}`);
  await assert.rejects(client.search({ query: "worker" }), /transport failed/);
  await assert.rejects(client.list(), /invalid Registry list response/);
  const oversized = new RegistryClient("https://registry.example", async () => new Response("x".repeat(MAX + 1), {
    status: 200, headers: { "content-type": "application/json" },
  }));
  await assert.rejects(oversized.list(), /response rejected/);
  const duplicate = new RegistryClient("https://registry.example", async () => new Response('{"items":[],"items":[],"total":0}', {
    status: 200, headers: { "content-type": "application/json" },
  }));
  await assert.rejects(duplicate.list(), /invalid Registry response/);
});

test("rejects insecure remote origins and request-selected excess", async () => {
  assert.throws(() => new RegistryClient("http://registry.example"), /invalid Registry/);
  const client = new RegistryClient("https://registry.example", async () => { throw new Error("must not run"); });
  await assert.rejects(client.list({ pageSize: 101 }), /invalid Registry list/);
});

const MAX = 2 * 1024 * 1024;
