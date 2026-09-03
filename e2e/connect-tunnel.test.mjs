import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";
import { ALLOWED_AUTHORITY, LISTEN_HOST, LISTEN_PORT, UPSTREAM_HOST, UPSTREAM_PORT,
  createConnectTunnel } from "./connect-tunnel.mjs";

const listen = (server) => new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, LISTEN_HOST, () => resolve(server.address().port));
});
const close = (server) => new Promise((resolve) => server.close(resolve));
const transaction = (port, bytes, keep = false) => new Promise((resolve, reject) => {
  const socket = net.connect(port, LISTEN_HOST, () => socket.write(bytes));
  const chunks = [];
  socket.on("data", (chunk) => chunks.push(chunk));
  socket.once("error", reject);
  if (keep) resolve({ socket, chunks });
  else socket.once("close", () => resolve(Buffer.concat(chunks)));
});
const exactRequest = (tail = Buffer.alloc(0)) => Buffer.concat([
  Buffer.from(`CONNECT ${ALLOWED_AUTHORITY} HTTP/1.1\r\nHost: ${ALLOWED_AUTHORITY}\r\n\r\n`), tail,
]);

test("constants and factory fix both hosts, authority, and CLI ports", async () => {
  assert.deepEqual([LISTEN_HOST, LISTEN_PORT, ALLOWED_AUTHORITY, UPSTREAM_HOST, UPSTREAM_PORT],
    ["127.0.0.1", 9323, "watch.example:443", "127.0.0.1", 8787]);
  assert.throws(() => createConnectTunnel({ host: "0.0.0.0" }), /only test loopback ports/);
  const tunnel = createConnectTunnel({ listenPort: 0, upstreamPort: 1 });
  const address = await tunnel.listen();
  assert.deepEqual([address.address, address.family], [LISTEN_HOST, "IPv4"]);
  await tunnel.close();
});

test("ordinary and ambiguous controls fail closed without upstream contact", async () => {
  let accepts = 0;
  const upstream = net.createServer(() => { accepts += 1; });
  const upstreamPort = await listen(upstream);
  const tunnel = createConnectTunnel({ listenPort: 0, upstreamPort });
  const { port } = await tunnel.listen();
  const get = await transaction(port, "GET / HTTP/1.1\r\nHost: watch.example\r\n\r\n");
  assert.match(get.toString(), /^HTTP\/1\.1 405 /);
  for (const control of [
    "CONNECT watch.example:443 HTTP/1.0\r\nHost: watch.example:443\r\n\r\n",
    "CONNECT watch.example:443 HTTP/1.1\r\n\r\n",
    "CONNECT other.example:443 HTTP/1.1\r\nHost: watch.example:443\r\n\r\n",
    "CONNECT WATCH.EXAMPLE:443 HTTP/1.1\r\nHost: watch.example:443\r\n\r\n",
    "CONNECT watch.example.:443 HTTP/1.1\r\nHost: watch.example:443\r\n\r\n",
    "CONNECT user@watch.example:443 HTTP/1.1\r\nHost: watch.example:443\r\n\r\n",
    "CONNECT watch.example:443:443 HTTP/1.1\r\nHost: watch.example:443\r\n\r\n",
    "CONNECT https://watch.example/ HTTP/1.1\r\nHost: watch.example:443\r\n\r\n",
    "CONNECT [127.0.0.1]:443 HTTP/1.1\r\nHost: watch.example:443\r\n\r\n",
    "CONNECT watch.example:443 HTTP/1.1\r\nHost: WATCH.EXAMPLE:443\r\n\r\n",
    "CONNECT watch.example:443 HTTP/1.1\r\nHost: watch.example:443\r\nHost: watch.example:443\r\n\r\n",
    "BROKEN\r\n\r\n",
  ]) {
    const response = await transaction(port, control);
    assert.ok(response.length === 0 || /^HTTP\/1\.1 403 /.test(response.toString()));
  }
  assert.equal(accepts, 0);
  await tunnel.close(); await close(upstream);
});

test("exact CONNECT preserves head and distinct binary bytes in both directions", async () => {
  const head = Buffer.from([0x16, 0x03, 0x01, 0x00, 0x03, 0xfa, 0x00, 0x7f]);
  const clientBytes = Buffer.from([0x00, 0xff, 0x31, 0x80, 0x0a]);
  const serverBytes = Buffer.from([0x17, 0x03, 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]);
  let accepts = 0;
  let receivedResolve;
  const received = new Promise((resolve) => { receivedResolve = resolve; });
  const upstream = net.createServer((socket) => {
    accepts += 1; socket.write(serverBytes); const chunks = [];
    socket.on("data", (chunk) => {
      chunks.push(chunk);
      if (Buffer.concat(chunks).length === head.length + clientBytes.length) {
        receivedResolve(Buffer.concat(chunks)); socket.end();
      }
    });
  });
  const upstreamPort = await listen(upstream);
  const tunnel = createConnectTunnel({ listenPort: 0, upstreamPort });
  const { port } = await tunnel.listen();
  const { socket, chunks } = await transaction(port, exactRequest(head), true);
  await new Promise((resolve) => {
    const poll = () => Buffer.concat(chunks).includes(Buffer.from("\r\n\r\n")) ? resolve() : setImmediate(poll);
    poll();
  });
  socket.write(clientBytes);
  assert.deepEqual(await received, Buffer.concat([head, clientBytes]));
  await new Promise((resolve) => socket.once("close", resolve));
  const response = Buffer.concat(chunks); const boundary = response.indexOf("\r\n\r\n") + 4;
  assert.equal(response.subarray(0, boundary).toString(), "HTTP/1.1 200 Connection Established\r\n\r\n");
  assert.deepEqual(response.subarray(boundary), serverBytes); assert.equal(accepts, 1);
  await tunnel.close(); await close(upstream);
});

test("refusal returns 502 once and active shutdown destroys pairs and releases the port", async () => {
  const vacant = net.createServer(); const refusedPort = await listen(vacant); await close(vacant);
  const refused = createConnectTunnel({ listenPort: 0, upstreamPort: refusedPort });
  const refusedAddress = await refused.listen();
  assert.match((await transaction(refusedAddress.port, exactRequest())).toString(), /^HTTP\/1\.1 502 /);
  assert.equal(refused.upstreams.size, 0); await refused.close();
  const serverSockets = [];
  const upstream = net.createServer((socket) => serverSockets.push(socket));
  const upstreamPort = await listen(upstream);
  const tunnel = createConnectTunnel({ listenPort: 0, upstreamPort });
  const address = await tunnel.listen();
  const connected = async () => {
    const active = await transaction(address.port, exactRequest(), true);
    await new Promise((resolve) => {
      const poll = () => Buffer.concat(active.chunks).includes(Buffer.from("200 Connection Established"))
        ? resolve() : setImmediate(poll);
      poll();
    });
    return active.socket;
  };
  let socket = await connected();
  assert.deepEqual([tunnel.clients.size, tunnel.upstreams.size], [1, 1]);
  const clientClosed = new Promise((resolve) => socket.once("close", resolve));
  socket.end(); await clientClosed;
  assert.deepEqual([tunnel.clients.size, tunnel.upstreams.size], [0, 0]);
  socket = await connected();
  const upstreamClosed = new Promise((resolve) => socket.once("close", resolve));
  serverSockets.at(-1).end(); await upstreamClosed;
  assert.deepEqual([tunnel.clients.size, tunnel.upstreams.size], [0, 0]);
  socket = await connected();
  const shutdownClosed = new Promise((resolve) => socket.once("close", resolve));
  await tunnel.close(); await shutdownClosed;
  assert.deepEqual([tunnel.clients.size, tunnel.upstreams.size], [0, 0]);
  const rebound = net.createServer(); await new Promise((resolve) => rebound.listen(address.port, LISTEN_HOST, resolve));
  await close(rebound); await close(upstream);
});
