import http from "node:http";
import net from "node:net";

export const LISTEN_HOST = "127.0.0.1";
export const LISTEN_PORT = 9323;
export const ALLOWED_AUTHORITY = "watch.example:443";
export const UPSTREAM_HOST = "127.0.0.1";
export const UPSTREAM_PORT = 8787;

const empty = (socket, status) => {
  if (socket.destroyed) return;
  socket.end(`HTTP/1.1 ${status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
};

export function createConnectTunnel(options = {}) {
  const keys = Object.keys(options).sort();
  if (keys.some((key) => !["listenPort", "upstreamPort"].includes(key))) {
    throw new TypeError("only test loopback ports are configurable");
  }
  const listenPort = options.listenPort ?? LISTEN_PORT;
  const upstreamPort = options.upstreamPort ?? UPSTREAM_PORT;
  if (![listenPort, upstreamPort].every((port) => Number.isInteger(port) && port >= 0 && port <= 65535)) {
    throw new TypeError("invalid loopback port");
  }
  const clients = new Set();
  const upstreams = new Set();
  const server = http.createServer({ maxHeaderSize: 4096 }, (_request, response) => {
    response.writeHead(405, { "content-length": "0", connection: "close" });
    response.end();
  });
  server.headersTimeout = 2_000;
  server.requestTimeout = 2_000;
  server.keepAliveTimeout = 1_000;
  server.on("clientError", (_error, socket) => socket.destroy());
  server.on("connect", (request, client, head) => {
    const hosts = [];
    for (let index = 0; index < request.rawHeaders.length; index += 2) {
      if (request.rawHeaders[index].toLowerCase() === "host") hosts.push(request.rawHeaders[index + 1]);
    }
    if (request.method !== "CONNECT" || request.httpVersion !== "1.1" ||
      request.url !== ALLOWED_AUTHORITY || hosts.length !== 1 || hosts[0] !== ALLOWED_AUTHORITY) {
      empty(client, "403 Forbidden");
      return;
    }
    const upstream = net.connect({ host: UPSTREAM_HOST, port: upstreamPort });
    clients.add(client); upstreams.add(upstream);
    let established = false;
    const closePair = () => {
      clients.delete(client); upstreams.delete(upstream);
      if (!client.destroyed) client.destroy();
      if (!upstream.destroyed) upstream.destroy();
    };
    client.setTimeout(15_000, closePair);
    upstream.setTimeout(5_000, () => {
      if (!established) empty(client, "502 Bad Gateway");
      closePair();
    });
    client.once("error", closePair); upstream.once("error", () => {
      if (!established) empty(client, "502 Bad Gateway");
      closePair();
    });
    client.once("close", closePair); upstream.once("close", closePair);
    upstream.once("connect", () => {
      established = true;
      upstream.setTimeout(15_000, closePair);
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length !== 0) upstream.write(head);
      client.pipe(upstream); upstream.pipe(client);
    });
  });
  return {
    server, clients, upstreams,
    listen() {
      return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen({ host: LISTEN_HOST, port: listenPort, ipv6Only: false }, () => {
          server.off("error", reject); resolve(server.address());
        });
      });
    },
    close() {
      for (const socket of [...clients, ...upstreams]) socket.destroy();
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

if (import.meta.main) {
  if (process.argv.length !== 2) throw new Error("connect tunnel accepts no arguments");
  const tunnel = createConnectTunnel();
  await tunnel.listen();
  console.log(`CONNECT ${LISTEN_HOST}:${LISTEN_PORT} -> ${ALLOWED_AUTHORITY} -> ${UPSTREAM_HOST}:${UPSTREAM_PORT}`);
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    const deadline = setTimeout(() => process.exit(1), 5_000);
    await tunnel.close(); clearTimeout(deadline); process.exit(0);
  };
  process.once("SIGINT", stop); process.once("SIGTERM", stop);
}
