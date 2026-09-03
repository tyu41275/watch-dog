import net from "node:net";
import { writeFile } from "node:fs/promises";

const allowedLine = "CONNECT watch.example:443 HTTP/1.1";

export function startConnectTunnel({ host = "127.0.0.1", port = 9323,
  upstreamHost = "127.0.0.1", upstreamPort = 8787, summaryPath } = {}) {
  const counters = { accepted_authorities: 0, rejected_authorities: 0,
    backend_dials: 0, backend_failures: 0, retained_payload_bytes: 0 };
  const sockets = new Set();
  const persist = async () => {
    if (summaryPath) await writeFile(summaryPath, `${JSON.stringify(counters, null, 2)}\n`);
  };
  const server = net.createServer((client) => {
    sockets.add(client); client.once("close", () => sockets.delete(client));
    let request = Buffer.alloc(0); let settled = false;
    const reject = () => {
      if (settled) return;
      settled = true; counters.rejected_authorities += 1;
      client.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
    };
    client.on("data", (chunk) => {
      if (settled) return;
      request = Buffer.concat([request, chunk]);
      if (request.length > 8_192) return reject();
      const end = request.indexOf("\r\n\r\n");
      if (end < 0) return;
      const lines = request.subarray(0, end).toString("ascii").split("\r\n");
      if (lines[0] !== allowedLine || lines.some((line) => /[^\x20-\x7e]/u.test(line))) {
        return reject();
      }
      settled = true; counters.accepted_authorities += 1; counters.backend_dials += 1;
      const upstream = net.createConnection({ host: upstreamHost, port: upstreamPort });
      sockets.add(upstream); upstream.once("close", () => sockets.delete(upstream));
      upstream.once("connect", () => {
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        const tail = request.subarray(end + 4);
        if (tail.length > 0) upstream.write(tail);
        client.pipe(upstream); upstream.pipe(client);
      });
      upstream.once("error", () => { counters.backend_failures += 1; client.destroy(); });
    });
    client.once("error", () => {});
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => resolve({
      address: server.address(),
      counters,
      async close() {
        for (const socket of sockets) socket.destroy();
        await new Promise((done) => server.close(done));
        await persist();
      },
    }));
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const tunnel = await startConnectTunnel({ summaryPath: process.env.WD_CONNECT_SUMMARY });
  const stop = async () => { await tunnel.close(); process.exit(0); };
  process.once("SIGTERM", () => { void stop(); });
  process.once("SIGINT", () => { void stop(); });
}
