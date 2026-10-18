/**
 * AstraNull Efficacy Lab: nfw-router server listeners.
 * Listens on declared test ports using standard Node.js runtime without external dependencies.
 */
const http = require('node:http');
const net = require('node:net');
const dgram = require('node:dgram');

// 1. TCP Port 80: Allowed HTTP service
const httpServer = http.createServer((req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/plain',
    'Server': 'astranull-nfw-target',
  });
  res.end('origin-ok\n');
});
httpServer.listen(80, '0.0.0.0', () => {
  console.log('[server] TCP port 80 (HTTP) listening on 0.0.0.0:80');
});

// 2. TCP Port 22: Management port (SSH banner exposure listener)
const sshServer = net.createServer((socket) => {
  socket.write('SSH-2.0-OpenSSH_9.0 AstraNull-Lab-Target\r\n');
  socket.on('error', () => {});
  // Hold connection until client closes
});
sshServer.listen(22, '0.0.0.0', () => {
  console.log('[server] TCP port 22 (SSH banner) listening on 0.0.0.0:22');
});

// 3. TCP Port 8083: Connection limit test port (connlimit 2)
let connlimitCount = 0;
const connlimitServer = net.createServer((socket) => {
  connlimitCount += 1;
  const id = connlimitCount;
  socket.on('error', () => {});
  socket.on('close', () => {});
});
connlimitServer.listen(8083, '0.0.0.0', () => {
  console.log('[server] TCP port 8083 (connlimit) listening on 0.0.0.0:8083');
});

// 4. TCP Port 8081: DROP target (listener ready if packet were to arrive)
const dropTcpServer = net.createServer((socket) => {
  socket.write('tcp-8081-drop-target-connected\n');
  socket.on('error', () => {});
});
dropTcpServer.listen(8081, '0.0.0.0', () => {
  console.log('[server] TCP port 8081 (drop target) listening on 0.0.0.0:8081');
});

// 5. TCP Port 8082: REJECT target (listener ready if packet were to arrive)
const rejectTcpServer = net.createServer((socket) => {
  socket.write('tcp-8082-reject-target-connected\n');
  socket.on('error', () => {});
});
rejectTcpServer.listen(8082, '0.0.0.0', () => {
  console.log('[server] TCP port 8082 (reject target) listening on 0.0.0.0:8082');
});

// 6. UDP Port 8053: Allowed UDP datagram responder
const udpAllowedSocket = dgram.createSocket('udp4');
udpAllowedSocket.on('message', (msg, rinfo) => {
  const reply = Buffer.from('ok\n');
  udpAllowedSocket.send(reply, 0, reply.length, rinfo.port, rinfo.address, (err) => {
    if (err) console.error('[server] UDP 8053 reply error:', err.message);
  });
});
udpAllowedSocket.on('error', (err) => {
  console.error('[server] UDP 8053 socket error:', err.message);
});
udpAllowedSocket.bind(8053, '0.0.0.0', () => {
  console.log('[server] UDP port 8053 (allowed) listening on 0.0.0.0:8053');
});

// 7. UDP Port 8054: Dropped UDP target (responder ready if packet were to arrive)
const udpDropSocket = dgram.createSocket('udp4');
udpDropSocket.on('message', (msg, rinfo) => {
  const reply = Buffer.from('ok\n');
  udpDropSocket.send(reply, 0, reply.length, rinfo.port, rinfo.address);
});
udpDropSocket.on('error', (err) => {
  console.error('[server] UDP 8054 socket error:', err.message);
});
udpDropSocket.bind(8054, '0.0.0.0', () => {
  console.log('[server] UDP port 8054 (drop target) listening on 0.0.0.0:8054');
});

console.log('[server] All server listeners initialized.');
