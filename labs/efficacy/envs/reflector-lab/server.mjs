import dgram from 'node:dgram';
import net from 'node:net';
import http from 'node:http';

const CHARGEN_PORT = 19;
const SSDP_PORT = 1900;
const STUN_PORT = 3478;
const REDIS_PORT = 6379;
const HEALTH_PORT = 8080;

const sockets = [];

// 1. CHARGEN (UDP 19)
const chargenReply = Buffer.from('RFC864 CHARGEN TEST SERVICE REFLECTOR-LAB ASTRANULL-EFFICACY\r\n', 'ascii');
const chargenSocket = dgram.createSocket('udp4');
chargenSocket.on('error', (err) => console.error('chargen socket error:', err));
chargenSocket.on('message', (_msg, rinfo) => {
  chargenSocket.send(chargenReply, rinfo.port, rinfo.address, (err) => {
    if (err) console.error('chargen send error:', err);
  });
});
chargenSocket.bind(CHARGEN_PORT, '0.0.0.0', () => {
  console.log(`CHARGEN responder listening on udp/${CHARGEN_PORT}`);
});
sockets.push(chargenSocket);

// 2. SSDP (UDP 1900)
const ssdpReply = Buffer.from(
  'HTTP/1.1 200 OK\r\n' +
  'ST: upnp:rootdevice\r\n' +
  'USN: uuid:12345678-1234-1234-1234-123456789012::upnp:rootdevice\r\n' +
  '\r\n',
  'ascii'
);
const ssdpSocket = dgram.createSocket('udp4');
ssdpSocket.on('error', (err) => console.error('ssdp socket error:', err));
ssdpSocket.on('message', (_msg, rinfo) => {
  ssdpSocket.send(ssdpReply, rinfo.port, rinfo.address, (err) => {
    if (err) console.error('ssdp send error:', err);
  });
});
ssdpSocket.bind(SSDP_PORT, '0.0.0.0', () => {
  console.log(`SSDP responder listening on udp/${SSDP_PORT}`);
});
sockets.push(ssdpSocket);

// 3. STUN (UDP 3478)
const stunSocket = dgram.createSocket('udp4');
stunSocket.on('error', (err) => console.error('stun socket error:', err));
stunSocket.on('message', (msg, rinfo) => {
  if (msg.length >= 20) {
    const reply = Buffer.alloc(20);
    reply.writeUInt16BE(0x0101, 0); // Binding Success Response
    reply.writeUInt16BE(0x0000, 2); // Message Length = 0
    reply.writeUInt32BE(0x2112a442, 4); // Magic Cookie
    msg.subarray(8, 20).copy(reply, 8); // Echo 12-byte Transaction ID
    stunSocket.send(reply, rinfo.port, rinfo.address, (err) => {
      if (err) console.error('stun send error:', err);
    });
  }
});
stunSocket.bind(STUN_PORT, '0.0.0.0', () => {
  console.log(`STUN responder listening on udp/${STUN_PORT}`);
});
sockets.push(stunSocket);

// 4. Redis (TCP 6379)
const redisServer = net.createServer((conn) => {
  conn.on('data', (data) => {
    const cmd = data.toString('utf8');
    if (/PING/i.test(cmd)) {
      conn.write('+PONG\r\n');
    } else {
      conn.write('-ERR unknown command\r\n');
    }
  });
  conn.on('error', () => {});
});
redisServer.listen(REDIS_PORT, '0.0.0.0', () => {
  console.log(`Redis mock server listening on tcp/${REDIS_PORT}`);
});

// 5. HTTP Health Check (TCP 8080)
const healthServer = http.createServer((req, res) => {
  if (req.url === '/health' || req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'healthy',
      service: 'anl-reflector-lab-exposed',
      chargen_udp: CHARGEN_PORT,
      ssdp_udp: SSDP_PORT,
      stun_udp: STUN_PORT,
      redis_tcp: REDIS_PORT,
    }));
  } else {
    res.writeHead(404);
    res.end();
  }
});
healthServer.listen(HEALTH_PORT, '0.0.0.0', () => {
  console.log(`Health check listening on tcp/${HEALTH_PORT}`);
});

// Graceful shutdown
function shutdown() {
  console.log('Shutting down server...');
  for (const s of sockets) {
    try { s.close(); } catch {}
  }
  try { redisServer.close(); } catch {}
  try { healthServer.close(); } catch {}
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
