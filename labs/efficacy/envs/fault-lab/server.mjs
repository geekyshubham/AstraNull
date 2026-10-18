import net from 'node:net';
import { execSync } from 'node:child_process';

const PORT = 18080;
const HOST = '127.0.0.1';
const BLOCKED_CLIENT_PORT = 40001;
const ALLOWED_CLIENT_PORT = 40002;

console.log('[fault-target] Initializing firewall rules for exact tuple DROP...');

try {
  // Flush previous rules and set default accept
  execSync('iptables -F', { stdio: 'inherit' });
  execSync('iptables -X', { stdio: 'inherit' });
  execSync('iptables -Z', { stdio: 'inherit' });
  execSync('iptables -P INPUT ACCEPT', { stdio: 'inherit' });
  execSync('iptables -P OUTPUT ACCEPT', { stdio: 'inherit' });
  execSync('iptables -P FORWARD ACCEPT', { stdio: 'inherit' });

  // Plant exact client/server tuple DROP rule:
  // src: 127.0.0.1:40001 -> dst: 127.0.0.1:18080
  execSync(`iptables -A INPUT -p tcp -s ${HOST} --sport ${BLOCKED_CLIENT_PORT} -d ${HOST} --dport ${PORT} -j DROP`, { stdio: 'inherit' });

  // Plant exact client/server tuple ACCEPT tracking rule:
  // src: 127.0.0.1:40002 -> dst: 127.0.0.1:18080
  execSync(`iptables -A INPUT -p tcp -s ${HOST} --sport ${ALLOWED_CLIENT_PORT} -d ${HOST} --dport ${PORT} -j ACCEPT`, { stdio: 'inherit' });

  console.log('[fault-target] Firewall rules configured successfully:');
  execSync('iptables -v -L INPUT -n --line-numbers', { stdio: 'inherit' });
} catch (err) {
  console.error('[fault-target] Failed to configure iptables:', err);
  process.exit(1);
}

const server = net.createServer((socket) => {
  const remote = `${socket.remoteAddress}:${socket.remotePort}`;
  console.log(`[fault-target] Accepted connection from ${remote}`);
  socket.write('ASTRANULL_CONNECT_FAULT_LAB_OK\n');
  socket.end();
});

server.on('error', (err) => {
  console.error('[fault-target] Server error:', err);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log(`[fault-target] TCP listener active on ${HOST}:${PORT}`);
});

process.on('SIGTERM', () => {
  console.log('[fault-target] SIGTERM received, shutting down');
  server.close(() => process.exit(0));
});

process.on('SIGINT', () => {
  console.log('[fault-target] SIGINT received, shutting down');
  server.close(() => process.exit(0));
});
