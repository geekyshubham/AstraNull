import net from 'node:net';
import { execSync } from 'node:child_process';

const PORT = 18080;
const HOST = '127.0.0.1';
const BLOCKED_CLIENT_PORT = 40001;

try {
  // 1. Verify iptables DROP rule is installed
  execSync(`iptables -C INPUT -p tcp -s ${HOST} --sport ${BLOCKED_CLIENT_PORT} -d ${HOST} --dport ${PORT} -j DROP`);

  // 2. Verify server responds to health connect on ephemeral port
  const client = net.connect({ host: HOST, port: PORT, localPort: 40003 });
  client.setTimeout(1000);

  let received = '';
  client.on('data', (chunk) => {
    received += chunk.toString('utf8');
  });

  client.on('end', () => {
    if (received.includes('ASTRANULL_CONNECT_FAULT_LAB_OK')) {
      process.exit(0);
    } else {
      console.error(`Unexpected healthcheck response: ${received}`);
      process.exit(1);
    }
  });

  client.on('timeout', () => {
    console.error('Healthcheck connect timed out');
    client.destroy();
    process.exit(1);
  });

  client.on('error', (err) => {
    console.error('Healthcheck connect error:', err);
    process.exit(1);
  });
} catch (err) {
  console.error('Healthcheck failed rule verification:', err);
  process.exit(1);
}
