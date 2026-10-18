import http from 'node:http';

const HEALTH_PORT = 8080;

const healthServer = http.createServer((req, res) => {
  if (req.url === '/health' || req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'healthy',
      service: 'anl-reflector-lab-protected',
      reflectors_exposed: false,
    }));
  } else {
    res.writeHead(404);
    res.end();
  }
});

healthServer.listen(HEALTH_PORT, '0.0.0.0', () => {
  console.log(`Protected host health check listening on tcp/${HEALTH_PORT}`);
});

function shutdown() {
  console.log('Shutting down protected host...');
  try { healthServer.close(); } catch {}
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
