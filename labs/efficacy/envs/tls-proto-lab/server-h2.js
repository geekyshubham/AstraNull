const http2 = require('node:http2');
const fs = require('node:fs');

const certPath = process.env.CERT_PATH || '/app/certs/valid_h2.crt';
const keyPath = process.env.KEY_PATH || '/app/certs/valid_h2.key';

// By default in Node.js, http2.createSecureServer advertises SETTINGS_MAX_CONCURRENT_STREAMS = 4294967295 (unbounded).
const server = http2.createSecureServer({
  cert: fs.readFileSync(certPath),
  key: fs.readFileSync(keyPath),
  allowHTTP1: true,
});

server.on('stream', (stream, headers) => {
  const path = headers[':path'] || '/';
  if (path === '/healthz') {
    stream.respond({ ':status': 200, 'content-type': 'text/plain' });
    stream.end('healthy\n');
    return;
  }
  stream.respond({ ':status': 200, 'content-type': 'text/plain' });
  stream.end('endpoint: h2-unbounded\nstatus: ok\n');
});

server.on('request', (req, res) => {
  if (req.url === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('healthy\n');
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('endpoint: h2-unbounded\nstatus: ok\n');
});

server.listen(443, '0.0.0.0', () => {
  console.log('HTTP/2 server listening on 0.0.0.0:443');
});
