import net from 'node:net';

const server = net.createServer(() => {});
server.listen({ host: '127.0.0.1', port: 0, backlog: 1, exclusive: true }, () => {
  process.send({ port: server.address().port });
});
setInterval(() => {}, 1 << 30);
