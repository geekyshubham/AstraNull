import assert from 'node:assert/strict';

// A connection is identified solely by observed socket endpoints, in the owned
// server's perspective. Never derive this identity from a scenario, job or receipt.
export function deliveryPeerTuple({ local_address, local_port, remote_address, remote_port }) {
  assert.equal(local_address, '127.0.0.1');
  assert.equal(remote_address, '127.0.0.1');
  assert.ok(Number.isInteger(local_port) && local_port > 0);
  assert.ok(Number.isInteger(remote_port) && remote_port > 0);
  return { local_address, local_port, remote_address, remote_port,
    connection_id: `${local_address}:${local_port}<-${remote_address}:${remote_port}` };
}

export function deliverySocketIdentity(socket) {
  return deliveryPeerTuple({ local_address: socket.localAddress, local_port: socket.localPort,
    remote_address: socket.remoteAddress, remote_port: socket.remotePort });
}

export function deliveryDatagramIdentity(server, peer) {
  const local = server.address();
  return deliveryPeerTuple({ local_address: local.address, local_port: local.port,
    remote_address: peer.address, remote_port: peer.port });
}

