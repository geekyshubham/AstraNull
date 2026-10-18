#!/usr/bin/env bash
set -eu

echo "[client] Configuring route to server net 172.31.32.0/24 via 172.31.31.2..."
ip route replace default via 172.31.31.2 2>/dev/null || ip route add 172.31.32.0/24 via 172.31.31.2 2>/dev/null || true

echo "[client] Routing table:"
ip -4 route

echo "[client] Ready for proofs."
exec tail -f /dev/null
