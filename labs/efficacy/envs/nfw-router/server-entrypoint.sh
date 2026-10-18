#!/usr/bin/env sh
set -eu

echo "[server] Setting up default gateway to router 172.31.32.2..."
ip route replace default via 172.31.32.2 2>/dev/null || ip route add 172.31.31.0/24 via 172.31.32.2 2>/dev/null || true

echo "[server] Routing table:"
ip -4 route

echo "[server] Starting Node server..."
exec node /app/server.js
