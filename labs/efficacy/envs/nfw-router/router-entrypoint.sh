#!/usr/bin/env bash
set -euo pipefail

echo "[router] Starting AstraNull NFW Router..."

# Verify IP forwarding enabled via compose sysctls
echo "[router] net.ipv4.ip_forward = $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 'unknown')"

# Identify interfaces
CLIENT_IF="$(ip -4 route list 172.31.31.0/24 | awk '{print $3}' | head -n1)"
SERVER_IF="$(ip -4 route list 172.31.32.0/24 | awk '{print $3}' | head -n1)"

if [ -z "${CLIENT_IF}" ] || [ -z "${SERVER_IF}" ]; then
  echo "[router] ERROR: Could not identify client or server network interfaces" >&2
  ip -4 route
  exit 1
fi

echo "[router] Client interface: ${CLIENT_IF} (172.31.31.0/24)"
echo "[router] Server interface: ${SERVER_IF} (172.31.32.0/24)"

# Add alias 172.31.31.10 on client interface if not already present
if ! ip -4 addr show dev "${CLIENT_IF}" | grep -q "172.31.31.10"; then
  ip addr add 172.31.31.10/24 dev "${CLIENT_IF}" label "${CLIENT_IF}:1" || true
fi

# Reset iptables nat and filter
iptables -F
iptables -t nat -F
iptables -X
iptables -t nat -X

# NAT PREROUTING: forward client-network-addressed packets to server (172.31.32.10)
iptables -t nat -A PREROUTING -i "${CLIENT_IF}" -d 172.31.31.2 -j DNAT --to-destination 172.31.32.10
iptables -t nat -A PREROUTING -i "${CLIENT_IF}" -d 172.31.31.10 -j DNAT --to-destination 172.31.32.10

# Default policies
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

# FORWARD rules
# Allow established and related connections
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow return traffic from server to client
iptables -A FORWARD -i "${SERVER_IF}" -o "${CLIENT_IF}" -j ACCEPT

# 1. TCP Allowed Port (80): Normal HTTP traffic allowed
iptables -A FORWARD -i "${CLIENT_IF}" -p tcp --dport 80 -j ACCEPT

# 2. Management Port (22): Declared deny port left open to prove exposure detection
iptables -A FORWARD -i "${CLIENT_IF}" -p tcp --dport 22 -j ACCEPT

# 3. Connection Limit Port (8083): Max 2 concurrent connections per source IP
iptables -A FORWARD -i "${CLIENT_IF}" -p tcp --dport 8083 -m connlimit --connlimit-above 2 -j REJECT --reject-with tcp-reset
iptables -A FORWARD -i "${CLIENT_IF}" -p tcp --dport 8083 -j ACCEPT

# 4. TCP DROP Port (8081): Dropped silently (times out)
iptables -A FORWARD -i "${CLIENT_IF}" -p tcp --dport 8081 -j DROP

# 5. TCP REJECT Port (8082): Refused immediately (RST)
iptables -A FORWARD -i "${CLIENT_IF}" -p tcp --dport 8082 -j REJECT --reject-with tcp-reset

# 6. UDP Allowed Port (8053): Normal UDP datagram allowed
iptables -A FORWARD -i "${CLIENT_IF}" -p udp --dport 8053 -j ACCEPT

# 7. UDP DROP Port (8054): Dropped silently
iptables -A FORWARD -i "${CLIENT_IF}" -p udp --dport 8054 -j DROP

# Default drop for any other forwarded traffic
iptables -A FORWARD -j DROP

echo "[router] iptables rules installed successfully."
iptables -L FORWARD -n -v

# Keep running
exec tail -f /dev/null
