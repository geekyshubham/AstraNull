#!/bin/sh
set -e

# IPv4 policy: DROP incoming TCP port 8080
iptables -F INPUT 2>/dev/null || true
iptables -A INPUT -p tcp --dport 8080 -j DROP

# IPv6 policy: NO drop rule (accept all)
ip6tables -F INPUT 2>/dev/null || true

echo "Firewall policy applied:"
echo "  IPv4: TCP port 8080 DROPPED"
echo "  IPv6: TCP port 8080 OPEN (no drop rule)"
exec nginx -g "daemon off;"
