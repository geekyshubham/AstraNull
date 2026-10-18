# AstraNull Efficacy Lab Report: `nfw-router`

- Date: 2026-10-17
- Lab ID: `nfw-router`
- Compose Project: `anl-nfw-router`
- Status: **RUNNING** (All containers healthy)

---

## 1. Network Topology & Target Definition

The lab creates two isolated internal Docker bridge networks (`internal: true`) in accordance with CONTRACT §32:
- `anl-nfw-router-client`: `172.31.31.0/24`
- `anl-nfw-router-server`: `172.31.32.0/24`

### Assigned Static Addresses

| Component | Container Name | Network Attached | IP Address | Purpose |
|---|---|---|---|---|
| **Router** | `anl-nfw-router-router` | `anl-nfw-router-client`<br>`anl-nfw-router-server` | `172.31.31.2` (alias `.10`)<br>`172.31.32.2` | Alpine Linux NFW router with iptables and forwarding |
| **Server** | `anl-nfw-router-server` | `anl-nfw-router-server` | `172.31.32.10` | Node.js target listening on test ports |
| **Proof Client** | `anl-nfw-router-client` | `anl-nfw-router-client` | `172.31.31.100` | In-network proof client |

### Probe Worker Target Specification
- **Probe Target Address**: `172.31.31.2` (the server as seen from the client network via the router)
- **Probe Network to Join**: `anl-nfw-router-client`

Because Docker bridge networks with `internal: true` do not route between each other on the host, a probe worker container joining `anl-nfw-router-client` reaches the server through the router at `172.31.31.2` (or alias `172.31.31.10`). The router's PREROUTING table DNATs this traffic to `172.31.32.10`, ensuring all packets traverse the `FORWARD` filter chain where firewall policies and connection limits are enforced.

---

## 2. Docker Image Inspect IDs

As required by the contract, image inspect digests (`docker image inspect --format '{{.Id}}'`):

| Image Name / Tag | Image Inspect ID (SHA-256) |
|---|---|
| `anl-nfw-router-router:local` | `sha256:72772f9c27541698e7ea744f54deb6d5b08a98ec57a585ccf17c685c2af7b2ba` |
| `anl-nfw-router-server:local` | `sha256:cdb7f9db9f43e948053011d749b43939b8c5bcefe99131491e768e0f759a594f` |
| `anl-nfw-router-client:local` | `sha256:90178e6e990e3d5350a777ac6a38f771c4142753042286d2dcd538ea5764a3e9` |
| `alpine:3.20` | `sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc` |
| `node:22-alpine` | `sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402` |
| `curlimages/curl:latest` | `sha256:a134550be58ab783810e613ae96fd253c38f7bdd16d9bf9be350700c7a29ac06` |

Container resource caps: all services capped at `cpus: 1.0` and `mem_limit: 768m`.

---

## 3. Container Health Evidence

Live status from `docker ps`:
```
CONTAINER ID   IMAGE                         STATUS                   PORTS     NAMES
34e0167f3e66   anl-nfw-router-router:local   Up 2 minutes (healthy)             anl-nfw-router-router
abe7f696b23f   anl-nfw-router-server:local   Up 3 minutes (healthy)             anl-nfw-router-server
773cebee9ea9   anl-nfw-router-client:local   Up 2 minutes (healthy)             anl-nfw-router-client
```

---

## 4. Planted Conditions & Independent Proof Logs

All proofs were executed from the client network `anl-nfw-router-client` targeting `172.31.31.2` using isolated throwaway containers. No attack or flood tooling was used (all proofs used under 4 sequential connects/datagrams).

### Proof 1: Allowed TCP Port (Port 80)
- **Planted Policy**: `iptables -A FORWARD -i eth0 -p tcp --dport 80 -j ACCEPT`
- **Command**: `docker run --rm --network anl-nfw-router-client curlimages/curl:latest -sS --max-time 3 http://172.31.31.2/`
- **Output**:
  ```
  origin-ok
  ```
- **Evidence**: Complete TCP 3-way handshake followed by HTTP 200 response with body `origin-ok`.

### Proof 2: Dropped TCP Port (Port 8081)
- **Planted Policy**: `iptables -A FORWARD -i eth0 -p tcp --dport 8081 -j DROP`
- **Command**: `docker run --rm --network anl-nfw-router-client alpine:3.20 nc -w 3 -z 172.31.31.2 8081`
- **Output**:
  ```
  Exit code: 1, Elapsed: 3s
  ```
- **Evidence**: Packets silently dropped by router without TCP RST or ICMP response; connection attempt times out after 3 seconds.

### Proof 3: Rejected TCP Port (Port 8082)
- **Planted Policy**: `iptables -A FORWARD -i eth0 -p tcp --dport 8082 -j REJECT --reject-with tcp-reset`
- **Command**: `docker run --rm --network anl-nfw-router-client alpine:3.20 nc -w 3 -z 172.31.31.2 8082`
- **Output**:
  ```
  Exit code: 1, Elapsed: 0s
  ```
- **Evidence**: Router immediately refuses connection via TCP RST in under 10ms (exit code 1).

### Proof 4a: Allowed UDP Port (Port 8053)
- **Planted Policy**: `iptables -A FORWARD -i eth0 -p udp --dport 8053 -j ACCEPT`
- **Command**: Send 1 UDP datagram to `172.31.31.2:8053` via throwaway `node:22-alpine` container.
- **Output**:
  ```
  UDP 8053 reply received: ok from 172.31.31.2:8053
  ```
- **Evidence**: Single datagram sent and single response datagram received.

### Proof 4b: Dropped UDP Port (Port 8054)
- **Planted Policy**: `iptables -A FORWARD -i eth0 -p udp --dport 8054 -j DROP`
- **Command**: Send 1 UDP datagram to `172.31.31.2:8054` via throwaway `node:22-alpine` container.
- **Output**:
  ```
  UDP 8054 dropped as expected (timed out with no reply after 2000ms)
  ```
- **Evidence**: Datagram silently dropped by router; no response received.

### Proof 5: TCP Connection Limit (Port 8083, cap 2 per source)
- **Planted Policy**:
  ```
  iptables -A FORWARD -i eth0 -p tcp --dport 8083 -m connlimit --connlimit-above 2 -j REJECT --reject-with tcp-reset
  iptables -A FORWARD -i eth0 -p tcp --dport 8083 -j ACCEPT
  ```
- **Command**: Exactly 3 sequential connection attempts from the same source IP in a throwaway container without closing earlier sockets.
- **Output**:
  ```
  Attempt 1: CONNECTED successfully
  Attempt 2: CONNECTED successfully
  Attempt 3: REFUSED/ERROR (ECONNREFUSED)
  CONNLIMIT PROOF PASSED: Connections 1 and 2 admitted, connection 3 refused (ECONNREFUSED)
  ```
- **Evidence**: Connections 1 and 2 established successfully; the 3rd connection is immediately refused with `ECONNREFUSED` by the router's `xt_connlimit` iptables rule.

### Proof 6: Reachable Management Port (Port 22 SSH banner)
- **Planted Policy**: Server listens on port 22 with SSH banner listener; router allows port 22.
- **Command**: `docker run --rm --network anl-nfw-router-client alpine:3.20 nc -w 3 172.31.31.2 22`
- **Output**:
  ```
  SSH-2.0-OpenSSH_9.0 AstraNull-Lab-Target
  ```
- **Evidence**: Complete TCP handshake and SSH banner received, proving management port exposure.

---

## 5. AstraNull Catalog Check Expectations

Ground truth is based on the verified lab configuration and the check definitions in `src/contracts/checks.mjs` and `src/services/correlation.mjs`:

| Check ID | Ground Truth Condition | Declared Rule | Expected Verdict | Why Justified |
|---|---|---|---|---|
| `nfw.declared_deny_tcp.safe` | TCP 22 is open to client | `network_policy`: port 22 deny | `gap` | Probe completes handshake on declared deny port from non-CDN address. Check logic classifies this as `exposed`. |
| `l3.basic_deny_rule.safe` | TCP 22 is open to client | `network_policy`: port 22 deny | `gap` | Bounded connect to declared deny target completes handshake. Check logic classifies this as `exposed`. |
| `nfw.management_port_exposure.safe` | Port 22 SSH banner listener open | `network_policy`: port 22 deny | `gap` | Bounded management scan finds open port 22 with declared deny rule. Check logic classifies this as `exposed`. |
| `nfw.connection_limit.safe` | Port 8083 connlimit capped at 2 | `connection_limits`: port 8083 max 2 | `inconclusive_expected` | Probe attempts 4 connections; 2 admitted, 2 refused at cap. Per specification, outside-in evidence cannot return `protected` for connection limits; it withholds verdict (`inconclusive`). |
| `nfw.declared_deny_udp.safe` | UDP 8054 dropped silently | `network_policy`: port 8054 deny | `inconclusive_expected` | UDP probe times out on dropped port 8054. Per specification, silence cannot prove a deny rule from outside-in evidence; verdict is withheld (`inconclusive`). |

---

## 6. Limitations & Notes

1. **Colima Host Isolation**: The Mac host cannot route directly into Docker's user-defined bridge subnets (`172.31.0.0/16`). All tests and proofs must be performed via containers attached to `anl-nfw-router-client`.
2. **Outside-In Evidence Boundaries**: As documented in AstraNull ADR-0008, outside-in probing cannot distinguish an unanswering firewall deny rule from a dropped packet due to routing or host failure. Hence, `nfw.declared_deny_udp.safe` on a properly dropped port and `nfw.connection_limit.safe` on an enforced cap are expected to conclude `inconclusive_expected` rather than `protected`.
3. **No Attack Tooling Used**: Only single connects, bounded datagrams, and exactly 3 sequential connection attempts were used.
4. **Lab State**: The lab environment remains running and ready for evaluation by the test harness.
