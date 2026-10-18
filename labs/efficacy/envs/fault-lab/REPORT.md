# AstraNull Efficacy Lab Report: fault-lab

## 1. Overview & Architecture

- **Lab ID**: `fault-lab`
- **Compose Project**: `anl-fault-lab`
- **Container Name**: `anl-fault-lab-target`
- **Network Mode**: `none` (isolated Linux network namespace with loopback interface `lo` only)
- **Base Image**: `node:24-bookworm-slim` pinned by digest (`node@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20`)
- **Built Image Tag**: `anl-fault-lab-target:local`
- **Image ID**: `sha256:772a23aab3820d69bc3837b00fa5fb2503f4395edc27bbcd1514b4e7295b64fb`
- **Base Image ID**: `sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20`

### Resource & Capability Restrictions
- **CPUs**: `1.0` (`NanoCpus=1000000000`)
- **Memory Limit**: `768m` (`Memory=805306368` bytes)
- **Capabilities Dropped**: `ALL`
- **Capabilities Added**: `NET_ADMIN`, `NET_RAW`
- **Security Options**: `no-new-privileges:true`
- **Port Bindings**: None (`{}`)
- **Network Interfaces**: Only `lo` (`127.0.0.1`, `::1`)

---

## 2. Planted Fault Condition

An exact client/server 4-tuple firewall drop rule is installed in Linux Netfilter (`iptables`) on container startup:
```bash
iptables -A INPUT -p tcp -s 127.0.0.1 --sport 40001 -d 127.0.0.1 --dport 18080 -j DROP
```
In parallel, an exact tracking rule for an allowed client tuple is installed:
```bash
iptables -A INPUT -p tcp -s 127.0.0.1 --sport 40002 -d 127.0.0.1 --dport 18080 -j ACCEPT
```
And a Node.js TCP listener is running on `127.0.0.1:18080`.

- **Blocked Tuple (Tuple 1)**: `127.0.0.1:40001 -> 127.0.0.1:18080` (TCP)
  When client initiates a connection, outgoing SYN arrives at `INPUT` on `lo` and is dropped silently by kernel Netfilter. Client retransmits TCP SYN packets until socket connect timeout occurs (`ETIMEDOUT`). The DROP rule packet and byte counters increment exclusively for this tuple.
- **Allowed Tuple (Tuple 2)**: `127.0.0.1:40002 -> 127.0.0.1:18080` (TCP)
  When client initiates a connection, TCP 3-way handshake completes in 1-2ms, data `ASTRANULL_CONNECT_FAULT_LAB_OK` is exchanged, and the connection closes cleanly. The Tuple 1 DROP rule counter is completely unaffected (0 drop increment).

---

## 3. Independent Proof & Health Verification

### 3.1 Container Healthcheck Evidence
The container runs an automated healthcheck command every 2s (`node /app/healthcheck.mjs`):
1. Verifies that the iptables DROP rule is actively installed in the kernel:
   `iptables -C INPUT -p tcp -s 127.0.0.1 --sport 40001 -d 127.0.0.1 --dport 18080 -j DROP`
2. Connects to `127.0.0.1:18080` from an unblocked client port (`40003`) and validates the response payload.
`docker inspect anl-fault-lab-target --format '{{.State.Health.Status}}'` returns:
```text
healthy
```

### 3.2 Dual-Tuple Connect & Iptables Counter Proof
Execution of `/app/prove.mjs` inside `anl-fault-lab-target` produced the following verification record:

```json
{
  "schema": "astranull.efficacy-proof.v1",
  "lab_id": "fault-lab",
  "timestamp": "2026-10-17T14:34:57.172Z",
  "network_mode": "none",
  "planted_fault": {
    "type": "exact_tuple_drop",
    "rule": "iptables -A INPUT -p tcp -s 127.0.0.1 --sport 40001 -d 127.0.0.1 --dport 18080 -j DROP",
    "blocked_tuple": {
      "src": "127.0.0.1:40001",
      "dst": "127.0.0.1:18080"
    },
    "allowed_tuple": {
      "src": "127.0.0.1:40002",
      "dst": "127.0.0.1:18080"
    }
  },
  "measurements": {
    "tuple2_execution": {
      "result": {
        "tuple": "127.0.0.1:40002 -> 127.0.0.1:18080",
        "result": "connected",
        "handshake_completed": true,
        "duration_ms": 2,
        "received_payload": "ASTRANULL_CONNECT_FAULT_LAB_OK"
      },
      "tuple1_drop_increment": 0,
      "tuple2_accept_increment": 3
    },
    "tuple1_execution": {
      "result": {
        "tuple": "127.0.0.1:40001 -> 127.0.0.1:18080",
        "result": "timeout",
        "handshake_completed": false,
        "duration_ms": 1502
      },
      "tuple1_drop_increment": 2
    }
  },
  "conclusions": {
    "tuple2_handshake_succeeded": true,
    "tuple2_did_not_increment_drop_rule": true,
    "tuple1_connect_timed_out": true,
    "tuple1_incremented_drop_rule_only": true,
    "isolation_verified": true
  }
}
```

### 3.3 Kernel Netfilter Rule Counters
Direct dump from `iptables -v -L INPUT -n -x`:
```text
Chain INPUT (policy ACCEPT 728 packets, 42164 bytes)
    pkts      bytes target     prot opt in     out     source               destination         
       4      240 DROP       6    --  *      *       127.0.0.1            127.0.0.1            tcp spt:40001 dpt:18080
       8      432 ACCEPT     6    --  *      *       127.0.0.1            127.0.0.1            tcp spt:40002 dpt:18080
```
- Each attempt of Tuple 1 increments the DROP rule by exactly 2 packets (initial SYN + 1 retransmission = 120 bytes).
- Tuple 2 and healthcheck connections increment only their respective matching rules / policy ACCEPT, never incrementing the DROP rule.

---

## 4. Manifest Expectations & Catalog Check Analysis

The AstraNull catalog defines 9 connection-oriented checks whose timeout branch obligations specifically require connect failure simulation (identified in `tests/fixtures/check-delivery-coverage.mjs` and `tests/unit/check-delivery-connect-branches.test.mjs`):
1. `l3.firewall_exposure_scan.safe` (`port_scan_bounded`)
2. `l3.ipv6_reachability.safe` (`tcp_connect`)
3. `l3.smtp_connection_flood.readiness` (`tcp_connect`)
4. `l3.ssh_connection_flood.readiness` (`tcp_connect`)
5. `l3.ftp_connection_flood.readiness` (`tcp_connect`)
6. `reflect.redis_direct_exposure.safe` (`tcp_connect`)
7. `nfw.management_port_exposure.safe` (`port_scan_bounded`)
8. `nfw.ipv6_parity.safe` (`tcp_connect`)
9. `nfw.connection_limit.safe` (`connection_limit_probe`)

### Manifest Ground Truth
All 9 checks are marked `not_applicable` with the justification:
`"The signed probe worker cannot join network none"`

Because `fault-lab` operates under `network_mode: none`, the container has no network interfaces attached to any Docker bridge or lab network, and no host ports are published. The AstraNull signed probe worker operates outside the container and cannot send probe traffic into `network_mode: none`. The connect fault proof is therefore verified independently inside the container namespace.

---

## 5. Limitations & Caveats

1. **Host Unreachability**: Because `network_mode: none` isolates the network namespace, no external network access is available to or from this container. Remote probes cannot reach this target.
2. **tcpdump Privilege Drop**: In Debian/Ubuntu, the standard `tcpdump` binary attempts to drop privileges to the `tcpdump` user via `setuid()`. Because the container strictly drops all capabilities except `NET_ADMIN` and `NET_RAW` (`no-new-privileges: true`), `setuid` fails. The independent proof relies on Linux kernel `iptables` rule packet/byte counters and Node.js connect timeouts, which operate natively under `NET_ADMIN` and `NET_RAW`.
3. **Colima Host Routing**: As documented in the contract, Colima cannot route to container IPs directly from the macOS host; however, for `fault-lab`, the container is completely isolated from all external routing.
