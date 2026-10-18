# AstraNull Efficacy Lab Report: nfw-ipv6-gap

## 1. Summary

- **Lab ID**: `nfw-ipv6-gap`
- **Compose Project**: `anl-nfw-ipv6-gap`
- **Network**: `anl-nfw-ipv6-gap-net` (`internal: true`, `enable_ipv6: true`)
- **Subnets**:
  - IPv4: `172.31.33.0/24`
  - IPv6: `fd00:a57a:33::/64`
- **Target Container**: `anl-nfw-ipv6-gap-target`
- **Target Addresses**:
  - IPv4: `172.31.33.10`
  - IPv6: `fd00:a57a:33::10`
- **Listening Ports**:
  - TCP 80: Health endpoint (open and accepting on both IPv4 and IPv6)
  - TCP 8080: Target application port (dropped on IPv4 by iptables; open and accepting on IPv6)

## 2. Docker Images & Inspect IDs

Image IDs obtained via `docker image inspect --format '{{.Id}}'`:
- `anl-nfw-ipv6-gap-target:local`: `sha256:aa00314f02b07f4a20e837890fd2952fda1e1b62ab0a15463718975ba9852805`
- `nginx:1.27-alpine`: `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`
- `curlimages/curl:latest`: `sha256:a134550be58ab783810e613ae96fd253c38f7bdd16d9bf9be350700c7a29ac06`
- `alpine:3.20`: `sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`

## 3. Planted Condition & Ground Truth

The service runs a dual-stack Nginx listener on ports 80 and 8080.
- **Port 80**: Serves as a neutral health check baseline on both IPv4 and IPv6 (`HTTP 200 healthy`).
- **Port 8080**: Both Nginx listeners (`listen 8080; listen [::]:8080;`) are active.
  - An IPv4 packet filter rule (`iptables -A INPUT -p tcp --dport 8080 -j DROP`) drops all incoming IPv4 TCP SYNs to port 8080, causing connection attempts to time out.
  - No matching drop rule exists in `ip6tables`. Consequently, incoming IPv6 TCP connections on `[fd00:a57a:33::10]:8080` complete the TCP three-way handshake and receive `HTTP 200 app-ok`.

## 4. Independent Verification Proof

Executed from throwaway containers attached to `anl-nfw-ipv6-gap-net` (no traffic external to the lab):

### Health Checks (TCP Port 80)
- **IPv4 (`172.31.33.10:80`)**:
  ```
  * Established connection to 172.31.33.10 (172.31.33.10 port 80) from 172.31.33.2 port 48576 
  < HTTP/1.1 200 OK
  healthy
  Exit code: 0
  ```
- **IPv6 (`[fd00:a57a:33::10]:80`)**:
  ```
  * Established connection to [fd00:a57a:33::10] (fd00:a57a:33::10 port 80) from fd00:a57a:33::2 port 53424 
  < HTTP/1.1 200 OK
  healthy
  Exit code: 0
  ```

### Planted Gap Proofs (TCP Port 8080)
- **IPv4 Connect (`172.31.33.10:8080`)**:
  - Command: `curl -v -m 3 http://172.31.33.10:8080/`
  - Output: `curl: (28) Connection timed out after 3001 milliseconds` (Exit code: 28)
  - Pure TCP connect (`nc -z -w 2 172.31.33.10 8080`): Timed out / dropped (Exit code: 1)
- **IPv6 Connect (`[fd00:a57a:33::10]:8080`)**:
  - Command: `curl -v -m 3 -6 http://[fd00:a57a:33::10]:8080/`
  - Output:
    ```
    * Established connection to [fd00:a57a:33::10] (fd00:a57a:33::10 port 8080) from fd00:a57a:33::2 port 41106 
    < HTTP/1.1 200 OK
    app-ok
    Exit code: 0
    ```
  - Pure TCP connect (`nc -z -w 2 fd00:a57a:33::10 8080`): Handshake completed (Exit code: 0)

## 5. Check Expectations & Justification

### `nfw.ipv6_parity.safe`
- **Expected Verdict**: `gap`
- **Justification**:
  - The catalog check definition (`src/contracts/checks.mjs:3548`) executes a `tcp_connect` probe with `address_family: 'both'`.
  - In `src/lib/safeNetworkProbes.mjs:911-1004`, `probeTcpConnect` resolves both IPv4 and IPv6 addresses and samples each family.
  - In `src/services/correlation.mjs:374-412`, when a declared deny rule exists for port 8080 (`network_policy`), the probe outcome on IPv4 is `timeout` (non-violating), while the outcome on IPv6 is `handshake` (`tcpOpen` = true, violating the declared deny).
  - The outcomes differ between families (`parity: 'mismatch'`), and IPv6 is identified as the leaking family (`violating: ['ipv6']`).
  - Correlation logic returns `verdict: 'exposed'` ("Declared deny for tcp/8080 (ipv6) ... was violated; IPv6 parity mismatch: ipv6 is the leaking family."). Under AstraNull's grading contract, this corresponds to `gap`.

### `l3.ipv6_reachability.safe`
- **Expected Verdict**: `gap`
- **Justification**:
  - The check (`src/contracts/checks.mjs:1056`) probes IPv6 reachability via `tcp_connect` against declared IPv6 targets.
  - In `src/contracts/missingControls/network.mjs:202-206`, the missing control is: "IPv6 ingress filtering does not match the declared protection expectation, so the target is reachable over IPv6 on ports or paths that the IPv4 policy restricts."
  - Because port 8080 is restricted on IPv4 by firewall policy but accepts connections on IPv6, probing IPv6 demonstrates reachable exposure violating the declared protection policy.

## 6. Limitations

- **Colima Host Routing**: The macOS host cannot directly route packets to internal container IP subnets (`172.31.33.0/24` or `fd00:a57a:33::/64`). All external verification and runner checks must run from a probe worker container attached to `anl-nfw-ipv6-gap-net`.
- **Pre-existing Subnet Conflict**: During initialization, an orphaned test network from October 14 (`bgp-fixture-acceptance-20261014101054-60488_default`) temporarily claimed `172.31.0.0/16`. Once cleared, `anl-nfw-ipv6-gap-net` successfully initialized with full IPv4 and IPv6 dual-stack addressing.
- **Compose Buildx**: Colima CLI environment uses standard `docker build` rather than compose buildx plugin 0.17+; `up.sh` invokes `docker build` directly to ensure reproducible image compilation.
