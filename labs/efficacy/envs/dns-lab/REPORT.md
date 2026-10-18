# AstraNull Efficacy Lab Report: dns-lab

## Summary
- **Lab ID**: `dns-lab`
- **Compose Project**: `anl-dns-lab`
- **Network**: `anl-dns-lab-net` (Subnet: `172.31.41.0/24`, `internal: true`)
- **Target**: `172.31.41.10:53` (UDP/TCP)
- **Synthetic Zone**: `lab.efficacy.invalid`
- **Container Name**: `anl-dns-lab-server`
- **Service Status**: Running, `healthy`
- **Resource Caps**: `cpus: 1.0`, `mem_limit: 768m`

## Image Identifiers
- **Server Image**: `anl-dns-lab/dns-server:latest`
  - Image ID: `sha256:84517447584490d7580246403de5b4c3fa8357befc4ae0a765cf5156de9377b3`
- **Base Image**: `alpine:3.20`
  - Image ID: `sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`

## Configuration & Planted Conditions
The DNS server runs BIND 9.18.49 configured as a strictly authoritative server for `lab.efficacy.invalid`:
1. **Authoritative NOERROR**: Serves `lab.efficacy.invalid` authoritatively (`flags: qr aa rd`).
2. **NXDOMAIN for Random Prefix**: Non-existent names in `lab.efficacy.invalid` return `status: NXDOMAIN` with SOA in authority section.
3. **Single NS Delegation**: Only one NS record (`ns1.lab.efficacy.invalid.`) is published, creating a single point of failure (secondary failover gap).
4. **AXFR Allowed (Zone Transfer Exposure)**: Zone transfers over TCP/53 are permitted to clients on the lab network (`allow-transfer { any; };`). The zone contains only synthetic records totaling 321 bytes (well under the 4 KiB limit).
5. **Closed Recursion**: Recursion is disabled (`recursion no; allow-recursion { none; };`). External queries return `REFUSED` (`RA=0`); no root hints, no forwarders, and queries never leave the container.
6. **No Amplification**: BIND is configured with `minimal-any yes;`, returning a compact 158-byte answer to ANY queries to prevent reflector abuse.

## Health Proof
Container `anl-dns-lab-server` healthcheck executes `dig +time=1 +tries=1 @127.0.0.1 SOA lab.efficacy.invalid`:
```text
docker inspect --format '{{.State.Health.Status}}' anl-dns-lab-server
-> healthy
```
Server log:
```text
running on Linux aarch64
loading configuration from '/etc/bind/named.conf'
listening on IPv4 interface lo, 127.0.0.1#53
listening on IPv4 interface eth0, 192.168.241.10#53
zone lab.efficacy.invalid/IN: loaded serial 2026101701
all zones loaded
running
```

## Planted Condition Proofs (Dig from Throwaway Container)

### 1. Authoritative NOERROR for Served Name
```text
$ dig @192.168.241.10 SOA lab.efficacy.invalid
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 43799
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; ANSWER SECTION:
lab.efficacy.invalid.	300	IN	SOA	ns1.lab.efficacy.invalid. hostmaster.lab.efficacy.invalid. 2026101701 7200 3600 1209600 300
```
```text
$ dig @192.168.241.10 A app.lab.efficacy.invalid
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 30949
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; ANSWER SECTION:
app.lab.efficacy.invalid. 300	IN	A	172.31.41.20
```

### 2. NXDOMAIN for Random Prefix Inside Zone
```text
$ dig @192.168.241.10 A random-nonexistent-subdomain.lab.efficacy.invalid
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 23225
;; flags: qr aa rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
;; AUTHORITY SECTION:
lab.efficacy.invalid.	300	IN	SOA	ns1.lab.efficacy.invalid. hostmaster.lab.efficacy.invalid. 2026101701 7200 3600 1209600 300
```

### 3. Single NS Record (Secondary Failover Gap)
```text
$ dig @192.168.241.10 NS lab.efficacy.invalid
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 57971
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2
;; ANSWER SECTION:
lab.efficacy.invalid.	300	IN	NS	ns1.lab.efficacy.invalid.
;; ADDITIONAL SECTION:
ns1.lab.efficacy.invalid. 300	IN	A	172.31.41.10
```

### 4. AXFR Allowed (Zone Transfer Exposure)
```text
$ dig @192.168.241.10 AXFR lab.efficacy.invalid
lab.efficacy.invalid.	300	IN	SOA	ns1.lab.efficacy.invalid. hostmaster.lab.efficacy.invalid. 2026101701 7200 3600 1209600 300
lab.efficacy.invalid.	300	IN	NS	ns1.lab.efficacy.invalid.
lab.efficacy.invalid.	300	IN	A	172.31.41.10
api.lab.efficacy.invalid. 300	IN	A	172.31.41.30
app.lab.efficacy.invalid. 300	IN	A	172.31.41.20
mail.lab.efficacy.invalid. 300	IN	A	172.31.41.40
ns1.lab.efficacy.invalid. 300	IN	A	172.31.41.10
txt1.lab.efficacy.invalid. 300	IN	TXT	"synthetic=evidence-token-lab-dns"
lab.efficacy.invalid.	300	IN	SOA	ns1.lab.efficacy.invalid. hostmaster.lab.efficacy.invalid. 2026101701 7200 3600 1209600 300
;; Query time: 0 msec
;; SERVER: 192.168.241.10#53(192.168.241.10) (TCP)
;; XFR size: 9 records (messages 1, bytes 321)
```

### 5. Closed Recursion (Does Not Leave Container)
```text
$ dig @192.168.241.10 A example.com +recurse
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 44639
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available
```

### 6. Minimal ANY Response (No Amplification)
```text
$ dig @192.168.241.10 ANY lab.efficacy.invalid
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 46262
;; flags: qr aa rd; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1
;; ANSWER SECTION:
lab.efficacy.invalid.	300	IN	SOA	ns1.lab.efficacy.invalid. hostmaster.lab.efficacy.invalid. 2026101701 7200 3600 1209600 300
lab.efficacy.invalid.	300	IN	NS	ns1.lab.efficacy.invalid.
lab.efficacy.invalid.	300	IN	A	172.31.41.10
;; MSG SIZE rcvd: 158
```

## Ground Truth Check Expectations

1. `dns.authoritative_response.safe`: **inconclusive_expected**
   - Probe profile: `dns_wire_query` (qtype: SOA, transport: udp).
   - In `src/lib/probeEvidenceTiers.mjs:10`, `dns_wire_query` is listed under `OBSERVATION_ONLY_PROBE_KINDS`.
   - In `src/services/correlation.mjs:922`, observation-only probes unconditionally correlate to `verdict: 'inconclusive'`. The check is designed to record metadata without concluding readiness/exposure.
2. `dns.random_prefix_nxdomain.safe`: **inconclusive_expected**
   - Probe profile: `dns_wire_query` (qtype: A, transport: udp).
   - Like above, `dns_wire_query` is an observation-only probe in AstraNull's correlation engine, returning `verdict: 'inconclusive'`.
3. `dns.secondary_failover.safe`: **gap**
   - Probe profile: `dns_failover_posture`.
   - Zone has `nameserver_count: 1` (`nameserver_count_below_two: true`).
   - In `src/services/correlation.mjs:787-790`, `correlateInferredMissingControl` matches and generates `inferredGap('medium', ...)` (`verdict: 'exposed'`).
4. `dns.zone_transfer_exposure.safe`: **gap**
   - Probe profile: `dns_axfr_leak`.
   - The nameserver permits AXFR over TCP 53, resulting in `outcome.axfr_leak === true`.
   - In `src/services/correlation.mjs:608-615`, `axfrLeaked()` matches and generates `verdict: 'exposed'`.
5. `dns.open_recursion_behavior.safe`: **inconclusive_expected**
   - Probe profile: `dns_open_recursion`.
   - Server refuses recursion (`REFUSED`, `RA=0`). In `src/lib/probeEvidenceTiers.mjs:24`, `dns_open_recursion` is listed under `OBSERVATION_ONLY_PROBE_KINDS`, yielding `verdict: 'inconclusive'`.
6. `dns.amplification_exposure.safe`: **not_applicable**
   - Per lab safety contract, no large ANY/TXT records were built to avoid creating an amplifier. `minimal-any yes;` ensures responses are compact (158 bytes).

## Address correction

The first proof ran on a fallback network, `anl-dns-lab-testnet` at `192.168.241.10`, because `172.31.0.0/16` was occupied. That fixture was later removed. `up.sh` no longer keeps the fallback. The server is now healthy on `anl-dns-lab-net` at `172.31.41.10`.

A later dig from a container on that network:

- `SOA lab.efficacy.invalid` returned `NOERROR` with the `aa` flag and one NS, `ns1.lab.efficacy.invalid`.
- AXFR of the same zone completed. The zone file is the small synthetic zone from the first proof (321 bytes on the wire in that proof).
