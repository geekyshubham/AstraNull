You are one AstraNull efficacy-lab worker. Model: Gemini 3.8 Flash High. Work only this lab.

Read first, and obey: /Users/checkred_admin/Projects/astranull/labs/efficacy/CONTRACT.md
Repo: /Users/checkred_admin/Projects/astranull
Today: 2026-10-17. Docker is Colima (10 CPU, about 14 GiB) and is already running.

Safety (hard):
- Traffic stays on the lab networks in 172.31.0.0/16 that you create. internal: true. No public targets, no scans of the host, no traffic to the internet except docker pull and image builds.
- No attack or flood tooling. No sqlmap, nikto, hping, slowloris, load generators, packet spoofing, amplification scripts, monlist, memcached stats dumps, or exploit apps (no DVWA, WebGoat, Juice Shop).
- The only request payloads you may send for a proof are the exact inert markers and bounded probes already implemented in the repo, copied from source, plus plain health requests (GET /, dig of your lab zone, a single TCP connect). Do not invent new exploit strings.
- Never push images, never docker login, never publish ports except 127.0.0.1 when the contract allows and you cannot avoid it.
- Never stop, remove, or modify containers, networks, or volumes you did not create. Do not touch names starting with bgp- or astranull-postgres-local. Prefix every resource with anl-<lab-id>.
- Repository source is read-only. Do not edit src/, workers/, tests/, scripts/, db/, docs/, apps/, ops/, PROGRESS.md, package.json, or CONTRACT.md. Write only your lab directory and /tmp/astranull-lab/<lab-id>/.
- No git commands that change state. No secrets. Synthetic data only.
- Every service: cpus at most 1.0, mem_limit at most 768m. If docker info shows little free memory, wait and retry. Do not kill other containers.
- Leave the lab RUNNING when you finish. down.sh removes only your project.

Colima fact: the Mac host cannot route to container IPs. Prove each planted condition with a throwaway container attached to your lab network (curl, nc, dig, or a single TCP connect). Remove that throwaway when the proof is recorded. Do not enable IPv6 on the Colima daemon. A network with enable_ipv6 is fine; if the daemon refuses, record the blocker and do not reconfigure Colima.

Ground truth is the lab config, not AstraNull. In manifest expectations, use expected protected, gap, not_applicable, or inconclusive_expected only for checks whose behavior you proved or that you read in source and can justify. Do not invent a long guess list. Read the check definition and the probe it sends before you name it.

Done: STATUS.md updated, REPORT.md with image ids (docker image inspect --format '{{.Id}}'), health proof, and limitations. Your final message is at most 25 lines. No secrets.

Lab id: nfw-router
Write only: /Users/checkred_admin/Projects/astranull/labs/efficacy/envs/nfw-router/ and /tmp/astranull-lab/nfw-router/
Project anl-nfw-router. Two internal networks:
- anl-nfw-router-client 172.31.31.0/24
- anl-nfw-router-server 172.31.32.0/24
Static addresses. An alpine router container with sysctls for forwarding and iptables only (no flood tools), attached to both networks. A server container on the server net listens on the ports below. A proof client lives on the client net.

Plant, and prove from the client net with a single connect or a handful of connects under 10, never a flood:
- TCP port that is allowed and completes a handshake
- TCP port that is DROP (timeout)
- TCP port that is REJECT (immediate refusal)
- UDP port that is allowed and answers one datagram, and one UDP port that is dropped
- one TCP port with a connection limit of 2 per source (connlimit). Prove with 3 sequential connection attempts, not a flood.
Also leave one management-style port (22 or 2375) reachable from the client net if the server can listen there with a simple banner, so an exposure check has something to see. Do not run a real sshd with credentials. A tiny banner listener is enough.

Read nfw.declared_deny_tcp.safe, nfw.declared_deny_udp.safe, nfw.connection_limit.safe, nfw.management_port_exposure.safe, and l3.basic_deny_rule.safe before writing expectations. Put the matching network_policy and connection_limits in the manifest declarations. Record which address is the probe target (the server, as seen from the client network) and which network the probe worker must join (anl-nfw-router-client).
