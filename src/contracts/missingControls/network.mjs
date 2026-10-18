export const MISSING_CONTROLS_NETWORK = Object.freeze({
  'amp.authoritative_resolver_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'No DNS response rate limiting is in place on the authoritative servers, so repeated queries from spoofed sources draw large NS and referral answers toward victims.',
    required_policy: 'Enable response rate limiting on the authoritative servers, cap identical answers per source prefix per second, and declare the RRL policy and thresholds.',
  },
  'amp.cldap_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'A directory service answers connectionless LDAP root DSE searches on UDP 389 from the internet, a well-known high-ratio amplification vector.',
    required_policy: 'Block inbound UDP 389 from the internet, restrict LDAP to internal networks or VPN users, and disable connectionless LDAP where it is not required.',
  },
  'amp.dns_any_txt_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'The authoritative servers return large TXT or ANY answers over UDP without response-size controls, so the zone can be abused for DNS amplification.',
    required_policy: 'Answer ANY queries minimally, keep TXT records small, enable response rate limiting and cap the EDNS UDP buffer so large answers fall back to TCP.',
  },
  'amp.memcached_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'Memcached answers UDP stats requests on port 11211 from the internet, exposing a cache server with one of the highest known amplification ratios.',
    required_policy: 'Disable the memcached UDP listener, bind memcached to private interfaces, and block inbound TCP and UDP 11211 from the internet.',
  },
  'amp.ntp_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'An NTP server answers mode 6 control queries (readvar) on UDP 123 from the internet, so it can be used for high-ratio NTP amplification.',
    required_policy: 'Restrict NTP with noquery, nomodify and notrap for all non-administrative sources, disable mode 6 and mode 7 responses, and serve time only to intended clients.',
  },
  'amp.smurf_broadcast_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'Directed-broadcast forwarding is not declared as disabled on edge routers, so packets sent to a subnet broadcast address can be amplified by every host on the segment.',
    required_policy: 'Disable IP directed-broadcast on all router interfaces, drop inbound packets addressed to subnet broadcast addresses at the edge, and declare the filtering policy.',
  },
  'dns.amplification_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'The DNS server answers ANY queries over UDP with full record sets and no size limit, so it returns large amplified responses to whatever source address is claimed.',
    required_policy: 'Return minimal responses to ANY queries, enable response rate limiting, and limit the EDNS UDP payload size so large answers require TCP.',
  },
  'dns.authoritative_response.safe': {
    control_family: 'dns_ddos_resilience',
    missing_control: 'The nameservers for the declared zone do not return an authoritative SOA answer to a single UDP query, indicating lame or unreachable authoritative service for the zone.',
    required_policy: 'Ensure every delegated nameserver serves the zone authoritatively with the AA flag set, keep parent and child NS records in sync, and monitor SOA answers from each server.',
  },
  'dns.dnsbomb.readiness': {
    control_family: 'dns_ddos_resilience',
    missing_control: 'No query-rate burst alert thresholds or TTL-elasticity posture is declared for the zone, so pulsed DNS bursts built from deferred resolver responses are neither detected nor absorbed.',
    required_policy: 'Configure query-rate burst alerts from DNS provider telemetry, cap resolver response deferral and outstanding queries, and declare TTL and burst thresholds for the zone.',
  },
  'dns.dnssec_expensive_query.safe': {
    control_family: 'dns_ddos_resilience',
    missing_control: 'The declared zone publishes no DNSKEY records, so it is not DNSSEC-signed and lacks the authenticated denial that resolvers use for aggressive negative caching during random-name floods.',
    required_policy: 'Sign the zone with a compact algorithm such as ECDSA P-256 or Ed25519, publish the DS record at the parent, and size nameservers for the cost of signed answers.',
  },
  'dns.doh_dot_exposure.readiness': {
    control_family: 'dns_recursion_restriction',
    missing_control: 'Declared DNS-over-HTTPS and DNS-over-TLS endpoints carry no query caps or client allow-lists, so the encrypted resolvers can be flooded or used for open recursion.',
    required_policy: 'Apply per-client query rate limits and connection caps on DoH (TCP 443) and DoT (TCP 853) endpoints, require client authentication or source allow-lists, and declare the policy.',
  },
  'dns.domain_lockup.readiness': {
    control_family: 'dns_recursion_restriction',
    missing_control: 'Resolvers have no declared limit on CNAME chain depth and no delegation-loop protection, so crafted aliases and circular delegations can lock up recursion for the zone.',
    required_policy: 'Cap CNAME chain length and referral depth on recursive resolvers, abort detected delegation loops, and declare the resolver loop-protection policy.',
  },
  'dns.garbage_flood.readiness': {
    control_family: 'dns_ddos_resilience',
    missing_control: 'The authoritative servers have no filtering for malformed or junk DNS queries, so garbage-query floods consume parsing and answer capacity on UDP 53.',
    required_policy: 'Drop malformed and non-DNS packets on UDP 53 at the edge, rate-limit invalid queries per source, and place DNS-aware scrubbing in front of the authoritative servers.',
  },
  'dns.laundering.readiness': {
    control_family: 'dns_recursion_restriction',
    missing_control: 'Recursive resolvers serving the zone have no declared per-client query caps or random-subdomain rejection, so they can be used to launder query floods toward the authoritative servers.',
    required_policy: 'Configure per-client query rate limits and per-zone and per-server fetch limits on recursive resolvers, reject random-subdomain patterns, and declare the resolver policy.',
  },
  'dns.multi_question_oversized.safe': {
    control_family: 'dns_ddos_resilience',
    missing_control: 'The nameserver is not hardened against DNS messages carrying multiple questions or oversized payloads, so malformed queries can consume parser resources or crash the service.',
    required_policy: 'Reject DNS messages whose question count is not one and oversized requests with FORMERR, cap EDNS buffer sizes, and keep the DNS server software patched.',
  },
  'dns.nxns_attack.readiness': {
    control_family: 'dns_ddos_resilience',
    missing_control: 'Nothing bounds glueless NS referrals for the zone, so NXNS-style referrals can make resolvers issue large numbers of lookups toward the authoritative servers.',
    required_policy: 'Run recursive resolvers patched to limit glueless NS fetches per referral, keep the zone NS set small with in-zone glue, and rate-limit referral answers on authoritative servers.',
  },
  'dns.open_recursion_behavior.safe': {
    control_family: 'dns_recursion_restriction',
    missing_control: 'The declared resolver performs recursive lookups for arbitrary internet clients, making it an open resolver that can be abused for amplification and cache poisoning.',
    required_policy: 'Restrict recursion to internal client networks with an access list, disable recursion on authoritative servers, and refuse recursive queries from all other sources.',
  },
  'dns.phantom_domain.readiness': {
    control_family: 'dns_recursion_restriction',
    missing_control: 'Recursive resolvers have no declared retry and timeout budgets for unresponsive delegations, so phantom-domain queries can hold outstanding recursion slots until they are exhausted.',
    required_policy: 'Set per-server and per-zone outstanding-query limits, short upstream timeouts and bounded retries on recursive resolvers, and declare the timeout policy.',
  },
  'dns.qname_minimization.readiness': {
    control_family: 'dns_recursion_restriction',
    missing_control: 'Recursive resolvers do not use QNAME minimisation, so full query names are sent to every upstream server and random-subdomain load is passed upstream unreduced.',
    required_policy: 'Enable QNAME minimisation on all recursive resolvers that serve the zone and declare the setting as part of the resolver policy.',
  },
  'dns.random_prefix_nxdomain.safe': {
    control_family: 'dns_ddos_resilience',
    missing_control: 'No random-subdomain protection is in place for the zone, so queries for random nonexistent names force authoritative lookups and NXDOMAIN answers that can overload the nameservers.',
    required_policy: 'Enable NXDOMAIN and random-prefix rate limiting, sign the zone so resolvers can cache negative answers aggressively, and use anycast authoritative DNS sized for query floods.',
  },
  'dns.secondary_failover.safe': {
    control_family: 'dns_ddos_resilience',
    missing_control: 'The zone has no independent secondary nameservers on separate networks, so an attack on one DNS provider or site leaves the zone without any authoritative answer.',
    required_policy: 'Delegate the zone to at least two independent authoritative services on different networks, keep them synchronised through secured zone transfer, and test failover.',
  },
  'dns.tcp_fallback.readiness': {
    control_family: 'dns_ddos_resilience',
    missing_control: 'The authoritative servers do not reliably answer DNS over TCP, so truncated responses and rate-limited clients cannot fall back to TCP during a UDP flood.',
    required_policy: 'Serve DNS over TCP 53 on every authoritative server with connection limits and idle timeouts, and allow inbound TCP 53 through the edge firewall.',
  },
  'dns.zone_transfer_exposure.safe': {
    control_family: 'dns_zone_transfer_restriction',
    missing_control: 'A nameserver for the zone permits full AXFR zone transfers to unauthenticated internet clients, exposing every record in the zone.',
    required_policy: 'Allow AXFR and IXFR only to declared secondary nameserver addresses authenticated with TSIG keys, and refuse transfer requests from every other source.',
  },
  'dns.zone_walking.readiness': {
    control_family: 'dns_ddos_resilience',
    missing_control: 'The signed zone has no declared NSEC3 or minimally covering NSEC denial, so the full set of names can be enumerated by walking NSEC records.',
    required_policy: 'Use NSEC3 with a low iteration count or online minimally covering NSEC responses for the signed zone, and declare the denial-of-existence method.',
  },
  'high_scale.application.request_only': {
    control_family: 'high_scale_ddos_validation',
    missing_control: 'Application-layer DDoS mitigation such as rate limiting, challenges and caching has not been proven at production-scale request rates, so a high-rate HTTP flood may exhaust origin capacity.',
    required_policy: 'Configure edge rate limits, bot challenges and caching for the declared L7 scope, then validate them through a SOC-authorized, provider-approved high-scale HTTP test with stop criteria.',
  },
  'high_scale.degradation_recovery.request_only': {
    control_family: 'high_scale_ddos_validation',
    missing_control: 'There are no measured degradation objectives or rehearsed recovery procedure for this service under sustained attack, so time to detect, mitigate and recover is unknown.',
    required_policy: 'Declare degradation and recovery objectives, maintain a recovery runbook, and run a SOC-governed drill with explicit stop criteria that measures detection, mitigation and recovery times.',
  },
  'high_scale.dns_high_query.request_only': {
    control_family: 'high_scale_ddos_validation',
    missing_control: 'The authoritative DNS service has not been proven to keep answering at the declared peak query rate, so its capacity and rate limiting under a query flood are unvalidated.',
    required_policy: 'Obtain DNS provider approval and a SOC authorization pack, then run a governed authoritative query-rate simulation against the declared zone with stop criteria and monitored answer latency.',
  },
  'high_scale.multi_vector.request_only': {
    control_family: 'high_scale_ddos_validation',
    missing_control: 'Mitigation has not been proven to hold when network-layer, protocol and application-layer floods arrive together, so a coordinated multi-vector attack may bypass single-vector protections.',
    required_policy: 'Coordinate a SOC-authorized multi-vector validation with the scrubbing provider under a declared scope and runbook, and confirm every vector is mitigated at the same time without service loss.',
  },
  'high_scale.volumetric.request_only': {
    control_family: 'high_scale_ddos_validation',
    missing_control: 'Upstream scrubbing capacity for the declared targets has not been validated at volumetric scale, so bandwidth and packet-rate floods may saturate links before mitigation engages.',
    required_policy: 'Enable always-on or on-demand volumetric scrubbing for the declared prefixes and validate it through a SOC-authorized, provider-approved volumetric test with defined abort thresholds.',
  },
  'l3.ack_flood.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'No stateful filtering of TCP ACK packets that belong to no established connection, and no packets-per-second budget, is declared, so ACK floods are passed through to hosts.',
    required_policy: 'Enable stateful inspection that drops ACK packets without a matching connection, set a packets-per-second threshold for upstream scrubbing, and declare both.',
  },
  'l3.basic_deny_rule.safe': {
    control_family: 'network_firewall_ingress',
    missing_control: 'A customer-declared TCP deny rule is not effective: the denied port still completes a TCP handshake from a non-CDN internet address in agreeing samples.',
    required_policy: 'Correct the firewall rule order or scope so the declared deny matches the port and internet source ranges, and make sure no broader allow rule evaluated earlier overrides it.',
  },
  'l3.connection_table_exhaustion.request_only': {
    control_family: 'network_connection_limits',
    missing_control: 'Connection-state limits on the firewall, load balancer or host have not been proven to hold under many concurrent half-open and idle connections, so the state table may fill and drop legitimate users.',
    required_policy: 'Set per-source and global connection caps, idle and half-open timeouts and state-table alarms, then validate them in a SOC-authorized connection-state scenario with abort criteria.',
  },
  'l3.firewall_exposure_scan.safe': {
    control_family: 'network_firewall_ingress',
    missing_control: 'No default-deny ingress rule limits the declared scan host to its intended public ports, so bounded port checks find additional TCP services reachable from the internet.',
    required_policy: 'Apply a default-deny inbound policy to the host, allow only the declared public service ports, and remove rules that open other ports to 0.0.0.0/0 or ::/0.',
  },
  'l3.forbidden_tcp_port.safe': {
    control_family: 'network_firewall_ingress',
    missing_control: 'The declared deny for this TCP port is not enforced: a TCP handshake completes from an internet address that the network policy says must be blocked.',
    required_policy: 'Add an inbound deny, or remove the allow, for the forbidden TCP port on every firewall, security group and load balancer in front of the host, for IPv4 and IPv6 sources.',
  },
  'l3.forbidden_udp_port.safe': {
    control_family: 'network_firewall_ingress',
    missing_control: 'The declared deny for this UDP port is not enforced at the network edge, so a service on the forbidden UDP port can still answer datagrams from the internet.',
    required_policy: 'Add an inbound UDP deny for the forbidden port on the host firewall and upstream network ACLs for all internet sources, and stop the listening service if it is not needed.',
  },
  'l3.fragmentation_flood.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'No IP fragment filtering or reassembly limits are declared, so fragment floods can exhaust reassembly buffers on the firewall or the host.',
    required_policy: 'Drop unexpected and overlapping fragments at the edge, cap reassembly memory and timeouts on firewalls and hosts, and declare the fragment policy.',
  },
  'l3.ftp_connection_flood.readiness': {
    control_family: 'network_connection_limits',
    missing_control: 'The FTP control port (TCP 21) accepts internet connections without declared per-source connection limits, so connection floods can exhaust FTP sessions and passive data ports.',
    required_policy: 'Limit concurrent and per-source FTP connections, bound the passive port range with timeouts, restrict access to known client ranges where possible, and declare the limits.',
  },
  'l3.gre_esp_flood.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'GRE (IP protocol 47) and ESP (IP protocol 50) are not filtered for hosts that do not terminate tunnels, so tunnel-protocol floods reach them unchecked.',
    required_policy: 'Drop IP protocols 47 and 50 at the network edge except toward declared VPN or tunnel endpoints, and rate-limit them toward those endpoints.',
  },
  'l3.icmp_flood.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'No ICMP rate limit or filtering policy is declared for this target, so echo requests and other ICMP types can be accepted at unbounded rates during a flood.',
    required_policy: 'Rate-limit ICMP echo at the edge, permit only required ICMP types such as path-MTU and unreachable messages, drop the rest, and declare the policy.',
  },
  'l3.ike_ipsec_negotiation.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'No IKE negotiation rate limit or cookie challenge is declared for the VPN endpoints, so IKE_SA_INIT floods on UDP 500 and 4500 can exhaust half-open security associations.',
    required_policy: 'Enable IKE cookie challenges under load, rate-limit IKE_SA_INIT per source on UDP 500 and 4500, cap half-open security associations, and declare the policy.',
  },
  'l3.ipv6_reachability.safe': {
    control_family: 'network_firewall_ingress',
    missing_control: 'IPv6 ingress filtering does not match the declared protection expectation, so the target is reachable over IPv6 on ports or paths that the IPv4 policy restricts.',
    required_policy: 'Mirror every IPv4 ingress allow and deny rule for ::/0 and put the AAAA address behind the same edge protection, so IPv6 exposure matches the declared behaviour.',
  },
  'l3.ipv6_volumetric.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'IPv6 traffic does not receive the same scrubbing and rate-limit coverage as IPv4, leaving the AAAA path open to volumetric floods that the IPv4 path would absorb.',
    required_policy: 'Route IPv6 prefixes through the same scrubbing service as IPv4, apply equivalent rate limits and detection thresholds, and declare IPv4 and IPv6 protection parity.',
  },
  'l3.multicast_broadcast_storm.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'No broadcast or multicast storm suppression is configured for edge segments, so a broadcast or multicast storm can saturate links and hosts on the segment.',
    required_policy: 'Enable storm-control thresholds for broadcast and multicast traffic on edge switch ports and routers, block multicast from the internet, and declare the suppression policy.',
  },
  'l3.nat_state_table.readiness': {
    control_family: 'network_connection_limits',
    missing_control: 'NAT and firewall state-table capacity and fill-level alerts are not declared, so a flood of new flows can exhaust translation or state entries without warning.',
    required_policy: 'Size NAT and firewall state tables for peak load plus attack headroom, shorten idle timeouts for embryonic flows, and alert at defined fill thresholds.',
  },
  'l3.out_of_state_tcp.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'No stateful firewall inspection that drops TCP packets outside an established or valid handshake state is declared, so out-of-state segments are passed to the host.',
    required_policy: 'Enable stateful inspection on the edge firewall with an explicit drop for invalid and out-of-state TCP packets, and declare the stateful policy.',
  },
  'l3.rst_flood.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'No filtering or rate limit for TCP RST packets is declared, so spoofed reset floods can reach hosts and tear down connections or overload connection tracking.',
    required_policy: 'Drop RST packets that do not match an existing connection and its sequence window, rate-limit RST packets per source, and declare the policy.',
  },
  'l3.sctp_exposure.readiness': {
    control_family: 'network_firewall_ingress',
    missing_control: 'SCTP (IP protocol 132) is not filtered for hosts that offer no SCTP service, so unexpected SCTP associations and INIT floods are accepted from the internet.',
    required_policy: 'Drop IP protocol 132 at the edge for every declared host that does not provide an SCTP service, and declare the filtering policy.',
  },
  'l3.sip_voip_flood.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'The SIP signalling port (UDP 5060) is reachable from the internet without a source allow-list or request rate limit, so SIP INVITE and REGISTER floods reach the VoIP service.',
    required_policy: 'Restrict UDP and TCP 5060 and 5061 to declared carrier and trunk ranges, rate-limit SIP requests per source, and place a session border controller in front of the VoIP service.',
  },
  'l3.smtp_connection_flood.readiness': {
    control_family: 'network_connection_limits',
    missing_control: 'The SMTP port (TCP 25) accepts internet connections without declared per-source connection and session limits, so connection floods can exhaust mail server slots.',
    required_policy: 'Configure per-source concurrent connection and connection-rate limits plus banner and session timeouts on the mail service, and declare the SMTP limits.',
  },
  'l3.ssh_connection_flood.readiness': {
    control_family: 'network_connection_limits',
    missing_control: 'The SSH port (TCP 22) accepts internet connections without a source allow-list or per-source connection-rate limit, so connection floods can exhaust unauthenticated session slots.',
    required_policy: 'Restrict TCP 22 to administrative ranges, or apply per-source connection-rate limits, caps on unauthenticated sessions and a short login grace time, and declare the SSH limits.',
  },
  'l3.syn_ack_flood.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'No filtering of unsolicited SYN-ACK packets is declared, so reflected or spoofed SYN-ACK floods reach hosts that never sent the matching SYN.',
    required_policy: 'Drop SYN-ACK packets that match no outbound SYN in the state table, enable upstream scrubbing for reflected SYN-ACK traffic, and declare the policy.',
  },
  'l3.syn_flood.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'No SYN-flood mitigation such as SYN cookies, half-open connection limits or upstream scrubbing is declared, so a SYN flood can fill the listen backlog and block new connections.',
    required_policy: 'Enable SYN cookies or a SYN proxy at the edge and on hosts, cap half-open connections per source and globally, and declare upstream SYN scrubbing.',
  },
  'l3.tcp_connection_flood.readiness': {
    control_family: 'network_connection_limits',
    missing_control: 'No concurrent-connection budget or per-source connection cap is declared for the service port, so a full-handshake connection flood can exhaust sockets and workers.',
    required_policy: 'Set per-source and total concurrent connection limits with idle timeouts on the load balancer or firewall in front of the service port, and declare the budget.',
  },
  'l3.tcp_flag_anomaly.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'Packets with invalid TCP flag combinations such as SYN+FIN, NULL or all-flags-set are not dropped at the edge, so malformed segments reach the service port.',
    required_policy: 'Add edge filters that drop TCP segments with invalid flag combinations, including SYN+FIN, SYN+RST, NULL and all-flags-set, and declare the filtering policy.',
  },
  'nfw.connection_limit.safe': {
    control_family: 'network_connection_limits',
    missing_control: 'No per-source connection cap is enforced: a single internet source keeps getting new concurrent connections admitted beyond the declared connection_limits budget.',
    required_policy: 'Enforce the declared per-source concurrent connection limit on the load balancer, firewall or host so connections above the cap are rejected or dropped.',
  },
  'nfw.declared_deny_tcp.safe': {
    control_family: 'network_firewall_ingress',
    missing_control: 'The declared TCP deny is not enforced at the network firewall: a non-CDN internet address completes a TCP handshake on a port the network policy marks as denied.',
    required_policy: 'Add or correct the inbound deny for the declared TCP port in every security group, network ACL and host firewall on the path, and remove overlapping allow rules.',
  },
  'nfw.declared_deny_udp.safe': {
    control_family: 'network_firewall_ingress',
    missing_control: 'The declared UDP deny is not enforced: a protocol-validated reply comes back from a non-CDN address on a UDP port that the network policy marks as denied.',
    required_policy: 'Add an inbound deny for the declared UDP port on every firewall and network ACL in the path for IPv4 and IPv6 sources, and disable the service if it is unused.',
  },
  'nfw.ipv6_parity.safe': {
    control_family: 'network_firewall_ingress',
    missing_control: 'Ingress rules are not equivalent for IPv4 and IPv6: one address family completes a handshake on a port that the declared deny blocks on the other family.',
    required_policy: 'Maintain one ingress policy applied to both 0.0.0.0/0 and ::/0 so every IPv4 deny has a matching IPv6 deny, and test the A and AAAA addresses after each change.',
  },
  'nfw.management_port_exposure.safe': {
    control_family: 'network_firewall_ingress',
    missing_control: 'Management and database ports such as SSH, RDP, SQL, Redis, Kubernetes and Docker accept TCP connections from the internet because no ingress firewall rule denies them.',
    required_policy: 'Deny inbound internet traffic (0.0.0.0/0 and ::/0) to management and database ports and allow them only from named administrative ranges such as a bastion or VPN.',
  },
  'nfw.perspective_allowlist.safe': {
    control_family: 'network_firewall_ingress',
    missing_control: 'The source allow-list on the declared port is not enforced: a probe perspective outside the allowed source ranges completes a TCP handshake that the network policy denies.',
    required_policy: 'Limit the inbound rule to the declared allowed source ranges, explicitly deny all other sources, and verify the rule from both an allowed and a denied network.',
  },
  'ops.alert_workflow_marker.safe': {
    control_family: 'operations_readiness',
    missing_control: 'No approved, signed alert webhook or SIEM hook is wired to receive DDoS alert markers, so an attack signal for this target is not shown to reach the responders who must act on it.',
    required_policy: 'Register a signed alert webhook or SIEM ingestion endpoint for DDoS alerts, approve it as the callback scope for this target, and confirm marker delivery reaches the on-call queue.',
  },
  'ops.attack_alert_coverage.readiness': {
    control_family: 'operations_readiness',
    missing_control: 'Alert routes do not cover attack-window signals such as request-rate spikes, error-budget burn and provider mitigation events, leaving blind spots when a DDoS begins.',
    required_policy: 'Create alerts for traffic-rate spikes, 5xx and latency error budgets, and provider mitigation start and stop events, and route each one to the on-call rotation for this target.',
  },
  'ops.autoscaling_cost.readiness': {
    control_family: 'operations_readiness',
    missing_control: 'No maximum-instance budget, spend cap or scale-in cooldown is declared for autoscaling, so an attack can drive unbounded scale-out cost or oscillating scale events.',
    required_policy: 'Set maximum instance counts and spend alerts on every autoscaling group serving this target, add scale-in cooldowns, and declare these guardrails as readiness evidence.',
  },
  'ops.kill_switch_drill.request_only': {
    control_family: 'operations_readiness',
    missing_control: 'The ability to halt a running validation or emergency change within a defined time has not been exercised in a governed drill, so the stop path is unproven.',
    required_policy: 'Schedule a SOC-authorized kill-switch drill, in dry-run or live-stop mode per the authorization pack, that measures time to halt and records the audit evidence.',
  },
  'ops.kill_switch_drill.safe': {
    control_family: 'operations_readiness',
    missing_control: 'No kill-switch state, audit trail or accepted drill record exists for this tenant, so there is no demonstrated way to stop validation traffic or mitigation changes immediately.',
    required_policy: 'Document a kill-switch runbook with named operators, record its configured state and audit trail, and keep accepted evidence of a recent dry-run drill for the declared scope.',
  },
  'ops.provider_telemetry.request_only': {
    control_family: 'operations_readiness',
    missing_control: 'DDoS provider telemetry is not proven to reach the customer monitoring stack during an attack, so mitigation events, dropped traffic and attack start are not visible in real time.',
    required_policy: 'Declare the provider telemetry endpoint, stream mitigation and attack events into the SIEM or monitoring stack, and verify delivery during a SOC-governed scenario with provider approval.',
  },
  'ops.runbook_contact_validation.request_only': {
    control_family: 'operations_readiness',
    missing_control: 'Emergency contacts and escalation owners in the DDoS runbook have not been proven reachable in a governed drill, so the escalation path may fail during a real attack.',
    required_policy: 'Keep the runbook roster current and run a SOC-authorized contact drill that pages each on-call owner and provider escalation contact and records acknowledgement times.',
  },
  'ops.runbook_contact_validation.safe': {
    control_family: 'operations_readiness',
    missing_control: 'There is no accepted, current DDoS runbook naming on-call owners and emergency escalation contacts for this target, so nobody is verifiably accountable when an attack starts.',
    required_policy: 'Publish a versioned DDoS response runbook with named on-call owners, escalation contacts and provider support channels, and upload it as accepted support readiness evidence.',
  },
  'reflect.chargen_qotd_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'Legacy CHARGEN, QOTD or Echo services (ports 19, 17 and 7) answer from the internet and can be abused to reflect and amplify traffic toward victims.',
    required_policy: 'Disable the CHARGEN, QOTD and Echo services on the host and block inbound UDP and TCP 7, 17 and 19 at the network edge.',
  },
  'reflect.coap_iot_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'A CoAP endpoint answers /.well-known/core requests on UDP 5683 from the internet, exposing IoT resources and acting as an amplification reflector.',
    required_policy: 'Block inbound UDP 5683 and 5684 from the internet, restrict CoAP to device management networks, and require DTLS-secured CoAP where remote access is needed.',
  },
  'reflect.dtls_sip_rdp_tftp_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'TFTP (UDP 69), DTLS, SIP OPTIONS or RDP over UDP answers unauthenticated requests from the internet, giving attackers a reflector with amplified responses.',
    required_policy: 'Block inbound TFTP on UDP 69 from the internet, limit DTLS, SIP and RDP UDP listeners to declared client ranges or a VPN, and disable UDP transports that are not needed.',
  },
  'reflect.ipmi_bmc_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'A baseboard management controller answers IPMI RMCP pings on UDP 623 from the internet, exposing out-of-band server management and acting as a reflector.',
    required_policy: 'Block inbound UDP 623 from the internet and place BMC and IPMI interfaces on an isolated management network reachable only through a VPN or bastion.',
  },
  'reflect.ipp_callback_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'A printing service answers IPP Get-Printer-Attributes requests on port 631 from the internet, allowing reflected callbacks and amplified responses.',
    required_policy: 'Block inbound TCP and UDP 631 from the internet, disable printer browsing on public interfaces, and restrict IPP to internal print networks.',
  },
  'reflect.jenkins_discovery_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'A CI server UDP auto-discovery listener on port 33848 answers from the internet, leaking server details and enabling amplified reflection.',
    required_policy: 'Disable UDP auto-discovery on the CI server, or bind it to internal interfaces, and block inbound UDP 33848 from the internet at the edge firewall.',
  },
  'reflect.l2tp_reflection_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'An L2TP endpoint answers control-connection requests on UDP 1701 from any internet source, allowing its control replies to be reflected toward victims.',
    required_policy: 'Restrict UDP 1701 to declared VPN client ranges, require IPsec protection for L2TP, and disable L2TP on hosts that do not terminate it.',
  },
  'reflect.legacy_device_discovery_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'A device discovery responder on UDP 3702 answers WS-Discovery probes from the internet, the behaviour of cameras, printers and consoles abused for amplified reflection.',
    required_policy: 'Block inbound UDP 3702 and other device discovery ports from the internet and disable discovery responders on devices that hold public addresses.',
  },
  'reflect.mdns_netbios_wsdiscovery_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'Local discovery services (mDNS on UDP 5353, NetBIOS name service on UDP 137 or WS-Discovery on UDP 3702) answer queries from the internet and can act as reflectors.',
    required_policy: 'Block inbound UDP 5353, 137 and 3702 from the internet and disable mDNS, NetBIOS name service and WS-Discovery on internet-facing interfaces.',
  },
  'reflect.mssql_resolver_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'The SQL Server browser service answers instance resolution requests on UDP 1434 from the internet, revealing instance details and acting as an amplification reflector.',
    required_policy: 'Block inbound UDP 1434 from the internet and disable the SQL Server browser service or bind it to internal interfaces only.',
  },
  'reflect.natpmp_amplification_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'A NAT-PMP service answers external-address requests on UDP 5351 from the internet, exposing gateway details and acting as a reflector.',
    required_policy: 'Disable NAT-PMP and PCP on the WAN interfaces of gateways and block inbound UDP 5351 from the internet.',
  },
  'reflect.openvpn_wireguard_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'A VPN endpoint on UDP 1194 answers unauthenticated reset or handshake packets from any source, allowing reflection and handshake floods.',
    required_policy: 'Require an HMAC on initial VPN packets (tls-auth or tls-crypt) so unsigned packets are dropped, rate-limit handshakes per source, and restrict the VPN port to expected client ranges.',
  },
  'reflect.portmap_service_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'The RPC portmapper on UDP 111, or a RIPv1 or RPC service, answers dump requests from the internet, leaking service maps and enabling amplified reflection.',
    required_policy: 'Block inbound UDP and TCP 111 and RIP on UDP 520 from the internet, bind rpcbind to internal interfaces only, or disable it where RPC is unused.',
  },
  'reflect.quic_reflection_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'QUIC on UDP 443 is advertised through Alt-Svc without a declared exposure intent, so a UDP listener that answers unvalidated Initial packets is published without amplification-limit review.',
    required_policy: 'Advertise HTTP/3 only where intended, enforce QUIC address validation and the threefold anti-amplification limit with Retry under load, and filter UDP 443 where QUIC is not offered.',
  },
  'reflect.redis_direct_exposure.safe': {
    control_family: 'network_firewall_ingress',
    missing_control: 'Redis on TCP 6379 completes handshakes from the internet despite a declared deny, exposing an often unauthenticated data store to remote access and abuse.',
    required_policy: 'Deny inbound TCP 6379 from the internet, bind Redis to private interfaces, enable authentication and protected mode, and allow only application subnets.',
  },
  'reflect.slp_amplification_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'A Service Location Protocol agent answers service requests on port 427 from the internet, which can be abused for very high-ratio amplification.',
    required_policy: 'Disable the SLP service on internet-facing hosts and block inbound UDP and TCP 427 at the edge firewall.',
  },
  'reflect.snmp_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'An SNMP agent answers community-string GET requests on UDP 161 from the internet, exposing device data and making the host an amplification reflector.',
    required_policy: 'Block inbound UDP 161 from the internet, restrict SNMP to management networks, replace v1 and v2c communities with SNMPv3 authentication, or disable the agent.',
  },
  'reflect.ssdp_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'An SSDP/UPnP service answers M-SEARCH discovery requests on UDP 1900 from the internet, making the host usable as a reflection and amplification source.',
    required_policy: 'Block inbound UDP 1900 from the internet at the edge firewall and disable UPnP and SSDP on internet-facing interfaces of routers, cameras and other devices.',
  },
  'reflect.stun_turn_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'A STUN/TURN server answers binding requests on UDP 3478 from any internet source without rate limiting, allowing reflected traffic toward spoofed victims.',
    required_policy: 'Require TURN credentials for relay use, rate-limit binding requests per source, and close UDP 3478 where the media relay is not in use.',
  },
  'reflect.tcp_middlebox_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'An in-path middlebox in front of the declared host answers TCP payloads without a completed handshake, so it can be abused for TCP-based reflection and amplification.',
    required_policy: 'Configure in-path filtering and inspection devices to require a valid TCP handshake before sending responses, and drop out-of-state TCP payload packets at the edge.',
  },
  'reflect.tp240_amplification_exposure.safe': {
    control_family: 'reflector_service_exposure',
    missing_control: 'A telephony appliance test facility answers status requests on UDP 10074 from the internet, a known very high-ratio amplification vector.',
    required_policy: 'Block inbound UDP 10074 from the internet and disable or patch out the telephony test facility on all public interfaces.',
  },
});
