export const MISSING_CONTROLS_APPLICATION = Object.freeze({
  'exploit.ip_options.posture': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'No policy is declared to strip or drop IP packets carrying options such as loose or strict source routing, so they may be accepted unrestricted.',
    required_policy: 'Configure edge routers and firewalls to drop or strip packets with IP options, including source-route and record-route options, and declare the policy.',
  },
  'exploit.land_attack.posture': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'No anti-spoofing rule is declared for packets whose source equals the destination or a loopback address, so Land class packets are not known to be dropped.',
    required_policy: 'Add ingress anti-spoofing rules that drop packets with source equal to destination, loopback, or your own address space arriving from the internet.',
  },
  'exploit.malformed_quic.posture': {
    control_family: 'http2_http3_protection',
    missing_control: 'No QUIC version allow-list or malformed-packet drop policy is declared, so the QUIC listener may parse unexpected versions and invalid datagrams.',
    required_policy: 'Restrict accepted QUIC versions to an explicit allow-list at the edge and drop malformed or unknown-version Initial packets before they reach the QUIC stack.',
  },
  'exploit.ping_of_death.posture': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'No drop policy for oversized or malformed reassembled datagrams is declared on edge devices, so Ping-of-Death class packets are not known to be filtered.',
    required_policy: 'Configure edge routers, firewalls or the scrubbing service to drop oversized and malformed ICMP and IP datagrams, and record the rule as a declared filtering policy.',
  },
  'exploit.quic_migration.posture': {
    control_family: 'http2_http3_protection',
    missing_control: 'No QUIC connection migration validation policy is declared, so connection-ID migration may be accepted without path validation and abused for amplification.',
    required_policy: 'Require PATH_CHALLENGE validation and anti-amplification limits on QUIC connection migration, or disable active migration on the edge listener.',
  },
  'exploit.teardrop.posture': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'No policy is declared for dropping overlapping or offset-anomalous IP fragments, so Teardrop class fragment attacks are not known to be filtered at the edge.',
    required_policy: 'Enable fragment validation that drops overlapping, tiny or offset-anomalous fragments on edge firewalls or the scrubbing service, and declare the policy.',
  },
  'l7.api_quota_exhaustion.safe': {
    control_family: 'waf_rate_limiting',
    missing_control: 'The API path enforces no per-key or per-client quota, so one consumer can exhaust shared capacity without receiving throttling responses.',
    required_policy: 'Enforce per-API-key and per-client request quotas at the gateway or edge, returning HTTP 429 with Retry-After once the declared quota window is exceeded.',
  },
  'l7.api_surface_scan.safe': {
    control_family: 'api_surface_protection',
    missing_control: 'API documentation and schema paths such as OpenAPI or Swagger files are publicly reachable, exposing the API surface without authentication.',
    required_policy: 'Remove public API documentation and schema files or protect them with authentication, and block well-known documentation paths at the edge.',
  },
  'l7.batch_api_abuse.validation': {
    control_family: 'api_surface_protection',
    missing_control: 'No maximum item count or concurrency cap is declared for batch API endpoints, so a single request can fan out into unbounded backend work.',
    required_policy: 'Cap the number of items per batch request and the concurrent batch jobs per client, rejecting oversized batches with HTTP 413 or 400.',
  },
  'l7.bot_challenge_marker.safe': {
    control_family: 'waf_bot_management',
    missing_control: 'No bot management challenge is applied to the declared protected URL, so automated non-browser clients receive the page without any interstitial or verification.',
    required_policy: 'Enable bot management on the protected URL so that clients without a valid browser signal receive a challenge or block before the request reaches the origin.',
  },
  'l7.cache_busting.safe': {
    control_family: 'cache_policy',
    missing_control: 'The cache key includes arbitrary query strings, so adding a random parameter turns a cacheable request into a cache miss that is forwarded to the origin.',
    required_policy: 'Normalise the cache key by ignoring or allow-listing query parameters on cacheable paths, and rate limit cache-miss traffic that varies only by unknown parameters.',
  },
  'l7.captcha_challenge_abuse.readiness': {
    control_family: 'waf_bot_management',
    missing_control: 'No challenge issuance budget is declared, so automated clients can repeatedly trigger CAPTCHA or challenge generation and its backend cost.',
    required_policy: 'Cap challenge issuance per client and per time window, and block clients that repeatedly fail or request challenges beyond the budget.',
  },
  'l7.checkout_abuse.validation': {
    control_family: 'waf_rate_limiting',
    missing_control: 'No checkout rate limit or inventory-hold expiry cap is declared, so automated carts can repeatedly reserve stock or hit payment flows.',
    required_policy: 'Enforce per-session and per-account checkout rate limits, short inventory-hold expiry and a cap on open carts per client.',
  },
  'l7.compressed_request_decompression.posture': {
    control_family: 'l7_request_limits',
    missing_control: 'No declared limit caps the decompressed size of compressed request bodies, so a small encoded body could expand into a large payload at the origin.',
    required_policy: 'Cap the decompressed request body size and ratio at the edge, and reject unsupported or oversize Content-Encoding values with HTTP 415 or 413.',
  },
  'l7.conditional_revalidation.readiness': {
    control_family: 'cache_policy',
    missing_control: 'No revalidation coalescing or rate cap is declared, so conditional requests can force repeated origin revalidation instead of being answered by the cache.',
    required_policy: 'Enable request collapsing and stale-while-revalidate at the cache, and rate limit conditional requests that bypass cached validators.',
  },
  'l7.connection_hoarding.readiness': {
    control_family: 'network_connection_limits',
    missing_control: 'No per-source connection or session cap with idle timeouts is declared for the application, so one client can accumulate and hold many open connections.',
    required_policy: 'Configure per-source concurrent connection and session caps with idle timeouts at the edge or load balancer, and document the thresholds as a control declaration.',
  },
  'l7.cors_posture.safe': {
    control_family: 'api_surface_protection',
    missing_control: 'The API returns a permissive CORS policy, such as reflecting any Origin or allowing credentials with a wildcard, so cross-origin browsers can call it freely.',
    required_policy: 'Return Access-Control-Allow-Origin only for an explicit allow-list of trusted origins, never combine wildcards with credentials, and restrict allowed methods and headers.',
  },
  'l7.elasticsearch_abuse.readiness': {
    control_family: 'api_surface_protection',
    missing_control: 'No query depth, timeout or cancellation cap is declared for the search cluster, so expensive user-driven queries could run unbounded.',
    required_policy: 'Enforce search query timeouts, maximum result windows, aggregation and wildcard limits, and automatic cancellation for queries reaching the search cluster.',
  },
  'l7.expensive_endpoint.safe': {
    control_family: 'waf_rate_limiting',
    missing_control: 'The declared expensive endpoint has no dedicated rate limit or challenge, so repeated requests reach costly backend work without being slowed down.',
    required_policy: 'Add an endpoint-specific rate rule or challenge for the expensive URL with a lower threshold than general traffic, and return HTTP 429 when it is exceeded.',
  },
  'l7.export_abuse.validation': {
    control_family: 'waf_rate_limiting',
    missing_control: 'The export or report endpoint has no dedicated rate limit, so a client can trigger repeated heavy report generation without being throttled.',
    required_policy: 'Limit export and report requests per client and per account, queue heavy exports asynchronously, and return HTTP 429 once the limit is reached.',
  },
  'l7.file_upload_abuse.readiness': {
    control_family: 'waf_rate_limiting',
    missing_control: 'No per-client upload count, rate or storage quota is declared for the upload endpoints, so one client can upload repeatedly and drive storage cost.',
    required_policy: 'Enforce per-client upload rate limits, maximum file size and per-account storage quotas on every declared upload endpoint.',
  },
  'l7.graphql_batch_abuse.validation': {
    control_family: 'api_surface_protection',
    missing_control: 'The GraphQL endpoint does not limit batched operations or field aliases, so one request can carry many operations that bypass per-request limits.',
    required_policy: 'Cap the number of operations per batch and aliases per query on the GraphQL endpoint, and count each batched operation against rate limits.',
  },
  'l7.graphql_complexity.safe': {
    control_family: 'api_surface_protection',
    missing_control: 'The GraphQL endpoint does not enforce query depth or cost limits, so a single deeply nested or expensive query is accepted and executed in full.',
    required_policy: 'Configure query depth, complexity and cost limits on the GraphQL endpoint, reject queries above them before execution, and disable introspection in production.',
  },
  'l7.header_size_boundary.safe': {
    control_family: 'l7_request_limits',
    missing_control: 'No request header size limit is enforced at the edge, so requests carrying oversized headers are accepted and forwarded rather than rejected early.',
    required_policy: 'Set a maximum total request header size and per-header size at the edge, rejecting larger requests with HTTP 431 or 400 before they are parsed by the origin.',
  },
  'l7.health_check_flood.readiness': {
    control_family: 'waf_rate_limiting',
    missing_control: 'Health endpoints have no declared rate cap and autoscaling has no cooldown guard, so traffic to health checks could distort scaling decisions.',
    required_policy: 'Restrict public access to health endpoints, rate limit them per client, and configure autoscaling cooldowns and scale-in protection.',
  },
  'l7.hpack_bomb.readiness': {
    control_family: 'http2_http3_protection',
    missing_control: 'The HTTP/2 endpoint does not advertise bounded HPACK table and header list sizes, so compressed headers can expand into large server memory use.',
    required_policy: 'Advertise a bounded SETTINGS_HEADER_TABLE_SIZE and SETTINGS_MAX_HEADER_LIST_SIZE and reject header blocks that decompress beyond them.',
  },
  'l7.http2_continuation.readiness': {
    control_family: 'http2_http3_protection',
    missing_control: 'The HTTP/2 endpoint does not cap CONTINUATION frames or total header block size, so a client can send endless header frames on one stream.',
    required_policy: 'Limit the number of CONTINUATION frames and total header list size per stream, and close connections that exceed the cap.',
  },
  'l7.http2_made_you_reset.readiness': {
    control_family: 'http2_http3_protection',
    missing_control: 'No protection against server-triggered stream resets (MadeYouReset) is declared, so malformed frames that make the server reset streams are not limited.',
    required_policy: 'Run an HTTP/2 stack patched for MadeYouReset and count server-side stream resets toward the per-connection reset limit, closing offending connections.',
  },
  'l7.http2_priority_abuse.readiness': {
    control_family: 'http2_http3_protection',
    missing_control: 'No cap on HTTP/2 priority tree depth or priority updates is declared, so PRIORITY frames can force repeated scheduling work on the server.',
    required_policy: 'Ignore client PRIORITY frames or cap priority tree size and priority update rate per connection on the HTTP/2 listener.',
  },
  'l7.http2_push_promise.readiness': {
    control_family: 'http2_http3_protection',
    missing_control: 'HTTP/2 server push is not declared disabled or budgeted, so PUSH_PROMISE streams may consume bandwidth and server resources without a cap.',
    required_policy: 'Disable HTTP/2 server push on the edge and origin, or cap pushed streams per connection by declared policy.',
  },
  'l7.http2_rapid_reset.validation': {
    control_family: 'http2_http3_protection',
    missing_control: 'The HTTP/2 endpoint does not show a rapid reset mitigation, so streams opened and immediately cancelled are not counted or limited per connection.',
    required_policy: 'Apply the vendor patch for CVE-2023-44487, cap RST_STREAM frames per connection and close abusive connections with GOAWAY.',
  },
  'l7.http_get_flood.validation': {
    control_family: 'waf_rate_limiting',
    missing_control: 'No requests-per-second limit for GET traffic is enforced on this path, so a single client can repeat GET requests without being throttled.',
    required_policy: 'Add a per-client GET rate rule at the edge matching the declared RPS limit, returning HTTP 429 or a challenge once the threshold is exceeded.',
  },
  'l7.http_method_restriction.safe': {
    control_family: 'http_method_policy',
    missing_control: 'No method allow-list is enforced at the edge for this URL, so unexpected HTTP methods are accepted and passed to the application instead of being rejected.',
    required_policy: 'Define an allow-list of the HTTP methods this URL needs and configure the edge to reject every other method with HTTP 405 or 403 before it reaches the origin.',
  },
  'l7.http_pipelining.readiness': {
    control_family: 'l7_request_limits',
    missing_control: 'No pipelining depth cap is declared where HTTP/1.1 pipelining is enabled, so one connection can queue many requests ahead of responses.',
    required_policy: 'Disable HTTP/1.1 pipelining at the edge or cap the number of pipelined requests per connection and close connections that exceed it.',
  },
  'l7.http_post_flood.validation': {
    control_family: 'waf_rate_limiting',
    missing_control: 'No POST rate or body-size limit is declared for the expensive POST endpoints, so repeated POST requests would reach the application without throttling.',
    required_policy: 'Declare and enforce per-client POST rate limits and body-size caps on each expensive POST endpoint, blocking or challenging clients above the threshold.',
  },
  'l7.http_range_abuse.readiness': {
    control_family: 'l7_request_limits',
    missing_control: 'No cap on the number or overlap of byte ranges is declared for large-object endpoints, so multi-range requests can multiply response cost.',
    required_policy: 'Limit the number of ranges per request, reject overlapping or unsorted ranges, and serve large objects from cache with range handling at the edge.',
  },
  'l7.json_xml_bomb.readiness': {
    control_family: 'waf_body_inspection',
    missing_control: 'No JSON nesting depth or XML entity expansion limit is declared for the API content types, so crafted documents could exhaust parser memory and CPU.',
    required_policy: 'Configure parser limits for maximum JSON depth, element count and body size, disable XML external entities and cap entity expansion at the edge and in the API.',
  },
  'l7.large_body_post.readiness': {
    control_family: 'l7_request_limits',
    missing_control: 'No request body size limit is declared for the upload endpoints, so very large bodies would be accepted and streamed to the origin.',
    required_policy: 'Set a maximum request body size at the edge for each upload endpoint and reject larger requests with HTTP 413 before forwarding.',
  },
  'l7.login_abuse_flow.safe': {
    control_family: 'waf_rate_limiting',
    missing_control: 'Login, OTP and signup paths accept repeated requests from one client without throttling, so credential stuffing or verification abuse is not limited.',
    required_policy: 'Apply strict per-IP and per-account rate limits on login, OTP and signup paths, escalating to a challenge or temporary block after the agreed number of attempts.',
  },
  'l7.low_and_slow.readiness': {
    control_family: 'l7_request_limits',
    missing_control: 'Low-and-slow clients that trickle request headers are not cut off, because no header timeout at or below the declared probe window applies.',
    required_policy: 'Enforce short header and idle timeouts plus a per-source concurrent connection cap so low-rate trickling connections are closed early.',
  },
  'l7.low_rate_rate_limit.safe': {
    control_family: 'waf_rate_limiting',
    missing_control: 'No per-client rate limit applies at the edge, so a single source can keep sending requests to this hostname without being throttled or challenged.',
    required_policy: 'Add a rate-based rule that throttles or blocks a client exceeding an agreed request rate per IP or session on this hostname, returning HTTP 429.',
  },
  'l7.mqtt_broker_exposure.readiness': {
    control_family: 'network_connection_limits',
    missing_control: 'No MQTT connection limit or anonymous-access restriction is declared, so internet clients may connect to the broker without authentication or caps.',
    required_policy: 'Disable anonymous MQTT access, require client authentication, and cap connections and connection attempts per source at the broker or network edge.',
  },
  'l7.oauth_token_abuse.validation': {
    control_family: 'waf_rate_limiting',
    missing_control: 'The OAuth or token endpoint accepts repeated requests from one client without throttling, so token minting and credential guessing are not limited.',
    required_policy: 'Rate limit the token endpoint per client ID and per source IP, lock out after repeated invalid grants, and return HTTP 429 above the threshold.',
  },
  'l7.otp_sms_cost.readiness': {
    control_family: 'waf_rate_limiting',
    missing_control: 'No per-recipient or per-tenant OTP and SMS budget is declared, so repeated verification requests could run up messaging cost without a cap.',
    required_policy: 'Set per-phone-number, per-IP and per-tenant OTP send limits with a daily spend budget and block destinations or prefixes that exceed them.',
  },
  'l7.password_reset.safe': {
    control_family: 'waf_rate_limiting',
    missing_control: 'The password reset endpoint has no rate limit or challenge, so a client can trigger reset requests repeatedly and generate email cost and account lockout pressure.',
    required_policy: 'Limit password reset requests per source IP and per target account, require a challenge after a small threshold, and return a uniform response for unknown accounts.',
  },
  'l7.qpack_bomb.readiness': {
    control_family: 'http2_http3_protection',
    missing_control: 'No QPACK dynamic table or encoder stream budget is declared for HTTP/3, so compressed headers can expand into large decoder memory use.',
    required_policy: 'Set bounded QPACK_MAX_TABLE_CAPACITY, QPACK_BLOCKED_STREAMS and maximum field section size on HTTP/3 listeners.',
  },
  'l7.redos.readiness': {
    control_family: 'exploit_mitigation',
    missing_control: 'No regex execution-time budget or complexity review is declared for pattern-matching endpoints, so crafted input could trigger catastrophic backtracking.',
    required_policy: 'Use linear-time regex engines or enforce per-request regex execution timeouts and input length limits on endpoints that apply patterns to user input.',
  },
  'l7.request_parser_size.posture': {
    control_family: 'l7_request_limits',
    missing_control: 'No URI or query-string size limit is enforced before parsing, so oversized request lines and parameters can reach the application parser.',
    required_policy: 'Enforce maximum URI, query-string and parameter count limits at the edge, rejecting oversize requests with HTTP 414 or 400 before parsing.',
  },
  'l7.search_abuse.validation': {
    control_family: 'waf_rate_limiting',
    missing_control: 'The search endpoint has no dedicated rate limit, so repeated search queries from one client reach the backend without throttling.',
    required_policy: 'Apply a per-client rate limit to the search path below the general site threshold and return HTTP 429 or a challenge when it is exceeded.',
  },
  'l7.signup_registration_abuse.validation': {
    control_family: 'waf_rate_limiting',
    missing_control: 'The signup endpoint accepts repeated registration attempts from one client without throttling, so mass fake-account creation is not limited.',
    required_policy: 'Apply per-IP and per-device signup rate limits with a challenge after a small threshold, and return HTTP 429 when the limit is exceeded.',
  },
  'l7.slow_post.readiness': {
    control_family: 'l7_request_limits',
    missing_control: 'No request body receive timeout or minimum upload rate is declared, so a client can hold a connection open by sending a POST body extremely slowly.',
    required_policy: 'Configure a body receive timeout and minimum transfer-rate floor at the edge or reverse proxy, closing uploads that fall below it.',
  },
  'l7.slow_read.readiness': {
    control_family: 'l7_request_limits',
    missing_control: 'No response send timeout or minimum client read rate is declared, so a client can hold server buffers by reading the response extremely slowly.',
    required_policy: 'Configure a response send timeout and minimum client read-rate floor on the edge or reverse proxy, closing connections that drain responses too slowly.',
  },
  'l7.slowloris.readiness': {
    control_family: 'l7_request_limits',
    missing_control: 'The edge does not close connections that send request headers very slowly, because no request header timeout at or below the probe window is enforced.',
    required_policy: 'Set a request header timeout of a few seconds at the edge and load balancer so connections that do not finish sending headers are closed.',
  },
  'l7.waf_marker_rule.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'The custom WAF rule that should block the declared marker header is not enforcing, so a request carrying the marker is forwarded instead of being denied at the edge.',
    required_policy: 'Deploy the agreed custom WAF rule that matches the marker header in blocking mode on this hostname and return a recognisable block response with a consistent status code.',
  },
  'l7.webhook_flood.readiness': {
    control_family: 'api_surface_protection',
    missing_control: 'No rate or retry budget is declared for webhook callbacks, so a burst of webhook events or retries can overwhelm the receiving or sending service.',
    required_policy: 'Set per-destination rate limits and capped exponential backoff retry budgets for outbound webhook deliveries, so a burst of events cannot flood a receiver or exhaust the sending service.',
  },
  'l7.wordpress_xmlrpc.readiness': {
    control_family: 'waf_custom_rules',
    missing_control: 'The XML-RPC endpoint is reachable and not blocked at the edge, so pingback and multicall requests can be used for amplification or credential abuse.',
    required_policy: 'Block the xmlrpc.php path at the edge or disable XML-RPC in the application, allowing it only for explicitly required trusted clients.',
  },
  'nfw.origin_lockdown.safe': {
    control_family: 'origin_protection',
    missing_control: 'The declared origin binding answers as the application for this hostname to a non-CDN source, so the expected origin lockdown is not in place.',
    required_policy: 'Restrict the declared origin binding to the CDN address ranges or an authenticated origin-pull channel so direct requests are refused or dropped.',
  },
  'origin.cdn_bypass.readiness': {
    control_family: 'origin_protection',
    missing_control: 'Some declared hostnames resolve outside the CDN, so part of the application can be reached without passing through edge protection.',
    required_policy: 'Proxy every declared hostname through the CDN, remove direct DNS records to origin addresses, and restrict the origin to edge traffic only.',
  },
  'origin.direct_bypass.safe': {
    control_family: 'origin_protection',
    missing_control: 'Nothing stops a client from sending requests for this hostname directly to the origin, so edge filtering, rate limits and bot controls can be bypassed entirely.',
    required_policy: 'Lock the origin to edge traffic with a firewall allow-list of edge ranges plus a shared-secret header or mutual TLS check, rejecting requests that lack it.',
  },
  'origin.direct_reachability.safe': {
    control_family: 'origin_protection',
    missing_control: 'The origin server accepts HTTP connections addressed straight to its IP, so traffic can reach the application without passing through the edge WAF, CDN or DDoS protection.',
    required_policy: 'Restrict origin ingress so only the edge provider address ranges or an authenticated origin-pull channel can connect on HTTP and HTTPS ports, and drop all other sources.',
  },
  'origin.dns_hostname_bypass.readiness': {
    control_family: 'origin_protection',
    missing_control: 'Hostnames in the declared inventory resolve to unprotected addresses, so attackers can use alternate DNS names to reach the origin directly.',
    required_policy: 'Route every hostname in the inventory through the edge or retire it, and block origin access from sources other than the edge provider.',
  },
  'origin.host_sni_bypass.safe': {
    control_family: 'origin_protection',
    missing_control: 'The origin serves this application when a request carries the protected Host header and TLS SNI but arrives outside the edge, so it does not verify that traffic came through the protected path.',
    required_policy: 'Configure the origin to serve the protected hostname only to connections from the edge, using source allow-lists and origin-pull client certificates, and return a denial for direct Host/SNI requests.',
  },
  'origin.identity_pair.get.v1': {
    control_family: 'origin_protection',
    missing_control: 'The bound origin address returns the same application identity to a direct GET request as the protected entry path, so content is served outside the edge.',
    required_policy: 'Make the bound origin address drop or refuse all direct requests from non-edge sources, using firewall allow-lists for edge address ranges and origin-pull authentication.',
  },
  'origin.identity_pair.head.v1': {
    control_family: 'origin_protection',
    missing_control: 'The bound origin address returns the same application identity to a direct HEAD request as the protected entry path, so a direct application path exists outside the edge.',
    required_policy: 'Make the bound origin address drop or refuse all direct requests from non-edge sources, using firewall allow-lists for edge address ranges and origin-pull authentication.',
  },
  'origin.leak_scan.safe': {
    control_family: 'origin_protection',
    missing_control: 'Public DNS for the apex or related records still exposes addresses that are not behind the edge, so attackers can discover and target the origin directly.',
    required_policy: 'Remove or proxy every public DNS record that resolves to origin infrastructure, rotate exposed origin addresses, and restrict the origin to accept traffic from the edge only.',
  },
  'path.protected_canary.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'No edge rule blocks or challenges anonymous requests to the declared protected path, so the canary resource behind it is reachable by any external client.',
    required_policy: 'Add an edge access rule for the protected path that blocks, challenges or requires authentication for unauthenticated clients before the request is forwarded to the origin.',
  },
  'pattern.adaptive_evasion.readiness': {
    control_family: 'waf_bot_management',
    missing_control: 'Protection relies only on static rules with no declared behavioural or anomaly detection, so traffic that changes its footprint can avoid detection.',
    required_policy: 'Enable behavioural and anomaly-based detection that baselines normal traffic and adapts mitigation automatically, alongside static WAF rules.',
  },
  'pattern.carpet_bombing.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'Declared DDoS scrubbing does not cover non-standard ports or every destination address in the range, so carpet-bombing attacks spread across addresses may evade detection.',
    required_policy: 'Extend scrubbing and network DDoS protection to whole prefixes and all ports, with subnet-level aggregate thresholds rather than per-host thresholds only.',
  },
  'pattern.pulse_wave.readiness': {
    control_family: 'operations_readiness',
    missing_control: 'No burst headroom, warm capacity pool or scale-in cooldown is declared, so short repeated traffic pulses could outpace autoscaling and degrade service.',
    required_policy: 'Keep pre-warmed capacity for burst traffic, set scale-in cooldowns longer than typical pulse intervals, and enable always-on mitigation rather than on-demand.',
  },
  'pattern.ransom_ddos.readiness': {
    control_family: 'operations_readiness',
    missing_control: 'No documented response runbook for ransom DDoS extortion exists, with no named decision owners, law-enforcement contacts or communication templates.',
    required_policy: 'Document a ransom DDoS runbook naming decision owners, provider escalation paths, law-enforcement contacts and communication templates, and rehearse it.',
  },
  'pattern.rate_limit_evasion.readiness': {
    control_family: 'waf_rate_limiting',
    missing_control: 'Rate limits key on a single dimension such as IP or one header, so attackers rotating addresses or header values can stay under every limit.',
    required_policy: 'Configure rate limits that aggregate across several dimensions such as session, API key, fingerprint and path, alongside per-IP limits.',
  },
  'pattern.residential_proxy.readiness': {
    control_family: 'waf_bot_management',
    missing_control: 'No IP reputation or ASN-based filtering is declared, so traffic relayed through residential proxy networks is treated like ordinary users.',
    required_policy: 'Use IP reputation and ASN classification to challenge or rate limit traffic from known proxy networks on sensitive and expensive paths.',
  },
  'pattern.spoofed_source.readiness': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'Ingress filtering against spoofed source addresses is not declared for every edge provider, so spoofed traffic may enter through an unfiltered path.',
    required_policy: 'Apply BCP38 ingress filtering or unicast reverse path forwarding on every edge provider and transit link, dropping packets with bogon or spoofed sources.',
  },
  'protocol.grpc_reflection_stream.safe': {
    control_family: 'api_surface_protection',
    missing_control: 'gRPC server reflection is reachable from the internet, so external clients can enumerate services and methods and open streams without an access policy.',
    required_policy: 'Disable gRPC reflection on public endpoints or restrict it to authenticated internal callers, and cap concurrent streams and message sizes per client.',
  },
  'protocol.http2_rapid_reset_readiness.safe': {
    control_family: 'http2_http3_protection',
    missing_control: 'The HTTP/2 endpoint lacks a declared rapid reset (CVE-2023-44487) mitigation, so clients that open and cancel streams in quick succession are not limited.',
    required_policy: 'Run an HTTP/2 stack patched for rapid reset and enforce a cap on stream resets per connection, closing connections that exceed it with GOAWAY.',
  },
  'protocol.http2_readiness.safe': {
    control_family: 'http2_http3_protection',
    missing_control: 'The HTTP/2 listener advertises permissive SETTINGS such as unbounded concurrent streams or very large windows, so no protocol-level resource caps protect the server.',
    required_policy: 'Configure HTTP/2 SETTINGS with bounded SETTINGS_MAX_CONCURRENT_STREAMS, header list size and initial window size appropriate for the application.',
  },
  'protocol.http2_stream_concurrency.safe': {
    control_family: 'http2_http3_protection',
    missing_control: 'The advertised HTTP/2 concurrent stream limit is missing or above the declared policy, so a single connection can open a large number of parallel streams.',
    required_policy: 'Set SETTINGS_MAX_CONCURRENT_STREAMS at or below the declared policy value, typically 100 or fewer, and enforce it on every HTTP/2 listener.',
  },
  'protocol.http3_control_stream.readiness': {
    control_family: 'http2_http3_protection',
    missing_control: 'HTTP/3 is advertised through Alt-Svc without a declared endpoint policy, so the QUIC control stream entry path is exposed without reviewed limits.',
    required_policy: 'Advertise HTTP/3 only on endpoints where the edge enforces QUIC connection limits, control stream validation and the same WAF policy as other protocols.',
  },
  'protocol.http3_quic_exposure.safe': {
    control_family: 'http2_http3_protection',
    missing_control: 'HTTP/3 over QUIC is advertised or reachable without a declared intent and matching protections, so a UDP-based entry path exists outside the reviewed HTTP/2 controls.',
    required_policy: 'Either disable HTTP/3 and the Alt-Svc advertisement, or enable it only where the edge applies QUIC version allow-lists, connection limits and the same WAF policy as HTTP/2.',
  },
  'protocol.sse_stream.readiness': {
    control_family: 'api_surface_protection',
    missing_control: 'No maximum duration or per-client stream cap is declared for server-sent events, so clients can hold many long-lived event streams open.',
    required_policy: 'Limit concurrent server-sent event streams per client, set a maximum stream duration and enforce a minimum reconnect interval.',
  },
  'protocol.websocket_connection_controls.safe': {
    control_family: 'api_surface_protection',
    missing_control: 'The WebSocket endpoint accepts upgrades without origin checks or per-client connection caps, so any client can open and hold long-lived connections.',
    required_policy: 'Validate the Origin header and authentication on WebSocket upgrades, and limit concurrent connections and connection lifetime per client at the edge.',
  },
  'protocol.websocket_message_rate.readiness': {
    control_family: 'api_surface_protection',
    missing_control: 'No per-connection message rate or frame size cap is declared for WebSockets, so one client can flood an open connection with messages.',
    required_policy: 'Enforce per-connection WebSocket message rate and maximum frame size limits, and close connections that exceed them.',
  },
  'tls.full_audit.safe': {
    control_family: 'tls_configuration',
    missing_control: 'The TLS audit found weaknesses in protocol versions, cipher suites or the certificate chain, so the endpoint does not meet a hardened TLS baseline.',
    required_policy: 'Serve a complete, valid certificate chain and restrict negotiation to TLS 1.2 and 1.3 with forward-secret AEAD ciphers, removing legacy protocols and weak suites.',
  },
  'tls.handshake_rate.readiness': {
    control_family: 'tls_configuration',
    missing_control: 'No TLS handshake rate cap or session resumption tuning is declared, so repeated full handshakes could consume terminator CPU without limit.',
    required_policy: 'Enable TLS session resumption with tickets or session IDs and enforce per-source new-handshake rate limits on the TLS terminator.',
  },
  'tls.idle_connection_timeout.safe': {
    control_family: 'l7_request_limits',
    missing_control: 'Idle TLS connections are kept open longer than the declared policy, so clients can hold connection slots without sending requests.',
    required_policy: 'Configure an idle and keep-alive timeout on the TLS terminator that matches the declared policy and closes connections that stay idle beyond it.',
  },
  'tls.ocsp_stapling.readiness': {
    control_family: 'tls_configuration',
    missing_control: 'The TLS endpoint does not staple an OCSP response, so clients must contact the certificate authority to check revocation during handshakes.',
    required_policy: 'Enable OCSP stapling on the TLS terminator with automatic refresh so each handshake includes a valid revocation response.',
  },
  'tls.profile_exposure.safe': {
    control_family: 'tls_configuration',
    missing_control: 'The endpoint still negotiates legacy TLS protocol versions or weak cipher suites, leaving an outdated and more expensive handshake profile exposed to the internet.',
    required_policy: 'Apply a TLS policy that allows only TLS 1.2 and 1.3 with modern AEAD cipher suites, and disable SSLv3, TLS 1.0, TLS 1.1 and CBC or export-grade ciphers.',
  },
  'tls.renegotiation.readiness': {
    control_family: 'tls_configuration',
    missing_control: 'Client-initiated TLS renegotiation is still accepted, so a client can force repeated expensive handshakes on an existing connection.',
    required_policy: 'Disable client-initiated renegotiation on the TLS terminator or serve TLS 1.3 only, which has no renegotiation; secure renegotiation alone does not stop renegotiation floods.',
  },
  'tls.slow_header_body_timeout.safe': {
    control_family: 'l7_request_limits',
    missing_control: 'The TLS endpoint keeps connections open while a client sends headers or body very slowly, because no header or body receive timeout is enforced.',
    required_policy: 'Set short request header and body receive timeouts with a minimum transfer rate on the TLS terminator, closing connections that fall below them.',
  },
  'tls.zero_rtt.readiness': {
    control_family: 'tls_configuration',
    missing_control: 'TLS 1.3 early data is accepted without a declared anti-replay guard, so replayed 0-RTT requests may be processed more than once.',
    required_policy: 'Disable 0-RTT early data or accept it only for idempotent requests with anti-replay protection and the Early-Data header forwarded to the origin.',
  },
});
