/**
 * Manifest — Wave 4 ticket W4-L7: close 68 E0 L7/API/protocol/non-HTTP resource-exhaustion
 * vectors. Consumed by the integration worker; this module edits nothing in checks.mjs,
 * resourceExhaustionTaxonomy.mjs, capabilityProbes.mjs, or probe-worker.mjs.
 *
 * Tiering discipline (per shared brief):
 *  - E3: a single bounded semantic probe reveals posture. HTTP/2 frame vectors reuse the
 *        existing http2_frame_probe check; HTTP/3/QPACK vectors map only to E2 because the
 *        compatibility http3_control_probe observes Alt-Svc metadata and no frame semantics. Declared-size /
 *        declared-encoding acceptance is read by the new (safe) l7_resource_posture_probe.
 *  - E4: fundamentally a flood or needs a real bomb / crafted exhaustion payload. Mapped to a
 *        governed scenario family (see src/contracts/governedScenarios.mjs) with a reason.
 *        governed_scenario_family is null where no flood analog exists (bomb/exploit/parser
 *        classes are the execution-only remainder of their resource family).
 *  - E1: declared-only cost/guardrail posture — reuses ops.autoscaling_cost.readiness.
 */

import { buildL7ResourcePostureProfile } from '../../lib/vectorProbes/l7ResourceProbes.mjs';

export const MANIFEST_ID = 'l7-resource';
export const OWNED_REGISTRY_IDS = Object.freeze([
  'APP-004', 'APP-012', 'APP-023', 'APP-025', 'APP-026', 'APP-028', 'APP-029', 'APP-032',
  'APP-033', 'APP-034', 'APP-035', 'APP-036', 'APP-037', 'APP-038', 'APP-039', 'APP-041',
  'APP-044', 'APP-045', 'APP-046', 'APP-047', 'APP-049', 'APP-057', 'APP-060', 'APP-067',
  'APP-071', 'APP-075', 'APP-076', 'APP-080', 'APP-081', 'APP-082', 'APP-083', 'APP-084',
  'APP-085', 'APP-090', 'APP-091', 'APP-117', 'APP-118', 'APP-119', 'APP-120', 'APP-124',
  'APP-125', 'APP-127', 'APP-129', 'APP-132', 'APP-134', 'APP-135', 'APP-137', 'APP-140',
  'APP-143', 'APP-145', 'APP-146', 'APP-147', 'APP-148', 'APP-152', 'APP-185', 'APP-186',
  'APP-187', 'APP-188', 'APP-189', 'APP-190', 'APP-191', 'APP-194', 'APP-196', 'APP-197',
  'APP-198', 'APP-199', 'APP-200', 'APP-201',
]);

export const PROPOSED_PROBE_KINDS = Object.freeze([
  {
    kind: 'l7_resource_posture_probe',
    max_requests: 3,
    rationale:
      'Reads declared-size / declared-encoding acceptance posture with <=3 bounded requests, '
      + 'each carrying a single tiny inert benign marker. Declares an oversize/compressed shape '
      + 'via headers only; never sends a decompression bomb, hash-collision set, or flood.',
  },
]);

export const PROPOSED_PROFILE_FIELDS = Object.freeze([
  {
    field: 'marker_class',
    validation: 'enum of declared_content_encoding | declared_oversize_uri',
    applies_to_kinds: ['l7_resource_posture_probe'],
  },
]);

export const PROPOSED_CHECKS = Object.freeze([
  {
    check_id: 'l7.compressed_request_decompression.posture',
    version: '1.0.0',
    name: 'Compressed Request Decompression Acceptance Posture (Safe)',
    vector_family: 'l7',
    description:
      'One or two bounded requests declare a compressed body (Content-Encoding gzip/br) with a '
      + 'declared-decompressed-size header and a tiny inert benign body — no decompression bomb is '
      + 'sent. Reads whether the origin rejects the declared shape (413/415/400) before doing work.',
    safety_class: 'safe',
    risk_class: 'safe',
    prerequisites: [],
    supported_targets: ['url', 'fqdn'],
    required_customer_setup: ['http_endpoint', 'decompression_limit_declaration'],
    evidence_required: ['probe_result'],
    stop_conditions: ['max_events_reached', 'max_duration_elapsed', 'customer_cancel', 'tenant_kill_switch'],
    verdict_logic:
      'Origin that rejects a declared oversize compressed request (413/415/431/400) is protected; '
      + 'one that accepts it for processing raises a decompression-acceptance readiness finding.',
    probe_profile: buildL7ResourcePostureProfile({ marker_class: 'declared_content_encoding', max_requests: 2 }),
    safety_constraints: { max_events: 2, max_duration_seconds: 90, max_concurrent_runs_per_target_group: 1 },
    default_expected_behavior: 'must_block_before_origin',
    remediation_template: 'Cap accepted request body / decompressed size and reject unsupported or oversize encodings at the edge.',
    explanation_template: 'Bounded declared-encoding acceptance probe correlated with declared decompression limits.',
    probe_simulation_profile: 'external_blocked',
  },
  {
    check_id: 'l7.request_parser_size.posture',
    version: '1.0.0',
    name: 'Request URI / Parameter Size Limit Posture (Safe)',
    vector_family: 'l7',
    description:
      'One bounded request carries a benign 1KB URI marker plus a declared-URI-length header. Reads '
      + 'whether the origin enforces a URI / query size limit (414/431/400) before parsing.',
    safety_class: 'safe',
    risk_class: 'safe',
    prerequisites: [],
    supported_targets: ['url', 'fqdn'],
    required_customer_setup: ['http_endpoint', 'request_size_limit_declaration'],
    evidence_required: ['probe_result'],
    stop_conditions: ['max_events_reached', 'max_duration_elapsed', 'customer_cancel', 'tenant_kill_switch'],
    verdict_logic:
      'Origin that rejects an oversize declared URI/query (414/431/400) is protected; one that accepts '
      + 'it for parsing raises a parser-size readiness finding.',
    probe_profile: buildL7ResourcePostureProfile({ marker_class: 'declared_oversize_uri', max_requests: 1 }),
    safety_constraints: { max_events: 1, max_duration_seconds: 90, max_concurrent_runs_per_target_group: 1 },
    default_expected_behavior: 'must_block_before_origin',
    remediation_template: 'Enforce URI, query-string, and header size limits at the edge and reject oversize requests before parsing.',
    explanation_template: 'Bounded declared-size acceptance probe correlated with declared request-size limits.',
    probe_simulation_profile: 'external_blocked',
  },
]);

// E3 / E2 / E1 mappings. Frame vectors reuse existing checks BY REFERENCE; posture vectors use the
// two new checks above; cost/wallet vectors reuse ops.autoscaling_cost.readiness (E1).
export const PROPOSED_REGISTRY_MAPPING = Object.freeze([
  // HTTP/2 frame-level vectors -> existing http2_frame_probe check (E3).
  { registry_id: 'APP-080', add_check_ids: ['l7.http2_continuation.readiness'], target_tier: 'E3' },
  { registry_id: 'APP-081', add_check_ids: ['l7.http2_continuation.readiness'], target_tier: 'E3' },
  { registry_id: 'APP-082', add_check_ids: ['l7.http2_continuation.readiness'], target_tier: 'E3' },
  { registry_id: 'APP-083', add_check_ids: ['l7.http2_continuation.readiness'], target_tier: 'E3' },
  { registry_id: 'APP-084', add_check_ids: ['l7.http2_continuation.readiness'], target_tier: 'E3' },
  { registry_id: 'APP-085', add_check_ids: ['l7.http2_continuation.readiness'], target_tier: 'E3' },
  { registry_id: 'APP-090', add_check_ids: ['l7.http2_continuation.readiness'], target_tier: 'E3' },
  { registry_id: 'APP-091', add_check_ids: ['l7.http2_continuation.readiness'], target_tier: 'E3' },
  // HTTP/3 frame / QPACK vectors -> Alt-Svc observation only (E2), not semantic frame evidence.
  { registry_id: 'APP-196', add_check_ids: ['protocol.http3_control_stream.readiness'], target_tier: 'E2' },
  { registry_id: 'APP-197', add_check_ids: ['protocol.http3_control_stream.readiness'], target_tier: 'E2' },
  // Declared-encoding / declared-size acceptance posture -> new l7_resource_posture_probe (E3).
  { registry_id: 'APP-033', add_check_ids: ['l7.compressed_request_decompression.posture'], target_tier: 'E3' },
  { registry_id: 'APP-025', add_check_ids: ['l7.request_parser_size.posture'], target_tier: 'E3' },
  // Denial-of-wallet / cost exhaustion -> existing declared cost-guardrail posture (E1).
  { registry_id: 'APP-135', add_check_ids: ['ops.autoscaling_cost.readiness'], target_tier: 'E1' },
  { registry_id: 'APP-137', add_check_ids: ['ops.autoscaling_cost.readiness'], target_tier: 'E1' },
]);

// E4 reclassification. governed_scenario_family is a valid GOVERNED_SCENARIO_FAMILIES id, or
// null where the class (bomb / exploit / parser) has no flood analog and is the execution-only
// remainder of its exhausted_resource family. AstraNull never builds the generator or payload.
export const PROPOSED_TIER_RECLASSIFICATION = Object.freeze([
  { registry_id: 'APP-004', target_tier: 'E4', exhausted_resource: 'application_l7', governed_scenario_family: 'http_post_flood', reason: 'State-changing PUT/PATCH/DELETE method flood; governed L7 write flood, no in-repo generator.' },
  { registry_id: 'APP-012', target_tier: 'E4', exhausted_resource: 'application_l7', governed_scenario_family: 'http_get_flood', reason: 'Large-response request flood (response amplification); governed L7 flood.' },
  { registry_id: 'APP-023', target_tier: 'E4', exhausted_resource: 'application_l7', governed_scenario_family: null, reason: 'HTTP request-smuggling availability requires crafted ambiguous/desynchronising requests AstraNull must never emit; offensive parser-desync validation is SOC/lab-only.' },
  { registry_id: 'APP-026', target_tier: 'E4', exhausted_resource: 'application_l7', governed_scenario_family: 'http_get_flood', reason: 'Error-log write exhaustion driven by request volume; governed L7 flood.' },
  { registry_id: 'APP-028', target_tier: 'E4', exhausted_resource: 'computational', governed_scenario_family: null, reason: 'Hash-collision DoS needs a crafted collision payload set; no collision generator in repo — governed/lab-only.' },
  { registry_id: 'APP-029', target_tier: 'E4', exhausted_resource: 'computational', governed_scenario_family: null, reason: 'Pathological sort/filter needs a crafted worst-case input payload; governed/lab-only.' },
  { registry_id: 'APP-032', target_tier: 'E4', exhausted_resource: 'computational', governed_scenario_family: null, reason: 'External-entity/resource-fetch exhaustion (XXE) needs a malicious entity/SSRF payload; offensive, SOC/lab-only.' },
  { registry_id: 'APP-034', target_tier: 'E4', exhausted_resource: 'memory_exhaustion', governed_scenario_family: null, reason: 'Image decompression/pixel bomb requires a real bomb file; no bomb generator — governed/lab-only.' },
  { registry_id: 'APP-035', target_tier: 'E4', exhausted_resource: 'memory_exhaustion', governed_scenario_family: null, reason: 'Document/archive processing exhaustion requires a real document/archive bomb; governed/lab-only.' },
  { registry_id: 'APP-036', target_tier: 'E4', exhausted_resource: 'computational', governed_scenario_family: null, reason: 'Server-side template rendering exhaustion needs a template-injection payload; offensive, SOC/lab-only.' },
  { registry_id: 'APP-037', target_tier: 'E4', exhausted_resource: 'memory_exhaustion', governed_scenario_family: null, reason: 'Deserialization resource-exhaustion needs a crafted deserialization payload; offensive, SOC/lab-only.' },
  { registry_id: 'APP-038', target_tier: 'E4', exhausted_resource: 'memory_exhaustion', governed_scenario_family: null, reason: 'Mass object-binding needs a large crafted binding payload; governed/lab-only.' },
  { registry_id: 'APP-039', target_tier: 'E4', exhausted_resource: 'memory_exhaustion', governed_scenario_family: 'app_connection_exhaustion', reason: 'Session-object memory exhaustion requires many stateful sessions at scale; governed.' },
  { registry_id: 'APP-041', target_tier: 'E4', exhausted_resource: 'memory_exhaustion', governed_scenario_family: null, reason: 'Memory-leak trigger requires a sustained triggering flood; governed, no in-repo generator.' },
  { registry_id: 'APP-044', target_tier: 'E4', exhausted_resource: 'backend_exhaustion', governed_scenario_family: 'database_exhaustion', reason: 'Hot-key/lock-contention requires concentrated contention load on a backend key; governed backend flood.' },
  { registry_id: 'APP-045', target_tier: 'E4', exhausted_resource: 'backend_exhaustion', governed_scenario_family: null, reason: 'Job/message/task queue flood requires sustained queue-saturation load; governed, no in-repo generator.' },
  { registry_id: 'APP-046', target_tier: 'E4', exhausted_resource: 'application_l7', governed_scenario_family: 'http_get_flood', reason: 'Retry storm is a retry-amplification flood; governed L7 flood.' },
  { registry_id: 'APP-047', target_tier: 'E4', exhausted_resource: 'application_l7', governed_scenario_family: 'cache_busting_at_scale', reason: 'Cache stampede/thundering-herd requires concurrent cache-miss load at scale; governed L7 flood.' },
  { registry_id: 'APP-049', target_tier: 'E4', exhausted_resource: 'backend_exhaustion', governed_scenario_family: null, reason: 'Recursive/cyclic service-call exhaustion needs a crafted recursive call-graph payload; governed/lab-only.' },
  { registry_id: 'APP-057', target_tier: 'E4', exhausted_resource: 'backend_exhaustion', governed_scenario_family: 'database_exhaustion', reason: 'N+1 ORM object-expansion multiplies backend queries under load; governed backend flood.' },
  { registry_id: 'APP-060', target_tier: 'E4', exhausted_resource: 'backend_exhaustion', governed_scenario_family: 'database_exhaustion', reason: 'Federated identity-provider exhaustion is a dependency flood; governed.' },
  { registry_id: 'APP-067', target_tier: 'E4', exhausted_resource: 'backend_exhaustion', governed_scenario_family: 'graphql_depth_at_scale', reason: 'GraphQL subscription exhaustion is a subscription/backend fan-out flood; governed.' },
  { registry_id: 'APP-071', target_tier: 'E4', exhausted_resource: 'memory_exhaustion', governed_scenario_family: null, reason: 'gRPC decompression exhaustion requires a real decompression bomb; no bomb generator — governed/lab-only.' },
  { registry_id: 'APP-075', target_tier: 'E4', exhausted_resource: 'state_exhaustion', governed_scenario_family: 'app_connection_exhaustion', reason: 'WebSocket broadcast/room fan-out needs many concurrent WS sessions to force amplification; governed connection flood.' },
  { registry_id: 'APP-076', target_tier: 'E4', exhausted_resource: 'memory_exhaustion', governed_scenario_family: null, reason: 'WebSocket compression exhaustion requires a real permessage-deflate bomb; governed/lab-only.' },
  { registry_id: 'APP-117', target_tier: 'E4', exhausted_resource: 'state_exhaustion', governed_scenario_family: 'app_connection_exhaustion', reason: 'SMTP mail-queue/backscatter is a non-HTTP command/connection flood; governed.' },
  { registry_id: 'APP-118', target_tier: 'E4', exhausted_resource: 'state_exhaustion', governed_scenario_family: 'app_connection_exhaustion', reason: 'IMAP/POP mailbox auth/command flood is a non-HTTP service flood; governed.' },
  { registry_id: 'APP-119', target_tier: 'E4', exhausted_resource: 'state_exhaustion', governed_scenario_family: 'app_connection_exhaustion', reason: 'LDAP bind flood is a non-HTTP service flood; governed.' },
  { registry_id: 'APP-120', target_tier: 'E4', exhausted_resource: 'backend_exhaustion', governed_scenario_family: 'database_exhaustion', reason: 'LDAP expensive-search exhaustion is a directory backend flood; governed.' },
  { registry_id: 'APP-124', target_tier: 'E4', exhausted_resource: 'state_exhaustion', governed_scenario_family: 'app_connection_exhaustion', reason: 'AMQP connection/channel exhaustion is a non-HTTP service flood; governed.' },
  { registry_id: 'APP-125', target_tier: 'E4', exhausted_resource: 'state_exhaustion', governed_scenario_family: 'app_connection_exhaustion', reason: 'AMQP queue/routing/message flood is a non-HTTP service flood; governed.' },
  { registry_id: 'APP-127', target_tier: 'E4', exhausted_resource: 'state_exhaustion', governed_scenario_family: 'app_connection_exhaustion', reason: 'RDP connection/auth flood is a non-HTTP service flood; governed.' },
  { registry_id: 'APP-129', target_tier: 'E4', exhausted_resource: 'state_exhaustion', governed_scenario_family: 'app_connection_exhaustion', reason: 'SMB/NFS file-service operation flood is a non-HTTP service flood; governed.' },
  { registry_id: 'APP-132', target_tier: 'E4', exhausted_resource: 'application_l7', governed_scenario_family: 'http_get_flood', reason: 'Media segment/transcode request flood; governed L7 flood.' },
  { registry_id: 'APP-134', target_tier: 'E4', exhausted_resource: 'application_l7', governed_scenario_family: 'http_post_flood', reason: 'SOAP/RPC operation flood; governed L7 flood.' },
  { registry_id: 'APP-140', target_tier: 'E4', exhausted_resource: 'application_l7', governed_scenario_family: 'http_get_flood', reason: 'Error-page/exception-generation flood; governed L7 flood.' },
  { registry_id: 'APP-143', target_tier: 'E4', exhausted_resource: 'backend_exhaustion', governed_scenario_family: 'database_exhaustion', reason: 'Third-party API fan-out/quota exhaustion is a dependency flood; governed.' },
  { registry_id: 'APP-145', target_tier: 'E4', exhausted_resource: 'backend_exhaustion', governed_scenario_family: 'database_exhaustion', reason: 'ML/LLM inference exhaustion is an expensive-backend flood; governed.' },
  { registry_id: 'APP-146', target_tier: 'E4', exhausted_resource: 'memory_exhaustion', governed_scenario_family: null, reason: 'Document/archive/image/media processing flood requires real heavy-processing payloads at volume; governed/lab-only.' },
  { registry_id: 'APP-147', target_tier: 'E4', exhausted_resource: 'backend_exhaustion', governed_scenario_family: null, reason: 'URL preview/crawler/SSRF fan-out exhaustion requires SSRF/fan-out payloads; offensive, SOC/lab-only.' },
  { registry_id: 'APP-148', target_tier: 'E4', exhausted_resource: 'application_l7', governed_scenario_family: 'http_post_flood', reason: 'Account-lockout denial is a credential-submission flood; governed and state-changing, must never lock real accounts.' },
  { registry_id: 'APP-152', target_tier: 'E4', exhausted_resource: 'exploit_dos', governed_scenario_family: null, reason: 'Crash/hang/deadlock/infinite-loop trigger is exploit-triggered availability; validation is isolated-lab SOC scope only.' },
  { registry_id: 'APP-185', target_tier: 'E4', exhausted_resource: 'packet_processing', governed_scenario_family: 'sip_flood', reason: 'Malformed SIP message flood; governed SIP scenario.' },
  { registry_id: 'APP-186', target_tier: 'E4', exhausted_resource: 'computational', governed_scenario_family: 'sip_flood', reason: 'SIP URI-length/field-count exhaustion via crafted oversize messages at volume; governed.' },
  { registry_id: 'APP-187', target_tier: 'E4', exhausted_resource: 'memory_exhaustion', governed_scenario_family: null, reason: 'HTTP/2 Bomb composite memory exhaustion requires a real multi-frame bomb; no bomb generator — governed/lab-only.' },
  { registry_id: 'APP-188', target_tier: 'E4', exhausted_resource: 'amplification', governed_scenario_family: null, reason: 'HTTP/3-to-HTTP/1.1 bandwidth amplification requires generating amplified downgrade traffic toward a victim; never emitted — governed.' },
  { registry_id: 'APP-189', target_tier: 'E4', exhausted_resource: 'state_exhaustion', governed_scenario_family: 'app_connection_exhaustion', reason: 'HTTP/3-to-HTTP/1.1 connection amplification opens many downgraded H1 connections; governed.' },
  { registry_id: 'APP-190', target_tier: 'E4', exhausted_resource: 'application_l7', governed_scenario_family: 'http_post_flood', reason: 'HTML5 ping-attribute browser fan-out flood is a distributed L7 flood; governed.' },
  { registry_id: 'APP-191', target_tier: 'E4', exhausted_resource: 'computational', governed_scenario_family: 'tls_handshake_exhaustion', reason: 'TLS session-resumption/ticket-validation flood is a crypto-CPU flood; governed.' },
  { registry_id: 'APP-194', target_tier: 'E4', exhausted_resource: 'application_l7', governed_scenario_family: 'http_post_flood', reason: 'Cache purge/invalidation CDN control-API flood; governed.' },
  { registry_id: 'APP-198', target_tier: 'E4', exhausted_resource: 'computational', governed_scenario_family: 'tls_handshake_exhaustion', reason: 'Fragmented TLS ClientHello quadratic reassembly needs a crafted fragmented handshake payload; offensive parser payload, governed/lab-only.' },
  { registry_id: 'APP-199', target_tier: 'E4', exhausted_resource: 'memory_exhaustion', governed_scenario_family: null, reason: 'STOMP unbounded-header-count memory exhaustion needs a crafted non-HTTP parser payload; governed/lab-only.' },
  { registry_id: 'APP-200', target_tier: 'E4', exhausted_resource: 'memory_exhaustion', governed_scenario_family: null, reason: 'Redis unterminated length-line decoder exhaustion needs a crafted non-HTTP decoder payload; governed/lab-only.' },
  { registry_id: 'APP-201', target_tier: 'E4', exhausted_resource: 'computational', governed_scenario_family: null, reason: 'Incremental XML rescanning CPU exhaustion needs a crafted trickle-fed XML payload; governed/lab-only.' },
]);
