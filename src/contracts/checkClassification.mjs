/**
 * Presentation-only classification of a check by the network layer it exercises and the protection control it tests.
 * Derived at read time from vector_family, probe kind and check id; never stored on catalog entries (that would change definition digests).
 */
export const CHECK_PROTECTION_CONTROLS = Object.freeze({
  waf: Object.freeze({ id: 'waf', short: 'WAF', label: 'web application firewall' }),
  network_firewall: Object.freeze({ id: 'network_firewall', short: 'NFW', label: 'network firewall' }),
  cdn_edge: Object.freeze({ id: 'cdn_edge', short: 'Edge', label: 'CDN or edge proxy' }),
  ddos: Object.freeze({ id: 'ddos', short: 'DDoS', label: 'DDoS mitigation service' }),
  dns_provider: Object.freeze({ id: 'dns_provider', short: 'DNS', label: 'DNS provider' }),
});

const layer = (osi, protocol = null) => Object.freeze({ osi, protocol, label: protocol ? `${osi} · ${protocol}` : osi });

const L3_IP = layer('L3', 'IP');
const L4_TCP = layer('L4', 'TCP');
const L4_UDP = layer('L4', 'UDP');
const L3_L4 = layer('L3/L4');
const L7_HTTP = layer('L7', 'HTTP');
const L7_DNS = layer('L7', 'DNS');

const KIND_LAYERS = Object.freeze({
  tcp_connect: L4_TCP,
  port_scan_bounded: L4_TCP,
  udp_probe: L4_UDP,
  reflection_service_probe: L4_UDP,
  quic_reachability: layer('L7', 'HTTP (Alt-Svc observation)'),
  dns_wire_query: L7_DNS,
  dns_open_recursion: L7_DNS,
  dnssec_posture: L7_DNS,
  dns_failover_posture: L7_DNS,
  dns_axfr_leak: L7_DNS,
  tls_audit: layer('L6', 'TLS'),
  tls_session: layer('L6', 'TLS'),
  http2_settings: layer('L7', 'HTTP/2'),
  http2_frame_probe: layer('L7', 'HTTP/2'),
  http3_control_probe: layer('L7', 'HTTP/3'),
  grpc_reflection_probe: layer('L7', 'gRPC'),
  websocket_upgrade_posture: layer('L7', 'WebSocket'),
  graphql_posture_probe: layer('L7', 'GraphQL'),
});

const ID_LAYER_HINTS = Object.freeze([
  [/(icmp|gre_esp|ipv6_volumetric|multicast|fragmentation|ping_of_death|teardrop|ip_options|land_attack|spoofed_source)/, L3_IP],
  [/(syn_flood|syn_ack|ack_flood|rst_flood|out_of_state_tcp|connection_table|nat_state)/, L4_TCP],
  [/sctp/, layer('L4', 'SCTP')],
  [/ike_ipsec/, L4_UDP],
  [/(quic)/, layer('L7', 'HTTP (Alt-Svc observation)')],
  [/(carpet_bombing|pulse_wave|volumetric)/, L3_L4],
  [/(dns_high_query)/, L7_DNS],
  [/(multi_vector)/, layer('L3–L7')],
  [/(http2)/, layer('L7', 'HTTP/2')],
  [/(http3)/, layer('L7', 'HTTP/3')],
  [/(websocket)/, layer('L7', 'WebSocket')],
  [/(sse_stream)/, layer('L7', 'SSE')],
  [/(rate_limit_evasion|adaptive_evasion|residential_proxy|application)/, L7_HTTP],
]);

const FAMILY_LAYERS = Object.freeze({
  l3_l4: L3_L4,
  reflection: L3_L4,
  amplification: L3_L4,
  dns: L7_DNS,
  tls: layer('L6', 'TLS'),
  protocol: L7_HTTP,
  l7: L7_HTTP,
  waf: L7_HTTP,
  path: L7_HTTP,
  origin: L7_HTTP,
});

const FAMILY_CONTROLS = Object.freeze({
  l3_l4: ['network_firewall'],
  reflection: ['network_firewall'],
  amplification: ['network_firewall'],
  dns: ['dns_provider'],
  tls: ['cdn_edge'],
  protocol: ['cdn_edge'],
  l7: ['waf'],
  waf: ['waf'],
  path: ['waf'],
  origin: ['cdn_edge', 'network_firewall'],
  high_scale: ['ddos'],
});

const WAF_KINDS = new Set([
  'waf_class_marker_probe',
  'waf_evasion_marker_probe',
  'waf_inspection_limit_probe',
  'waf_enforcement_probe',
  'waf_fingerprint_observation',
  'waf_method_policy_probe',
  'rate_limit_canary_probe',
]);
const EDGE_L7_ID = /(slowloris|slow_read|slow_post|low_and_slow|connection_hoarding|http2_rapid_reset|made_you_reset|continuation|hpack|push_promise|http2_priority)/;

function controlsFor(family, kind, checkId) {
  if (EDGE_L7_ID.test(checkId) && (family === 'l7' || family === 'protocol')) return ['cdn_edge'];
  if (WAF_KINDS.has(kind)) return ['waf'];
  if (family === 'exploit') return /quic/.test(checkId) ? ['cdn_edge'] : ['network_firewall'];
  if (family === 'pattern') return /(rate_limit_evasion|adaptive_evasion|residential_proxy)/.test(checkId) ? ['waf'] : ['ddos'];
  return FAMILY_CONTROLS[family] ?? [];
}

function layerFor(family, kind, checkId) {
  if (family === 'operations') return null;
  if (KIND_LAYERS[kind]) return KIND_LAYERS[kind];
  if (family === 'tls' && kind === 'slow_header_probe') return L7_HTTP;
  const hint = ID_LAYER_HINTS.find(([pattern]) => pattern.test(checkId));
  if (hint) return hint[1];
  return FAMILY_LAYERS[family] ?? null;
}

export function classifyCheck(check) {
  if (!check || typeof check !== 'object') return { layer: null, controls: [], declaration_only: false };
  const family = String(check.vector_family ?? '');
  const kind = String(check.probe_profile?.kind ?? check.request?.kind ?? '');
  const checkId = String(check.check_id ?? '');
  return {
    layer: layerFor(family, kind, checkId),
    controls: controlsFor(family, kind, checkId).map((id) => CHECK_PROTECTION_CONTROLS[id]),
    declaration_only: kind === 'metadata_marker',
  };
}

/** API projection fields: `layer` label, `protection_controls` ids, and `declaration_only`. */
export function checkClassificationFields(check) {
  const { layer: resolved, controls, declaration_only } = classifyCheck(check);
  return {
    layer: resolved?.label ?? null,
    protection_controls: controls.map((control) => control.id),
    declaration_only: declaration_only === true,
  };
}

export const CHECK_IMPACT_CLASSES = Object.freeze({
  non_invasive: Object.freeze({
    id: 'non_invasive',
    label: 'Non-invasive',
    summary: 'Ordinary, well-formed lookups or requests any client could send. No attack-shaped payloads and no pressure on connection state.',
  }),
  invasive: Object.freeze({
    id: 'invasive',
    label: 'Invasive',
    summary: 'Bounded, attack-shaped traffic: WAF markers, malformed or oversized requests, request bursts, held connections, scans or bypass attempts. It can trigger WAF, IDS or SOC alerts.',
  }),
});

const NON_INVASIVE_KINDS = new Set([
  'metadata_marker',
  'tcp_connect',
  'dns_wire_query',
  'dnssec_posture',
  'dns_failover_posture',
  'http_head',
  'tls_audit',
  'http2_settings',
  'quic_reachability',
  'ops_readiness',
  'alert_webhook_ping',
  'waf_fingerprint_observation',
  'cors_posture_probe',
  'websocket_upgrade_posture',
]);

const INVASIVE_FAMILIES = new Set(['amplification', 'reflection', 'exploit', 'high_scale']);

/** Presentation-only traffic impact: unknown kinds and SOC-gated or amplification-shaped checks fail safe to invasive. */
export function classifyCheckImpact(check) {
  if (!check || typeof check !== 'object') return CHECK_IMPACT_CLASSES.invasive;
  const family = String(check.vector_family ?? '');
  const kind = String(check.probe_profile?.kind ?? check.request?.kind ?? '');
  const checkId = String(check.check_id ?? '');
  if (kind === 'metadata_marker') return CHECK_IMPACT_CLASSES.non_invasive;
  if (check.safety_class === 'soc_gated' || INVASIVE_FAMILIES.has(family) || /(_any_|amplif)/.test(checkId)) return CHECK_IMPACT_CLASSES.invasive;
  return NON_INVASIVE_KINDS.has(kind) ? CHECK_IMPACT_CLASSES.non_invasive : CHECK_IMPACT_CLASSES.invasive;
}
