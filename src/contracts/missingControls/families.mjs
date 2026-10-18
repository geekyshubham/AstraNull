export const CONTROL_LAYERS = Object.freeze(['network', 'edge_waf', 'edge_cdn', 'dns', 'origin', 'operations']);

export const CONTROL_FAMILIES = Object.freeze({
  network_firewall_ingress: { label: 'Network firewall ingress rules', layer: 'network' },
  network_connection_limits: { label: 'Per-source connection limits', layer: 'network' },
  l3_l4_ddos_protection: { label: 'Network-layer DDoS protection', layer: 'network' },
  reflector_service_exposure: { label: 'Reflector/amplifier service exposure', layer: 'network' },
  waf_managed_rules: { label: 'WAF managed rule sets', layer: 'edge_waf' },
  waf_custom_rules: { label: 'WAF custom rules and block signature', layer: 'edge_waf' },
  waf_request_normalization: { label: 'WAF decoding and normalization', layer: 'edge_waf' },
  waf_body_inspection: { label: 'WAF request body inspection', layer: 'edge_waf' },
  waf_rate_limiting: { label: 'Rate-limiting rules', layer: 'edge_waf' },
  waf_bot_management: { label: 'Bot management and challenges', layer: 'edge_waf' },
  http_method_policy: { label: 'HTTP method allow-list', layer: 'edge_waf' },
  l7_request_limits: { label: 'HTTP request size and timeout limits', layer: 'edge_cdn' },
  cache_policy: { label: 'CDN cache-key and caching policy', layer: 'edge_cdn' },
  tls_configuration: { label: 'TLS configuration', layer: 'edge_cdn' },
  http2_http3_protection: { label: 'HTTP/2 and HTTP/3 protocol protections', layer: 'edge_cdn' },
  api_surface_protection: { label: 'API surface protection', layer: 'edge_waf' },
  origin_protection: { label: 'Origin lockdown', layer: 'origin' },
  dns_zone_transfer_restriction: { label: 'DNS zone transfer restriction', layer: 'dns' },
  dns_recursion_restriction: { label: 'DNS recursion restriction', layer: 'dns' },
  dns_ddos_resilience: { label: 'DNS DDoS resilience', layer: 'dns' },
  exploit_mitigation: { label: 'Vulnerability virtual patching', layer: 'edge_waf' },
  operations_readiness: { label: 'DDoS response operations readiness', layer: 'operations' },
  high_scale_ddos_validation: { label: 'Authorized high-scale DDoS validation', layer: 'operations' },
});

export const REMEDIATION_PROVIDERS = Object.freeze(['gcp', 'aws', 'azure', 'cloudflare', 'akamai', 'fastly', 'generic']);
