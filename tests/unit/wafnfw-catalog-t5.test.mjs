import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  CHECK_CATALOG,
  MAX_REQUESTS_BY_PROBE_KIND,
  checkRequiresAdditionalInput,
  getCheckById,
  validateCheckDefinition,
} from '../../src/contracts/checks.mjs';

const NEW_IDS = [
  'waf.sqli_managed_marker.safe',
  'waf.xss_managed_marker.safe',
  'waf.path_traversal_managed_marker.safe',
  'waf.ssti_marker.safe',
  'waf.scanner_signature_marker.safe',
  'waf.evasion_double_url.safe',
  'waf.evasion_mixed_url.safe',
  'waf.evasion_case_fold.safe',
  'waf.http_method_policy_enforced.safe',
  'waf.rate_limit_canary.validation',
  'waf.body_json_marker.soc',
  'waf.body_form_marker.soc',
  'waf.body_multipart_marker.soc',
  'waf.body_inspection_limit.soc',
  'waf.response_dlp_canary.soc',
  'nfw.declared_deny_tcp.safe',
  'nfw.declared_deny_udp.safe',
  'nfw.management_port_exposure.safe',
  'nfw.ipv6_parity.safe',
  'nfw.connection_limit.safe',
  'nfw.origin_lockdown.safe',
  'nfw.perspective_allowlist.safe',
];

describe('T5 WAF/NFW catalog', () => {
  it('keeps unique ids and a 275-definition catalog', () => {
    assert.equal(CHECK_CATALOG.length, 275);
    assert.equal(new Set(CHECK_CATALOG.map((row) => row.check_id)).size, 275);
  });

  it('validates every new check against the catalog schema', () => {
    for (const id of NEW_IDS) {
      const check = getCheckById(id);
      assert.ok(check, id);
      assert.deepEqual(validateCheckDefinition(check), [], id);
    }
  });

  it('renames opaque class-markers to Custom Canary Rule and keeps ids stable', () => {
    const renamed = CHECK_CATALOG.filter((check) => (
      check.probe_profile?.kind === 'waf_class_marker_probe'
      && check.probe_profile?.assurance_scope === 'custom_canary_rule'
    ));
    assert.ok(renamed.length >= 14);
    for (const check of renamed) {
      assert.match(check.name, /^Custom Canary Rule:/);
      assert.match(check.description, /inert/);
      assert.equal(check.rule_family, 'custom_canary');
      assert.doesNotMatch(check.verdict_logic, /attack-class protection/i);
    }
    assert.equal(getCheckById('waf.http_method_policy_marker.safe').check_id, 'waf.http_method_policy_marker.safe');
  });

  it('treats SQLi/XSS/path-traversal as managed markers and SSTI as a custom canary', () => {
    const sqli = getCheckById('waf.sqli_managed_marker.safe');
    assert.equal(sqli.rule_family, 'managed');
    assert.equal(sqli.probe_profile.assurance_scope, 'managed_rule_marker');
    assert.equal(sqli.probe_profile.marker_class, 'sqli');
    const ssti = getCheckById('waf.ssti_marker.safe');
    assert.equal(ssti.rule_family, 'custom_canary');
    assert.equal(ssti.probe_profile.assurance_scope, 'custom_canary_rule');
    assert.match(ssti.probe_profile.marker, /astranull-ssti/);
  });

  it('keeps SOC body checks gated with no probe_profile', () => {
    for (const id of ['waf.body_json_marker.soc', 'waf.body_form_marker.soc', 'waf.body_multipart_marker.soc', 'waf.body_inspection_limit.soc', 'waf.response_dlp_canary.soc']) {
      const check = getCheckById(id);
      assert.equal(check.safety_class, 'soc_gated');
      assert.equal(check.probe_profile, undefined);
      assert.ok(check.required_customer_setup.includes('canary_sink'));
      assert.equal(check.planner_profile.kind, 'canary_sink_body_plan');
    }
  });

  it('marks port-less TCP/UDP checks not runnable without a port', () => {
    for (const id of ['l3.tcp_flag_anomaly.readiness', 'l3.tcp_connection_flood.readiness', 'reflect.tcp_middlebox_exposure.safe']) {
      const check = getCheckById(id);
      assert.equal(check.mechanism_supported, false, id);
      assert.equal(checkRequiresAdditionalInput(check), true, id);
    }
    assert.equal(getCheckById('l3.ssh_connection_flood.readiness').probe_profile.default_port, 22);
    assert.equal(getCheckById('l3.smtp_connection_flood.readiness').probe_profile.default_port, 25);
    assert.equal(getCheckById('l3.ftp_connection_flood.readiness').probe_profile.default_port, 21);
    assert.equal(getCheckById('reflect.redis_direct_exposure.safe').probe_profile.default_port, 6379);
    assert.equal(getCheckById('l3.sip_voip_flood.readiness').probe_profile.default_port, 5060);
  });

  it('names composite reflection checks after the payloads T2 actually sends', () => {
    const mdns = getCheckById('reflect.mdns_netbios_wsdiscovery_exposure.safe');
    assert.match(mdns.name, /mDNS/);
    assert.match(mdns.name, /NetBIOS/);
    assert.match(mdns.name, /WS-Discovery/);
    assert.deepEqual(mdns.probe_profile.payload_profiles, ['mdns_ptr_query', 'netbios_nbstat', 'ws_discovery_probe']);
    assert.equal(mdns.probe_profile.max_requests, 4);
    const dtls = getCheckById('reflect.dtls_sip_rdp_tftp_exposure.safe');
    assert.match(dtls.name, /DTLS/);
    assert.match(dtls.name, /SIP/);
    assert.deepEqual(dtls.probe_profile.payload_profiles, ['tftp_read_request', 'dtls_client_hello', 'sip_options', 'rdp_udp_syn']);
    assert.equal(dtls.probe_profile.max_requests, 4);
  });

  it('raises wave-1 per-kind budgets and keeps connection_limit_probe at 12', () => {
    assert.equal(MAX_REQUESTS_BY_PROBE_KIND.tcp_connect, 2);
    assert.equal(MAX_REQUESTS_BY_PROBE_KIND.udp_probe, 2);
    assert.equal(MAX_REQUESTS_BY_PROBE_KIND.reflection_service_probe, 4);
    assert.equal(MAX_REQUESTS_BY_PROBE_KIND.dns_axfr_leak, 5);
    assert.equal(MAX_REQUESTS_BY_PROBE_KIND.connection_limit_probe, 12);
    assert.equal(getCheckById('nfw.connection_limit.safe').probe_profile.max_requests, 12);
    assert.equal(getCheckById('dns.zone_transfer_exposure.safe').probe_profile.max_requests, 5);
    assert.equal(checkRequiresAdditionalInput(getCheckById('waf.http_method_policy_enforced.safe')), false);
    assert.equal(checkRequiresAdditionalInput(getCheckById('nfw.origin_lockdown.safe')), true);
    assert.equal(checkRequiresAdditionalInput(getCheckById('nfw.perspective_allowlist.safe')), true);
  });

  it('does not add RFI or CVE virtual-patching self-serve checks', () => {
    assert.equal(CHECK_CATALOG.some((check) => /rfi/i.test(check.check_id) && check.safety_class === 'safe'), false);
    assert.equal(CHECK_CATALOG.some((check) => /virtual.?patch/i.test(check.check_id)), false);
  });
});
