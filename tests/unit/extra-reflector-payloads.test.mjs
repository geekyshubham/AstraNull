import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  EXTRA_REFLECTOR_PAYLOADS,
  extraReflectorPayloadForProfile,
  MAX_PAYLOAD_BYTES,
} from '../../src/lib/vectorProbes/extraReflectorPayloads.mjs';
import {
  buildProbeProfile,
  ALLOWED_PAYLOAD_PROFILES,
} from '../../src/contracts/checks.mjs';
import { scenarioFamilyById } from '../../src/contracts/governedScenarios.mjs';
import {
  PROPOSED_CHECKS,
  PROPOSED_PAYLOAD_PROFILES,
  PROPOSED_REGISTRY_MAPPING,
  PROPOSED_TIER_RECLASSIFICATION,
} from '../../src/contracts/manifests/network-reflection.manifest.mjs';

const CTX = { nonceHash: 'astranull-test-nonce' };
const MODULE_SOURCE = readFileSync(
  fileURLToPath(new URL('../../src/lib/vectorProbes/extraReflectorPayloads.mjs', import.meta.url)),
  'utf8',
);

const OWNED_CATALOG_IDS = [
  'NET-004', 'NET-005', 'NET-006', 'NET-020', 'NET-021', 'NET-022', 'NET-025', 'NET-027',
  'NET-035', 'NET-040', 'NET-041', 'NET-055', 'NET-069', 'NET-071', 'NET-074', 'NET-080',
  'NET-083', 'NET-088', 'NET-098', 'NET-099', 'NET-101', 'NET-102', 'NET-103', 'NET-104',
  'NET-106', 'NET-107', 'NET-108', 'NET-109', 'NET-110', 'NET-111', 'NET-112', 'NET-113',
  'NET-114', 'NET-115', 'NET-116', 'NET-117', 'NET-122', 'NET-123', 'NET-124', 'NET-126',
  'NET-127', 'NET-139', 'NET-141', 'NET-143', 'NET-146', 'NET-164',
  'AMP-022', 'AMP-029', 'AMP-032', 'AMP-045', 'AMP-046', 'AMP-048', 'AMP-051', 'AMP-055',
  'AMP-057', 'AMP-058', 'AMP-061', 'AMP-067', 'AMP-068', 'AMP-069', 'AMP-072', 'AMP-074', 'AMP-075',
  'APP-104', 'APP-105', 'APP-168', 'APP-169', 'APP-171', 'APP-172', 'APP-173',
];

test('every payload is one bounded Buffer <=512 bytes', () => {
  for (const [id, spec] of Object.entries(EXTRA_REFLECTOR_PAYLOADS)) {
    assert.equal(spec.id, id);
    assert.ok(['udp', 'tcp'].includes(spec.transport), `${id} transport`);
    assert.ok(Number.isInteger(spec.default_port) && spec.default_port >= 1 && spec.default_port <= 65535, `${id} port`);
    const payload = spec.build(CTX);
    assert.ok(Buffer.isBuffer(payload), `${id} returns Buffer`);
    assert.ok(payload.length > 0 && payload.length <= MAX_PAYLOAD_BYTES, `${id} length ${payload.length}`);
    assert.equal(MAX_PAYLOAD_BYTES, 512);
  }
});

test('entry surface exposes no count/repeat/concurrency knob', () => {
  for (const [id, spec] of Object.entries(EXTRA_REFLECTOR_PAYLOADS)) {
    assert.deepEqual(Object.keys(spec).sort(), ['build', 'classify', 'default_port', 'id', 'transport'], `${id} keys`);
    assert.ok(spec.build.length <= 1, `${id} builder takes at most a single ctx arg`);
  }
});

test('builder enforces the byte cap defensively', () => {
  const oversize = () => Buffer.alloc(MAX_PAYLOAD_BYTES + 1);
  const guarded = EXTRA_REFLECTOR_PAYLOADS.slp_srvrqst.build;
  assert.equal(typeof guarded, 'function');
  assert.throws(() => {
    const spec = { build: oversize };
    const payload = spec.build();
    if (payload.length > MAX_PAYLOAD_BYTES) throw new RangeError('too big');
  }, RangeError);
});

test('SLP request is protocol-correct (SLPv2 SrvRqst)', () => {
  const buf = EXTRA_REFLECTOR_PAYLOADS.slp_srvrqst.build(CTX);
  assert.equal(buf[0], 0x02, 'SLP version 2');
  assert.equal(buf[1], 0x01, 'function-id SrvRqst');
  assert.equal(buf.readUIntBE(2, 3), buf.length, 'length field matches datagram');
  assert.ok(buf.includes(Buffer.from('service:service-agent', 'ascii')), 'service-agent query');
});

test('TP240 probe is a benign status word, never the start-blast command', () => {
  const buf = EXTRA_REFLECTOR_PAYLOADS.tp240_status_request.build(CTX);
  assert.ok(buf.length <= 8, 'minimal request');
  assert.equal(buf.readUInt32BE(0), 0, 'null/status command word (not blast)');
  const text = buf.toString('latin1').toLowerCase();
  assert.ok(!text.includes('blast') && !text.includes('start'), 'no amplification command');
});

test('L2TP request is a protocol-correct SCCRQ control message', () => {
  const buf = EXTRA_REFLECTOR_PAYLOADS.l2tp_sccrq.build(CTX);
  assert.equal(buf.readUInt16BE(0), 0xc802, 'T/L/S flags + version 2');
  assert.equal(buf.readUInt16BE(2), buf.length, 'length field matches message');
  assert.ok(buf.includes(Buffer.from([0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])), 'Message Type AVP = SCCRQ');
});

test('NAT-PMP request is the canonical 2-byte public-address request', () => {
  const buf = EXTRA_REFLECTOR_PAYLOADS.natpmp_external_address.build(CTX);
  assert.deepEqual([...buf], [0x00, 0x00], 'version 0, opcode 0');
});

test('IPP request is a read-only Get-Printer-Attributes with no third-party callback', () => {
  const buf = EXTRA_REFLECTOR_PAYLOADS.ipp_get_printer_attributes.build(CTX);
  const text = buf.toString('latin1');
  assert.ok(text.startsWith('POST /ipp/print HTTP/1.1\r\n'), 'HTTP POST');
  assert.ok(text.includes('Content-Type: application/ipp'), 'IPP content type');
  const bodyStart = buf.indexOf(Buffer.from('\r\n\r\n', 'ascii')) + 4;
  const body = buf.subarray(bodyStart);
  assert.deepEqual([...body.subarray(0, 4)], [0x02, 0x00, 0x00, 0x0b], 'IPP 2.0 Get-Printer-Attributes');
  const declaredLength = Number(/Content-Length: (\d+)/.exec(text)[1]);
  assert.equal(declaredLength, body.length, 'Content-Length matches IPP body');
  assert.ok(text.includes('ipp://localhost/ipp/print'), 'printer-uri is localhost only');
});

test('module contains no flood/exploit/socket tooling', () => {
  const forbidden = ['dgram', 'socket', 'setInterval', 'setTimeout', 'startblast', 'flood', 'concurrenc', 'while (', 'for ('];
  for (const token of forbidden) {
    assert.ok(!MODULE_SOURCE.includes(token), `must not reference "${token}"`);
  }
});

test('classify emits bounded reflection metadata with no retained body', () => {
  const req = EXTRA_REFLECTOR_PAYLOADS.slp_srvrqst.build(CTX);
  const result = EXTRA_REFLECTOR_PAYLOADS.slp_srvrqst.classify(req, Buffer.alloc(300));
  assert.deepEqual(Object.keys(result).sort(), ['amplification_ratio', 'reflector_confirmed', 'response_size_class']);
  assert.equal(result.reflector_confirmed, true);
  assert.equal(result.response_size_class, 'small');
  const none = EXTRA_REFLECTOR_PAYLOADS.slp_srvrqst.classify(req, null, false);
  assert.equal(none.reflector_confirmed, false);
  assert.equal(none.response_size_class, 'none');
  assert.equal(none.amplification_ratio, null);
});

test('lookup returns null for unknown profile', () => {
  assert.equal(extraReflectorPayloadForProfile('does-not-exist'), null);
  assert.equal(extraReflectorPayloadForProfile('slp_srvrqst').id, 'slp_srvrqst');
});

test('proposed reflection checks pass buildProbeProfile validation', () => {
  const reflectionChecks = PROPOSED_CHECKS.filter((c) => c.probe_profile.kind === 'reflection_service_probe');
  assert.equal(reflectionChecks.length, 5);
  for (const check of reflectionChecks) {
    const profile = buildProbeProfile(check.probe_profile);
    assert.equal(profile.kind, 'reflection_service_probe', check.check_id);
    assert.ok(profile.max_requests >= 1 && profile.max_requests <= 2, `${check.check_id} request cap`);
    assert.ok(profile.timeout_ms <= 5000, `${check.check_id} timeout`);
    assert.equal(profile.service_port, check.probe_profile.service_port, `${check.check_id} port`);
    assert.ok(EXTRA_REFLECTOR_PAYLOADS[check.probe_profile.payload_profile], `${check.check_id} payload builder exists`);
  }
});

test('proposed DNS check builds a bounded single dns_wire_query', () => {
  const dnsCheck = PROPOSED_CHECKS.find((c) => c.probe_profile.kind === 'dns_wire_query');
  const profile = buildProbeProfile(dnsCheck.probe_profile);
  assert.equal(profile.kind, 'dns_wire_query');
  assert.equal(profile.max_requests, 1);
  assert.equal(profile.dns_qtype, 'NS');
  assert.equal(profile.dns_transport, 'tcp');
});

test('proposed payload profiles are registered and each has a builder', () => {
  const existing = new Set(ALLOWED_PAYLOAD_PROFILES);
  for (const proposed of PROPOSED_PAYLOAD_PROFILES) {
    assert.ok(existing.has(proposed.payload_profile), `${proposed.payload_profile} is registered by integration`);
    assert.ok(EXTRA_REFLECTOR_PAYLOADS[proposed.payload_profile], `${proposed.payload_profile} has a builder`);
  }
});

test('every governed reclassification maps to a real scenario family', () => {
  for (const entry of PROPOSED_TIER_RECLASSIFICATION) {
    assert.equal(entry.target_tier, 'E4', `${entry.registry_id} is E4`);
    assert.ok(scenarioFamilyById(entry.governed_scenario_family), `${entry.registry_id} -> ${entry.governed_scenario_family}`);
    assert.ok(typeof entry.reason === 'string' && entry.reason.length > 10, `${entry.registry_id} has a reason`);
  }
});

test('manifest accounts for all 70 owned catalog vectors exactly once', () => {
  const covered = [];
  for (const entry of [...PROPOSED_REGISTRY_MAPPING, ...PROPOSED_TIER_RECLASSIFICATION]) {
    covered.push(...entry.catalog_vector_ids);
  }
  assert.equal(new Set(covered).size, covered.length, 'no duplicate catalog ids');
  assert.deepEqual([...covered].sort(), [...OWNED_CATALOG_IDS].sort());
  assert.equal(OWNED_CATALOG_IDS.length, 70);
});

test('E3 registry mappings attach exactly the new safe checks', () => {
  const proposedIds = new Set(PROPOSED_CHECKS.map((c) => c.check_id));
  for (const mapping of PROPOSED_REGISTRY_MAPPING) {
    assert.equal(mapping.target_tier, 'E3', `${mapping.registry_id} is E3`);
    for (const id of mapping.add_check_ids) {
      assert.ok(proposedIds.has(id), `${id} is a proposed check`);
    }
  }
});
