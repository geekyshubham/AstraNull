import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { verifyProbeJobSignature } from '../../src/lib/probeJobs.mjs';
import { CHECK_DELIVERY_INVENTORY, accountDeliveryReceipts, deliveryDisposition, deliveryFingerprint, deliveryMaterial } from '../fixtures/check-delivery-coverage.mjs';
import { createCheckDeliveryFixtures, executeMemoryDelivery, DELIVERY_WORKER_SECRET, assertOwnedProtocolReceipt } from '../helpers/check-delivery-fixtures.mjs';
import { assertExistingBehaviorCase } from '../helpers/existing-behavior-coverage.mjs';

const rows = new Map(CHECK_DELIVERY_INVENTORY.rows.map((row) => [row.check_id, row]));

describe('live catalog delivery accounting', () => {
  it('reconciles all definitions, vectors, default IDs, metadata declarations and kinds', () => {
    assert.deepEqual(CHECK_DELIVERY_INVENTORY.summary, {
      definitions: 273, vectors: 721, default_fqdn_safe_ids: 167, allowed_kinds: 44,
      distinct_delivery_fingerprints: 264,
      dispositions: { additional_target_input: 14, supported_observation: 92, additional_signed_scope: 1, governance_inline: 2, supported_semantic_safe: 39, soc_request_only: 22, declaration_only: 72, unsupported_delivery: 31 },
    });
    assert.equal(new Set(CHECK_DELIVERY_INVENTORY.rows.map((row) => row.check_id)).size, 273);
    for (const row of rows.values()) {
      assert.ok(row.delivery_material.supported_targets.length > 0);
      assert.ok(row.check_version && row.definition_digest && row.delivery_fingerprint);
      assert.deepEqual(row.delivery_material, deliveryMaterial(CHECK_CATALOG.find((c) => c.check_id === row.check_id)));
    }
    for (const alias of CHECK_DELIVERY_INVENTORY.aliases) {
      assert.ok(alias.check_ids.length > 1);
      for (const id of alias.check_ids) assert.equal(rows.get(id).delivery_fingerprint, alias.fingerprint);
    }
  });
  it('fingerprints every delivery field, not merely mechanism identity', () => {
    const base = CHECK_CATALOG.find((check) => check.probe_profile.kind === 'dns_wire_query');
    for (const key of Object.keys(deliveryMaterial(base))) {
      const changed = structuredClone(base);
      if (key === 'profile') changed.probe_profile = { ...changed.probe_profile, fixture_delivery_change: 'different' };
      else if (key === 'customer_runnable') changed.safety_constraints.customer_runnable = false;
      else changed[key] = key === 'default_expected_behavior' ? 'must_reach_origin' : { fixture_delivery_change: changed[key] };
      assert.notEqual(deliveryFingerprint(changed), deliveryFingerprint(base), key);
    }
    for (const key of ['qtype', 'transport', 'method', 'path', 'port', 'evasion_transform', 'marker_class', 'payload_profile', 'assertions', 'max_requests', 'timeout_ms']) {
      const changed = structuredClone(base); changed.probe_profile[key] = `different-${key}`;
      assert.notEqual(deliveryFingerprint(changed), deliveryFingerprint(base), key);
      assert.equal(changed.mechanism_id, base.mechanism_id);
    }
  });
  it('missing supported proof is an explicit failing gap, never default unsupported', () => {
    const missing = accountDeliveryReceipts([]);
    assert.equal(missing.complete, false);
    assert.equal(missing.gaps.length, 273);
    assert.equal(missing.gaps.filter((row) => row.disposition.startsWith('supported_')).length, 131);
  });
});

// Every catalog definition has its OWN signed invocation or actual admission call.
// A shared complete delivery fingerprint never licenses copying another receipt.
describe('every shipped catalog definition: actual bounded delivery or exact existing refusal', { concurrency: false }, () => {
  let fixtures;
  const receipts = [];
  before(async () => { fixtures = await createCheckDeliveryFixtures(); });
  after(async () => { await fixtures?.close(); });
  for (const check of CHECK_CATALOG) {
    it(`${check.check_id} / ${deliveryDisposition(check).disposition}`, async (t) => {
      const fixture = fixtures.forCheck(check);
      const result = await executeMemoryDelivery(check, fixture);
      await assertExistingBehaviorCase(t, { channel: 'delivery', receipt: result.receipt }, async () => {
        const row = rows.get(check.check_id);
        const { receipt } = result;
        assert.equal(receipt.check_id, check.check_id);
        assert.equal(receipt.check_version, row.check_version);
        assert.equal(receipt.definition_digest, row.definition_digest);
        assert.equal(receipt.delivery_fingerprint, row.delivery_fingerprint);
        assert.deepEqual(receipt.prerequisites, check.prerequisites ?? []);
        assert.deepEqual(receipt.required_customer_setup, check.required_customer_setup ?? []);
        assert.ok(check.supported_targets.includes(receipt.declared_target.kind));
        if (['none', 'admission_refusal'].includes(row.execution)) {
          assert.equal(result.started.error, row.reason);
          assert.equal(receipt.actual_wire.length, 0);
          assert.equal(receipt.job_id, null);
          assert.equal(fixture.resolverCalls().length, 0);
          assert.ok(receipt.audits.length > 0);
        } else if (row.execution === 'inline') {
          assert.equal(result.run.status, 'verdicted');
          assert.equal(receipt.job_id, null);
          assert.equal(receipt.actual_wire.length, 0);
          assert.equal(result.event.metadata.scenario, check.probe_profile.scenario);
          // Missing customer operational declaration cannot become network proof.
          assert.equal(result.verdict.verdict, 'inconclusive');
        } else {
          const { job, run, event, verdict, outcome, body, readiness } = result;
          assert.equal(verifyProbeJobSignature(job, DELIVERY_WORKER_SECRET), true);
          assert.equal(job.tenant_id, run.tenant_id);
          assert.equal(event.tenant_id, run.tenant_id);
          assert.equal(verdict.tenant_id, run.tenant_id);
          assert.equal(job.test_run_id, run.id);
          assert.equal(event.test_run_id, run.id);
          assert.equal(verdict.test_run_id, run.id);
          assert.equal(job.check_id, check.check_id);
          assert.equal(event.check_id, check.check_id);
          assert.equal(verdict.check_id, check.check_id);
          assert.equal(run.check_version, row.check_version);
          assert.equal(run.provenance_json.digest, row.definition_digest);
          assert.equal(event.nonce_hash, job.nonce_hash);
          assert.equal(run.correlation.nonce_hash, job.nonce_hash);
          assert.equal(job.target_id, event.target_id);
          assert.equal(job.target.id, event.target_id);
          assert.equal(verdict.target_id, event.target_id);
          assert.equal(event.metadata.probe_job_id, job.id);
          assert.equal(event.metadata.execution_receipt.digest, receipt.execution_receipt.digest);
          assert.equal(event.metadata.external_result, outcome.external_result);
          assert.deepEqual(event.metadata.safety_attestation, body.safety_attestation);
          assert.ok(verdict.evidence_ids.includes(event.id));
          assert.equal(verdict.confidence, 'external_only');
          assert.equal(body.safety_attestation.probe_requests_sent + body.safety_attestation.destination_resolver_attempts, body.safety_attestation.total_operations);
          assert.ok(body.safety_attestation.probe_requests_sent <= job.constraints.max_probe_requests);
          assert.ok(body.safety_attestation.destination_resolver_attempts <= job.constraints.max_destination_resolver_attempts);
          assert.ok(body.safety_attestation.total_operations <= job.constraints.max_total_operations);
          assert.ok(body.safety_attestation.duration_ms <= job.constraints.timeout_ms);
          for (const action of ['test_run.started', 'probe_job.created', 'probe_job.execution_reserved', 'probe_job.result_ingested']) assert.ok(receipt.audits.some((audit) => audit.action === action), action);
          if (row.execution === 'socket') {
            assertOwnedProtocolReceipt(check, receipt);
            const dnsOnly = ['dns_wire_query', 'dnssec_posture', 'dns_axfr_leak', 'dns_open_recursion', 'dns_failover_posture', 'dns_resolve'].includes(row.kind);
            assert.ok(receipt.actual_wire.some((wire) => dnsOnly ? ['dns_udp', 'dns_tcp'].includes(wire.transport) : !['dns_udp', 'dns_tcp'].includes(wire.transport)), 'actual probe transport, not only destination resolution');
            if (row.evidence_tier !== 'E3' || outcome.metadata.enforcement !== 'enforced') assert.equal(readiness.coverage.passed_count, 0);
          } else {
            assert.equal(outcome.external_result, 'not_run');
            assert.equal(outcome.metadata.inconclusive_reason ?? outcome.metadata.not_run_reason, row.reason);
            assert.equal(outcome.total_operations, 0);
            assert.equal(receipt.actual_wire.length, 0);
            assert.equal(fixture.resolverCalls().length, 0);
            assert.equal(readiness.coverage.passed_count, 0);
          }
        }
        receipts.push(receipt);
        return ['current catalog definition and full delivery fingerprint bound', 'actual admission or worker/reservation/ingestion/publication exercised', 'exact tenant/check/version/run/job/nonce/caps/custody binding checked', 'real owned wire evidence or exact no-I/O refusal checked', 'conservative readiness and declaration limits checked'];
      });
    });
  }
  it('reconciles default definition receipts without claiming missing required branches complete', () => {
    const result = accountDeliveryReceipts(receipts, CHECK_DELIVERY_INVENTORY, { definitionsOnly: true });
    const full = accountDeliveryReceipts(receipts);
    assert.equal(full.complete, false);
    assert.equal(full.branch_gaps.length, CHECK_DELIVERY_INVENTORY.branch_obligations.length);
    assert.equal(result.complete, true, JSON.stringify({ errors: result.errors, gaps: result.gaps }));
    assert.equal(result.invoked_definitions, 273);
    assert.equal(new Set(receipts.map((receipt) => receipt.invocation_id)).size, 273);
    // Mutations of ACTUAL receipts must not be admitted as current proof.
    const duplicate = accountDeliveryReceipts([...receipts, receipts[0]]);
    assert.ok(duplicate.errors.some((error) => error.startsWith('duplicate_definition_invocation:')));
    const stale = structuredClone(receipts); stale[0].delivery_fingerprint = 'stale';
    assert.ok(accountDeliveryReceipts(stale).errors.some((error) => error.startsWith('catalog_binding_mismatch:')));
  });
});
