import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { PRODUCTION_RELEASE_EVIDENCE_KINDS } from '../../src/contracts/productionReleaseEvidence.mjs';
import {
  gateHasRequiredEvidence,
  loadEvidenceCloseoutManifest,
  applyReleasePlanCloseouts,
} from '../../scripts/apply-release-gate-closeouts.mjs';
import { completeEvidenceRecords } from '../fixtures/productionReleaseEvidenceComplete.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-closeout-validation-'));
  tempDirs.push(dir);
  return dir;
}

function writeManifest(records) {
  const manifestPath = path.join(tempDir(), 'records.json');
  writeFileSync(manifestPath, `${JSON.stringify({
    schema_version: 1,
    artifact_type: 'production_release_evidence_records',
    release_id: 'rel-closeout-validation',
    environment: 'staging',
    submittable: true,
    dry_run: false,
    records,
  }, null, 2)}\n`);
  return loadEvidenceCloseoutManifest(manifestPath);
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

/**
 * These closeouts write `**Closed**` into tracked release docs, so an evidence record
 * whose payload does not satisfy its contract must not count. Matching on evidence-kind
 * names alone let an empty payload close a documented gate, and that doc edit is durable.
 */
describe('release gate closeout evidence validation', () => {
  it('does not count a kind whose evidence payload fails contract validation', () => {
    const manifest = writeManifest([
      { kind: 'third_party_security_review', evidence: {}, status: 'accepted' },
    ]);
    assert.equal(manifest.kindsPresent.has('third_party_security_review'), false);
    assert.equal(gateHasRequiredEvidence('Independent security review', manifest), false);
  });

  it('counts the same kind once its evidence payload is contract-valid', () => {
    const [valid] = completeEvidenceRecords(['third_party_security_review']);
    const manifest = writeManifest([{ ...valid, status: 'accepted' }]);
    assert.equal(manifest.kindsPresent.has('third_party_security_review'), true);
    assert.equal(gateHasRequiredEvidence('Independent security review', manifest), true);
  });

  it('leaves a doc gate open when its evidence is present in name only', () => {
    const manifest = writeManifest([
      { kind: 'third_party_security_review', evidence: {}, status: 'accepted' },
    ]);
    const input = [
      '## Production release gates',
      '| Gate | Owner | Evidence | Status |',
      '| Independent security review | Security | report | **Open** |',
    ].join('\n');
    const output = applyReleasePlanCloseouts(input, manifest);
    assert.ok(output.includes('**Open**'), 'gate must stay open on unvalidated evidence');
    assert.equal(output.includes('**Closed**'), false);
  });

  it('keeps the full-inventory requirement for release-summarizing gates', () => {
    // These two gates previously mapped to [], an implicit "require full inventory"
    // sentinel. Naming their kinds explicitly must not loosen them.
    const partial = writeManifest(
      completeEvidenceRecords([
        'evidence_snapshot_manifest',
        'staging_e2e_matrix',
        'third_party_security_review',
        'compliance_legal_signoff',
        'ui_accessibility_matrix',
        'placement_confidence_staging',
      ]).map((record) => ({ ...record, status: 'accepted' })),
    );
    assert.equal(partial.inventoryComplete, false);
    assert.equal(gateHasRequiredEvidence('P0 enterprise gap backlog', partial), false);
    assert.equal(
      gateHasRequiredEvidence('Staging readiness attestation (profile-aware)', partial),
      false,
    );

    const complete = writeManifest(
      completeEvidenceRecords(PRODUCTION_RELEASE_EVIDENCE_KINDS)
        .map((record) => ({ ...record, status: 'accepted' })),
    );
    assert.equal(complete.inventoryComplete, true);
    assert.equal(gateHasRequiredEvidence('P0 enterprise gap backlog', complete), true);
    assert.equal(
      gateHasRequiredEvidence('Staging readiness attestation (profile-aware)', complete),
      true,
    );
  });

  it('returns false for gates with no mapping at all', () => {
    const manifest = writeManifest(
      completeEvidenceRecords(PRODUCTION_RELEASE_EVIDENCE_KINDS)
        .map((record) => ({ ...record, status: 'accepted' })),
    );
    assert.equal(gateHasRequiredEvidence('Gate that does not exist', manifest), false);
  });
});
