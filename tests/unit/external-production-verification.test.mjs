import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  aggregateExternalProductionVerification,
  buildLiveExternalVerificationManifestTemplate,
  EXTERNAL_VERIFICATION_DOMAINS,
  validateExternalVerificationManifest,
} from '../../src/contracts/externalProductionVerification.mjs';
import {
  aggregateProductionReadinessGapAudit,
} from '../../scripts/production-readiness-gap-audit.mjs';
import { PRODUCTION_RELEASE_EVIDENCE_KINDS } from '../../src/contracts/productionReleaseEvidence.mjs';
import {
  completeEvidenceRecords,
  PRODUCTION_RELEASE_EVIDENCE_COMPLETE,
  stampAcceptedReleaseRecords,
} from '../fixtures/productionReleaseEvidenceComplete.mjs';
import {
  liveExternalEvidenceRecords,
  liveExternalVerificationManifest,
} from '../fixtures/externalProductionVerificationLive.mjs';
import {
  externalVerificationExitCode,
  loadExternalVerificationInputs,
} from '../../scripts/verify-external-production-readiness.mjs';
import { resolveReleaseIdFromEvidence } from '../../scripts/attach-external-verification-markers.mjs';

import { CLOSED_RELEASE_DOC_OPTIONS } from '../fixtures/releaseDocGateMarkdown.mjs';

const closedChecklistOptions = CLOSED_RELEASE_DOC_OPTIONS;

describe('external production verification contract', () => {
  it('fails closed with no evidence and no manifest', () => {
    const report = aggregateExternalProductionVerification([], { manifest: null });
    assert.equal(report.complete, false);
    assert.equal(report.live_external_count, 0);
    assert.equal(report.unverified_count, EXTERNAL_VERIFICATION_DOMAINS.length);
    assert.ok(report.blocker_summary.length > 0);
  });

  it('stays metadata_only when manifest is absent but repo evidence exists', () => {
    const records = completeEvidenceRecords(PRODUCTION_RELEASE_EVIDENCE_KINDS).map((entry) => ({
      ...entry,
      status: 'accepted',
    }));
    const report = aggregateExternalProductionVerification(records, { manifest: null });
    assert.equal(report.complete, false);
    assert.equal(report.metadata_only_count, EXTERNAL_VERIFICATION_DOMAINS.length);
    assert.equal(report.live_external_count, 0);
    assert.ok(report.domains.every((domain) => domain.tier === 'metadata_only'));
  });

  it('accepts kms provider_class and structured drill_reference for live external checks', () => {
    const records = liveExternalEvidenceRecords().map((record) => {
      if (record.kind !== 'kms_vault_posture') return record;
      return {
        ...record,
        evidence: {
          ...record.evidence,
          vault_summary: {
            provider_class: 'cloud_hsm',
            vault_reference: 'vaultref://vendor/production/astranull-secrets',
          },
          drill_reference: {
            drill_id: 'kms_posture_drill_live',
            drill_evidence_uri: 'evidence://drill/kms-live',
          },
        },
      };
    });
    const manifest = liveExternalVerificationManifest();
    const kms = aggregateExternalProductionVerification(records, { manifest })
      .domains.find((entry) => entry.id === 'kms_hsm_custody');
    assert.equal(kms?.tier, 'live_external');
  });

  it('accepts notification providers with encrypted refs and no explicit metadata-only delivery_mode', () => {
    const records = liveExternalEvidenceRecords().map((record) => {
      if (record.kind !== 'notification_provider_config') return record;
      const { delivery_mode: _ignored, ...provider } = record.evidence.providers[0];
      return {
        ...record,
        evidence: {
          ...record.evidence,
          providers: [{ ...provider }],
        },
      };
    });
    const manifest = liveExternalVerificationManifest();
    const notification = aggregateExternalProductionVerification(records, { manifest })
      .domains.find((entry) => entry.id === 'notification_provider_credentials');
    assert.equal(notification?.tier, 'live_external');
  });

  it('passes live_external when manifest and live evidence prerequisites are satisfied', () => {
    const records = liveExternalEvidenceRecords();
    const manifest = liveExternalVerificationManifest();
    const report = aggregateExternalProductionVerification(records, { manifest });
    assert.equal(report.complete, true);
    assert.equal(report.live_external_count, EXTERNAL_VERIFICATION_DOMAINS.length);
    assert.equal(report.unverified_count, 0);
    assert.ok(report.domains.every((domain) => domain.tier === 'live_external'));
    assert.equal(validateExternalVerificationManifest(manifest).ok, true);
  });

  it('keeps customer_production_ready false when repo production_ready is true', () => {
    const releaseId = 'rel_repo_ready';
    const records = stampAcceptedReleaseRecords(
      [
        ...completeEvidenceRecords(PRODUCTION_RELEASE_EVIDENCE_KINDS),
        {
          kind: 'staging_e2e_matrix',
          evidence: PRODUCTION_RELEASE_EVIDENCE_COMPLETE.staging_e2e_matrix,
        },
      ],
      releaseId,
    );
    const report = aggregateProductionReadinessGapAudit(
      { releaseId, records },
      closedChecklistOptions,
    );
    assert.equal(report.production_ready, true);
    assert.equal(report.customer_production_ready, false);
    assert.equal(report.external_verification.complete, false);
    assert.ok(
      report.blocker_summary.some((line) => line.includes('customer_production_ready is false')),
    );
  });

  it('sets customer_production_ready true only with live external verification', () => {
    const releaseId = 'rel_customer_ready';
    const records = liveExternalEvidenceRecords(releaseId);
    const manifest = liveExternalVerificationManifest(releaseId);
    const report = aggregateProductionReadinessGapAudit(
      { releaseId, records },
      {
        ...closedChecklistOptions,
        externalVerificationManifest: manifest,
      },
    );
    assert.equal(report.production_ready, true);
    assert.equal(report.customer_production_ready, true);
    assert.equal(report.external_verification.complete, true);
  });

  it('buildLiveExternalVerificationManifestTemplate validates and is not self-attesting', () => {
    const manifest = buildLiveExternalVerificationManifestTemplate({
      releaseId: 'rel_template',
      operatorReference: 'operator://qa/lead',
    });
    const validation = validateExternalVerificationManifest(manifest);
    assert.equal(validation.ok, true);
    // The gate generates this manifest, so it must not assert its own verification.
    assert.equal(manifest.domains.enterprise_idp_mfa.tier, 'pending');
    assert.equal(manifest.verification_tier, 'pending');
    for (const domain of Object.values(manifest.domains)) {
      assert.equal(domain.tier, 'pending');
      assert.deepEqual(domain.retained_artifact_refs, []);
    }
  });

  it('does not count an unfilled manifest template as live_external', () => {
    // The bare template ships tier 'pending' as a fill-me-in marker. Even with fully
    // live evidence records, a manifest no operator affirmatively attested must fall
    // back to metadata_only and block launch.
    const records = liveExternalEvidenceRecords();
    const unfilledManifest = buildLiveExternalVerificationManifestTemplate({
      releaseId: 'rel-live-external-2026-07-04',
      operatorReference: 'operator://security/release-lead',
      createdAt: '2026-07-04T00:00:00.000Z',
    });
    const report = aggregateExternalProductionVerification(records, { manifest: unfilledManifest });
    assert.equal(report.complete, false);
    assert.equal(report.live_external_count, 0);
    assert.ok(report.domains.every((domain) => domain.tier === 'metadata_only'));
    assert.ok(
      report.domains.every((domain) => domain.blockers.includes('manifest_tier_pending')),
    );
  });

  it('rejects arbitrary strings as retained_artifact_refs', () => {
    // retained_artifact_refs previously accepted any non-empty string, so five
    // arbitrary values in a manifest the gate itself generates satisfied the gate.
    const records = liveExternalEvidenceRecords();
    const manifest = liveExternalVerificationManifest();
    for (const entry of Object.values(manifest.domains)) {
      entry.retained_artifact_refs = ['x'];
    }
    const report = aggregateExternalProductionVerification(records, { manifest });
    assert.equal(report.complete, false);
    assert.equal(report.live_external_count, 0);
    assert.ok(
      report.domains.every((domain) =>
        domain.blockers.includes('manifest_retained_artifact_refs_not_custody_shaped')),
    );
  });

  it('requires retained_artifact_refs to carry a digest and differ from custody_uri', () => {
    const records = liveExternalEvidenceRecords();

    const noDigest = liveExternalVerificationManifest();
    for (const entry of Object.values(noDigest.domains)) {
      entry.retained_artifact_refs = ['retained://external/idp/rel-2026-07-04'];
    }
    const noDigestReport = aggregateExternalProductionVerification(records, { manifest: noDigest });
    assert.equal(noDigestReport.complete, false);
    assert.ok(
      noDigestReport.domains.every((domain) =>
        domain.blockers.includes('manifest_retained_artifact_refs_missing_digest')),
    );

    // Echoing custody_uri back as its own retained artifact pins nothing new.
    const echoed = liveExternalVerificationManifest();
    for (const entry of Object.values(echoed.domains)) {
      entry.custody_uri = `custody://external/thing?sha256=${'b'.repeat(64)}`;
      entry.retained_artifact_refs = [entry.custody_uri];
    }
    const echoedReport = aggregateExternalProductionVerification(records, { manifest: echoed });
    assert.equal(echoedReport.complete, false);
    assert.ok(
      echoedReport.domains.every((domain) =>
        domain.blockers.includes('manifest_retained_artifact_refs_duplicate_custody_uri')),
    );
  });

  it('verify script exit code is 1 until live external verification completes', () => {
    const incomplete = aggregateExternalProductionVerification([], { manifest: null });
    const complete = aggregateExternalProductionVerification(
      liveExternalEvidenceRecords(),
      { manifest: liveExternalVerificationManifest() },
    );
    assert.equal(externalVerificationExitCode(incomplete), 1);
    assert.equal(externalVerificationExitCode(complete), 0);
  });

  it('loadExternalVerificationInputs tolerates missing files', () => {
    const loaded = loadExternalVerificationInputs({
      evidence: '/tmp/does-not-exist-records.json',
      manifest: '/tmp/does-not-exist-manifest.json',
      autoAttachManifest: false,
    });
    assert.deepEqual(loaded.records, []);
    assert.equal(loaded.manifest, null);
    assert.equal(resolveReleaseIdFromEvidence('/tmp/does-not-exist-records.json'), null);
  });

  it('auto-attaches external verification manifest when evidence exists and manifest is missing', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-ext-verify-'));
    const evidencePath = path.join(dir, 'records.json');
    const manifestPath = path.join(dir, 'external-manifest.json');
    writeFileSync(evidencePath, `${JSON.stringify({
      release_id: 'rel_auto_attach',
      records: liveExternalEvidenceRecords('rel_auto_attach'),
    }, null, 2)}\n`);
    const loaded = loadExternalVerificationInputs({
      evidence: evidencePath,
      manifest: manifestPath,
      autoAttachManifest: true,
    });
    assert.equal(existsSync(manifestPath), true);
    assert.equal(loaded.manifest?.release_id, 'rel_auto_attach');
    rmSync(dir, { recursive: true, force: true });
  });
});