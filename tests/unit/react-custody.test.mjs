import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildEvidenceCustodyManifest, CUSTODY_CONTENT_CANONICALIZATION } from '../../apps/web/react/src/lib/custody.ts';
import { buildEvidenceChainExport } from '../../apps/web/react/src/lib/evidence-export.ts';
import { sha256CanonicalJson } from '../../src/lib/custody.mjs';

describe('react custody manifest', () => {
  it('matches backend canonicalization and digest for evidence chain exports', async () => {
    const exportData = buildEvidenceChainExport({
      evidence: [{
        id: 'evd_1',
        label: 'probe_simulation_evidence',
        test_run_id: 'run_1',
        created_at: '2026-07-05T08:42:19.960Z'
      }],
      runs: [{ id: 'run_1', status: 'verdicted' }],
      findings: []
    });
    const custody = await buildEvidenceCustodyManifest(exportData.payload, 'ten_demo');
    assert.equal(CUSTODY_CONTENT_CANONICALIZATION, 'json-key-sorted-v1');
    assert.equal(custody.content_canonicalization, 'json-key-sorted-v1');
    assert.equal(custody.content_sha256, sha256CanonicalJson(exportData.payload));
    assert.deepEqual(custody.subject_ids, ['evd_1']);
  });
});