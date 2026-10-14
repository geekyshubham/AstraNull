import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  CANARY_SINK_BODY_MAX_REQUESTS,
  INSPECTION_LIMIT_PADDING_KB,
  SYNTHETIC_PAN,
  gradeCanarySinkBodyResults,
  planCanarySinkBodyTests,
} from '../../src/lib/vectorProbes/canarySinkBodyPlan.mjs';
import { planCanarySinkBodyTests as contractPlan } from '../../src/contracts/wafOffensive.mjs';
import { CAPABILITY_PROBE_DISPATCH } from '../../src/lib/capabilityProbes.mjs';
import { BENIGN_CLASS_MARKERS } from '../../src/lib/inertWafMarkers.mjs';

const SINK = 'https://edge.example.test/canary';

describe('SOC canary-sink body planner', () => {
  it('is not a worker probe kind', () => {
    assert.equal(CAPABILITY_PROBE_DISPATCH.canary_sink_body_plan, undefined);
    assert.equal(contractPlan, planCanarySinkBodyTests);
  });

  it('plans json, form, multipart, inspection limits and response DLP', () => {
    const plan = planCanarySinkBodyTests({ canarySinkUrl: SINK });
    assert.ok(plan.requests.length <= CANARY_SINK_BODY_MAX_REQUESTS);
    const byVariant = Object.fromEntries(plan.requests.map((row) => [row.id, row]));
    assert.equal(byVariant.json_marker.content_type, 'application/json');
    assert.equal(byVariant.json_marker.content_length, Buffer.byteLength(byVariant.json_marker.body));
    assert.ok(byVariant.json_marker.body.includes(BENIGN_CLASS_MARKERS.sqli));
    assert.equal(byVariant.form_marker.content_type, 'application/x-www-form-urlencoded');
    assert.ok(byVariant.multipart_marker.filename.endsWith('.txt'));
    assert.ok(byVariant.multipart_marker.body.includes(BENIGN_CLASS_MARKERS.path_traversal));
    for (const kb of INSPECTION_LIMIT_PADDING_KB) {
      const row = byVariant[`inspection_limit_${kb}kb`];
      const parsed = JSON.parse(row.body);
      assert.equal(parsed.pad.length, kb * 1024);
      assert.equal(row.content_length, Buffer.byteLength(row.body));
      assert.ok(row.body.indexOf(parsed.pad) < row.body.indexOf(BENIGN_CLASS_MARKERS.sqli));
    }
    assert.equal(byVariant.response_dlp_pan.synthetic_pan, SYNTHETIC_PAN);
    assert.ok(byVariant.response_dlp_pan.url.endsWith('/astranull-dlp-canary'));
    for (const row of plan.requests) {
      assert.equal(new URL(row.url).origin, new URL(SINK).origin);
    }
  });

  it('rejects a URL that is not the declared sink', () => {
    assert.throws(
      () => planCanarySinkBodyTests({
        canarySinkUrl: 'https://other.example/canary',
        declaredCanarySinkUrl: SINK,
      }),
      (err) => err.code === 'sink_url_mismatch',
    );
    assert.throws(
      () => planCanarySinkBodyTests({ canarySinkUrl: 'http://edge.example.test/canary' }),
      (err) => err.code === 'invalid_canary_sink',
    );
  });

  it('caps the plan at 12 requests', () => {
    const variants = Array.from({ length: 13 }, () => 'json');
    assert.throws(
      () => planCanarySinkBodyTests({ canarySinkUrl: SINK, variants }),
      (err) => err.code === 'plan_cap_exceeded',
    );
  });

  it('grades fail-open at the first allowed inspection-limit size', () => {
    const plan = planCanarySinkBodyTests({
      canarySinkUrl: SINK,
      variants: ['json', 'inspection_limit_8kb', 'inspection_limit_16kb', 'inspection_limit_64kb', 'response_dlp'],
    });
    const graded = gradeCanarySinkBodyResults(plan, [
      { id: 'json_marker', blocked: true, status_code: 403 },
      { id: 'inspection_limit_8kb', blocked: true, status_code: 403 },
      { id: 'inspection_limit_16kb', allowed: true, status_code: 200 },
      { id: 'inspection_limit_64kb', allowed: true, status_code: 200 },
      { id: 'response_dlp_pan', pan_visible: false, pan_masked: true, status_code: 200 },
    ]);
    assert.equal(graded.inspection_limit_fail_open_at_kb, 16);
    assert.equal(graded.response_dlp.pan_masked, true);
    assert.equal(graded.response_dlp.pan_visible, false);
    assert.equal(graded.variant_results[0].outcome, 'blocked');
  });
});
