import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildWafReportPayload } from '../../src/lib/wafReports.mjs';

describe('WAF report validation pass rates', () => {
  it('counts only finalized summary_json.validation_passed true', () => {
    const validations = [
      {
        id: 'run_full_protected',
        status: 'finalized',
        summary_json: { validation_passed: true },
      },
      {
        id: 'run_edge_only',
        status: 'finalized',
        summary_json: { validation_passed: false, edge_protected: true },
      },
      {
        id: 'run_missing_summary_pass',
        status: 'finalized',
        summary_json: {},
      },
      {
        id: 'run_not_finalized',
        status: 'running',
        summary_json: { validation_passed: true },
      },
    ];
    const scenarioResultsByRunId = new Map([
      ['run_full_protected', [{ passed: false }]],
      ['run_edge_only', [{ passed: true }]],
      ['run_missing_summary_pass', [{ passed: true }]],
    ]);

    const report = buildWafReportPayload('compliance_audit', {
      validations,
      scenarioResultsByRunId,
    });

    assert.deepEqual(report.validation_pass_rates, {
      total_finalized: 3,
      passed: 1,
      pass_rate: 33.33,
    });
    for (const entry of report.control_mapping_appendix.entries) {
      assert.equal(entry.live_metrics.validation_pass_rate, 33.33);
    }
  });
});
