import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  generateCheckProbeLogs,
  buildScanLiveLogs,
  WAF_FINGERPRINT_PHASES,
} from '../../apps/web/react/src/lib/live-probe-logs.mjs';

describe('Live probe logs generator', () => {
  it('generates 13 phases plus handshake and analysis for waf.fingerprint.safe', () => {
    const row = {
      checkId: 'waf.fingerprint.safe',
      name: 'Outside-In WAF Scanner (Safe)',
      status: 'running',
      requestsSent: 13,
      maxRequests: 16,
      probeKind: 'outside_in_waf_scan',
      startedAt: '2026-10-04T12:46:00.000Z',
    };

    const logs = generateCheckProbeLogs(row, 'astranull.site');
    assert.ok(logs.length >= 15, `Expected at least 15 log entries, got ${logs.length}`);

    // Verify session init, DNS and TLS
    assert.equal(logs[0].tag, 'INIT');
    assert.ok(logs[0].message.includes('waf.fingerprint.safe'));
    assert.equal(logs[1].tag, 'DNS');
    assert.ok(logs[1].message.includes('astranull.site'));
    assert.equal(logs[2].tag, 'TLS');

    // Verify probe phases
    const probeLogs = logs.filter((l) => ['PROBE', 'MARKER', 'EVASION', 'CONFUSION', 'BYPASS'].includes(l.tag));
    assert.equal(probeLogs.length, 13, 'Expected exactly 13 probe and marker phase logs');

    // Verify analysis and wait
    const analysisLogs = logs.filter((l) => l.tag === 'ANALYSIS');
    assert.ok(analysisLogs.length >= 2, 'Expected edge analysis logs');
    assert.ok(logs.some((l) => l.tag === 'WAIT'), 'Running check should show wait for finalization');
  });

  it('generates generic probe sequence for other checks', () => {
    const row = {
      checkId: 'tls.weak_cipher_posture.safe',
      name: 'Weak Cipher Posture',
      status: 'passed',
      verdict: 'passed',
      label: 'Passed',
      requestsSent: 2,
      maxRequests: 4,
      probeKind: 'tls_session',
      response: 'Connected',
      startedAt: '2026-10-04T12:40:00.000Z',
    };

    const logs = generateCheckProbeLogs(row, 'checkout.acme.com');
    assert.ok(logs.length >= 5);
    assert.equal(logs[0].tag, 'INIT');
    assert.ok(logs.some((l) => l.tag === 'VERDICT'));
  });

  it('buildScanLiveLogs merges scan activity and individual check logs', () => {
    const scan = {
      id: 'scn_test_1',
      status: 'running',
    };
    const rows = [
      {
        checkId: 'waf.fingerprint.safe',
        name: 'Outside-In WAF Scanner (Safe)',
        status: 'running',
        requestsSent: 13,
        maxRequests: 16,
      },
    ];
    const activityItems = [
      {
        id: 'act_1',
        at: '2026-10-04T12:45:00.000Z',
        kind: 'scan',
        summary: 'Started multi-check scan on checkout.acme.com',
      },
    ];

    const logs = buildScanLiveLogs(scan, rows, activityItems, 'checkout.acme.com');
    assert.ok(logs.length > 5);
    assert.ok(logs.some((l) => l.message.includes('Started multi-check scan')));
    assert.ok(logs.some((l) => l.checkId === 'waf.fingerprint.safe'));
  });
});
