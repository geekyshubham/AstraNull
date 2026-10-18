import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evidenceStory, proofRows, storyFamily, storyTone } from '../../apps/web/react/src/lib/evidence-story.mjs';

describe('evidence story', () => {
  it('maps check ids and vector families to story families', () => {
    assert.equal(storyFamily('origin.leak_scan.safe'), 'origin');
    assert.equal(storyFamily('l3.forbidden_tcp_port.safe'), 'network');
    assert.equal(storyFamily('anything', 'l3_l4'), 'network');
    assert.equal(storyFamily('protocol.http2_readiness.safe'), 'tls');
    assert.equal(storyFamily('dns.amplification_exposure.safe', 'amplification'), 'reflection');
    assert.equal(storyFamily('ops.kill_switch_drill.safe'), 'operations');
    assert.equal(storyFamily('mystery.check'), '');
  });

  it('classifies outcomes into four tones', () => {
    assert.equal(storyTone('penetrated'), 'gap');
    assert.equal(storyTone('protected'), 'pass');
    assert.equal(storyTone('inconclusive'), 'review');
    assert.equal(storyTone(''), 'not_tested');
    assert.equal(storyTone('penetrated', true), 'not_tested');
  });

  it('leads with a plain headline and family fix steps for a gap', () => {
    const story = evidenceStory({ checkId: 'origin.direct_bypass.safe', outcome: 'penetrated' });
    assert.equal(story.kicker, 'Gap confirmed');
    assert.match(story.headline, /origin server answered/);
    assert.match(story.why, /bypass your DDoS protection/);
    assert.equal(story.fix.length, 2);
  });

  it('never overclaims for observation-only checks', () => {
    const story = evidenceStory({ checkId: 'origin.leak_scan.safe', outcome: 'penetrated', observationOnly: true });
    assert.equal(story.kicker, 'Observation');
    assert.match(story.headline, /observation, not a confirmed verdict/);
  });

  it('falls back to the recorded remediation and explanation without family copy', () => {
    const story = evidenceStory({ checkId: 'mystery.check', outcome: 'fail', remediation: 'Patch it.', explanation: 'Recorded explanation.' });
    assert.deepEqual(story.fix, ['Patch it.']);
    assert.equal(story.why, 'Recorded explanation.');
    const passed = evidenceStory({ checkId: 'waf.marker_rule.safe', outcome: 'pass' });
    assert.deepEqual(passed.fix, []);
    assert.equal(passed.why, '');
  });

  it('builds proof rows only from recorded values', () => {
    assert.deepEqual(proofRows({ tone: 'gap' }), []);
    const rows = proofRows({
      tone: 'gap',
      observed: 'Penetrated',
      expected: 'Must block before origin',
      request: [{ key: 'max_requests', value: '3' }, { key: 'timeout_ms', value: '5000' }],
      response: [{ key: 'status_code', value: '200' }],
      proof: { addresses: ['203.0.113.24'], matched_signals: [], fingerprints: [] },
    });
    assert.deepEqual(rows.map((row) => row.key), ['observed', 'expected', 'addresses']);
    assert.equal(rows[0].tone, 'fail');
    assert.equal(rows[0].detail, 'Response status 200');
    assert.equal(rows[1].detail, 'at most 3, 5000 ms timeout');
  });
});
