import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { readFileSync } from 'node:fs';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { CHECK_IMPACT_CLASSES, classifyCheckImpact } from '../../src/contracts/checkClassification.mjs';

const byId = (id) => CHECK_CATALOG.find((check) => check.check_id === id);
const impactOf = (id) => classifyCheckImpact(byId(id)).id;

describe('invasive and non-invasive check classification', () => {
  it('assigns every catalog check exactly one impact class', () => {
    const ids = new Set(Object.keys(CHECK_IMPACT_CLASSES));
    for (const check of CHECK_CATALOG) assert.ok(ids.has(classifyCheckImpact(check).id), check.check_id);
  });

  it('treats ordinary lookups, handshakes and declarations as non-invasive', () => {
    for (const id of ['l3.icmp_flood.readiness', 'dns.authoritative_response.safe', 'tls.profile_exposure.safe', 'waf.fingerprint.safe', 'protocol.http2_readiness.safe']) {
      assert.equal(impactOf(id), 'non_invasive', id);
    }
  });

  it('treats attack-shaped, bursting, scanning and SOC-gated checks as invasive', () => {
    for (const id of ['waf.evasion_unicode_normalization.safe', 'waf.low_rate_limit.safe', 'l3.firewall_exposure_scan.safe', 'reflect.ssdp_exposure.safe', 'origin.direct_reachability.safe', 'l7.http2_rapid_reset.validation', 'l3.connection_table_exhaustion.request_only']) {
      assert.equal(impactOf(id), 'invasive', id);
    }
  });

  it('fails safe to invasive for unknown probe kinds and missing input', () => {
    assert.equal(classifyCheckImpact({ check_id: 'x.new.safe', vector_family: 'l7', probe_profile: { kind: 'brand_new_probe' } }).id, 'invasive');
    assert.equal(classifyCheckImpact(null).id, 'invasive');
  });

  it('shows the traffic impact filter, row badge and review sentence on the validate tab', () => {
    const queue = readFileSync(new URL('../../apps/web/react/src/components/targets/domain-protection.tsx', import.meta.url), 'utf8');
    const detail = readFileSync(new URL('../../apps/web/react/src/pages/target-detail-view.tsx', import.meta.url), 'utf8');
    assert.match(queue, /className="td-impact" role="group" aria-labelledby="td-impact-title"/);
    assert.match(queue, /<CheckImpactBadge impact=\{rowImpact\(row\)\} \/>/);
    assert.match(detail, /<dt>Traffic impact<\/dt>/);
  });
});

describe('target detail findings count', () => {
  it('counts unique findings, not repeat detections, in the Findings tab', () => {
    const detail = readFileSync(new URL('../../apps/web/react/src/pages/target-detail-view.tsx', import.meta.url), 'utf8');
    assert.match(detail, /const openFindings = deduplicatedOpenFindings\s*\.map\(\(item\) => item\.representative\)/);
    assert.match(detail, /\{ id: 'findings' as const, label: 'Findings', count: openFindings\.length \}/);
  });

  it('shows target facts only on the overview tab', () => {
    const detail = readFileSync(new URL('../../apps/web/react/src/pages/target-detail-view.tsx', import.meta.url), 'utf8');
    assert.match(detail, /\{tab === 'overview' \? \(\n\s*<section className="td-facts"/);
  });
});
