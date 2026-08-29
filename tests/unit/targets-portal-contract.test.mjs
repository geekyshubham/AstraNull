import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const PAGES = new URL('../../apps/web/react/src/pages/', import.meta.url);
const readPage = (name) => readFileSync(new URL(name, PAGES), 'utf8');

describe('Targets portal contract', () => {
  it('renders the required inventory fields and safe add/remove behavior', () => {
    const source = readPage('targets-page.tsx');

    for (const label of [
      'Target',
      'Target group',
      'Verification',
      'Test eligibility',
      'Added from',
      'Added',
    ]) {
      assert.match(source, new RegExp(`label: '${label}'`));
    }
    assert.match(source, /\/v1\/target-groups\/\$\{encodeURIComponent\(groupId\)\}\/targets/);
    assert.match(source, /method: 'POST'/);
    assert.match(source, /source_app: 'AstraNull portal'/);
    assert.match(source, /method: 'DELETE'/);
    assert.match(source, /Existing evidence is retained/);
    assert.match(source, /Declared inventory is not automatic discovery/);
    assert.match(source, /ownership evidence and safety policy/);
  });

  it('keeps target-group scheduling and removal on bounded, real APIs', () => {
    const source = readPage('target-group-detail-view.tsx');

    assert.match(source, /window\.confirm\(/);
    assert.match(source, /method: 'DELETE'/);
    assert.match(source, /requestJson\(config, session, '\/v1\/test-policies'/);
    assert.match(source, /safe_windows: \[\{ day, start, end, timezone \}\]/);
    assert.match(source, /customer-runnable check/);
    assert.match(source, /They do not authorize or launch unmanaged DDoS traffic/);
  });

  it('keeps integration domain intake and requested DNS providers visible', () => {
    const source = readPage('page-components.tsx');

    for (const provider of ['GoDaddy', 'Namecheap', 'Hetzner DNS']) {
      assert.match(source, new RegExp(`label: '${provider}'`));
    }
    assert.match(source, /\+ Add single domain/);
    assert.match(source, /handleAddSingleDomain/);
    assert.match(source, /\/v1\/target-groups\/\$\{encodeURIComponent\(effectiveDomainTargetGroupId\)\}\/targets/);
    assert.match(source, /kind: 'fqdn'/);
  });
});
