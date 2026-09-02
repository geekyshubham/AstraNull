import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const repository = readFileSync(
  new URL('../../src/persistence/postgres/highScaleRepository.mjs', import.meta.url),
  'utf8',
);
const server = readFileSync(new URL('../../src/server.mjs', import.meta.url), 'utf8');

/**
 * The SOC authorization pack validator (`artifactBindingErrors` in lib/highScalePolicy.mjs)
 * requires `approved_delivery_patterns` and `authorization_binding` on the `test_plan` and
 * `scope_and_rate_plan` artifacts. The Postgres metadata projection dropped both, so the pack
 * stayed permanently `partial` and SOC approve returned 409 `authorization_pack_incomplete`
 * forever — high-scale governance could never complete in Postgres mode.
 */
describe('postgres high-scale artifact metadata parity', () => {
  it('persists the approved delivery patterns and authorization binding', () => {
    const start = repository.indexOf('function artifactToMetadata');
    const block = repository.slice(start, repository.indexOf('\n}', start));
    assert.match(block, /approved_delivery_patterns: artifact\.approved_delivery_patterns/);
    assert.match(block, /authorization_binding: artifact\.authorization_binding/);
  });

  it('restores both fields when reading the row back', () => {
    const start = repository.indexOf('function artifactFromRow');
    const block = repository.slice(start, repository.indexOf('\n}', start));
    assert.match(block, /approved_delivery_patterns: meta\.approved_delivery_patterns \?\? \[\]/);
    assert.match(block, /authorization_binding: meta\.authorization_binding/);
    // Legacy rows stored the binding only inside retained_artifact_metadata.
    assert.match(block, /retained_artifact_metadata\)\.authorization_binding/);
  });

  it('keeps every proof field the pack validator reads in both projections', () => {
    const toMeta = repository.slice(
      repository.indexOf('function artifactToMetadata'),
      repository.indexOf('\n}', repository.indexOf('function artifactToMetadata')),
    );
    const fromRow = repository.slice(
      repository.indexOf('function artifactFromRow'),
      repository.indexOf('\n}', repository.indexOf('function artifactFromRow')),
    );
    for (const field of [
      'valid_window',
      'approved_targets',
      'approved_scenario_families',
      'approved_delivery_patterns',
      'approved_limits',
      'authorization_binding',
    ]) {
      assert.ok(toMeta.includes(field), `artifactToMetadata must persist ${field}`);
      assert.ok(fromRow.includes(field), `artifactFromRow must restore ${field}`);
    }
  });
});

describe('postgres tenant route wiring guard', () => {
  it('returns postgres_route_not_wired instead of throwing when tenants is unwired', () => {
    assert.match(
      server,
      /persistenceMode === 'postgres'\s*&& !serviceDeps\.tenants\s*&& \(path === '\/v1\/tenants\/current'/,
    );
    assert.match(server, /postgres_route_not_wired/);
  });
});
