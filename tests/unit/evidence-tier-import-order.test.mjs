import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { it } from 'node:test';
import { fileURLToPath } from 'node:url';

it('derives evidence tiers when the taxonomy is imported first and alone in a fresh process', () => {
  const script = `
    const taxonomy = await import('./src/contracts/resourceExhaustionTaxonomy.mjs');
    const distribution = {};
    for (const vector of taxonomy.ATTACK_VECTOR_REGISTRY) {
      distribution[vector.evidence_tier] = (distribution[vector.evidence_tier] ?? 0) + 1;
    }
    process.stdout.write(JSON.stringify(distribution));
  `;
  const stdout = execFileSync(
    process.execPath,
    ['--input-type=module', '--eval', script],
    { cwd: fileURLToPath(new URL('../..', import.meta.url)), encoding: 'utf8' },
  );

  assert.deepEqual(JSON.parse(stdout), {
    E1: 59,
    E2: 36,
    E3: 79,
    E4: 80,
  });
});
