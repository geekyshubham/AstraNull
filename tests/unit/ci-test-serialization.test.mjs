import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { it } from 'node:test';

it('runs timing-sensitive Node suites serially in CI, as in npm and Make', async () => {
  const workflow = await readFile(new URL('../../.github/workflows/ci.yml', import.meta.url), 'utf8');
  for (const suite of ['unit', 'integration', 'e2e']) {
    const command = workflow.split('\n').find((line) => line.includes(`tests/${suite}/*.test.mjs`));
    assert.ok(command, `${suite} CI command must exist`);
    assert.match(command, /\bnode --test --test-concurrency=1\b/, `${suite} CI must preserve serial fixture and timing isolation`);
  }
});
