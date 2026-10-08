import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { Script } from 'node:vm';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { VECTOR_LIBRARY } from '../../src/contracts/vectorLibrary.mjs';
import { WAF_VENDOR_SIGNATURES } from '../../src/lib/data/edgeSignatureData.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const escapeHtml = value => value.replaceAll('&', '&amp;').replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');

test('capability reference generates from any directory with complete inert source and valid navigation', () => {
  const result = JSON.parse(execFileSync(process.execPath,
    [path.join(root, 'scripts/generate-capabilities-html.mjs')], { cwd: tmpdir(), encoding: 'utf8' }));
  const html = readFileSync(result.output, 'utf8');
  assert.equal(result.checks, CHECK_CATALOG.length);
  assert.equal(result.vectors, VECTOR_LIBRARY.length);
  assert.equal(result.waf_vendor_rules, Object.keys(WAF_VENDOR_SIGNATURES).length);

  // Escaped source cannot contribute markup IDs or executable scripts.
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  const uniqueIds = new Set(ids);
  assert.equal(uniqueIds.size, ids.length, 'duplicate HTML IDs');
  for (const check of CHECK_CATALOG) assert.ok(uniqueIds.has(`check-${check.check_id}`));
  for (const vector of VECTOR_LIBRARY) assert.ok(uniqueIds.has(`vector-${vector.vector_id}`));
  for (const vendor of Object.keys(WAF_VENDOR_SIGNATURES)) assert.ok(uniqueIds.has(`vendor-${vendor}`));
  for (const [, href] of html.matchAll(/<a\b[^>]*href="([^"]+)"/g)) {
    if (href.startsWith('#')) assert.ok(uniqueIds.has(href.slice(1)), `broken fragment ${href}`);
    else assert.ok(existsSync(path.resolve(path.dirname(result.output), href)), `missing file ${href}`);
  }
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length, 1, 'only the document filter/navigation script may execute');
  assert.doesNotThrow(() => new Script(scripts[0][1]));
  assert.doesNotMatch(html, /<(?:img|iframe|object|embed)\b|<script\s+[^>]*src=|<link\b/i);
  for (const file of ['src/lib/asnLookup.mjs', 'src/lib/data/asnEdgeData.mjs',
    'src/lib/initialEdgeDetection.mjs', 'src/services/initialEdgeDetections.mjs',
    'src/lib/targetExecutionScope.mjs']) {
    assert.ok(html.includes(escapeHtml(readFileSync(path.join(root, file), 'utf8'))), `missing inert ${file}`);
  }
  const narrative = html.slice(html.indexOf('<section id="cdn-waf"'), html.indexOf('<section id="waf-verdicts"'));
  const fingerprint = CHECK_CATALOG.find(check => check.check_id === 'waf.fingerprint.safe');
  assert.ok(narrative.includes(`version ${fingerprint.version} selects`));
  assert.ok(narrative.includes('partial_provider_observation'));
  assert.ok(narrative.includes('518 matcher rules'));
  assert.ok(html.includes('working_tree_changes_at_generation'));
});
