#!/usr/bin/env node
/**
 * Regenerates the vendored edge-fingerprint corpus in `src/lib/data/edgeSignatureData.mjs`.
 *
 * Why a generator instead of a runtime dependency: the two upstream projects are a Python CLI
 * (wafw00f) and a Go library (cdncheck). Shelling out to either would add a foreign runtime per
 * target, bypass tenant audit/rate bounds, and — for wafw00f — fire XSS/SQLi/LFI/RCE payloads at
 * customer targets, which AstraNull's governed probe path forbids. Their durable value is the
 * signature corpus, not the control flow, so we port the data and keep our own bounded probe path.
 *
 * Upstream sources (attribution retained in the emitted module):
 *   - wafw00f  — 3-clause BSD, Copyright (c) 2009-2026 WAFW00F Developers
 *   - cdncheck — MIT, Copyright (c) 2021 ProjectDiscovery, Inc.
 *
 * Usage:
 *   node scripts/generate-edge-signatures.mjs --wafw00f <clone> --cdncheck <clone> [--out <path>]
 *
 * Signature tiers:
 *   `passive`    — wafw00f matchHeader/matchCookie with attack=False (their default). Decidable
 *                  from one ordinary GET, so these run on every fingerprint.
 *   `block_page` — matchContent/matchStatus/matchReason (attack=True is their default) plus any
 *                  explicit attack=True header match. These need a response the WAF actually
 *                  blocked, so AstraNull only evaluates them against block-page evidence already
 *                  captured by an authorized bounded check. The generator keeps them so the
 *                  classifier can use that evidence, never to justify sending attack traffic.
 */

import { readdirSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = { out: 'src/lib/data/edgeSignatureData.mjs' };
  for (let i = 2; i < argv.length; i += 1) {
    const key = argv[i];
    if (key === '--wafw00f') args.wafw00f = argv[++i];
    else if (key === '--cdncheck') args.cdncheck = argv[++i];
    else if (key === '--out') args.out = argv[++i];
  }
  return args;
}

/** Python `re` accepts a few constructs JS spells differently; normalize then verify it compiles. */
function toJsPattern(pythonPattern) {
  let pattern = pythonPattern
    .replace(/\(\?P<([A-Za-z_][A-Za-z0-9_]*)>/g, '(?<$1>')
    .replace(/\(\?P=([A-Za-z_][A-Za-z0-9_]*)\)/g, '\\k<$1>');
  // Inline `(?i)` is a Python-only prefix; every match below is already case-insensitive.
  pattern = pattern.replace(/\(\?i\)/g, '');
  try {
    new RegExp(pattern, 'i');
  } catch {
    return null;
  }
  return pattern;
}

/**
 * The plugins are machine-uniform: each `is_waf` body is a flat list of single-line
 * `self.matchX(...)` calls over string literals. That makes a scanner sufficient and keeps this
 * repo Node-only (no Python needed to rebuild the corpus).
 */
function extractPluginSignatures(source) {
  const signatures = [];
  const unparsed = [];

  const nameMatch = source.match(/^NAME\s*=\s*(['"])([\s\S]*?)\1/m);
  const displayName = nameMatch ? nameMatch[2] : null;

  const callRe = /self\.(matchHeader|matchCookie|matchContent|matchStatus|matchReason)\(([\s\S]*?)\)\s*(?::|\n)/g;
  for (const call of source.matchAll(callRe)) {
    const kind = call[1];
    const rawArgs = call[2];
    const explicitAttack = /attack\s*=\s*True/.test(rawArgs);
    const argText = rawArgs.replace(/,?\s*attack\s*=\s*(?:True|False)\s*/g, '').trim();

    if (kind === 'matchHeader') {
      const tuple = argText.match(
        /^\(\s*(?:r|u|b)?(['"])([\s\S]*?)\1\s*,\s*(?:r|u|b)?(['"])([\s\S]*?)\3\s*,?\s*\)$/,
      );
      if (!tuple) {
        unparsed.push(`${kind}(${argText})`);
        continue;
      }
      const pattern = toJsPattern(tuple[4]);
      if (pattern === null) {
        unparsed.push(`${kind}(${argText})`);
        continue;
      }
      signatures.push({
        signal: 'header',
        header: tuple[2].toLowerCase(),
        pattern,
        tier: explicitAttack ? 'block_page' : 'passive',
      });
      continue;
    }

    if (kind === 'matchCookie') {
      const literal = argText.match(/^(?:r|u|b)?(['"])([\s\S]*?)\1$/);
      if (!literal) {
        unparsed.push(`${kind}(${argText})`);
        continue;
      }
      const pattern = toJsPattern(literal[2]);
      if (pattern === null) {
        unparsed.push(`${kind}(${argText})`);
        continue;
      }
      signatures.push({
        signal: 'cookie',
        pattern,
        tier: explicitAttack ? 'block_page' : 'passive',
      });
      continue;
    }

    if (kind === 'matchStatus') {
      const status = Number(argText);
      if (!Number.isInteger(status)) {
        unparsed.push(`${kind}(${argText})`);
        continue;
      }
      // matchStatus defaults to attack=True upstream: a bare status code only means "WAF" when
      // the request was one the WAF would reject.
      signatures.push({ signal: 'status', status, tier: 'block_page' });
      continue;
    }

    const literal = argText.match(/^(?:r|u|b)?(['"])([\s\S]*?)\1$/);
    if (!literal) {
      unparsed.push(`${kind}(${argText})`);
      continue;
    }
    if (kind === 'matchReason') {
      signatures.push({ signal: 'reason', value: literal[2], tier: 'block_page' });
      continue;
    }
    const pattern = toJsPattern(literal[2]);
    if (pattern === null) {
      unparsed.push(`${kind}(${argText})`);
      continue;
    }
    // matchContent also defaults to attack=True upstream.
    signatures.push({ signal: 'content', pattern, tier: 'block_page' });
  }

  return { displayName, signatures, unparsed };
}

function loadWafSignatures(clonePath) {
  const pluginDir = path.join(clonePath, 'wafw00f', 'plugins');
  const files = readdirSync(pluginDir).filter((f) => f.endsWith('.py') && f !== '__init__.py');
  const vendors = {};
  const report = { plugins: 0, passive: 0, blockPage: 0, unparsed: 0, passiveVendors: 0 };

  for (const file of files.sort()) {
    const key = path.basename(file, '.py');
    const source = readFileSync(path.join(pluginDir, file), 'utf8');
    const { displayName, signatures, unparsed } = extractPluginSignatures(source);
    if (signatures.length === 0) continue;
    report.plugins += 1;
    report.unparsed += unparsed.length;
    for (const sig of signatures) {
      if (sig.tier === 'passive') report.passive += 1;
      else report.blockPage += 1;
    }
    if (signatures.some((s) => s.tier === 'passive')) report.passiveVendors += 1;
    vendors[key] = { name: displayName ?? key, signatures };
  }
  return { vendors, report };
}

/**
 * cdncheck's IP path needs no HTTP request at all, which is exactly why it composes with the
 * passive HTTP tier into one observation. We take `cdn` + `waf` CIDRs and the `common` CNAME
 * suffixes; the `cloud` category is ~129k CIDRs of general AWS/Azure/GCP space that answers
 * "where is the origin hosted", not "is there a CDN or WAF at the edge", so it stays out.
 */
function loadEdgeRanges(clonePath) {
  const data = JSON.parse(readFileSync(path.join(clonePath, 'sources_data.json'), 'utf8'));
  const normalize = (group) => Object.fromEntries(
    Object.entries(group ?? {})
      .map(([provider, values]) => [provider, [...new Set(values)].sort()])
      .filter(([, values]) => values.length > 0)
      .sort(([a], [b]) => a.localeCompare(b)),
  );
  const cdnRanges = normalize(data.cdn);
  const wafRanges = normalize(data.waf);
  const suffixes = normalize(data.common);
  const count = (group) => Object.values(group).reduce((sum, v) => sum + v.length, 0);
  return {
    cdnRanges,
    wafRanges,
    suffixes,
    report: {
      cdnRanges: count(cdnRanges),
      wafRanges: count(wafRanges),
      suffixes: count(suffixes),
    },
  };
}

function main() {
  const args = parseArgs(process.argv);
  if (!args.wafw00f || !args.cdncheck) {
    console.error('usage: generate-edge-signatures.mjs --wafw00f <clone> --cdncheck <clone>');
    process.exit(2);
  }

  const { vendors, report } = loadWafSignatures(args.wafw00f);
  const { cdnRanges, wafRanges, suffixes, report: rangeReport } = loadEdgeRanges(args.cdncheck);

  const body = `/**
 * Vendored edge-fingerprint corpus. GENERATED — do not edit by hand.
 * Regenerate with \`node scripts/generate-edge-signatures.mjs\`.
 *
 * WAF/CDN vendor signatures ported from wafw00f (3-clause BSD,
 * Copyright (c) 2009-2026 WAFW00F Developers). CDN/WAF address ranges and CNAME suffixes ported
 * from cdncheck (MIT, Copyright (c) 2021 ProjectDiscovery, Inc.). Both notices are retained in
 * docs/attribution/edge-fingerprint-sources.md.
 *
 * \`passive\` signatures are decidable from one ordinary GET. \`block_page\` signatures describe
 * what a WAF returns when it rejects a request; AstraNull evaluates them only against block-page
 * evidence an authorized bounded check already captured, and never sends attack payloads to
 * manufacture them.
 */

/** @type {Readonly<Record<string, { name: string, signatures: ReadonlyArray<Record<string, unknown>> }>>} */
export const WAF_VENDOR_SIGNATURES = Object.freeze(${JSON.stringify(vendors, null, 2)});

/** CDN provider address ranges (cdncheck \`cdn\`). */
export const CDN_ADDRESS_RANGES = Object.freeze(${JSON.stringify(cdnRanges, null, 2)});

/** WAF provider address ranges (cdncheck \`waf\`). */
export const WAF_ADDRESS_RANGES = Object.freeze(${JSON.stringify(wafRanges, null, 2)});

/** Edge CNAME suffixes shared by CDN and WAF products (cdncheck \`common\`). */
export const EDGE_CNAME_SUFFIXES = Object.freeze(${JSON.stringify(suffixes, null, 2)});

export const EDGE_CORPUS_STATS = Object.freeze({
  waf_vendors: ${Object.keys(vendors).length},
  passive_signatures: ${report.passive},
  block_page_signatures: ${report.blockPage},
  cdn_ranges: ${rangeReport.cdnRanges},
  waf_ranges: ${rangeReport.wafRanges},
  cname_suffixes: ${rangeReport.suffixes},
});
`;

  const outPath = path.resolve(args.out);
  mkdirSync(path.dirname(outPath), { recursive: true });
  writeFileSync(outPath, body);

  console.log('generate-edge-signatures: ok');
  console.log(`  wafw00f plugins ported : ${report.plugins}`);
  console.log(`  vendors with passive   : ${report.passiveVendors}`);
  console.log(`  passive signatures     : ${report.passive}`);
  console.log(`  block-page signatures  : ${report.blockPage}`);
  console.log(`  unparsed calls         : ${report.unparsed}`);
  console.log(`  cdn ranges / waf ranges: ${rangeReport.cdnRanges} / ${rangeReport.wafRanges}`);
  console.log(`  cname suffixes         : ${rangeReport.suffixes}`);
  console.log(`  wrote                  : ${path.relative(process.cwd(), outPath)}`);
}

main();
