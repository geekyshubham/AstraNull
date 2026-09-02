#!/usr/bin/env node
/** Emit the complete FQDN/external-only/no-agent vector matrix. No probes are run. */
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { buildVectorTargetMatrix } from '../src/contracts/vectorTargetMatrix.mjs';

function parseArgs(argv) {
  let out = null;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--out' && argv[index + 1]) {
      out = argv[index + 1];
      index += 1;
    } else {
      throw new Error(`Unknown argument: ${argv[index]}`);
    }
  }
  return { out };
}

export function emitVectorTargetMatrix({ out = null } = {}) {
  const matrix = buildVectorTargetMatrix();
  const rendered = `${JSON.stringify(matrix, null, 2)}\n`;
  if (out) {
    mkdirSync(path.dirname(out), { recursive: true });
    writeFileSync(out, rendered, 'utf8');
  } else {
    process.stdout.write(rendered);
  }
  return matrix;
}

function main() {
  emitVectorTargetMatrix(parseArgs(process.argv.slice(2)));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    console.error(`vector-target-matrix: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
