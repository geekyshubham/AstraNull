#!/usr/bin/env node
import { statSync } from 'node:fs';

const file = process.argv[2];
const maxAgeSeconds = Number(process.argv[3] ?? 120);
if (!file || !Number.isFinite(maxAgeSeconds) || maxAgeSeconds <= 0) process.exit(2);
try {
  const ageMs = Date.now() - statSync(file).mtimeMs;
  process.exit(ageMs >= 0 && ageMs <= maxAgeSeconds * 1000 ? 0 : 1);
} catch {
  process.exit(1);
}
