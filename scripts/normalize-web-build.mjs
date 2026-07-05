import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const GENERATED_FILES = [
  'apps/web/react-app.js',
  'apps/web/react-app.css',
];

for (const rel of GENERATED_FILES) {
  const file = path.join(ROOT, rel);
  const text = readFileSync(file, 'utf8');
  const normalized = text.replace(/\t/g, '  ');
  if (normalized !== text) {
    writeFileSync(file, normalized);
  }
}

console.log('normalize-web-build: ok');
