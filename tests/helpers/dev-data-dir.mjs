/**
 * Points the dev JSON store (`src/store.mjs`) at a per-process temp directory.
 *
 * Importing this module has the side effect, deliberately: `ASTRANULL_DEV_DATA_DIR` has to
 * be set before any test module body runs, because a suite that boots a server and then
 * restores a `{ ...process.env }` snapshot taken at module scope would otherwise erase a
 * later assignment. ES module imports evaluate in source order ahead of the importing
 * module's body, so a side-effect import is the only placement that survives that pattern.
 *
 * Without it, a suite run from the repo root reads and rewrites the developer's real
 * `.data/astranull-dev.json` — observed live as a seeded dev store being clobbered
 * mid-session by `tests/integration/auth-boundary.test.mjs` and
 * `tests/unit/external-discovery.test.mjs`.
 */
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_DATA_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../.data',
);

/** @type {string | null} */
let isolatedDir = null;

/**
 * Idempotently assigns `ASTRANULL_DEV_DATA_DIR` a fresh temp dir for this process.
 * Safe to call again after a test restores or deletes the variable.
 * @returns {string} the isolated data directory
 */
export function useIsolatedDevDataDir() {
  if (!isolatedDir) {
    const preset = process.env.ASTRANULL_DEV_DATA_DIR?.trim();
    if (preset && path.resolve(preset) !== REPO_DATA_DIR) {
      isolatedDir = path.resolve(preset);
    } else {
      isolatedDir = mkdtempSync(path.join(realpathSync(os.tmpdir()), 'astranull-test-store-'));
      const dir = isolatedDir;
      process.on('exit', () => {
        try {
          rmSync(dir, { recursive: true, force: true });
        } catch {
          // Teardown only; a leftover temp dir must never fail a suite.
        }
      });
    }
  }
  process.env.ASTRANULL_DEV_DATA_DIR = isolatedDir;
  return isolatedDir;
}

/** Absolute path of the repo `.data` directory that tests must never touch. */
export const REPO_DEV_DATA_DIR = REPO_DATA_DIR;

useIsolatedDevDataDir();
