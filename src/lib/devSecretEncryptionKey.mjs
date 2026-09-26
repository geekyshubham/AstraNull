import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { resolvePersistenceMode } from '../config.mjs';
import { resolveDeploymentProfile } from './deploymentProfile.mjs';

export const DEV_SECRET_KEY_FILENAME = 'dev-secret-encryption.key';
const HEX_KEY_RE = /^[0-9a-f]{64}$/i;

function resolveDevDataDir(env, cwd) {
  const override = String(env.ASTRANULL_DEV_DATA_DIR ?? '').trim();
  if (override) return path.isAbsolute(override) ? override : path.join(cwd, override);
  return path.join(cwd, '.data');
}

export function developerSecretKeyEligibility(env = process.env) {
  if ((env.NODE_ENV ?? 'development') === 'production') return { eligible: false, reason: 'production' };
  if (resolveDeploymentProfile(env)) return { eligible: false, reason: 'deployment_profile' };
  if (String(env.ASTRANULL_SECRET_ENCRYPTION_KEY ?? '').trim()) return { eligible: false, reason: 'configured' };
  const persistenceMode = resolvePersistenceMode(env);
  if (persistenceMode === 'postgres') return { eligible: false, reason: 'postgres' };
  return { eligible: true, persistenceMode };
}

/** Developer-validation only; production, deployment profiles, Postgres, and explicit keys are untouched. */
export function ensureDeveloperSecretEncryptionKey(env = process.env, options = {}) {
  const eligibility = developerSecretKeyEligibility(env);
  if (!eligibility.eligible) return { applied: false, reason: eligibility.reason };
  const warn = options.warn ?? ((message) => console.warn(message));

  if (eligibility.persistenceMode === 'memory' || env.ASTRANULL_NO_PERSIST === '1') {
    env.ASTRANULL_SECRET_ENCRYPTION_KEY = randomBytes(32).toString('hex');
    warn('AstraNull developer mode: generated an ephemeral in-memory secret encryption key. Vault secrets will not survive a restart. Set ASTRANULL_SECRET_ENCRYPTION_KEY for anything beyond local development.');
    return { applied: true, source: 'ephemeral' };
  }

  const dataDir = resolveDevDataDir(env, options.cwd ?? process.cwd());
  const keyPath = path.join(dataDir, DEV_SECRET_KEY_FILENAME);
  let key = existsSync(keyPath) ? readFileSync(keyPath, 'utf8').trim() : '';
  let source = 'file';
  if (!HEX_KEY_RE.test(key)) {
    key = randomBytes(32).toString('hex');
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(keyPath, `${key}\n`, { encoding: 'utf8', mode: 0o600 });
    chmodSync(keyPath, 0o600);
    source = 'generated';
  }
  env.ASTRANULL_SECRET_ENCRYPTION_KEY = key;
  warn(`AstraNull developer mode: using a local secret encryption key from ${keyPath} (${source}). It is for local development only; production requires an explicit ASTRANULL_SECRET_ENCRYPTION_KEY.`);
  return { applied: true, source, keyPath };
}
