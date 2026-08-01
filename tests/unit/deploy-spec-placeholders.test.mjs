/**
 * Guards the DigitalOcean deploy against a silently unfilled spec placeholder.
 *
 * `digitalocean/app_action/deploy@v2` REPLACES the entire app spec with `.do/app.yaml`,
 * substituting `${VAR}` from the deploy step's `env:` block. A placeholder with no matching
 * env var does not fail the action — it reaches the container as an empty string or as the
 * literal `${VAR}`, and it overwrites whatever value the live app previously held.
 *
 * That is how the OIDC signing-key rotation was staged to fail: `.do/app.yaml` declared
 * `ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON` as a SECRET, but the workflow never passed it.
 * The deploy would have shipped a `${...}` template as the auth trust root, the container would
 * have failed closed at startup, App Platform would have rejected the rollout, and the previous
 * revision — serving the key published in this repo's public git history — would have kept
 * running. A green pipeline, a live site, and the vulnerability still open.
 *
 * Setting the value by hand on the live app does not help either: the next deploy replaces the
 * spec and erases it. The workflow is the only durable place for it.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
/** The spec the deploy action actually applies. */
const SPEC_PATH = '.do/app.yaml';
/**
 * Both app specs. `.do/app.yaml` deploys the prebuilt image; `ops/digitalocean/app.yaml` is the
 * build-from-source variant. They declare the same env contract and drift silently, so the
 * value-shape rules below are asserted against both.
 */
const SPEC_PATHS = [SPEC_PATH, 'ops/digitalocean/app.yaml'];
const WORKFLOW_PATH = '.github/workflows/deploy-digitalocean.yml';
const DEPLOY_STEP_NAME = 'Deploy to App Platform';

const read = (relative) => readFileSync(path.join(repoRoot, relative), 'utf8');

/**
 * The full YAML block for one `- key: NAME` env entry, comments included.
 *
 * The entry runs until the next line indented at or above the `-` marker, so `scope:`, `type:`,
 * `value:` and any interleaved comments all belong to it.
 *
 * @returns {string | null} null when the spec does not declare the key at all.
 */
function envEntry(specText, key) {
  const lines = specText.split('\n');
  const startIndex = lines.findIndex((line) =>
    new RegExp(`^\\s*-\\s+key:\\s*${key}\\s*$`).test(line));
  if (startIndex === -1) return null;

  const markerIndent = lines[startIndex].indexOf('-');
  const block = [lines[startIndex]];
  for (let i = startIndex + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.trim() === '') continue;
    if (line.search(/\S/) <= markerIndent) break;
    block.push(line);
  }
  return block.join('\n');
}

/**
 * Placeholders the deploy step must supply from `env:`.
 *
 * `${resource.KEY}` (e.g. `${astranull-db.DATABASE_URL}`) is excluded: those are App Platform
 * bindings resolved by the platform itself, not by the action's env substitution.
 */
function envPlaceholders(specText) {
  const found = [...specText.matchAll(/\$\{([A-Za-z0-9_.-]+)\}/g)].map((match) => match[1]);
  return [...new Set(found.filter((name) => !name.includes('.')))].sort();
}

/**
 * Env keys declared on the deploy step only.
 *
 * Scoped to that step deliberately: a name that merely appears somewhere else in the workflow
 * (a build arg, another job) is not passed to the action and must not satisfy the guard.
 */
function deployStepEnvKeys(workflowText) {
  const lines = workflowText.split('\n');
  const stepIndex = lines.findIndex((line) => line.trim() === `- name: ${DEPLOY_STEP_NAME}`);
  assert.notEqual(stepIndex, -1, `no "${DEPLOY_STEP_NAME}" step found in ${WORKFLOW_PATH}`);

  const stepIndent = lines[stepIndex].indexOf('-');
  let envIndex = -1;
  for (let i = stepIndex + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.trim() === '' || line.trim().startsWith('#')) continue;
    const indent = line.search(/\S/);
    // Dedent to the step marker means this step ended without an env: block.
    if (indent <= stepIndent) break;
    if (line.trim() === 'env:') {
      envIndex = i;
      break;
    }
  }
  assert.notEqual(envIndex, -1, `"${DEPLOY_STEP_NAME}" step declares no env: block`);

  const envIndent = lines[envIndex].search(/\S/);
  const keys = [];
  for (let i = envIndex + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.trim() === '' || line.trim().startsWith('#')) continue;
    if (line.search(/\S/) <= envIndent) break;
    const key = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:/.exec(line);
    if (key) keys.push(key[1]);
  }
  return keys.sort();
}

describe('digitalocean deploy spec placeholders', () => {
  const spec = read(SPEC_PATH);
  const workflow = read(WORKFLOW_PATH);

  it('passes every spec placeholder through the deploy step env', () => {
    const required = envPlaceholders(spec);
    const provided = new Set(deployStepEnvKeys(workflow));
    const missing = required.filter((name) => !provided.has(name));
    assert.deepEqual(
      missing,
      [],
      `${SPEC_PATH} interpolates ${missing.join(', ')} but the "${DEPLOY_STEP_NAME}" step does `
      + 'not pass them. The deploy would overwrite the live value with an unfilled template.',
    );
  });

  it('reads the spec the workflow actually deploys', () => {
    // A guard pointed at the wrong file proves nothing, so pin the action's input.
    assert.match(workflow, /app_spec_location:\s*\.do\/app\.yaml/);
  });

  it('sources the OIDC signing key from a secret, never a literal', () => {
    // The whole point of the rotation: the key must not be readable in the repo.
    for (const relative of SPEC_PATHS) {
      const entry = envEntry(read(relative), 'ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON');
      assert.ok(entry, `${relative} must declare ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON`);
      assert.match(entry, /type: SECRET/, relative);
      assert.doesNotMatch(entry, /PRIVATE KEY/, relative);
    }
  });

  /**
   * The fixture is JSON, so substitution yields a value starting with `{`.
   *
   * app_action substitutes textually, and unquoted YAML parses a leading `{` as a flow
   * mapping rather than a string. App Platform then rejects the entire spec:
   *
   *   cannot unmarshal object into Go struct field
   *   AppVariableDefinition.services.envs.value of type string
   *
   * That killed deploy run 30693505011 after the image had already been built, signed and
   * pushed. Single quotes make it a YAML string and keep the JSON's `"` and the PEM's
   * escaped `\n` literal.
   */
  it('single-quotes any placeholder whose value is JSON', () => {
    for (const relative of SPEC_PATHS) {
      const entry = envEntry(read(relative), 'ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON');
      const valueLine = entry.split('\n').find((line) => /^\s*value:/.test(line)) ?? '';
      assert.match(
        valueLine,
        /value:\s*'\$\{ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON\}'\s*$/,
        `${relative}: the fixture placeholder must be single-quoted, or App Platform parses `
        + 'the substituted JSON as a YAML mapping and rejects the spec.',
      );
    }
  });

  it('never inlines private key material in either spec', () => {
    for (const relative of [SPEC_PATH, 'ops/digitalocean/app.yaml']) {
      assert.doesNotMatch(read(relative), /-----BEGIN [A-Z ]*PRIVATE KEY-----/, relative);
    }
  });
});
