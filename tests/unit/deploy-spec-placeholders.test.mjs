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
import { ROLES } from '../../src/contracts/roles.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
/** The spec the deploy action actually applies. */
const SPEC_PATH = '.do/app.yaml';
/**
 * Both app specs. `.do/app.yaml` deploys the prebuilt image; `ops/digitalocean/app.yaml` is the
 * build-from-source variant. They declare the same env contract and drift silently, so the
 * value-shape rules below are asserted against both.
 */
const SPEC_PATHS = [SPEC_PATH, 'ops/digitalocean/app.yaml'];
/**
 * The spec applied by hand, per its own header:
 * `doctl apps create --spec ops/digitalocean/app.yaml`.
 *
 * doctl reads the file off disk, so the operator's shell never expands anything, and no action
 * substitutes into it either — app_action is pinned to SPEC_PATH (asserted below).
 *
 * Whether doctl performs any `${VAR}` substitution of its own is NOT verified here; it is not
 * believed to, but nothing in this repo executes it. The rules below are written so the answer
 * does not matter: a placeholder on this path is only ever safe if an operator sets the real
 * value on the app, so what is pinned is that the spec does not grow new placeholders and that
 * the one it keeps carries the instructions for setting it.
 */
const DOCTL_SPEC_PATH = 'ops/digitalocean/app.yaml';
const FIXTURE_KEY = 'ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON';
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
 * The contiguous `#` comment block immediately above a `- key: NAME` line.
 *
 * `envEntry` deliberately starts AT the key line, so it captures the interleaved notes but not
 * the leading ones. Reading upward from the key — rather than searching the whole file — is what
 * makes "the warning is attached to THIS entry" the thing being asserted.
 *
 * @returns {string} '' when the key is absent or carries no leading comment.
 */
function commentBlockAbove(specText, key) {
  const lines = specText.split('\n');
  const startIndex = lines.findIndex((line) =>
    new RegExp(`^\\s*-\\s+key:\\s*${key}\\s*$`).test(line));
  if (startIndex === -1) return '';

  const block = [];
  for (let i = startIndex - 1; i >= 0; i -= 1) {
    if (!lines[i].trim().startsWith('#')) break;
    block.unshift(lines[i]);
  }
  return block.join('\n');
}

/**
 * A spec with whole-line `#` comments removed, so only lines App Platform actually reads remain.
 *
 * Used for the doctl placeholder scan below. `envPlaceholders` is deliberately left scanning raw
 * text for SPEC_PATH — over-reporting a `${FOO}` that appears only in prose there is harmless,
 * it just forces the workflow to pass FOO. But these specs' comments now quote `${VAR}` while
 * EXPLAINING placeholder substitution, and flagging documentation as a deployed value would make
 * the doctl assertion fail for a reason that has nothing to do with what gets deployed.
 * Trailing inline comments are not stripped: a `#` inside a quoted value is legal YAML and
 * cutting at it would corrupt the value.
 */
function directiveLines(specText) {
  return specText
    .split('\n')
    .filter((line) => !line.trim().startsWith('#'))
    .join('\n');
}

/** An env entry with comment lines dropped and indentation collapsed, for cross-spec comparison. */
function envEntryDirectives(specText, key) {
  const entry = envEntry(specText, key);
  if (entry == null) return null;
  return entry
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#'))
    .join('\n');
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

  /**
   * The same silent-overwrite failure as above, on the path the passthrough test cannot cover.
   *
   * That test reads SPEC_PATH only, because the workflow env is what fills SPEC_PATH's
   * placeholders. DOCTL_SPEC_PATH has no such backstop: its header documents it as applied by
   * hand, and no substitution step exists for it anywhere in the repo. A `${VAR}` added here is
   * therefore shipped literally, and for a SECRET that means the app takes an unusable value —
   * fail-closed startup on `apps update` (previous revision keeps serving), never booting at all
   * on `apps create`.
   *
   * The fixture key is allowlisted rather than removed: the entry has to stay declared and
   * single-quoted for the two tests above, so the placeholder is load-bearing as a marker. What
   * makes it safe is the operator note pinned by the next test, not its absence.
   */
  it('adds no unfillable placeholder to the hand-applied doctl spec', () => {
    const unfillable = envPlaceholders(directiveLines(read(DOCTL_SPEC_PATH)))
      .filter((name) => name !== FIXTURE_KEY);
    assert.deepEqual(
      unfillable,
      [],
      `${DOCTL_SPEC_PATH} interpolates ${unfillable.join(', ')}, but nothing substitutes into it: `
      + `doctl applies the file verbatim and app_action is pinned to ${SPEC_PATH}. The literal `
      + 'template would be deployed as the value. Set it on the app instead, or hard-code it here.',
    );
  });

  it('warns the operator that the doctl path leaves the fixture placeholder unfilled', () => {
    // Load-bearing, not decorative: the allowlist above only holds because an operator following
    // this spec's header is told the placeholder is inert and where to put the real secret.
    // Asserted on the comment block attached to the entry, so a note buried elsewhere in the file
    // (or in the other spec) cannot satisfy it.
    const note = commentBlockAbove(read(DOCTL_SPEC_PATH), FIXTURE_KEY);
    assert.match(
      note,
      /doctl/,
      `${DOCTL_SPEC_PATH}: the ${FIXTURE_KEY} note must state that the doctl path does not fill `
      + 'the placeholder.',
    );
    assert.match(
      note,
      /app_spec_location|app_action/,
      `${DOCTL_SPEC_PATH}: the ${FIXTURE_KEY} note must record that the substituting action is `
      + `pinned to ${SPEC_PATH}, so this spec never gets substituted.`,
    );
    assert.match(
      note,
      /dashboard/i,
      `${DOCTL_SPEC_PATH}: the ${FIXTURE_KEY} note must tell the operator to set the secret on the `
      + 'app (DO dashboard) rather than relying on shell or CLI expansion.',
    );
  });

  /**
   * `npm run do:bootstrap` applies DOCTL_SPEC_PATH too, and it edits the file by string match.
   *
   * scripts/digitalocean-bootstrap.mjs appends ASTRANULL_SECRET_ENCRYPTION_KEY and
   * ASTRANULL_PROBE_WORKER_SECRET by replacing one exact comment line in this spec, then hands the
   * result to `doctl apps create/update`. `String.replace` with a string needle is a silent no-op
   * when it misses: reword or reindent that line and the script still runs, still reports success,
   * and creates an app with no encryption key and no probe secret. Editing the comments in this
   * spec is exactly how that anchor gets broken, which is why the guard lives here.
   *
   * The anchor is read out of the script rather than restated, so this observes the shipped needle.
   */
  it('keeps the anchor line the bootstrap script patches secrets into', () => {
    const script = read('scripts/digitalocean-bootstrap.mjs');
    const anchor = /\breplace\(\s*'((?:[^'\\]|\\.)*)'/.exec(script)?.[1];
    assert.ok(
      anchor,
      'could not find the string literal that scripts/digitalocean-bootstrap.mjs replaces. If the '
      + 'script was refactored, update this guard — do not delete it: a missed anchor makes the '
      + 'script skip both secrets silently.',
    );
    assert.ok(
      read(DOCTL_SPEC_PATH).includes(anchor),
      `${DOCTL_SPEC_PATH} no longer contains the line scripts/digitalocean-bootstrap.mjs patches `
      + `(${JSON.stringify(anchor)}), so \`npm run do:bootstrap\` would deploy with no `
      + 'ASTRANULL_SECRET_ENCRYPTION_KEY and no ASTRANULL_PROBE_WORKER_SECRET, and report success.',
    );
  });

  it('keeps the fixture entry byte-identical across both specs', () => {
    // These specs drift silently — that is why the rules here run over both. This pins the entry
    // as a whole rather than one field at a time, so a change to scope/type/value in one spec
    // cannot land without the other. Comments are excluded: the doctl spec carries a warning that
    // is deliberately absent from the action-applied spec, which does get substituted.
    assert.equal(
      envEntryDirectives(read(DOCTL_SPEC_PATH), FIXTURE_KEY),
      envEntryDirectives(read(SPEC_PATH), FIXTURE_KEY),
      `${FIXTURE_KEY} differs between ${SPEC_PATH} and ${DOCTL_SPEC_PATH}. Whichever spec is `
      + 'applied must configure the auth trust root identically.',
    );
  });

  it('never inlines private key material in either spec', () => {
    for (const relative of [SPEC_PATH, 'ops/digitalocean/app.yaml']) {
      assert.doesNotMatch(read(relative), /-----BEGIN [A-Z ]*PRIVATE KEY-----/, relative);
    }
  });

  /** The `value:` of an env entry, with YAML's optional surrounding quotes removed. */
  function envValue(specText, key) {
    const entry = envEntry(specText, key);
    if (entry == null) return null;
    const line = entry.split('\n').find((candidate) => /^\s*value:/.test(candidate));
    if (!line) return null;
    return line.replace(/^\s*value:\s*/, '').trim().replace(/^'(.*)'$/, '$1').replace(/^"(.*)"$/, '$1');
  }

  /**
   * The role map is load-bearing for login, not cosmetic.
   *
   * `config.mjs` sets `requireExplicitRoleMap` whenever NODE_ENV=production — including the
   * hosted-staging profile, which used to be exempt. `pickRole` then skips every candidate that the
   * map does not name, so with this entry missing NO token resolves a role and every sign-in fails
   * with `invalid_role`. Deleting it from a spec is therefore a full auth outage on the next deploy,
   * and the deploy would look green: startup does not read the map, so /health and /ready still pass.
   */
  it('maps every platform role in both specs, because production resolves roles only through the map', () => {
    for (const relative of SPEC_PATHS) {
      const raw = envValue(read(relative), 'ASTRANULL_OIDC_ROLE_MAP');
      assert.ok(
        raw,
        `${relative} must set ASTRANULL_OIDC_ROLE_MAP. Production enables requireExplicitRoleMap, `
        + 'so without it pickRole resolves nothing and every login fails with invalid_role.',
      );
      const mapped = new Set(
        raw.split(',').map((entry) => entry.split(':')[1]?.trim()).filter(Boolean),
      );
      const missing = ROLES.filter((role) => !mapped.has(role));
      assert.deepEqual(
        missing,
        [],
        `${relative}: ASTRANULL_OIDC_ROLE_MAP omits ${missing.join(', ')} — users holding those `
        + 'roles could not sign in.',
      );
    }
  });

  /**
   * The staff map's ABSENCE is the control, so this guards against "completing" the config.
   *
   * Staff authority over /internal/admin is not tenant-scoped. With no staff map configured and
   * requireExplicitRoleMap on, `pickStaffRole` refuses every `staff_role` claim — which is what
   * retires the staff bearers minted before the bundled staff-login mint was closed. Adding an
   * identity staff map here would make an attacker-chosen claim value authoritative again and
   * reopen exactly that hole. Staff roles must come from a real IdP instead.
   */
  it('sets no staff role map in either spec, keeping staff role resolution fail-closed', () => {
    for (const relative of SPEC_PATHS) {
      assert.equal(
        envEntry(read(relative), 'ASTRANULL_OIDC_STAFF_ROLE_MAP'),
        null,
        `${relative} must NOT set ASTRANULL_OIDC_STAFF_ROLE_MAP: it would let a staff_role token `
        + 'claim resolve to platform staff authority, reopening the anonymous internal_admin path.',
      );
    }
  });
});
