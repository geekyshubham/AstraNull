/**
 * Guards the Node major version the project builds and tests on.
 *
 * Two separate holes are covered here, and both were reachable through a green pipeline.
 *
 * 1. END-OF-LIFE / NON-LTS RUNTIMES. Node's release lines alternate: even-numbered majors
 *    (20, 22, 24) are promoted to LTS and get ~30 months of support; ODD-numbered majors
 *    (21, 23, 25) are NEVER promoted to LTS and reach end-of-life roughly eight months
 *    after release. v25 opened 2025-10-15 and was already end-of-life on 2026-06-01 —
 *    no `lts` field ever appeared for it in nodejs/Release schedule.json. Shipping an odd
 *    line therefore means running production on a runtime that will not receive security
 *    patches, and it can happen through an ordinary-looking base-image bump.
 *
 * 2. CI TESTING A DIFFERENT RUNTIME THAN IT SHIPS. `node-version` in the workflows is
 *    independent of the `FROM node:` line in the Dockerfiles. Six dependabot PRs proposed
 *    moving seven Dockerfiles to node:25-alpine; every one reported a green `verify`,
 *    because the workflows install Node 22 regardless of what the images build on. The
 *    green check was evidence about Node 22 and said nothing at all about Node 25. Any
 *    drift between the two is silent, so this test requires them to agree.
 *
 * The load-bearing part of the guard is this test, not `package.json` engines: npm treats
 * `engines` as advisory unless `engine-strict=true` is set, and there is no .npmrc in this
 * repo, so `npm ci` on an unsupported line prints a warning and succeeds. (Turning on
 * engine-strict would be a reasonable belt-and-braces addition, but it is a maintainer
 * call: it would also break local installs for anyone still on Node 20.)
 *
 * TO UPGRADE: edit ALLOWED_NODE_MAJORS below, then update the Dockerfiles and workflows to
 * match. That constant is intentionally the only knob.
 */
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/**
 * The Node majors this project is allowed to build, test or ship on.
 *
 * Both are even-numbered LTS lines: v22 (Jod) is supported to 2027-04-30, v24 (Krypton) to
 * 2028-04-30. Add the next even LTS here when upgrading; do not add an odd major to make a
 * bump pass, because an odd major is by definition a line that never becomes LTS.
 */
const ALLOWED_NODE_MAJORS = [22, 24];

/** Directories that are not ours to police. */
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.venv']);

/**
 * Every Dockerfile in the repo, found by walking the tree.
 *
 * Deliberately discovered rather than hand-listed: a hard-coded list of the seven known
 * Dockerfiles would silently exempt the eighth one somebody adds later, which is exactly
 * the kind of gap this test exists to close.
 */
function findDockerfiles(dir = REPO_ROOT, found = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) findDockerfiles(full, found);
    else if (/^Dockerfile(\..+)?$/.test(name)) found.push(path.relative(REPO_ROOT, full));
  }
  return found;
}

/**
 * Every workflow, discovered for the same reason the Dockerfiles are: a hand-listed set
 * silently exempts whatever gets added later.
 *
 * This omission was real, not hypothetical. The list used to name ci.yml,
 * deploy-aws.yml and portal-revamp.yml, leaving guardianbot.yml — the ONE workflow
 * that was already SHA-pinned, and the style model the others were pinned to match —
 * unchecked. Unpinning it to `@main` kept the suite green.
 */
function findWorkflows() {
  const dir = path.join(REPO_ROOT, '.github', 'workflows');
  return readdirSync(dir)
    .filter((name) => /\.ya?ml$/.test(name))
    .map((name) => `.github/workflows/${name}`)
    .sort();
}

const WORKFLOW_PATHS = findWorkflows();

const read = (relative) => readFileSync(path.join(REPO_ROOT, relative), 'utf8');

/**
 * Every `FROM node:<tag>` base image in one Dockerfile, with its major parsed out.
 *
 * Non-node base images (scratch, alpine, distroless) are not our concern here. A `node:`
 * image whose tag has no leading integer — `node:latest`, `node:lts-alpine` — yields a null
 * major and is reported as unpinned rather than quietly skipped: those tags float across
 * majors, so they could land on an odd line without any file in the repo changing.
 */
function nodeBaseImages(dockerfileText) {
  const images = [];
  const pattern = /^\s*FROM\s+(?:--\S+\s+)*node:(\S+)/gim;
  for (const match of dockerfileText.matchAll(pattern)) {
    const reference = match[1];
    // Strip any digest before reading the tag, so `22-alpine@sha256:...` parses as 22.
    const tag = reference.split('@')[0];
    const major = /^(\d+)/.exec(tag);
    images.push({
      reference,
      tag,
      major: major ? Number(major[1]) : null,
      digestPinned: reference.includes('@sha256:'),
    });
  }
  return images;
}

/** Every `node-version:` value declared in one workflow, quotes stripped. */
function workflowNodeVersions(workflowText) {
  return [...workflowText.matchAll(/^\s*node-version:\s*['"]?([^'"\s#]+)/gm)]
    .map((match) => match[1]);
}

const dockerfiles = findDockerfiles();

/**
 * The subset of workflows that installs Node.
 *
 * Action pinning applies to EVERY workflow, but the runtime assertions only apply where a
 * runtime is declared: guardianbot.yml delegates to a reusable workflow and sets no
 * node-version, so demanding one there would be noise. Derived rather than listed, so a new
 * Node-using workflow is covered the day it lands.
 */
const NODE_WORKFLOW_PATHS = WORKFLOW_PATHS.filter(
  (relative) => workflowNodeVersions(read(relative)).length > 0,
);

describe('node runtime version pin', () => {
  /**
   * A guard that scans nothing passes everything.
   *
   * If a refactor moves the Dockerfiles, renames them, or breaks the walk above, every
   * assertion below becomes a vacuous loop over an empty array and this file would keep
   * reporting green while guarding nothing.
   *
   * The anchor is the Dockerfile the deploy workflow actually builds, read out of the
   * workflow rather than hard-coded here, so the two cannot drift. A plain count would be
   * the weaker choice: deleting a legacy image is legitimate, and a failing count invites
   * lowering the number, which quietly shrinks the guard instead of fixing the walk.
   */
  it('discovers the Dockerfiles and workflows it claims to guard', () => {
    const compose = read('ops/aws/docker-compose.yml');
    const built = /^\s*dockerfile:\s*(\S+)/m.exec(compose);
    assert.ok(built, 'ops/aws/docker-compose.yml declares no `dockerfile:` for the image build.');
    assert.ok(
      dockerfiles.includes(built[1]),
      `the walk found ${dockerfiles.length} Dockerfile(s) (${dockerfiles.join(', ') || 'none'}) `
      + `but not ${built[1]}, the one ops/aws/docker-compose.yml builds and ships. Fix the walk: a `
      + 'scan that misses the production image makes every assertion below vacuous.',
    );
    assert.ok(WORKFLOW_PATHS.length > 0, 'the workflow walk found nothing to pin-check.');
    // NODE_WORKFLOW_PATHS is derived by filtering, so a broken node-version regex would
    // empty it and turn the runtime assertions into vacuous loops while staying green.
    assert.ok(
      NODE_WORKFLOW_PATHS.includes('.github/workflows/ci.yml'),
      `no node-version was detected in ci.yml. Node-using workflows found: `
      + `${NODE_WORKFLOW_PATHS.join(', ') || 'none'}. If the detection broke, every runtime `
      + 'assertion below is vacuous.',
    );
  });

  it('builds every image on an allowed, even-numbered Node major', () => {
    for (const relative of dockerfiles) {
      const images = nodeBaseImages(read(relative));
      for (const image of images) {
        assert.notEqual(
          image.major,
          null,
          `${relative} uses the floating base image node:${image.reference}. A tag with no `
          + 'explicit major moves across majors on its own and could land on an odd, non-LTS '
          + 'line without any change in this repo.',
        );
        assert.equal(
          image.major % 2,
          0,
          `${relative} builds on node:${image.reference}. Node ${image.major} is an ODD major: `
          + 'odd release lines are never promoted to LTS and reach end-of-life about eight '
          + 'months after release, so they stop receiving security patches. Use an even LTS '
          + `line (${ALLOWED_NODE_MAJORS.join(' or ')}).`,
        );
        assert.ok(
          ALLOWED_NODE_MAJORS.includes(image.major),
          `${relative} builds on node:${image.reference}, which is outside the allowed set `
          + `[${ALLOWED_NODE_MAJORS.join(', ')}]. If Node ${image.major} is a supported even `
          + 'LTS line you actually intend to move to, add it to ALLOWED_NODE_MAJORS in this '
          + 'test and update the workflows in the same change.',
        );
      }
    }
  });

  it('installs an allowed, even-numbered Node major in every workflow', () => {
    for (const relative of NODE_WORKFLOW_PATHS) {
      for (const version of workflowNodeVersions(read(relative))) {
        const major = /^(\d+)/.exec(version);
        assert.ok(
          major,
          `${relative} sets node-version: ${version}, which names no explicit major. `
          + '"lts/*" and "latest" resolve differently over time, so CI would silently move '
          + 'between runtimes.',
        );
        const value = Number(major[1]);
        assert.equal(
          value % 2,
          0,
          `${relative} sets node-version: ${version}. Node ${value} is an ODD major and will `
          + 'never become LTS, so CI would be validating against a runtime that goes '
          + 'end-of-life within months.',
        );
        assert.ok(
          ALLOWED_NODE_MAJORS.includes(value),
          `${relative} sets node-version: ${version}, outside the allowed set `
          + `[${ALLOWED_NODE_MAJORS.join(', ')}].`,
        );
      }
    }
  });

  /**
   * The consistency rule, and the one that would have caught the node:25 PRs.
   *
   * Those PRs changed only the Dockerfiles. CI kept installing Node 22, so `verify` passed
   * on a runtime the merged artifact would not have used — a green check that carried no
   * evidence about the runtime being shipped. Requiring one single major across images and
   * workflows means a base-image bump cannot be merged until CI is actually running on it.
   */
  it('tests on the same Node major it ships, across every image and workflow', () => {
    // Collected as a flat list of (label, major) pairs, NOT a Map keyed by file path. A Map
    // would let each later `FROM node:` line overwrite the earlier one, so a multi-stage
    // Dockerfile whose builder stage ran a different major than its final stage would pass
    // while genuinely drifting. Every stage is its own entry, labelled by index.
    const entries = [];
    for (const relative of dockerfiles) {
      const images = nodeBaseImages(read(relative));
      images.forEach((image, index) => {
        if (image.major == null) return;
        const label = images.length > 1 ? `${relative}[stage ${index + 1}]` : relative;
        entries.push([label, image.major]);
      });
    }
    for (const relative of NODE_WORKFLOW_PATHS) {
      const versions = workflowNodeVersions(read(relative));
      versions.forEach((version, index) => {
        const major = /^(\d+)/.exec(version);
        if (!major) return;
        const label = versions.length > 1 ? `${relative}[#${index + 1}]` : relative;
        entries.push([label, Number(major[1])]);
      });
    }

    const distinct = new Set(entries.map(([, major]) => major));
    assert.equal(
      distinct.size,
      1,
      'Node major drifted between the images and the workflows that test them: '
      + `${entries.map(([f, m]) => `${f}=${m}`).join(', ')}. `
      + 'CI would be producing green checks about a runtime the deployed image does not use.',
    );
  });

  /**
   * Tag-only base images are mutable: `node:22-alpine` is republished continuously, so two
   * builds of the same commit can contain different bytes. Digest pinning is what makes the
   * image the AWS VM builds from ops/aws/Dockerfile mean anything.
   */
  it('pins every node base image to a digest, not just a tag', () => {
    for (const relative of dockerfiles) {
      for (const image of nodeBaseImages(read(relative))) {
        assert.ok(
          image.digestPinned,
          `${relative} uses node:${image.reference} with no @sha256: digest. The tag is `
          + 'republished upstream, so the same commit would not rebuild to the same image.',
        );
      }
    }
  });
});

/**
 * Third-party actions must resolve through immutable commit SHAs.
 *
 * `actions/checkout@v4` is a tag, and a tag is a pointer its owner can move at any time.
 * tj-actions/changed-files (March 2025) is the worked example: a retargeted tag exfiltrated
 * secrets from every workflow that referenced it by major version.
 *
 * The deploy job is the one that matters most. It holds ASTRANULL_AWS_SSH_KEY, so a
 * retargeted action tag would get a shell on the production VM. Signature verification
 * cannot be stronger than the actions that produce the deploy.
 */
describe('workflow action pinning', () => {
  /** `uses:` lines that resolve within GitHub-hosted refs, i.e. everything but ./local paths. */
  function externalUses(workflowText) {
    return [...workflowText.matchAll(/^\s*(?:-\s+)?uses:\s*(\S+)/gm)]
      .map((match) => match[1])
      // `./` resolves inside this repo, so there is no third party to pin. `docker://` names
      // a container image, which carries a tag or its own image digest and cannot take a git
      // commit SHA — demanding one would be an unsatisfiable failure.
      .filter((reference) => !reference.startsWith('./') && !reference.startsWith('docker://'));
  }

  it('pins every third-party action to a full commit SHA', () => {
    for (const relative of WORKFLOW_PATHS) {
      const references = externalUses(read(relative));
      for (const reference of references) {
        const ref = reference.split('@')[1];
        assert.ok(
          ref && /^[0-9a-f]{40}$/.test(ref),
          `${relative} resolves ${reference} through a mutable ref. Pin it to the full 40-char `
          + 'commit SHA with a trailing `# vN.N.N` comment (resolve with '
          + '`gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`); dependabot keeps SHA pins '
          + 'updated via the github-actions ecosystem in .github/dependabot.yml.',
        );
      }
    }
  });

  /**
   * Workflows written by a generator, identified by their own header marker.
   *
   * .github/workflows/guardianbot.yml carries "Generated by guardianctl" and the git history
   * has repeated "chore(guardianbot): regenerate pinned workflow" commits, so anything added
   * to it by hand is overwritten on the next regeneration. Requiring a trailing version
   * comment there would go red on a file this repository cannot durably fix.
   *
   * Only the COMMENT requirement is relaxed. The SHA pin itself — the property that actually
   * stops a moving tag from executing in a credentialed job — still applies to every
   * workflow, generated or not, and guardianbot.yml already satisfies it.
   */
  const isGenerated = (relative) => /^#.*\bGenerated by\b/im.test(read(relative));

  it('records the human-readable version beside each pin', () => {
    // A bare SHA is safe but unreviewable: nobody can tell v4.4.0 from an arbitrary commit.
    // The trailing comment is also what dependabot rewrites when it proposes a bump.
    const reviewable = WORKFLOW_PATHS.filter((relative) => !isGenerated(relative));
    assert.ok(
      reviewable.length > 0,
      'every workflow looks generated, so this assertion checks nothing — verify isGenerated.',
    );
    for (const relative of reviewable) {
      const lines = read(relative).split('\n')
        .filter((line) => /^\s*(?:-\s+)?uses:\s*\S+@[0-9a-f]{40}/.test(line));
      for (const line of lines) {
        assert.match(
          line,
          /@[0-9a-f]{40}\s+#\s*v?\d+\.\d+/,
          `${relative}: ${line.trim()} has no trailing version comment, so the pinned SHA `
          + 'cannot be reviewed or upgraded by hand.',
        );
      }
    }
  });
});
