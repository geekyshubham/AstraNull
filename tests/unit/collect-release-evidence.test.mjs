import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  PRODUCTION_RELEASE_EVIDENCE_KINDS,
  validateProductionReleaseEvidence,
} from '../../src/contracts/productionReleaseEvidence.mjs';
import {
  RELEASE_EVIDENCE_COLLECTORS,
  buildCollectionContext,
  buildCollectorCommand,
  buildRecordsPayload,
  collectReleaseEvidence,
  extractProductionReleaseRecord,
  main,
  parseArgs,
  runCollector,
  validateCollectedRecord,
  validateUiAccessibilityCollectorAcceptance,
} from '../../scripts/collect-release-evidence.mjs';
import {
  adaptContractEvidence,
  buildCollectorScriptInput,
} from '../../scripts/lib/releaseEvidenceCollectorInputs.mjs';
import {
  REQUIRED_PAGES,
  createUiAccessibilityMatrixArtifact,
} from '../../scripts/ui-accessibility-matrix-evidence.mjs';
import { createReleaseEvidenceBundle } from '../../scripts/release-evidence-bundle.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-collect-evidence-'));
  tempDirs.push(dir);
  return dir;
}

function liveUiAccessibilityMatrix() {
  const runs = REQUIRED_PAGES.flatMap((page) => ['desktop', 'mobile'].map((viewport) => ({
    page,
    viewport,
    browser: 'chromium',
    axe_status: 'pass',
    keyboard_status: 'pass',
    screen_reader_status: 'pass',
    issues: { critical: 0, serious: 0, moderate: 0, minor: 0 },
    captured_at: '2026-08-30T12:00:00.000Z',
    notes: 'axe executed; keyboard traversal executed; screen-reader semantics executed',
  })));
  return {
    schema_version: 1,
    artifact_type: 'ui_accessibility_matrix_input',
    environment: 'staging',
    evidence_uri: 'evidence://ui/accessibility-matrix/staging',
    runs,
    pages: Object.fromEntries(REQUIRED_PAGES.map((page) => [
      page,
      { runs: runs.filter((run) => run.page === page) },
    ])),
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('collect release evidence orchestrator', () => {
  it('parses defaults and explicit CLI arguments', () => {
    assert.deepEqual(parseArgs([]), {
      outDir: 'output/release-evidence',
      releaseId: 'rel-staging-sim-2026-07-03',
      environment: 'staging-sim',
      dryRun: false,
      continueOnError: false,
      help: false,
    });
    assert.deepEqual(parseArgs([
      '--out-dir',
      'tmp/out',
      '--release-id',
      'rel_custom',
      '--environment',
      'staging-sim',
      '--dry-run',
    ]), {
      outDir: 'tmp/out',
      releaseId: 'rel_custom',
      environment: 'staging-sim',
      dryRun: true,
      continueOnError: false,
      help: false,
    });
    assert.throws(() => parseArgs(['--unknown']), /Unknown argument/);
  });

  it('defines collectors for every production release evidence kind', () => {
    assert.equal(RELEASE_EVIDENCE_COLLECTORS.length, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
    const kinds = new Set(RELEASE_EVIDENCE_COLLECTORS.map((entry) => entry.kind));
    for (const kind of PRODUCTION_RELEASE_EVIDENCE_KINDS) {
      assert.ok(kinds.has(kind), `missing collector for ${kind}`);
    }
  });

  it('builds npm/node commands with --out paths', () => {
    const outDir = tempDir();
    const context = buildCollectionContext({
      outDir,
      releaseId: 'rel_test',
      environment: 'staging-sim',
    });
    const migration = RELEASE_EVIDENCE_COLLECTORS.find((entry) => entry.kind === 'migration_apply');
    const command = buildCollectorCommand(migration, context);
    assert.equal(command.command, process.execPath);
    assert.ok(command.args.includes('--out'));
    assert.ok(command.artifactPath.endsWith('migration_apply.json'));
    assert.ok(command.args.includes('--environment'));
    assert.ok(command.args.includes('staging-sim'));
  });

  it('extracts production release records without rehearsal_only', () => {
    const context = buildCollectionContext({
      releaseId: 'rel_extract',
      environment: 'staging-sim',
    });
    const record = extractProductionReleaseRecord('migration_apply', {
      production_release_evidence: {
        kind: 'migration_apply',
        evidence: adaptContractEvidence('migration_apply', context),
      },
    }, context);
    assert.equal(record.kind, 'migration_apply');
    assert.equal(record.status, 'accepted');
    assert.equal(record.release_id, 'rel_extract');
    assert.equal(record.rehearsal_only, undefined);
    validateCollectedRecord(record);
  });

  it('dry-run mode collects all kinds without executing subprocesses', async () => {
    const outDir = tempDir();
    let invoked = 0;
    const summary = await collectReleaseEvidence({
      outDir,
      releaseId: 'rel_dry_run',
      environment: 'staging-sim',
      dryRun: true,
      runCommand: () => {
        invoked += 1;
        return { status: 1, stdout: '', stderr: 'should not run' };
      },
    });

    assert.equal(invoked, 0);
    assert.equal(summary.kindsCollected, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
    assert.equal(summary.kindsFailed, 0);
    assert.ok(existsSync(summary.recordsPath));

    const payload = JSON.parse(readFileSync(summary.recordsPath, 'utf8'));
    assert.equal(payload.release_id, 'rel_dry_run');
    assert.equal(payload.environment, 'staging-sim');
    assert.equal(payload.rehearsal_only, undefined);
    assert.equal(payload.records.length, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);

    assert.equal(payload.dry_run, true);
    assert.equal(payload.submittable, false);
    const uiRecord = payload.records.find((record) => record.kind === 'ui_accessibility_matrix');
    assert.ok(uiRecord);
    assert.ok(uiRecord.evidence.runs.every((run) => run.axe_status === 'fail'));
    assert.ok(uiRecord.evidence.runs.every((run) => run.keyboard_status === 'fail'));
    assert.ok(uiRecord.evidence.runs.every((run) => run.screen_reader_status === 'fail'));

    for (const record of payload.records) {
      assert.equal(record.status, 'draft');
      assert.equal(record.submittable, false);
      assert.equal(record.dry_run, true);
      assert.notEqual(record.rehearsal_only, true);
      const validation = validateProductionReleaseEvidence(record.kind, record.evidence);
      assert.equal(validation.ok, true, `${record.kind} should be contract-valid`);
    }
  });

  it('dry-run local-staging does not fabricate a passed staging E2E matrix', async () => {
    const outDir = tempDir();
    await assert.rejects(() => collectReleaseEvidence({
      outDir,
      releaseId: 'rel-local-staging-2026-07-03',
      environment: 'local-staging',
      dryRun: true,
      runCommand: () => ({ status: 1, stdout: '', stderr: 'should not run' }),
    }), /staging_e2e_matrix record failed contract validation/);

    const artifactPath = path.join(outDir, 'staging_e2e_matrix.json');
    const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
    assert.equal(artifact.overall_status, 'incomplete');
    assert.ok(artifact.scenarios.some((scenario) => scenario.status === 'not_run'));
  });

  it('runCollector dry-run writes per-kind artifacts and records', () => {
    const outDir = tempDir();
    const context = buildCollectionContext({
      outDir,
      dryRun: true,
      environment: 'staging-sim',
    });
    const collector = RELEASE_EVIDENCE_COLLECTORS.find((entry) => entry.kind === 'operator_runbook_exercise');
    const result = runCollector(collector, context);
    assert.equal(result.ok, true);
    assert.equal(result.dryRun, true);
    assert.ok(existsSync(result.artifactPath));
    assert.equal(result.record.kind, 'operator_runbook_exercise');
    assert.equal(result.record.evidence.environment, 'staging-sim');
  });

  it('builds third_party_security_review input from contract evidence, not operator runbook live input', () => {
    const context = buildCollectionContext({
      outDir: tempDir(),
      environment: 'staging',
      releaseId: 'rel-hosted-staging-2026-07-03',
    });
    const { input } = buildCollectorScriptInput('third_party_security_review', context);
    assert.equal(input.reviewer_org, 'Independent Security Review Co');
    assert.ok(input.review_report_uri);
    assert.equal(input.environment, undefined);
  });

  it('builds local-staging E2E matrix input as pending until executed matrix exists', () => {
    const context = buildCollectionContext({
      outDir: tempDir(),
      environment: 'local-staging',
      releaseId: 'rel-local-staging-2026-07-03',
    });
    const { input } = buildCollectorScriptInput('staging_e2e_matrix', context);
    const byId = new Map(input.scenarios.map((scenario) => [scenario.scenario_id, scenario]));

    for (const scenarioId of [
      'oidc_login',
      'signed_agent_registration',
      'signed_probe_worker',
      'safe_validation_loop',
      'verdict_explanation',
      'report_export_custody',
      'soc_high_scale_governance',
    ]) {
      assert.equal(byId.get(scenarioId).status, 'not_run', `${scenarioId} should be pending`);
    }
  });

  it('fails closed when staging accessibility live input is absent', () => {
    const outDir = tempDir();
    const context = buildCollectionContext({
      outDir,
      environment: 'staging',
      releaseId: 'rel_staging_missing_ui',
      continueOnError: true,
      createdAt: '2026-08-30T12:05:00.000Z',
    });
    const built = buildCollectorScriptInput('ui_accessibility_matrix', context);

    assert.equal(built.inputSource, 'pending-live-ui-accessibility-matrix');
    assert.equal(built.input.runs.length, REQUIRED_PAGES.length * 2);
    for (const run of built.input.runs) {
      assert.equal(run.axe_status, 'fail');
      assert.equal(run.keyboard_status, 'fail');
      assert.equal(run.screen_reader_status, 'fail');
      assert.match(run.notes, /not_run:.*pending/);
      assert.equal(Object.values(run).includes('pass'), false);
    }

    const acceptance = validateUiAccessibilityCollectorAcceptance(built.input, {
      requireRunnerSource: true,
      inputSource: built.inputSource,
      environment: context.environment,
    });
    assert.equal(acceptance.ok, false);
    assert.ok(acceptance.source_errors.includes('input_source'));
    assert.ok(acceptance.incomplete_checks.some((field) => field.endsWith('.axe_status')));

    const pendingArtifact = createUiAccessibilityMatrixArtifact({
      evidence: built.input,
      createdAt: context.createdAt,
    });
    const pendingRecord = extractProductionReleaseRecord(
      'ui_accessibility_matrix',
      pendingArtifact,
      context,
    );
    assert.equal(pendingRecord.status, 'draft');
    assert.equal(pendingRecord.submittable, false);
    assert.throws(
      () => validateCollectedRecord(pendingRecord, { requireSubmittable: true }),
      /requires completed, passed live checks/,
    );

    const forgedAcceptedRecord = {
      ...pendingRecord,
      status: 'accepted',
      submittable: undefined,
    };
    assert.throws(
      () => validateCollectedRecord(forgedAcceptedRecord, { requireSubmittable: true }),
      /requires completed, passed live checks/,
    );

    const completeRecords = PRODUCTION_RELEASE_EVIDENCE_KINDS.map((kind) => (
      kind === 'ui_accessibility_matrix'
        ? pendingRecord
        : {
          kind,
          evidence: adaptContractEvidence(kind, context),
          status: 'accepted',
          release_id: context.releaseId,
        }
    ));
    const payload = buildRecordsPayload(completeRecords, context);
    assert.equal(payload.records.length, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
    assert.equal(payload.collection_complete, false);
    assert.equal(payload.submittable, false);
    assert.throws(() => createReleaseEvidenceBundle(payload), /non-submittable/);

    const forgedPayload = buildRecordsPayload(
      completeRecords.map((record) => (
        record.kind === 'ui_accessibility_matrix' ? forgedAcceptedRecord : record
      )),
      context,
    );
    assert.equal(forgedPayload.collection_complete, false);
    assert.equal(forgedPayload.submittable, false);

    let invoked = 0;
    const collector = RELEASE_EVIDENCE_COLLECTORS.find((entry) => entry.kind === 'ui_accessibility_matrix');
    const result = runCollector(collector, context, {
      runCommand: () => {
        invoked += 1;
        return { status: 0, stdout: '', stderr: '' };
      },
    });
    assert.equal(invoked, 0);
    assert.equal(result.ok, false);
    assert.equal(result.record, undefined);
    assert.match(result.error, /requires completed, passed output/);
  });

  it('rejects malformed and issue-bearing live accessibility files despite forged provenance', () => {
    const cases = [
      {
        name: 'duplicate 13th pair',
        mutate(matrix) {
          matrix.runs.push(structuredClone(matrix.runs[0]));
        },
        expectedProblem: 'duplicate_pair:dashboard:desktop',
      },
      {
        name: 'not_run browser',
        mutate(matrix) {
          matrix.runs[0].browser = 'not_run';
        },
        expectedProblem: 'runs[0].browser',
      },
      {
        name: 'moderate issue',
        mutate(matrix) {
          matrix.runs[0].issues.moderate = 1;
        },
        expectedProblem: 'runs[0].issues.moderate',
      },
      {
        name: 'minor issue',
        mutate(matrix) {
          matrix.runs[0].issues.minor = 1;
        },
        expectedProblem: 'runs[0].issues.minor',
      },
      ...[
        ['invalid date text', 'not-a-date'],
        ['impossible date', '2026-02-30T12:00:00.000Z'],
        ['timestamp without milliseconds', '2026-08-30T12:00:00Z'],
        ['timestamp with offset', '2026-08-30T08:00:00.000-04:00'],
        ['numeric capture time', 1788091200000],
        ['null capture time', null],
      ].map(([name, capturedAt]) => ({
        name,
        mutate(matrix) {
          matrix.runs[0].captured_at = capturedAt;
        },
        expectedProblem: 'runs[0].captured_at',
      })),
    ];

    for (const testCase of cases) {
      const outDir = tempDir();
      const context = buildCollectionContext({
        outDir,
        environment: 'staging',
        releaseId: `rel_${testCase.name.replaceAll(/[^a-z0-9]+/gi, '_')}`,
        continueOnError: true,
        createdAt: '2026-08-30T12:05:00.000Z',
      });
      const matrix = liveUiAccessibilityMatrix();
      testCase.mutate(matrix);
      writeFileSync(
        path.join(outDir, 'ui-accessibility-matrix-input.json'),
        `${JSON.stringify(matrix, null, 2)}\n`,
      );

      const built = buildCollectorScriptInput('ui_accessibility_matrix', context);
      assert.equal(built.inputSource, 'invalid-live-ui-accessibility-matrix', testCase.name);
      const forgedSourceAcceptance = validateUiAccessibilityCollectorAcceptance(built.input, {
        requireRunnerSource: true,
        inputSource: 'run-live-ui-accessibility-matrix',
        environment: context.environment,
      });
      assert.equal(forgedSourceAcceptance.ok, false, testCase.name);
      assert.ok(
        [...forgedSourceAcceptance.run_shape_errors, ...forgedSourceAcceptance.incomplete_checks]
          .includes(testCase.expectedProblem),
        testCase.name,
      );

      const artifact = createUiAccessibilityMatrixArtifact({
        evidence: built.input,
        createdAt: context.createdAt,
      });
      const record = extractProductionReleaseRecord('ui_accessibility_matrix', artifact, context);
      assert.equal(record.status, 'draft', testCase.name);
      assert.equal(record.submittable, false, testCase.name);

      const forgedAcceptedRecord = { ...record, status: 'accepted', submittable: undefined };
      assert.throws(
        () => validateCollectedRecord(forgedAcceptedRecord, { requireSubmittable: true }),
        /requires completed, passed live checks/,
        testCase.name,
      );

      const records = PRODUCTION_RELEASE_EVIDENCE_KINDS.map((kind) => (
        kind === 'ui_accessibility_matrix'
          ? forgedAcceptedRecord
          : {
            kind,
            evidence: adaptContractEvidence(kind, context),
            status: 'accepted',
            release_id: context.releaseId,
          }
      ));
      const payload = buildRecordsPayload(records, context);
      assert.equal(payload.collection_complete, false, testCase.name);
      assert.equal(payload.submittable, false, testCase.name);
      assert.throws(() => createReleaseEvidenceBundle(payload), /non-submittable/, testCase.name);

      let invoked = 0;
      const collector = RELEASE_EVIDENCE_COLLECTORS.find((entry) => entry.kind === 'ui_accessibility_matrix');
      const result = runCollector(collector, context, {
        runCommand: () => {
          invoked += 1;
          return { status: 0, stdout: '', stderr: '' };
        },
      });
      assert.equal(invoked, 0, testCase.name);
      assert.equal(result.ok, false, testCase.name);
      assert.match(result.error, /requires completed, passed output/, testCase.name);
    }
  });

  it('accepts complete passed output from the live accessibility runner', () => {
    const outDir = tempDir();
    const context = buildCollectionContext({
      outDir,
      environment: 'staging',
      releaseId: 'rel_staging_live_ui',
      createdAt: '2026-08-30T12:05:00.000Z',
    });
    writeFileSync(
      path.join(outDir, 'ui-accessibility-matrix-input.json'),
      `${JSON.stringify(liveUiAccessibilityMatrix(), null, 2)}\n`,
    );

    const collector = RELEASE_EVIDENCE_COLLECTORS.find((entry) => entry.kind === 'ui_accessibility_matrix');
    const result = runCollector(collector, context, {
      runCommand: (_command, args) => {
        const inputPath = args[args.indexOf('--input') + 1];
        const outPath = args[args.indexOf('--out') + 1];
        const artifact = createUiAccessibilityMatrixArtifact({
          evidence: JSON.parse(readFileSync(inputPath, 'utf8')),
          createdAt: context.createdAt,
        });
        writeFileSync(outPath, `${JSON.stringify(artifact, null, 2)}\n`);
        return { status: 0, stdout: '', stderr: '' };
      },
    });

    assert.equal(result.ok, true);
    assert.equal(result.record.status, 'accepted');
    assert.equal(result.record.submittable, undefined);
    assert.doesNotThrow(() => validateCollectedRecord(result.record, { requireSubmittable: true }));
    assert.equal(result.record.evidence.runs.length, REQUIRED_PAGES.length * 2);

    const completeRecords = PRODUCTION_RELEASE_EVIDENCE_KINDS.map((kind) => (
      kind === 'ui_accessibility_matrix'
        ? result.record
        : {
          kind,
          evidence: adaptContractEvidence(kind, context),
          status: 'accepted',
          release_id: context.releaseId,
        }
    ));
    const payload = buildRecordsPayload(completeRecords, context);
    assert.equal(payload.collection_complete, true);
    assert.equal(payload.submittable, true);
    const bundle = createReleaseEvidenceBundle(payload);
    assert.equal(bundle.records.find((record) => record.kind === 'ui_accessibility_matrix').validation.ok, true);
  });

  it('records payload is suitable for gap audit input shape', () => {
    const context = buildCollectionContext({ environment: 'staging-sim' });
    const records = PRODUCTION_RELEASE_EVIDENCE_KINDS.map((kind) => ({
      kind,
      evidence: adaptContractEvidence(kind, context),
      status: 'accepted',
      release_id: context.releaseId,
    }));
    const payload = buildRecordsPayload(records, context);
    assert.equal(Array.isArray(payload.records), true);
    assert.equal(payload.records.length, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
    assert.equal(payload.rehearsal_only, undefined);
  });

  it('main returns 0 for dry-run help and collection', async () => {
    assert.equal(await main(['--help']), 0);
    const outDir = tempDir();
    assert.equal(await main(['--out-dir', outDir, '--dry-run']), 0);
  });
});
