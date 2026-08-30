#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactObject } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/ui-accessibility-matrix-evidence.json';

export const REQUIRED_PAGES = Object.freeze([
  'dashboard',
  'test_runs',
  'soc_console',
  'high_scale_request',
  'reports_export_custody_preview',
  'findings',
]);

export const REQUIRED_VIEWPORTS = Object.freeze(['desktop', 'mobile']);

export const REQUIRED_RUN_FIELDS = Object.freeze([
  'viewport',
  'browser',
  'axe_status',
  'keyboard_status',
  'screen_reader_status',
  'issues',
]);

export const REQUIRED_ISSUE_SEVERITIES = Object.freeze(['critical', 'serious', 'moderate', 'minor']);

const ALLOWED_STATUSES = new Set(['pass', 'fail', 'skip', 'not_applicable']);

const FORBIDDEN_KEYS = new Set([
  'authorization',
  'body',
  'connection_string',
  'credential',
  'database_url',
  'dom_snapshot',
  'headers',
  'html',
  'html_blob',
  'image_blob',
  'jpeg_data',
  'log_blob',
  'logs_blob',
  'page_html',
  'page_source',
  'password',
  'payload',
  'png_data',
  'raw_body',
  'raw_headers',
  'raw_html',
  'raw_log',
  'screenshot',
  'screenshot_data',
  'screenshots',
  'secret',
  'token',
]);

function normalizeKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  return true;
}

export function collectForbiddenFields(value, fieldPath = '') {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenFields(entry, `${fieldPath}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = fieldPath ? `${fieldPath}.${key}` : key;
    const normalized = normalizeKey(key);
    if (FORBIDDEN_KEYS.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenFields(nested, keyPath));
  }
  return findings;
}

export function extractMatrixRuns(evidence) {
  if (Array.isArray(evidence?.runs)) {
    return evidence.runs.map((run) => ({ ...run }));
  }
  if (evidence?.pages && typeof evidence.pages === 'object') {
    const runs = [];
    for (const [page, pageEntry] of Object.entries(evidence.pages)) {
      const pageRuns = Array.isArray(pageEntry?.runs) ? pageEntry.runs : [];
      for (const run of pageRuns) {
        runs.push({ ...run, page: run.page ?? page });
      }
    }
    return runs;
  }
  return [];
}

function normalizeViewport(value) {
  if (!hasValue(value)) return null;
  return String(value).trim().toLowerCase();
}

function normalizePage(value) {
  if (!hasValue(value)) return null;
  return String(value).trim().toLowerCase();
}

function issueCount(issues, severity) {
  const raw = issues?.[severity];
  if (!Number.isInteger(raw) || raw < 0) return null;
  return raw;
}

export function validateUiAccessibilityMatrixEvidence(evidence) {
  const forbidden_fields = [...new Set(collectForbiddenFields(evidence))].sort();
  const runs = extractMatrixRuns(evidence);
  const missing_pages = [];
  const missing_viewports = [];
  const missing_run_fields = [];
  const invalid_run_fields = [];
  const unresolved_critical = [];
  const browsers = new Set();

  if (runs.length === 0) {
    return {
      ok: false,
      forbidden_fields,
      missing_pages: [...REQUIRED_PAGES],
      missing_viewports: [],
      missing_run_fields: ['runs'],
      invalid_run_fields: [],
      unresolved_critical: [],
      browsers: [],
      summary: null,
    };
  }

  const runsByPage = new Map();
  for (const run of runs) {
    const page = normalizePage(run.page);
    if (!page) {
      missing_run_fields.push('run.page');
      continue;
    }
    if (!runsByPage.has(page)) runsByPage.set(page, []);
    runsByPage.get(page).push(run);
  }

  for (const page of REQUIRED_PAGES) {
    const pageRuns = runsByPage.get(page) ?? [];
    if (pageRuns.length === 0) {
      missing_pages.push(page);
      continue;
    }
    const viewportsPresent = new Set();
    for (const run of pageRuns) {
      const viewport = normalizeViewport(run.viewport);
      if (viewport) viewportsPresent.add(viewport);

      for (const field of REQUIRED_RUN_FIELDS) {
        if (field === 'issues') {
          if (!run.issues || typeof run.issues !== 'object') {
            missing_run_fields.push(`${page}.${field}`);
            continue;
          }
          for (const severity of REQUIRED_ISSUE_SEVERITIES) {
            if (issueCount(run.issues, severity) === null) {
              missing_run_fields.push(`${page}.issues.${severity}`);
            }
          }
          const critical = issueCount(run.issues, 'critical');
          if (critical !== null && critical > 0) {
            unresolved_critical.push(`${page}:${viewport ?? 'unknown'}:${run.browser ?? 'unknown'}`);
          }
          continue;
        }
        if (!hasValue(run[field])) {
          missing_run_fields.push(`${page}.${field}`);
        } else if (field.endsWith('_status') && !ALLOWED_STATUSES.has(String(run[field]).trim().toLowerCase())) {
          invalid_run_fields.push(`${page}.${field}`);
        }
      }

      if (hasValue(run.browser)) browsers.add(String(run.browser).trim().toLowerCase());
    }

    for (const viewport of REQUIRED_VIEWPORTS) {
      if (!viewportsPresent.has(viewport)) {
        missing_viewports.push(`${page}:${viewport}`);
      }
    }
  }

  const dedupe = (items) => [...new Set(items)].sort();
  const missing_run_fields_deduped = dedupe(missing_run_fields);
  const ok = forbidden_fields.length === 0
    && missing_pages.length === 0
    && missing_viewports.length === 0
    && missing_run_fields_deduped.length === 0
    && invalid_run_fields.length === 0
    && unresolved_critical.length === 0
    && browsers.size >= 1;

  return {
    ok,
    forbidden_fields,
    missing_pages: dedupe(missing_pages),
    missing_viewports: dedupe(missing_viewports),
    missing_run_fields: missing_run_fields_deduped,
    invalid_run_fields: dedupe(invalid_run_fields),
    unresolved_critical: dedupe(unresolved_critical),
    browsers: [...browsers].sort(),
    summary: {
      run_count: runs.length,
      pages_covered: REQUIRED_PAGES.filter((page) => (runsByPage.get(page) ?? []).length > 0),
      browsers: [...browsers].sort(),
      issue_totals: REQUIRED_ISSUE_SEVERITIES.reduce((acc, severity) => {
        acc[severity] = runs.reduce((sum, run) => sum + (issueCount(run.issues, severity) ?? 0), 0);
        return acc;
      }, {}),
    },
  };
}

const UI_ACCESSIBILITY_STATUS_FIELDS = Object.freeze([
  'axe_status',
  'keyboard_status',
  'screen_reader_status',
]);

function isCanonicalIsoUtcTimestamp(value) {
  if (typeof value !== 'string') return false;
  const timestamp = new Date(value);
  return Number.isFinite(timestamp.getTime()) && timestamp.toISOString() === value;
}

export function validateUiAccessibilityCollectorAcceptance(evidence, options = {}) {
  const validation = validateUiAccessibilityMatrixEvidence(evidence);
  const runs = extractMatrixRuns(evidence);
  const incompleteChecks = [];
  const runShapeErrors = [];
  const expectedPairCounts = new Map(
    REQUIRED_PAGES.flatMap((page) => (
      REQUIRED_VIEWPORTS.map((viewport) => [`${page}:${viewport}`, 0])
    )),
  );

  if (runs.length !== REQUIRED_PAGES.length * REQUIRED_VIEWPORTS.length) {
    runShapeErrors.push(`runs.length:${runs.length}`);
  }

  runs.forEach((run, index) => {
    const pair = `${run?.page ?? ''}:${run?.viewport ?? ''}`;
    if (!expectedPairCounts.has(pair)) {
      runShapeErrors.push(`runs[${index}].pair:${pair}`);
    } else {
      expectedPairCounts.set(pair, expectedPairCounts.get(pair) + 1);
    }

    if (run?.browser !== 'chromium') {
      incompleteChecks.push(`runs[${index}].browser`);
    }
    for (const field of UI_ACCESSIBILITY_STATUS_FIELDS) {
      if (run?.[field] !== 'pass') {
        incompleteChecks.push(`runs[${index}].${field}`);
      }
    }
    if (!isCanonicalIsoUtcTimestamp(run?.captured_at)) {
      incompleteChecks.push(`runs[${index}].captured_at`);
    }
    for (const severity of REQUIRED_ISSUE_SEVERITIES) {
      if (issueCount(run?.issues, severity) !== 0) {
        incompleteChecks.push(`runs[${index}].issues.${severity}`);
      }
    }
  });

  for (const [pair, count] of expectedPairCounts) {
    if (count === 0) runShapeErrors.push(`missing_pair:${pair}`);
    if (count > 1) runShapeErrors.push(`duplicate_pair:${pair}`);
  }

  const sourceErrors = [];
  if (options.requireRunnerSource === true) {
    if (options.inputSource !== 'run-live-ui-accessibility-matrix') {
      sourceErrors.push('input_source');
    }
    if (evidence?.schema_version !== 1) sourceErrors.push('schema_version');
    if (evidence?.artifact_type !== 'ui_accessibility_matrix_input') sourceErrors.push('artifact_type');
    if (evidence?.environment !== options.environment) sourceErrors.push('environment');
    if (evidence?.evidence_uri !== `evidence://ui/accessibility-matrix/${options.environment}`) {
      sourceErrors.push('evidence_uri');
    }
  }

  return {
    ok: validation.ok
      && incompleteChecks.length === 0
      && runShapeErrors.length === 0
      && sourceErrors.length === 0,
    validation,
    incomplete_checks: [...new Set(incompleteChecks)].sort(),
    run_shape_errors: [...new Set(runShapeErrors)].sort(),
    source_errors: [...new Set(sourceErrors)].sort(),
  };
}

export function uiAccessibilityAcceptanceProblems(acceptance) {
  return [
    ...acceptance.validation.forbidden_fields.map((field) => `forbidden:${field}`),
    ...acceptance.validation.missing_pages.map((field) => `missing_page:${field}`),
    ...acceptance.validation.missing_viewports.map((field) => `missing_viewport:${field}`),
    ...acceptance.validation.missing_run_fields.map((field) => `missing:${field}`),
    ...acceptance.validation.invalid_run_fields.map((field) => `invalid:${field}`),
    ...acceptance.validation.unresolved_critical.map((field) => `critical:${field}`),
    ...acceptance.run_shape_errors.map((field) => `invalid_shape:${field}`),
    ...acceptance.incomplete_checks.map((field) => `not_passed:${field}`),
    ...acceptance.source_errors.map((field) => `invalid_source:${field}`),
  ];
}

function fieldSummary(fields) {
  return fields.length > 0 ? fields.join(', ') : 'none';
}

export function assertValidUiAccessibilityMatrixEvidence(evidence) {
  const validation = validateUiAccessibilityMatrixEvidence(evidence);
  if (validation.ok) return validation;
  if (validation.forbidden_fields.length > 0) {
    throw new Error(`Forbidden artifact field(s): ${fieldSummary(validation.forbidden_fields)}`);
  }
  if (validation.missing_pages.length > 0) {
    throw new Error(`Missing page coverage: ${fieldSummary(validation.missing_pages)}`);
  }
  if (validation.missing_viewports.length > 0) {
    throw new Error(`Missing viewport coverage: ${fieldSummary(validation.missing_viewports)}`);
  }
  if (validation.unresolved_critical.length > 0) {
    throw new Error(`Unresolved critical accessibility issue(s): ${fieldSummary(validation.unresolved_critical)}`);
  }
  if (validation.missing_run_fields.includes('runs')) {
    throw new Error('Evidence must include runs[] or pages.{page}.runs[]');
  }
  if (validation.missing_run_fields.length > 0) {
    throw new Error(`Missing run metadata: ${fieldSummary(validation.missing_run_fields)}`);
  }
  if (validation.invalid_run_fields.length > 0) {
    throw new Error(`Invalid run metadata: ${fieldSummary(validation.invalid_run_fields)}`);
  }
  throw new Error('UI accessibility matrix evidence is incomplete');
}

export function createUiAccessibilityMatrixArtifact(input = {}) {
  const evidence = input.evidence ?? input;
  const validation = assertValidUiAccessibilityMatrixEvidence(evidence);
  const runs = extractMatrixRuns(evidence).map((run) => redactObject({
    page: normalizePage(run.page),
    viewport: normalizeViewport(run.viewport),
    browser: hasValue(run.browser) ? String(run.browser).trim() : null,
    axe_status: run.axe_status,
    keyboard_status: run.keyboard_status,
    screen_reader_status: run.screen_reader_status,
    issues: REQUIRED_ISSUE_SEVERITIES.reduce((acc, severity) => {
      acc[severity] = issueCount(run.issues, severity) ?? 0;
      return acc;
    }, {}),
    ...(hasValue(run.captured_at) ? { captured_at: String(run.captured_at) } : {}),
    ...(hasValue(run.notes) ? { notes: String(run.notes) } : {}),
  }));

  return {
    schema_version: 1,
    artifact_type: 'ui_accessibility_matrix_evidence',
    created_at: input.createdAt ?? new Date().toISOString(),
    validation: {
      ok: validation.ok,
      pages: REQUIRED_PAGES,
      viewports: REQUIRED_VIEWPORTS,
      browsers: validation.browsers,
    },
    summary: validation.summary,
    runs,
    caveats: [
      'Artifact records metadata-only browser/accessibility matrix summaries.',
      'Production UX signoff still requires staged execution, SOC/legal custody where applicable, and live-data fidelity checks.',
    ],
  };
}

export function parseArgs(argv = []) {
  const opts = {
    input: null,
    out: DEFAULT_OUT,
    validateOnly: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--input') opts.input = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help && !opts.input) throw new Error('--input is required');
  return opts;
}

function readInputJson(inputPath) {
  return JSON.parse(readFileSync(inputPath, 'utf8'));
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log('Usage: node scripts/ui-accessibility-matrix-evidence.mjs --input evidence.json [--out file] [--validate-only]');
    return 0;
  }

  const evidence = readInputJson(opts.input);
  const artifact = createUiAccessibilityMatrixArtifact({ evidence });

  if (opts.validateOnly) {
    console.log(`ui-accessibility-matrix-evidence: ok (${artifact.runs.length} run(s), browsers=${artifact.validation.browsers.join(', ')})`);
    return 0;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(`ui-accessibility-matrix-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`ui-accessibility-matrix-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}