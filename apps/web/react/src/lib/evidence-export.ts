import type { DataItem } from './types';

export type EvidenceChainExport = {
  payload: {
    exported_at: string;
    evidence_ids: string[];
    chain: DataItem[];
    orphan_references: DataItem[];
  };
  json: string;
  idList: string;
};

function getString(item: DataItem, keys: string[]) {
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return '';
}

export function buildEvidenceChainExport(input: {
  evidence?: DataItem[];
  runs?: DataItem[];
  verdicts?: DataItem[];
  findings?: DataItem[];
}): EvidenceChainExport {
  const evidence = input.evidence ?? [];
  const runs = input.runs ?? [];
  const verdicts = input.verdicts ?? [];
  const findings = input.findings ?? [];
  const runById = Object.fromEntries(runs.map((run) => [getString(run, ['id']), run]));
  const chain = evidence.map((item) => {
    const testRunId = getString(item, ['test_run_id']);
    const run = testRunId ? runById[testRunId] : null;
    const verdict = verdicts.find((entry) => getString(entry, ['test_run_id']) === testRunId)
      ?? verdicts.find((entry) => {
        const evidenceIds = Array.isArray(entry.evidence_ids) ? entry.evidence_ids as string[] : [];
        return evidenceIds.includes(getString(item, ['id']));
      });
    const linkedFindings = findings.filter((finding) => {
      const evidenceIds = Array.isArray(finding.evidence_ids) ? finding.evidence_ids as string[] : [];
      return evidenceIds.includes(getString(item, ['id']));
    });
    return {
      evidence_id: getString(item, ['id']),
      label: getString(item, ['label']),
      test_run_id: testRunId || null,
      run_status: run ? getString(run, ['status']) : null,
      verdict: verdict ? getString(verdict, ['verdict']) : null,
      verdict_confidence: verdict?.confidence ?? null,
      finding_ids: linkedFindings.map((finding) => getString(finding, ['id'])),
      created_at: item.created_at ?? null
    };
  });
  const orphanReferences: DataItem[] = [];
  for (const verdict of verdicts) {
    const evidenceIds = Array.isArray(verdict.evidence_ids) ? verdict.evidence_ids as string[] : [];
    for (const evidenceId of evidenceIds) {
      if (!evidence.some((item) => getString(item, ['id']) === evidenceId)) {
        orphanReferences.push({
          evidence_id: evidenceId,
          test_run_id: getString(verdict, ['test_run_id']),
          verdict: getString(verdict, ['verdict']),
          source: 'verdict_reference'
        });
      }
    }
  }
  const payload = {
    exported_at: new Date().toISOString(),
    evidence_ids: evidence.map((item) => getString(item, ['id'])).filter(Boolean),
    chain,
    orphan_references: orphanReferences
  };
  return {
    payload,
    json: JSON.stringify(payload, null, 2),
    idList: payload.evidence_ids.join('\n')
  };
}

export function summarizeEvidenceExport(exportData: EvidenceChainExport) {
  return [
    ['Evidence IDs', String(exportData.payload.evidence_ids.length)],
    ['Chain links', String(exportData.payload.chain.length)],
    ['Orphan references', String(exportData.payload.orphan_references.length)],
    ['Exported at', exportData.payload.exported_at]
  ] as const;
}