import { Target } from 'lucide-react';
import { Badge } from '../ui/badge';
import { EmptyState } from '../ui/empty-state';
// The coverage derivation lives in plain ESM so `node --test` can exercise the SHIPPED logic.
// It previously lived here and was re-implemented inside the test file, where the copy drifted:
// it dropped the nested `check.check_id` / `target_group.id` fallbacks, so those shapes were
// handled in production and covered nowhere.
import type { FamilyCoverage, FamilyCoverageStatus } from '../../lib/vector-coverage.mjs';
import { VECTOR_FAMILIES, familyCheckIds, familyCoverage } from '../../lib/vector-coverage.mjs';
// @ts-ignore Plain ESM keeps executive labels directly testable with node:test.
import { plainCheckName } from '../../lib/plain-language.mjs';
import './charts.css';

type VectorHeatmapProps = {
  checks: Record<string, unknown>[];
  targets: Record<string, unknown>[];
  testPolicies: Record<string, unknown>[];
  runs: Record<string, unknown>[];
  evidence: Record<string, unknown>[];
};

const COVERAGE_TONE: Record<FamilyCoverageStatus, string> = {
  evidence: 'success',
  run: 'warn',
  policy: 'warn',
  none: 'danger',
  'no-data': 'muted',
};

const COVERAGE_LABEL: Record<FamilyCoverageStatus, string> = {
  evidence: 'Evidence',
  run: 'Run',
  policy: 'Policy',
  none: 'No record',
  'no-data': 'No data',
};

function coverageTitle(coverage: FamilyCoverage) {
  if (coverage.status === 'no-data') {
    return 'No checks mapped to this vector family for this domain.';
  }
  return `${coverage.evidenceCount} evidence · ${coverage.runCount} runs · ${coverage.policyCount} policies`;
}

function HeatmapCell({ coverage, domainName, familyName }: { coverage: FamilyCoverage; domainName: string; familyName: string }) {
  const tone = COVERAGE_TONE[coverage.status];
  const detail = coverageTitle(coverage);
  return (
    <span
      className={`heatmap-cell heatmap-${tone} matrix-cell`}
      data-status={coverage.status}
      title={detail}
      aria-label={`${domainName}, ${familyName}: ${COVERAGE_LABEL[coverage.status]}. ${detail}`}
    >
      <strong>{COVERAGE_LABEL[coverage.status]}</strong>
      {coverage.status === 'no-data' ? null : (
        <small>{coverage.evidenceCount} evidence</small>
      )}
    </span>
  );
}

function HeatmapLegend() {
  return (
    <div className="heatmap-legend" aria-label="Coverage status legend">
      <Badge tone="success">Evidence</Badge>
      <Badge tone="warn">Policy/run</Badge>
      <Badge tone="danger">No record</Badge>
      <Badge tone="muted">No data</Badge>
    </div>
  );
}

export function VectorHeatmap({ checks, targets, testPolicies, runs, evidence }: VectorHeatmapProps) {
  const domains = targets;

  if (domains.length === 0) {
    return (
      <EmptyState
        icon={Target}
        title="No declared domains yet."
        body="Declare domains before coverage can be calculated from policies, runs, or evidence."
      />
    );
  }

  return (
    <div className="stack-tight">
      <p className="muted small">
        Summary across five broad vector families. The resource-exhaustion matrix covers the complete taxonomy separately.
      </p>
      <div
        className="heatmap"
        tabIndex={0}
        role="region"
        aria-label="Vector coverage summary matrix, scrollable"
      >
        <table className="matrix-table">
          <caption className="sr-only">
            Vector coverage by declared domain: {domains.length} domains across {VECTOR_FAMILIES.length} vector families.
          </caption>
          <thead>
            <tr>
              <th scope="col"><span className="heatmap-head matrix-corner">Domain</span></th>
              {VECTOR_FAMILIES.map((family) => (
                <th scope="col" key={family.label}>
                  <span className="heatmap-head">{plainCheckName(family.label)}</span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {domains.map((domain, domainIndex) => {
              const targetId = String(domain.id ?? '');
              const domainName = String(domain.value ?? domain.id ?? 'Declared domain');
              return (
                <tr key={targetId || `group-${domainIndex}`}>
                  <th scope="row"><span className="heatmap-name">{domainName}</span></th>
                  {VECTOR_FAMILIES.map((family) => {
                    const coverage = familyCoverage({
                      checkIds: familyCheckIds(checks, family),
                      targetId,
                      testPolicies,
                      runs,
                      evidence,
                    });
                    return (
                      <td key={`${domainIndex}-${family.label}`}>
                        <HeatmapCell coverage={coverage} domainName={domainName} familyName={plainCheckName(family.label)} />
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <HeatmapLegend />
    </div>
  );
}
