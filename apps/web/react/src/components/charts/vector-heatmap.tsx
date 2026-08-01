import { Target } from 'lucide-react';
import type { CSSProperties } from 'react';
import { Fragment } from 'react';
import { Badge } from '../ui/badge';
import { EmptyState } from '../ui/empty-state';
// The coverage derivation lives in plain ESM so `node --test` can exercise the SHIPPED logic.
// It previously lived here and was re-implemented inside the test file, where the copy drifted:
// it dropped the nested `check.check_id` / `target_group.id` fallbacks, so those shapes were
// handled in production and covered nowhere.
import type { FamilyCoverage, FamilyCoverageStatus } from '../../lib/vector-coverage.mjs';
import { VECTOR_FAMILIES, familyCheckIds, familyCoverage } from '../../lib/vector-coverage.mjs';

type VectorHeatmapProps = {
  checks: Record<string, unknown>[];
  targetGroups: Record<string, unknown>[];
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

const HEATMAP_CELL_STYLE: Record<FamilyCoverageStatus, CSSProperties> = {
  evidence: {
    background: 'color-mix(in oklab, var(--success), transparent 90%)',
    color: 'var(--success)',
  },
  run: {
    background: 'color-mix(in oklab, var(--warn), transparent 90%)',
    color: 'var(--warn)',
  },
  policy: {
    background: 'color-mix(in oklab, var(--warn), transparent 90%)',
    color: 'var(--warn)',
  },
  none: {
    background: 'color-mix(in oklab, var(--danger), transparent 91%)',
    color: 'var(--danger)',
  },
  'no-data': {
    border: '1px solid var(--border)',
    background: 'color-mix(in oklab, var(--fg), transparent 94%)',
    color: 'var(--fg-2)',
  },
};

function coverageTitle(coverage: FamilyCoverage) {
  if (coverage.status === 'no-data') {
    return 'No checks mapped to this vector family for this target group.';
  }
  return `${coverage.evidenceCount} evidence · ${coverage.runCount} runs · ${coverage.policyCount} policies`;
}

function HeatmapCell({ coverage }: { coverage: FamilyCoverage }) {
  const tone = COVERAGE_TONE[coverage.status];
  return (
    <span
      className={`heatmap-cell heatmap-${tone}`}
      style={HEATMAP_CELL_STYLE[coverage.status]}
      title={coverageTitle(coverage)}
    >
      {COVERAGE_LABEL[coverage.status]}
    </span>
  );
}

function HeatmapLegend() {
  return (
    <div className="heatmap-legend">
      <Badge tone="success">Evidence</Badge>
      <Badge tone="warn">Policy/run</Badge>
      <Badge tone="danger">No record</Badge>
      <Badge tone="muted">No data</Badge>
    </div>
  );
}

export function VectorHeatmap({ checks, targetGroups, testPolicies, runs, evidence }: VectorHeatmapProps) {
  const groups = targetGroups.slice(0, 5);

  if (groups.length === 0) {
    return (
      <EmptyState
        icon={Target}
        title="No declared target groups yet."
        body="Declare target groups before coverage can be calculated from policies, runs, or evidence."
      />
    );
  }

  const gridStyle = { '--heatmap-cols': VECTOR_FAMILIES.length } as CSSProperties;

  return (
    <div className="heatmap">
      <div className="heatmap-grid heatmap-grid--variable" style={gridStyle}>
        <span className="heatmap-head">Target group</span>
        {VECTOR_FAMILIES.map((family) => (
          <span className="heatmap-head" key={family.label}>
            {family.label}
          </span>
        ))}
        {groups.map((group, groupIndex) => (
          <Fragment key={String(group.id ?? groupIndex)}>
            <strong className="heatmap-name">{String(group.name ?? group.id ?? 'Declared group')}</strong>
            {VECTOR_FAMILIES.map((family) => {
              const groupId = String(group.id ?? '');
              const coverage = familyCoverage({
                checkIds: familyCheckIds(checks, family),
                groupId,
                testPolicies,
                runs,
                evidence,
              });
              return <HeatmapCell key={`${groupIndex}-${family.label}`} coverage={coverage} />;
            })}
          </Fragment>
        ))}
      </div>
      <HeatmapLegend />
    </div>
  );
}