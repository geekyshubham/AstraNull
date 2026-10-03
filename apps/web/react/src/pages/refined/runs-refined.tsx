import { isValidElement, useMemo, useState, type HTMLAttributes, type ReactNode } from 'react';
import { Info, ShieldCheck } from 'lucide-react';
import { DataTable, type TableColumn } from '../../components/ui/table';
import { Select, type SelectOption } from '../../components/ui/select';
import { Tabs } from '../../components/ui/tabs';
import { VariantSwitch } from '../../components/ui/variant-switch';
import { classifyVerdict } from '../../lib/dashboard-metrics';
import type { DesignVariant } from '../../lib/design-variant';
import { hasEvidenceBackedVerdict, publishedRunVerdict } from '../../lib/run-verdict';
import type { DataItem, PortalConfig, PortalData, PortalDataset, Session } from '../../lib/types';
import { cn, formatNumber, formatRunDuration, pluralize } from '../../lib/utils';
import './runs-refined.css';

/**
 * Everything the Refined test-runs view needs. State, mutations, the 8s live refresh,
 * permission gates, the SOC gate panel, and modals stay owned by ValidationSurfacePage.
 */
export interface RunsRefinedProps {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: (datasets?: readonly PortalDataset[]) => Promise<void>;
  variant: DesignVariant;
  onVariantChange: (next: DesignVariant) => void;
  /** '' when idle, else e.g. `cancel-<id>`, `finalize-<id>`, 'refresh-runs'. */
  busy: string;
  message: string;
  error: string;
  /** canStartRun(role): gates scan launch and per-row Cancel/Finalize (already applied in runColumns). */
  canManageScans: boolean;
  /** high_scale:request: gates the SOC request action (already applied in headerActions). */
  canRequestHighScale: boolean;
  inFlightRunCount: number;
  activeScanCount: number;
  /** e.g. "2 active runs, 1 active scan"; '' when nothing is live. */
  liveCounts: string;
  canOpenVectorLibrary: boolean;
  startDisabledReason: string;
  /** RunsPageHeadActions, wired with the same gates as classic. */
  headerActions: ReactNode;
  /** RunsSocGatePanel, wired to page busy/message/error state. */
  socGatePanel?: ReactNode;
  scanStatusFilter: string;
  scanStatusOptions: SelectOption[];
  onScanStatusFilterChange: (value: string) => void;
  /** ValidationScansTable for the filtered scans, wired to the scan launcher. */
  validationScansTable: ReactNode;
  runColumns: TableColumn<DataItem>[];
  /** Runs sorted newest first and filtered by runStatusFilter. */
  filteredRuns: DataItem[];
  runStatusFilter: string;
  runStatusOptions: SelectOption[];
  onRunStatusFilterChange: (value: string) => void;
  getRunRowProps: (item: DataItem) => Omit<HTMLAttributes<HTMLTableRowElement>, 'key'>;
  runsEmptyState: ReactNode;
  /** Cancel and finalize ConfirmModals plus ValidationScanLauncher. */
  modals: ReactNode;
}

type RunsView = 'history' | 'scans';

/** Matches the classic placeholder glyph; written as an escape so no U+2014 appears in source. */
const DASH_PLACEHOLDER = String.fromCharCode(0x2014);

/**
 * Classic cells render a muted dash when a value or action is absent. Refined copy says
 * what is missing instead. Only the exact classic placeholder is replaced, so the cell
 * logic (and the Cancel/Finalize permission gate) stays owned by the parent's columns.
 */
function replaceDashPlaceholder(node: ReactNode, text: string): ReactNode {
  if (
    isValidElement<{ children?: ReactNode; className?: string }>(node)
    && node.type === 'span'
    && node.props.className === 'muted'
    && node.props.children === DASH_PLACEHOLDER
  ) {
    return <span className="rf-quiet">{text}</span>;
  }
  return node;
}

/** Wraps each classic column so Refined CSS can style it by key without re-implementing it. */
function refineRunColumns(columns: TableColumn<DataItem>[]): TableColumn<DataItem>[] {
  return columns.map((column) => {
    const render = column.key === 'duration'
      ? (item: DataItem) => <code className="rf-duration">{formatRunDuration(item, 'Not recorded')}</code>
      : column.render;
    const placeholder = column.key === 'actions' ? 'No actions' : 'Unavailable';
    return {
      ...column,
      render: (item: DataItem) => (
        <div className={`rf-cell rf-cell-${column.key}`}>{replaceDashPlaceholder(render(item), placeholder)}</div>
      )
    };
  });
}

/** Evidence-backed verdict mix, using the same evidence gate as the run history verdict column. */
function useVerdictMix(runs: DataItem[], evidence: DataItem[]) {
  return useMemo(() => {
    let pass = 0;
    let gap = 0;
    let review = 0;
    for (const run of runs) {
      if (!hasEvidenceBackedVerdict(run, evidence)) continue;
      const verdictClass = classifyVerdict(publishedRunVerdict(run));
      if (verdictClass === 'pass') pass += 1;
      else if (verdictClass === 'gap') gap += 1;
      else if (verdictClass === 'review') review += 1;
    }
    return { pass, gap, review, total: pass + gap + review };
  }, [runs, evidence]);
}

export function RunsRefined(props: RunsRefinedProps) {
  const { data, message, error } = props;
  const [view, setView] = useState<RunsView>('history');
  const live = props.inFlightRunCount > 0 || props.activeScanCount > 0;
  const mix = useVerdictMix(data.runs, data.evidence);
  const runsUnavailable = Boolean(data.loadErrors.runs) && data.runs.length === 0;
  const scansUnavailable = Boolean(data.loadErrors.validationScans) && data.validationScans.length === 0;
  const scheduledScanCount = data.validationScans.filter((scan) => scan.status === 'scheduled').length;
  const columns = refineRunColumns(props.runColumns);
  const vectorLibraryNote = !props.canOpenVectorLibrary && props.startDisabledReason
    ? `Open the vector library once ready. ${props.startDisabledReason}`
    : 'Customer-safe runs start in the vector library, where you select the exact target group, target, vector, and mapped bounded check.';
  const launchBlocked = !props.canOpenVectorLibrary && Boolean(props.startDisabledReason);

  return (
    <div className="content refined rf-runs">
      <header className="rf-header">
        <div className="rf-header-copy">
          <p className="rf-eyebrow">Validation history</p>
          <h1>Test runs</h1>
          <p className="rf-header-description">
            Bounded safe checks and direct validation runs with lifecycle state, correlated verdict, confidence when published, and sealed evidence.
          </p>
        </div>
        <div className="rf-header-actions">
          <VariantSwitch value={props.variant} onChange={props.onVariantChange} />
          {props.headerActions}
        </div>
      </header>

      <section className="rf-summary-strip rf-runs-summary" aria-label="Run summary">
        <div className="rf-stat">
          <span className="rf-stat-label">Runs</span>
          <span className="rf-stat-value">{runsUnavailable ? 'Unavailable' : formatNumber(data.runs.length)}</span>
          <span className="rf-stat-hint">{runsUnavailable ? 'Run history could not be read' : `${pluralize(data.runs.length, 'run')} recorded`}</span>
        </div>
        <div className="rf-stat">
          <span className="rf-stat-label">In progress</span>
          <span className="rf-stat-value">{runsUnavailable ? 'Unavailable' : formatNumber(props.inFlightRunCount)}</span>
          <span className="rf-stat-hint">
            {props.inFlightRunCount > 0 ? 'Verdicts publish when the observation window closes' : 'No planned, running, or collecting runs'}
          </span>
        </div>
        <div className="rf-stat">
          <span className="rf-stat-label">Evidence-backed verdicts</span>
          <span className="rf-stat-value">{runsUnavailable ? 'Unavailable' : formatNumber(mix.total)}</span>
          {mix.total > 0 ? (
            <>
              <span className="rf-mix-bar" aria-hidden="true">
                {mix.pass > 0 ? <span className="rf-mix-seg is-pass" style={{ flexGrow: mix.pass }} /> : null}
                {mix.review > 0 ? <span className="rf-mix-seg is-review" style={{ flexGrow: mix.review }} /> : null}
                {mix.gap > 0 ? <span className="rf-mix-seg is-gap" style={{ flexGrow: mix.gap }} /> : null}
              </span>
              <span className="rf-stat-hint">
                {`${formatNumber(mix.pass)} as expected, ${formatNumber(mix.review)} to review, ${formatNumber(mix.gap)} ${pluralize(mix.gap, 'gap')}`}
              </span>
            </>
          ) : (
            <span className="rf-stat-hint">{runsUnavailable ? 'Run history could not be read' : 'No published verdict with bound evidence yet'}</span>
          )}
        </div>
        <div className="rf-stat">
          <span className="rf-stat-label">Active scans</span>
          <span className="rf-stat-value">{scansUnavailable ? 'Unavailable' : formatNumber(props.activeScanCount)}</span>
          <span className="rf-stat-hint">
            {scansUnavailable
              ? 'Scans could not be read'
              : `${formatNumber(scheduledScanCount)} scheduled, ${formatNumber(data.validationScans.length)} total`}
          </span>
        </div>
      </section>

      {message || error ? (
        <div className={error ? 'form-banner error' : 'form-banner neutral'} role={error ? 'alert' : 'status'} aria-live="polite">{error || message}</div>
      ) : null}

      {launchBlocked ? (
        <div className="form-banner neutral" role="note">{vectorLibraryNote}</div>
      ) : null}

      <section className="rf-runs-data" aria-label="Runs and scans">
        <div className="rf-runs-viewbar">
          <Tabs<RunsView>
            ariaLabel="Run views"
            value={view}
            onChange={setView}
            getTabId={(id) => `rf-runs-tab-${id}`}
            getPanelId={(id) => `rf-runs-panel-${id}`}
            options={[
              { id: 'history', label: 'Run history', count: runsUnavailable ? undefined : data.runs.length },
              { id: 'scans', label: 'Validation scans', count: scansUnavailable ? undefined : data.validationScans.length }
            ]}
          />
          {/* Mounted while idle so the change to live is announced. */}
          <p className={cn('rf-live', live && 'is-live')} role="status" aria-live="polite">
            <span className="rf-live-dot" aria-hidden="true" />
            <span>{live ? `Live: ${props.liveCounts}. Refreshing every 8s.` : 'Idle. Live status auto-refreshes while a run or scan is in progress.'}</span>
          </p>
        </div>

        <div
          className="rf-runs-panel"
          id="rf-runs-panel-history"
          role="tabpanel"
          aria-labelledby="rf-runs-tab-history"
          hidden={view !== 'history'}
        >
          <div className="rf-runs-panel-head">
            <div className="rf-runs-panel-copy">
              <p>Open a row for probe results, correlation, and custody chain.</p>
              {launchBlocked ? null : (
                <p className="rf-runs-note" role="note">
                  <Info size={14} aria-hidden="true" />
                  <span>{vectorLibraryNote}</span>
                </p>
              )}
            </div>
            <div className="rf-toolbar">
              <span className="rf-chip" title="Verdicts show only when a published verdict has bound evidence"><ShieldCheck aria-hidden="true" />Evidence backed</span>
              <div className="rf-runs-filter" role="group" aria-label="Run history filters">
                <Select label="Lifecycle status" value={props.runStatusFilter} options={props.runStatusOptions} onChange={props.onRunStatusFilterChange} />
              </div>
            </div>
          </div>
          <div className="rf-panel rf-panel-flush">
            <DataTable
              className="validation-runs-table"
              columns={columns}
              items={props.filteredRuns}
              getRowProps={props.getRunRowProps}
              empty={props.runsEmptyState}
              loadError={data.loadErrors.runs}
              onRetry={() => void props.onRefresh()}
            />
          </div>
        </div>

        <div
          className="rf-runs-panel"
          id="rf-runs-panel-scans"
          role="tabpanel"
          aria-labelledby="rf-runs-tab-scans"
          hidden={view !== 'scans'}
        >
          <div className="rf-runs-panel-head">
            <div className="rf-runs-panel-copy">
              <p>Multi-check scans run one bounded child run at a time. Scheduled scans dispatch at their planned time and stay editable until then.</p>
            </div>
            <div className="rf-toolbar">
              <div className="rf-runs-filter" role="group" aria-label="Validation scan filters">
                <Select label="Scan status" value={props.scanStatusFilter} options={props.scanStatusOptions} onChange={props.onScanStatusFilterChange} />
              </div>
            </div>
          </div>
          <div className="rf-panel rf-panel-flush">{props.validationScansTable}</div>
        </div>
      </section>

      {props.modals}
    </div>
  );
}
