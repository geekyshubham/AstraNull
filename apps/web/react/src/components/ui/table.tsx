import type { HTMLAttributes, ReactNode } from 'react';
import { cn, DEPLOYMENT_MODE_GAP_MESSAGE } from '../../lib/utils';

const DATA_TABLE_STYLES = `
.table-wrap:has(> .data-table),
.table-wrap.data-table-empty-wrap {
  width: 100%;
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--surface);
  box-shadow: 0 1px 0 color-mix(in oklab, var(--fg), transparent 96%) inset;
}
.table-wrap > .data-table {
  border-collapse: separate;
  border-spacing: 0;
}
.table-wrap > .data-table:has(.table-empty-row) {
  width: 100%;
  table-layout: fixed;
}
.table-wrap .table-empty-row td,
.table-wrap .table-empty {
  width: 100%;
  min-width: 0;
  max-width: 100%;
  box-sizing: border-box;
  overflow-wrap: anywhere;
}
.table-wrap .data-table .data-table-head th {
  height: 44px;
  padding: 0 var(--space-4);
  font-family: var(--font-body);
  font-size: var(--text-xs);
  letter-spacing: normal;
  text-transform: none;
  color: var(--fg-2);
  font-weight: 600;
  background: color-mix(in oklab, var(--surface-raised), var(--fg) 2%);
  border-bottom: 1px solid var(--border-strong);
}
.table-wrap .data-table .data-table-head th:first-child {
  border-top-left-radius: calc(var(--radius-lg) - 1px);
}
.table-wrap .data-table .data-table-head th:last-child {
  border-top-right-radius: calc(var(--radius-lg) - 1px);
}
.table-wrap .data-table tbody td {
  min-height: 52px;
  padding: 13px var(--space-4);
  border-bottom-color: var(--border-soft);
  background: var(--surface);
  transition: background var(--motion-fast) var(--motion-ease), color var(--motion-fast) var(--motion-ease);
}
.table-wrap .data-table tbody tr.table-row-zebra td {
  background: color-mix(in oklab, var(--surface), var(--fg) 1.6%);
}
.table-wrap .data-table tbody tr:hover td,
.table-wrap .data-table tbody tr.table-row-zebra:hover td {
  background: color-mix(in oklab, var(--surface), var(--accent) 5%);
}
.table-wrap .data-table tbody tr:last-child td:first-child {
  border-bottom-left-radius: calc(var(--radius-lg) - 1px);
}
.table-wrap .data-table tbody tr:last-child td:last-child {
  border-bottom-right-radius: calc(var(--radius-lg) - 1px);
}
.table-wrap .data-table tbody .btn-sm {
  min-height: 34px;
  padding-block: 0;
}
@media (max-width: 900px) {
  .table-wrap .data-table tbody .btn-sm {
    min-height: 44px;
    padding-block: 10px;
  }
}
@media (max-width: 700px) {
  .table-wrap:has(> .data-table) {
    border-radius: var(--radius-md);
  }
  .table-wrap .data-table .data-table-head th,
  .table-wrap .data-table tbody td {
    padding-inline: var(--space-3);
  }
  .table-wrap .data-table tbody tr,
  .table-wrap .data-table tbody td,
  .table-wrap .data-table .data-table-cell-content {
    min-width: 0;
    max-width: 100%;
  }
  .table-wrap .data-table tbody td,
  .table-wrap .data-table .data-table-cell-content {
    white-space: normal;
    overflow-wrap: anywhere;
  }
  .table-wrap .data-table tbody td .row-actions--compact {
    flex-wrap: wrap;
  }
}
@media (prefers-reduced-motion: reduce) {
  .table-wrap .data-table tbody tr td {
    transition: none;
  }
}
`;

export type TableColumn<T> = {
  key: string;
  label: string;
  render: (item: T) => ReactNode;
};

type DataTableProps<T> = {
  columns: TableColumn<T>[];
  items: T[];
  empty: ReactNode;
  className?: string;
  selectedId?: string | number | null;
  getRowId?: (item: T, index: number) => string | number;
  getRowProps?: (item: T, index: number) => Omit<HTMLAttributes<HTMLTableRowElement>, 'key'>;
  /**
   * Why this dataset could not be refreshed. With no items, the error replaces the empty state.
   * With cached items, the error remains visible above those retained rows.
   */
  loadError?: string | null;
  /** Retry affordance for `loadError`. Omitted renders the message alone. */
  onRetry?: () => void;
};

/**
 * Distinguishes a deployment-mode gap from a transient fault. A route that is
 * not wired in this deployment will never succeed, so offering Retry there is
 * misleading.
 */
function isDeploymentModeMessage(message: string) {
  return message === DEPLOYMENT_MODE_GAP_MESSAGE;
}

export function TableLoadError({
  message,
  onRetry,
  retainedRows = false
}: {
  message: string;
  onRetry?: () => void;
  retainedRows?: boolean;
}) {
  const permanent = isDeploymentModeMessage(message);
  return (
    <div className="form-banner error table-load-error" role="alert">
      <span>
        {permanent ? message : `Could not load — ${message}`}
        {retainedRows ? ' Showing previously loaded rows below.' : ''}
      </span>
      {onRetry && !permanent ? (
        <button type="button" className="btn btn-ghost btn-sm" onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  );
}

function TableHeaderRow<T>({ columns }: { columns: TableColumn<T>[] }) {
  return (
    <thead className="data-table-head">
      <tr>
        {columns.map((column) => (
          <th key={column.key} scope="col">
            {column.label}
          </th>
        ))}
      </tr>
    </thead>
  );
}

type DataTableBodyRowProps<T> = {
  item: T;
  index: number;
  columns: TableColumn<T>[];
  isSelected: boolean;
  rowProps: Omit<HTMLAttributes<HTMLTableRowElement>, 'key'>;
};

function DataTableBodyRow<T>({
  item,
  index,
  columns,
  isSelected,
  rowProps
}: DataTableBodyRowProps<T>) {
  const { className: rowClassName, onClick, onKeyDown, ...restRowProps } = rowProps;
  const zebra = index % 2 === 1;
  const nestedInteractiveOwnsEvent = (event: { target: EventTarget | null; currentTarget: EventTarget | null }) => {
    const target = event.target;
    if (!(target instanceof Element) || target === event.currentTarget) return false;
    const owner = target.closest('a, button, input, select, textarea, summary, [role="button"], [role="link"]');
    return owner !== null && owner !== event.currentTarget;
  };

  return (
    <tr
      {...restRowProps}
      className={cn(zebra && 'table-row-zebra', isSelected && 'table-row-selected', rowClassName)}
      aria-selected={isSelected ? true : restRowProps['aria-selected']}
      onClick={onClick ? (event) => {
        if (nestedInteractiveOwnsEvent(event)) return;
        onClick(event);
      } : undefined}
      onKeyDown={onKeyDown ? (event) => {
        // A nested link, button, input, or other focusable descendant owns its keyboard event.
        // The row handler runs only while focus is on the row itself.
        if (event.target !== event.currentTarget) return;
        onKeyDown(event);
      } : undefined}
    >
      {columns.map((column) => (
        <td key={column.key} data-label={column.label}>
          <div className="data-table-cell-content">{column.render(item)}</div>
        </td>
      ))}
    </tr>
  );
}

function DataTableChrome<T>({
  columns,
  className,
  children
}: {
  columns: TableColumn<T>[];
  className?: string | undefined;
  children: ReactNode;
}) {
  return (
    <>
      <style>{DATA_TABLE_STYLES}</style>
      {/* tabIndex=0 makes the horizontally-scrollable region keyboard-accessible
          (WCAG 2.1.1 / axe scrollable-region-focusable). role+label name it. */}
      <div
        className={cn('table-wrap', className)}
        tabIndex={0}
        role="region"
        aria-label={`${columns.map((column) => column.label).join(', ')} data table`}
      >
        <table className="data-table">
          <TableHeaderRow columns={columns} />
          {children}
        </table>
      </div>
    </>
  );
}

export function DataTable<T>({
  columns,
  items,
  empty,
  className,
  selectedId = null,
  getRowId,
  getRowProps,
  loadError = null,
  onRetry
}: DataTableProps<T>) {
  const failureMessage = loadError?.trim() ?? '';
  if (items.length === 0) {
    return (
      <>
        <style>{DATA_TABLE_STYLES}</style>
        <div
          className={cn('table-wrap data-table-empty-wrap', className)}
          tabIndex={0}
          role="region"
          aria-label={`${columns.map((column) => column.label).join(', ')} data table, empty`}
        >
          <div className="table-empty">
            {failureMessage ? <TableLoadError message={failureMessage} onRetry={onRetry} /> : empty}
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      {failureMessage ? (
        <TableLoadError message={failureMessage} onRetry={onRetry} retainedRows />
      ) : null}
      <DataTableChrome columns={columns} className={className}>
        <tbody>
          {items.map((item, index) => {
            const rowId = getRowId?.(item, index) ?? index;
            const isSelected = selectedId != null && selectedId === rowId;
            const rowProps = getRowProps?.(item, index) ?? {};

            return (
              <DataTableBodyRow
                key={rowId}
                item={item}
                index={index}
                columns={columns}
                isSelected={isSelected}
                rowProps={rowProps}
              />
            );
          })}
        </tbody>
      </DataTableChrome>
    </>
  );
}
