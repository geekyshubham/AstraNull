import type { HTMLAttributes, ReactNode } from 'react';
import { cn, DEPLOYMENT_MODE_GAP_MESSAGE } from '../../lib/utils';

const DATA_TABLE_STYLES = `
.table-wrap .data-table .data-table-head th {
  font-family: var(--font-mono);
  font-size: 10.5px;
  letter-spacing: var(--tracking-caps);
  text-transform: uppercase;
  color: var(--fg-2);
  font-weight: 500;
  background: color-mix(in oklab, var(--fg), transparent 96%);
  border-bottom: 1px solid var(--border);
}
.table-wrap .data-table tbody tr.table-row-zebra td {
  background: color-mix(in oklab, var(--fg), transparent 98%);
}
.table-wrap .data-table tbody tr.table-row-zebra:hover td {
  background: color-mix(in oklab, var(--accent), transparent 97%);
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
   * Why this dataset is missing. When set, `items` is a fallback rather than
   * data, so the error is shown INSTEAD of the empty state — an operator must
   * never read "no findings" when the truth is "findings failed to load".
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

export function TableLoadError({ message, onRetry }: { message: string; onRetry?: () => void }) {
  const permanent = isDeploymentModeMessage(message);
  return (
    <div className="form-banner error table-load-error" role="alert">
      <span>{permanent ? message : `Could not load — ${message}`}</span>
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
  rowId: string | number;
  isSelected: boolean;
  rowProps: Omit<HTMLAttributes<HTMLTableRowElement>, 'key'>;
};

function DataTableBodyRow<T>({
  item,
  index,
  columns,
  rowId,
  isSelected,
  rowProps
}: DataTableBodyRowProps<T>) {
  const { className: rowClassName, ...restRowProps } = rowProps;
  const zebra = index % 2 === 1;

  return (
    <tr
      {...restRowProps}
      className={cn(zebra && 'table-row-zebra', isSelected && 'table-row-selected', rowClassName)}
      aria-selected={isSelected ? true : restRowProps['aria-selected']}
    >
      {columns.map((column) => (
        <td key={column.key} data-label={column.label}>
          {column.render(item)}
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
      <div className={cn('table-wrap', className)} tabIndex={0} role="region" aria-label="Data table, scrollable">
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
  if (items.length === 0) {
    const failed = Boolean(loadError && loadError.trim());
    return (
      <DataTableChrome columns={columns} className={className}>
        <tbody>
          <tr className="table-empty-row">
            <td colSpan={columns.length}>
              <div className="table-empty">
                {failed ? <TableLoadError message={String(loadError).trim()} onRetry={onRetry} /> : empty}
              </div>
            </td>
          </tr>
        </tbody>
      </DataTableChrome>
    );
  }

  return (
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
              rowId={rowId}
              isSelected={isSelected}
              rowProps={rowProps}
            />
          );
        })}
      </tbody>
    </DataTableChrome>
  );
}