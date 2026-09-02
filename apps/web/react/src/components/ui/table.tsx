import type { HTMLAttributes, ReactNode } from 'react';
import { cn, DEPLOYMENT_MODE_GAP_MESSAGE } from '../../lib/utils';
import { useScrollEdges } from '../../lib/scroll-edges';

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
  const { setScrollNode, edges } = useScrollEdges<HTMLDivElement>();

  return (
    // The outer element carries the edge affordance: it must not scroll with
    // the content it shades.
    <div className="table-scroller" data-scroll-x={edges}>
      {/* tabIndex=0 makes the horizontally-scrollable region keyboard-accessible
          (WCAG 2.1.1 / axe scrollable-region-focusable). role+label name it. */}
      <div
        ref={setScrollNode}
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
    </div>
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
