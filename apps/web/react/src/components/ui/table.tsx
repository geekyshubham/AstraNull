import type { HTMLAttributes, ReactNode } from 'react';
import { cn } from '../../lib/utils';

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
};

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
      <div className={cn('table-wrap', className)}>
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
  getRowProps
}: DataTableProps<T>) {
  if (items.length === 0) {
    return (
      <DataTableChrome columns={columns} className={className}>
        <tbody>
          <tr className="table-empty-row">
            <td colSpan={columns.length}>
              <div className="table-empty">{empty}</div>
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