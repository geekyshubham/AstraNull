import type { HTMLAttributes, ReactNode } from 'react';
import { cn } from '../../lib/utils';

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
    <thead>
      <tr>
        {columns.map((column) => (
          <th key={column.key}>{column.label}</th>
        ))}
      </tr>
    </thead>
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
      <div className={cn('table-wrap', className)}>
        <table>
          <TableHeaderRow columns={columns} />
          <tbody>
            <tr className="table-empty-row">
              <td colSpan={columns.length}>
                <div className="table-empty">{empty}</div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div className={cn('table-wrap', className)}>
      <table>
        <TableHeaderRow columns={columns} />
        <tbody>
          {items.map((item, index) => {
            const rowId = getRowId?.(item, index) ?? index;
            const isSelected = selectedId != null && selectedId === rowId;
            const rowProps = getRowProps?.(item, index) ?? {};
            const { className: rowClassName, ...restRowProps } = rowProps;

            return (
              <tr
                key={rowId}
                {...restRowProps}
                className={cn(isSelected && 'table-row-selected', rowClassName)}
                aria-selected={isSelected ? true : restRowProps['aria-selected']}
              >
                {columns.map((column) => (
                  <td key={column.key} data-label={column.label}>{column.render(item)}</td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
