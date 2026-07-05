import type { ReactNode } from 'react';
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

export function DataTable<T>({ columns, items, empty, className }: DataTableProps<T>) {
  if (items.length === 0) {
    return (
      <div className={cn('table-wrap', className)}>
        <table>
          <TableHeaderRow columns={columns} />
        </table>
        {empty}
      </div>
    );
  }
  return (
    <div className={cn('table-wrap', className)}>
      <table>
        <TableHeaderRow columns={columns} />
        <tbody>
          {items.map((item, index) => (
            <tr key={index}>
              {columns.map((column) => (
                <td key={column.key}>{column.render(item)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
