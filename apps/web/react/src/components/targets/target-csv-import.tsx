import { useId, useState, type ChangeEvent, type FormEvent } from 'react';
import { FileUp } from 'lucide-react';
import { FormModal } from '../../lib/crud-ui';
import { sessionHasPermission } from '../../lib/dataset-access.mjs';
import { apiErrorMessage } from '../../lib/error-messages';
import {
  importTargetCsv,
  summarizeTargetCsv,
  TARGET_CSV_MAX_BYTES,
  TARGET_CSV_MAX_ROWS,
  validateTargetCsvFile,
  type TargetCsvImportResult,
  type TargetCsvRowError,
  type TargetCsvSummary
} from '../../lib/target-csv-import';
import type { PortalConfig, Session } from '../../lib/types';
import { Button } from '../ui/button';
import { DataTable, type TableColumn } from '../ui/table';

const ROW_ERROR_COLUMNS: TableColumn<TargetCsvRowError>[] = [
  { key: 'row', label: 'Row', render: (item) => (item.row === null ? '—' : <span className="tabular-nums">{item.row}</span>) },
  { key: 'error', label: 'Error', render: (item) => item.error }
];

export function TargetCsvImportButton({
  config,
  session,
  onImported
}: {
  config: PortalConfig;
  session: Session;
  onImported: () => Promise<void>;
}) {
  const inputId = useId();
  const helpId = useId();
  const [open, setOpen] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [summary, setSummary] = useState<TargetCsvSummary | null>(null);
  const [fileError, setFileError] = useState('');
  const [submitError, setSubmitError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<TargetCsvImportResult | null>(null);

  if (!sessionHasPermission(session, 'target_group:write')) return null;

  function reset() {
    setFile(null);
    setSummary(null);
    setFileError('');
    setSubmitError('');
    setResult(null);
  }

  function close() {
    if (submitting) return;
    setOpen(false);
    reset();
  }

  async function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const selected = event.target.files?.[0] ?? null;
    reset();
    if (!selected) return;
    const sizeError = validateTargetCsvFile(selected);
    if (sizeError) {
      setFileError(sizeError);
      return;
    }
    const nextSummary = summarizeTargetCsv(await selected.text());
    const rowError = validateTargetCsvFile(selected, nextSummary);
    setSummary(nextSummary);
    if (rowError) {
      setFileError(rowError);
      return;
    }
    setFile(selected);
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file || submitting) return;
    setSubmitting(true);
    setSubmitError('');
    try {
      const imported = await importTargetCsv(config, session, file);
      setResult(imported);
      setFile(null);
      if (imported.created.length > 0) await onImported().catch(() => undefined);
    } catch (err) {
      setSubmitError(apiErrorMessage(err, 'CSV import failed.'));
    } finally {
      setSubmitting(false);
    }
  }

  const rowCount = summary?.rowCount ?? 0;

  return (
    <>
      <Button size="sm" variant="secondary" onClick={() => setOpen(true)}><FileUp size={14} aria-hidden="true" /> Import CSV</Button>
      <FormModal
        open={open}
        title="Import targets from CSV"
        description="Declare several targets at once. Every row is validated before anything is saved: if any row is rejected, nothing is imported and each rejected row is listed with its reason. Nothing is discovered automatically."
        onClose={close}
      >
        <form className="product-form" onSubmit={(event) => void handleSubmit(event)} aria-busy={submitting || undefined}>
          <label className="full" htmlFor={inputId}>
            <span>CSV file</span>
            <input
              id={inputId}
              type="file"
              accept=".csv,text/csv"
              aria-describedby={helpId}
              disabled={submitting}
              onChange={(event) => void handleFileChange(event)}
            />
          </label>
          <p className="muted small full" id={helpId}>
            One target per row (FQDN, URL, or IP, with an optional header row). Up to {TARGET_CSV_MAX_ROWS} rows and {TARGET_CSV_MAX_BYTES / 1024} KB per file.
          </p>
          {fileError ? <p className="form-banner error full" role="alert">{fileError}</p> : null}
          {file && summary ? (
            <p className="form-banner neutral full" role="status">
              {rowCount} target row{rowCount === 1 ? '' : 's'} ready to import from {file.name}
              {summary.hasHeader ? ' (header row skipped)' : ''}.
            </p>
          ) : null}
          {submitError ? <p className="form-banner error full" role="alert">{submitError}</p> : null}
          {result ? (
            <div className="full stack-tight" role="status" aria-live="polite">
              <p className={result.errors.length > 0 ? 'form-banner info' : 'form-banner'}>
                Created {result.created.length} target{result.created.length === 1 ? '' : 's'}
                {result.errors.length > 0 ? `; ${result.errors.length} row${result.errors.length === 1 ? ' was' : 's were'} rejected. The import is all-or-nothing, so fix these rows and upload again.` : '.'}
              </p>
              {result.errors.length > 0 ? (
                <DataTable
                  columns={ROW_ERROR_COLUMNS}
                  items={result.errors}
                  getRowId={(item) => `${item.row ?? 'row'}-${item.error}`}
                  empty={null}
                />
              ) : null}
            </div>
          ) : null}
          <div className="form-actions full">
            <Button type="button" variant="ghost" onClick={close} disabled={submitting}>{result ? 'Done' : 'Cancel'}</Button>
            <Button type="submit" loading={submitting} disabled={!file || Boolean(fileError)}>
              {file ? `Import ${rowCount} target${rowCount === 1 ? '' : 's'}` : 'Import'}
            </Button>
          </div>
        </form>
      </FormModal>
    </>
  );
}
