import type { DataItem } from './types';

export const ORIGIN_IMPORT_MAX_BYTES: number;
export const ORIGIN_IMPORT_MAX_RECORDS: number;
export const ORIGIN_CLUE_SOURCE_LABELS: Readonly<Record<string, string>>;
export function originClueSourceLabel(value: string): string;
export function originCluesErrorState(error: unknown): 'disabled' | 'forbidden' | 'unsupported' | 'error';
export function originClueImportBody(input: { sourceKind: string; sourceRef: string; content: string }): DataItem;
export function originCluesPage(payload: unknown, targetId: string): DataItem;
