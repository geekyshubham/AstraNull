import type { DataItem } from './types';
export type RecordedExchange = { id: string; exchangeId: string; source: DataItem; events: DataItem[]; request: DataItem | null; response: DataItem | null; failure: DataItem | null; bodyComplete: boolean; conflictFields: string[]; state: 'not_sent' | 'failed' | 'partial' | 'captured' };
export function safeCaptureText(value: unknown): string;
export function safeCaptureUrl(value: unknown): string;
export function captureHeaders(value: unknown): Array<{ name: string; value: string }> | null;
export function recordedExchanges(items: DataItem[]): { exchanges: RecordedExchange[]; lifecycle: DataItem[] };
export function exchangeCopyText(exchange: RecordedExchange): string;
