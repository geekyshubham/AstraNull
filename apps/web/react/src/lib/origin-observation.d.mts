import type { DataItem } from './types';

export const ORIGIN_OBSERVATION_LABELS: Readonly<Record<string, string>>;
export const ORIGIN_OBSERVATION_GAP_LABELS: Readonly<Record<string, string>>;
export function originObservation(meta: DataItem | null | undefined): DataItem | null;
export function originObservationLabel(meta: DataItem | null | undefined, fallback?: string): string;
export function originIdentityLabel(meta: DataItem | null | undefined): string;
