import type { DataItem, Session } from './types';
export type RecordedActivityState = { snapshot: DataItem | null; record: DataItem | null; error: unknown; lastUpdated: string; updating: boolean; revision: number };
export type ActivitySubscription = { setActive(active: boolean): void; unsubscribe(): void };
export type RecordedActivityReader = { getState(): RecordedActivityState; subscribe(listener: (state: RecordedActivityState) => void, active?: boolean): ActivitySubscription; refresh(): void; dispose(): void };
export declare const ACTIVITY_POLL_MS: number;
export declare const ACTIVITY_MAX_BACKOFF_MS: number;
export declare const EMPTY_ACTIVITY_STATE: Readonly<RecordedActivityState>;
export declare function activityIsLive(snapshot: DataItem | null | undefined): boolean;
export declare function activityPath(kind: 'run' | 'scan', id: string, cursor?: string): string;
export declare function mergeActivityItems(previous?: DataItem[], incoming?: DataItem[]): DataItem[];
export declare function captureWarnings(snapshot: DataItem | null): string[];
export declare function stopStateLabel(stop: unknown): string;
export declare function activityItemsToEvents(snapshot: DataItem | null): DataItem[];
export declare function createRecordedActivityReader(options: { kind?: 'run' | 'scan'; id: string; read: (path: string, options: { signal: AbortSignal }) => Promise<unknown> }): RecordedActivityReader;

export declare function createActivityReaderKey(): (scope: { identity: string; authMode: string; session: Session; kind?: 'run' | 'scan'; id: string }) => string;
