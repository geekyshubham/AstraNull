import type { CheckRow } from './domain-checks.mjs';
import type { DataItem } from './types';

export type LiveLogLevel =
  | 'init'
  | 'dns'
  | 'tls'
  | 'probe'
  | 'recv'
  | 'marker'
  | 'evasion'
  | 'confusion'
  | 'bypass'
  | 'analysis'
  | 'verdict'
  | 'info'
  | 'warn'
  | 'error';

export type LiveLogEntry = {
  id: string;
  timestamp: string;
  timeDisplay: string;
  level: LiveLogLevel;
  tag: string;
  message: string;
  detail?: string;
  checkId?: string;
  checkName?: string;
  phase?: string;
  requestsSent?: number;
  maxRequests?: number;
  statusCode?: number;
  latencyMs?: number;
};

export declare const WAF_FINGERPRINT_PHASES: readonly {
  id: string;
  name: string;
  method: string;
  path: string;
  tag: string;
  level: string;
  summary: string;
}[];

export declare function generateCheckProbeLogs(
  row: CheckRow,
  targetValue?: string,
  runEvents?: DataItem[]
): LiveLogEntry[];

export declare function buildScanLiveLogs(
  scan: DataItem | null,
  rows?: CheckRow[],
  activityItems?: DataItem[],
  targetValue?: string
): LiveLogEntry[];
