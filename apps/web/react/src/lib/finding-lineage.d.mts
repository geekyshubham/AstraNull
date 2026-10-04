export type FindingRunRef = { testRunId: string; status: string; createdAt: string; finalized: boolean | null; reason: string };
export type FindingLineageView = {
  originating: FindingRunRef | null;
  retests: FindingRunRef[];
  laterSamePair: FindingRunRef[];
  latest: { testRunId: string; relation: string; status: string; finalized: boolean | null; pending: boolean; completedAt: string } | null;
  closedAt: string;
  siblingClosure: false;
};
export function readFindingLineage(finding: Record<string, unknown>): FindingLineageView;
