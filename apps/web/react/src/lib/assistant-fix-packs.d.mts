export type FixPack = {
  title: string; provider: string; finding_id: string;
  prerequisites: string[]; steps: string[]; verification: string[]; rollback: string[]; limitations: string[];
  sources: { id: string; title: string; url: string }[]; citations: string[];
};
export type FixPackScope = { findingId: string; provider: string; controlFamily: string; docs: string[] };
export function sanitizeFixPack(value: unknown, scope: FixPackScope): FixPack | null;
export function fixPackCopyText(pack: FixPack): string;
