export type StoryTone = 'gap' | 'pass' | 'review' | 'not_tested';

export type EvidenceStory = {
  family: string;
  tone: StoryTone;
  observationOnly: boolean;
  kicker: string;
  headline: string;
  tested: string;
  why: string;
  fix: string[];
};

export type ProofRow = { key: string; tone: 'fail' | 'pass' | 'neutral'; title: string; detail: string };

type Field = { key: string; value: string };

export function storyFamily(checkId: string, vectorFamily?: string): string;
export function storyTone(outcome: string, notTested?: boolean): StoryTone;
export function evidenceStory(input?: {
  checkId?: string;
  vectorFamily?: string;
  outcome?: string;
  notTested?: boolean;
  observationOnly?: boolean;
  remediation?: string;
  explanation?: string;
}): EvidenceStory;
export function proofRows(input: {
  tone: string;
  observed?: string;
  expected?: string;
  request?: Field[];
  response?: Field[];
  proof?: { addresses?: string[]; matched_signals?: string[]; fingerprints?: string[]; cnames?: string[] } | null;
}): ProofRow[];
