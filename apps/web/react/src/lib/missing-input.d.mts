export const REQUIRED_INPUT_MISSING: 'required_input_missing';
export const NOT_TESTED_LABEL: string;
export const NOT_TESTED_DETAIL: string;

export type RequiredInputMissing = {
  reason: string;
  label: string;
  message: string;
  serverMessage: boolean;
  section: string;
  cta: string;
  tone: 'muted';
};

export function notTestedSentence(code: string | null | undefined): string;
export function requiredInputMissing(source: unknown): RequiredInputMissing | null;
export function requiredInputMissingHref(info: RequiredInputMissing | null | undefined, targetId: string | null | undefined): string;
