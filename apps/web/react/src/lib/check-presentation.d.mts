export type CheckPresentation = { name: string; purpose: string; limitations: string; next_step: string; mechanism: string };
export function checkPresentation(checkOrId: unknown): CheckPresentation;
