export type ExpectationConflict = { entry_path_id: string; conflicts: string[] };

export function parseExpectationConflicts(value: unknown): ExpectationConflict[];
export function expectationConflictLabel(code: unknown): string;
