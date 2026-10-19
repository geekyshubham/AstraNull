export type AssistantEntityType = 'target' | 'finding' | 'run' | 'check' | 'scan' | 'report' | 'schedule' | 'group';
export type AssistantPageContext = {
  route: string;
  title: string;
  kind: string;
  entity?: { type: AssistantEntityType; id: string };
  tab?: string;
  filters?: Record<string, string>;
  facts?: Record<string, string>;
};
export type PublishedPageContext = {
  route: string;
  title?: string;
  entity?: { type: AssistantEntityType; id: string };
  tab?: string;
  filters?: Record<string, string | number | boolean | null | undefined>;
  facts?: Record<string, string | number | boolean | null | undefined>;
};

export const MAX_FILTERS: number;
export const MAX_FACTS: number;
export const MAX_FACT_VALUE: number;
export const ENTITY_TYPES: readonly AssistantEntityType[];
export function sanitizePageContext(value: unknown): AssistantPageContext | null;
export function parseRouteHash(hash: string): { route: string; params: Record<string, string> };
export function derivedFacts(route: string, entityId: string, data: unknown): Record<string, string>;
export function buildPageContext(input: {
  route: string;
  params?: Record<string, string>;
  title?: string;
  data?: unknown;
  published?: PublishedPageContext | null;
}): AssistantPageContext | null;
export function contextIds(page: AssistantPageContext | null | undefined): Partial<Record<'target_id' | 'finding_id' | 'run_id' | 'check_id' | 'scan_id', string>>;
export function describePageContext(page: AssistantPageContext | null | undefined): string;
export function pageSuggestions(kind: string | undefined): string[];
