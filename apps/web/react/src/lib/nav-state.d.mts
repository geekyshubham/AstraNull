export type NavListState = {
  filters?: Record<string, string>;
  sort?: string;
  view?: string;
  tab?: string;
  check?: string;
  selectedRowId?: string;
  focusKey?: string;
  page?: number;
  pageSize?: number;
  scrollTop?: number;
  expanded?: string[];
};

export declare const NAV_STATE_PREFIX: string;
export declare const NAV_FILTER_KEYS: Readonly<Record<string, 'search' | 'slug' | 'label' | 'token'>>;
export declare const NAV_STATE_TTL_MS: number;
export declare function navScopeKey(session: unknown): string;
export declare function sanitizeNavState(input: unknown): NavListState;
export declare function navStateStorageKey(scope: string, route: string): string;
export declare function saveNavState(scope: string, route: string, state: NavListState, now?: number): boolean;
export declare function loadNavState(scope: string, route: string, now?: number): NavListState | null;
export declare function clearNavState(keepScope?: string): void;
