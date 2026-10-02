export type NotificationChannelId = 'slack' | 'teams' | 'email' | 'webhook';

export type NotificationChannelMeta = {
  readonly id: NotificationChannelId;
  readonly label: string;
  readonly kind: string;
  readonly description: string;
  readonly destinationLabel: string;
  readonly placeholder: string;
  readonly hint: string;
  readonly docsUrl: string;
  readonly docsLabel: string;
  readonly inputType: 'url' | 'email';
};

export type NotificationTriggerOption = {
  readonly id: string;
  readonly label: string;
  readonly detail: string;
};

export type DeliveryTone = 'success' | 'warn' | 'danger' | 'info' | 'muted';

export declare const MAX_DESTINATION_LENGTH: number;
export declare const NOTIFICATION_CHANNELS: readonly NotificationChannelMeta[];
export declare const NOTIFICATION_TRIGGER_OPTIONS: readonly NotificationTriggerOption[];
export declare const DEFAULT_NOTIFICATION_TRIGGERS: readonly string[];

export declare function findNotificationChannel(channelId: unknown): NotificationChannelMeta | null;
export declare function notificationChannelLabel(channelId: unknown): string;
export declare function notificationTriggerLabel(triggerId: unknown): string;
export declare function validateChannelDestination(
  channel: string,
  raw: unknown
): { ok: true; destination: string; warning?: string } | { ok: false; error: string };
export declare function normalizeSelectedTriggers(
  selected: unknown
): { ok: true; triggers: string[] } | { ok: false; error: string };
export type DeliverySource = 'authoritative' | 'window';
export declare function deliveryStatusPresentation(
  status: unknown,
  context?: { source?: DeliverySource; windowSize?: number }
): { label: string; tone: DeliveryTone; detail: string };
export declare function resolveRuleLatestDelivery(
  ruleId: string,
  input?: {
    latestDeliveries?: Record<string, Record<string, unknown> | null> | null;
    eventsLatest?: Map<string, Record<string, unknown>>;
    windowSize?: number;
  }
): { attempt: Record<string, unknown> | null; source: DeliverySource; windowSize?: number };
export declare function notificationSessionKey(session: unknown): string;
export type LatestRequestToken = { readonly generation: number; readonly key: string };
export declare function createLatestRequestGuard(): {
  begin(key: string): LatestRequestToken;
  isCurrent(token: LatestRequestToken, currentKey?: string): boolean;
  cancel(): void;
};
export declare function buildRuleUpdateBody(
  channel: string,
  draft: { destination?: unknown; triggers?: unknown }
):
  | { ok: true; body: { triggers: string[]; destination?: string }; warning?: string }
  | { ok: false; field: 'destination' | 'triggers'; error: string };
export declare function latestAttemptByRule(events: unknown): Map<string, Record<string, unknown>>;
export declare function summarizeChannelRules(rules: unknown): Record<string, { total: number; enabled: number }>;
export declare function buildSampleChannelPayload(channel: string): Record<string, unknown>;
