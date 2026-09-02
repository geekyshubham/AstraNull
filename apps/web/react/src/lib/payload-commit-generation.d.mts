export type PayloadCommitTicket = Readonly<{
  generation: number;
  routeKey: string;
}>;

export interface PayloadCommitGate {
  activate(routeKey: string): number;
  begin(routeKey: string): PayloadCommitTicket;
  isCurrent(ticket: PayloadCommitTicket | null | undefined): boolean;
}

export declare function createPayloadCommitGate(initialRouteKey?: string): PayloadCommitGate;

export declare function runGenerationKeyedPayload<T>(options: {
  gate: PayloadCommitGate;
  routeKey: string;
  load: (isCurrent: () => boolean) => Promise<T>;
  onCommit: (payload: T) => void;
  onError: (error: unknown) => void;
  onSettled?: () => void;
}): Promise<boolean>;
