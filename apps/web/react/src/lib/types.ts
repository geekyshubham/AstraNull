import type { LucideIcon } from 'lucide-react';

export type SurfaceKind = 'overview' | 'scope' | 'validation' | 'governance' | 'staff';

export type RouteId =
  | 'dashboard'
  | 'environments'
  | 'environment-detail'
  | 'target-groups'
  | 'targets'
  | 'target-group-detail'
  | 'target-detail'
  | 'agents'
  | 'agent-detail'
  | 'checks'
  | 'check-detail'
  | 'test-policies'
  | 'policy-detail'
  | 'runs'
  | 'run-detail'
  | 'findings'
  | 'finding-detail'
  | 'evidence-detail'
  | 'reports'
  | 'report-detail'
  | 'integrations'
  | 'notifications'
  | 'audit'
  | 'release-evidence'
  | 'settings'
  | 'support'
  | 'subscription'
  | 'admin'
  | 'tenant-detail'
  | 'internal-soc'
  | 'queue-detail';

export type PortalDataset =
  | 'state'
  | 'tenant'
  | 'deploymentFeatures'
  | 'targetGroups'
  | 'targets'
  | 'agents'
  | 'checks'
  | 'testPolicies'
  | 'runs'
  | 'findings'
  | 'evidence'
  | 'highScale'
  | 'reports'
  | 'notifications'
  | 'releaseEvidence'
  | 'releaseAttestation'
  | 'audit'
  | 'connectors'
  | 'secrets'
  | 'bootstrapTokens'
  | 'serviceAccounts'
  | 'wafAssets'
  | 'wafCoverage'
  | 'wafCoverageSummary'
  | 'wafRiskRoadmap'
  | 'wafValidations'
  | 'wafDriftEvents'
  | 'wafExceptions'
  | 'wafValidationPlans'
  | 'wafRetests'
  | 'wafActionItems'
  | 'cvePipeline'
  | 'supplyChainRisks'
  | 'discoveryEntities'
  | 'discoveryCandidates'
  | 'discoveryInbox'
  | 'discoverySummary'
  | 'subscriptionSummary'
  | 'internalOverview'
  | 'internalSignupRequests'
  | 'internalTenants'
  | 'internalApprovalRequests'
  | 'internalAudit';

export const CORE_PORTAL_DATASETS = [
  'state',
  'tenant',
  'deploymentFeatures'
] as const satisfies readonly PortalDataset[];

export const PORTAL_ROUTE_DATASETS = {
  dashboard: ['targetGroups', 'agents', 'checks', 'testPolicies', 'runs', 'findings', 'evidence', 'wafCoverageSummary'],
  environments: ['targetGroups', 'agents', 'runs', 'findings'],
  'environment-detail': ['targetGroups', 'agents', 'checks', 'runs', 'findings'],
  'target-groups': ['targetGroups', 'runs'],
  targets: ['targets', 'targetGroups'],
  'target-group-detail': ['targetGroups', 'agents', 'checks', 'testPolicies', 'connectors'],
  'target-detail': [],
  agents: ['targetGroups', 'agents', 'releaseEvidence'],
  'agent-detail': ['agents', 'audit', 'checks', 'runs'],
  checks: ['targetGroups', 'checks', 'runs', 'findings', 'evidence'],
  'check-detail': ['checks', 'runs'],
  'test-policies': ['targetGroups', 'checks', 'testPolicies'],
  'policy-detail': ['checks', 'testPolicies'],
  runs: ['targetGroups', 'checks', 'runs', 'findings', 'evidence', 'highScale'],
  'run-detail': ['targetGroups', 'checks', 'runs', 'findings', 'evidence'],
  findings: ['targetGroups', 'checks', 'runs', 'findings', 'evidence'],
  'finding-detail': ['findings', 'wafActionItems'],
  'evidence-detail': ['evidence', 'findings'],
  reports: ['reports', 'audit'],
  'report-detail': ['targetGroups', 'runs', 'findings', 'reports'],
  integrations: ['connectors', 'secrets', 'targetGroups'],
  notifications: ['notifications'],
  audit: ['audit'],
  'release-evidence': ['releaseEvidence', 'releaseAttestation'],
  settings: ['targetGroups', 'agents', 'evidence', 'secrets', 'bootstrapTokens', 'serviceAccounts'],
  support: ['subscriptionSummary'],
  subscription: ['subscriptionSummary'],
  admin: ['internalOverview', 'internalSignupRequests', 'internalTenants', 'internalApprovalRequests', 'internalAudit'],
  'tenant-detail': ['agents', 'internalTenants', 'internalApprovalRequests'],
  'internal-soc': ['findings', 'highScale', 'internalTenants', 'internalApprovalRequests'],
  'queue-detail': ['targetGroups', 'highScale']
} as const satisfies Record<RouteId, readonly PortalDataset[]>;

export type NavItem = {
  id: RouteId;
  label: string;
  group: SurfaceKind;
  description: string;
  icon: LucideIcon;
  count?: string;
};

export type Session = {
  mode?: string;
  principal?: string;
  tenant_id?: string;
  user_id?: string;
  role?: string;
  staff_id?: string;
  staff_role?: string;
  staff_login_path?: string;
  access_token?: string;
  expires_at?: number;
};

export type PortalConfig = {
  authMode: string;
  siteConfig: Record<string, unknown>;
  bundledLoginEnabled: boolean;
  /** Server offers the credential lane: POST /v1/auth/login + /v1/auth/set-password. */
  passwordLoginEnabled: boolean;
  loginUrl: string;
  portalPath: string;
  staffLoginPath: string;
};

export type ReadinessFactor = {
  key?: string;
  label?: string;
  score?: number;
  weight?: number;
  reason?: string;
  detail?: string;
};

export type ReadinessPostureSegment = {
  key: 'pass' | 'review' | 'gap';
  label: string;
  count: number;
  pct: number;
};

export type StatePayload = {
  tenant_id?: string;
  readiness?: {
    score?: number;
    factors?: ReadinessFactor[];
    summary?: string;
    delta?: number;
    posture?: {
      pass?: number;
      review?: number;
      gap?: number;
      total?: number;
    };
  };
  target_groups?: number;
  agents_online?: number;
  agents_total?: number;
  recent_runs?: DataItem[];
  open_findings?: number;
  high_scale_requests?: number;
  last_validation_at?: string;
  kill_switch?: {
    active?: boolean;
    enabled?: boolean;
    reason?: string;
    updated_at?: string;
  };
};

export type DataItem = Record<string, unknown>;

export type PortalData = {
  state: StatePayload | null;
  tenant: DataItem | null;
  targetGroups: DataItem[];
  targetGroupsMeta: DataItem | null;
  targets: DataItem[];
  targetsMeta: DataItem | null;
  agents: DataItem[];
  checks: DataItem[];
  testPolicies: DataItem[];
  runs: DataItem[];
  findings: DataItem[];
  evidence: DataItem[];
  highScale: DataItem[];
  reports: DataItem[];
  /** Authoritative report kind/format options from `GET /v1/reports`. */
  reportCapabilities: DataItem | null;
  notificationRules: DataItem[];
  notificationEvents: DataItem[];
  releaseEvidence: DataItem[];
  releaseAttestation: DataItem | null;
  audit: DataItem[];
  connectors: DataItem[];
  secrets: DataItem[];
  bootstrapTokens: DataItem[];
  serviceAccounts: DataItem[];
  wafAssets: DataItem[];
  wafCoverage: DataItem | null;
  wafCoverageSummary: DataItem | null;
  wafRiskRoadmap: DataItem | null;
  wafValidations: DataItem[];
  wafDriftEvents: DataItem[];
  wafExceptions: DataItem[];
  wafValidationPlans: DataItem[];
  wafRetests: DataItem[];
  wafActionItems: DataItem[];
  cvePipeline: DataItem[];
  supplyChainRisks: DataItem[];
  discoveryEntities: DataItem[];
  discoveryCandidates: DataItem[];
  discoveryInbox: DataItem[];
  discoverySummary: DataItem | null;
  subscriptionSummary: DataItem | null;
  internalOverview: DataItem | null;
  internalSignupRequests: DataItem[];
  internalTenants: DataItem[];
  internalApprovalRequests: DataItem[];
  internalAudit: DataItem[];
  deploymentFeatures: DataItem | null;
  /**
   * Per-dataset hydrate failures, keyed by the PortalData field name above.
   *
   * An absent key means the dataset loaded (an empty array is genuinely empty).
   * A present key means the array/object beside it is a FALLBACK, not data — the
   * surface must say so instead of rendering a silent empty state.
   */
  loadErrors: Record<string, string>;
  loaded: boolean;
  error: string | null;
};

export type BadgeTone = 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';
