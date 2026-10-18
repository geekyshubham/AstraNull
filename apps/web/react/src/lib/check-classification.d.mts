export type CheckProtectionControlId = 'waf' | 'network_firewall' | 'cdn_edge' | 'ddos' | 'dns_provider';

export type CheckProtectionControl = Readonly<{ id: CheckProtectionControlId; short: string; label: string }>;

export type CheckLayer = Readonly<{ osi: string; protocol: string | null; label: string }>;

export declare const CHECK_PROTECTION_CONTROLS: Readonly<Record<CheckProtectionControlId, CheckProtectionControl>>;

export declare function classifyCheck(check: unknown): {
  layer: CheckLayer | null;
  controls: CheckProtectionControl[];
  declaration_only: boolean;
};

export declare function checkClassificationFields(check: unknown): {
  layer: string | null;
  protection_controls: CheckProtectionControlId[];
  declaration_only: boolean;
};

export type CheckImpactId = 'non_invasive' | 'invasive';

export type CheckImpactClass = Readonly<{ id: CheckImpactId; label: string; summary: string }>;

export declare const CHECK_IMPACT_CLASSES: Readonly<Record<CheckImpactId, CheckImpactClass>>;

export declare function classifyCheckImpact(check: unknown): CheckImpactClass;
