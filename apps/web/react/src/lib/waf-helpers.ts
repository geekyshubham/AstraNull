import type { DataItem } from './types';
import { formatDate } from './utils';

export const WAF_POSTURE_TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'roadmap', label: 'Roadmap' },
  { id: 'assets', label: 'Assets' }
] as const;

export type WafPostureTabId = (typeof WAF_POSTURE_TABS)[number]['id'];

export const DRIFT_EVENT_STATUSES = [
  'open',
  'acknowledged',
  'remediation_started',
  'retest_pending',
  'resolved',
  'accepted_risk',
  'false_positive'
] as const;

export const VALIDATION_PLAN_SCENARIOS = ['marker', 'fingerprint', 'origin_bypass'] as const;

export function retestForDriftEvent(retests: DataItem[] = [], driftEventId: string) {
  if (!driftEventId) return null;
  return retests
    .filter((item) => item.drift_event_id === driftEventId)
    .sort((left, right) => String(right.updated_at ?? right.created_at ?? '').localeCompare(String(left.updated_at ?? left.created_at ?? '')))[0] ?? null;
}

const WAF_ROADMAP_TIER_META: Record<string, { label: string; window: string }> = {
  tier_1: { label: 'Tier 1', window: '0–14 days' },
  tier_2: { label: 'Tier 2', window: '15–60 days' },
  tier_3: { label: 'Tier 3', window: '61–180 days' },
  tier_4: { label: 'Tier 4', window: 'Quarterly review' }
};

export function computeWafAssetPassRate(assetId: string, validations: DataItem[] = [], lookbackDays = 30): number | null {
  if (!assetId || validations.length === 0) return null;
  const cutoff = new Date();
  cutoff.setUTCDate(cutoff.getUTCDate() - Math.max(1, lookbackDays));
  const cutoffIso = cutoff.toISOString();
  const relevant = validations.filter((run) => {
    const summary = run.summary_json as DataItem | undefined;
    return run.waf_asset_id === assetId
      && run.status === 'finalized'
      && String(run.finalized_at ?? run.created_at ?? '') >= cutoffIso;
  });
  if (relevant.length === 0) return null;
  const passed = relevant.filter((run) => {
    const summary = run.summary_json as DataItem | undefined;
    return summary?.validation_passed === true;
  }).length;
  return Math.round((passed / relevant.length) * 10000) / 100;
}

export function formatWafPassRateDisplay(rate: number | null | undefined, lookbackDays = 30): string {
  if (rate == null || !Number.isFinite(Number(rate))) return '—';
  return `${Math.round(Number(rate) * 100) / 100}% (${lookbackDays}d)`;
}

export function formatWafRuleHealthDisplay(effectiveness: DataItem | null | undefined): string {
  if (!effectiveness || typeof effectiveness !== 'object') return '—';
  const ruleCount = effectiveness.rule_count;
  if (!Number.isFinite(Number(ruleCount))) return '—';
  const count = Math.floor(Number(ruleCount));
  const updated = effectiveness.last_rule_update_at ? formatDate(effectiveness.last_rule_update_at) : null;
  return updated ? `${count} rules · updated ${updated}` : `${count} rules`;
}

export function roadmapTierIds(): string[] {
  return ['tier_1', 'tier_2', 'tier_3', 'tier_4'];
}

export function roadmapTierMeta(tierId: string) {
  return WAF_ROADMAP_TIER_META[tierId] ?? { label: tierId, window: '' };
}

export function roadmapTotalItems(tiers: Record<string, DataItem[] | undefined> = {}): number {
  return roadmapTierIds().reduce((sum, tierId) => sum + (tiers[tierId]?.length ?? 0), 0);
}