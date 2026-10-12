import { assessPostureAssurance, assetInCohortAsOf, snapshotAvailableAsOf, snapshotObservedAt } from '../lib/wafPostureAssurance.mjs';
import {
  WAF_RISK_METHOD,
  assignPriorityBand,
  computeAssetRiskAssessment,
  deriveRecommendedAction,
  hostnameFromCanonicalUrl,
} from './wafRiskService.mjs';

const STATUS_KEYS = ['protected', 'edge_protected', 'underprotected', 'unprotected', 'unknown', 'excluded'];

const CRITICAL_BUSINESS_VALUES = new Set([
  'critical',
  'payment',
  'checkout',
  'pii',
  'auth',
  'admin',
  'internal_admin',
  'api',
  'high',
]);

function emptyStatusCounts() {
  return {
    protected: 0,
    edge_protected: 0,
    underprotected: 0,
    unprotected: 0,
    unknown: 0,
    excluded: 0,
  };
}

function statusForAsset(asset, snapshot, asOf = new Date()) {
  const status = assessPostureAssurance({ asset, snapshot, asOf }).status;
  return STATUS_KEYS.includes(status) ? status : 'unknown';
}

function coverageRatioFromCounts(counts, total) {
  const denominator = total - (counts.excluded ?? 0);
  if (denominator <= 0) return 0;
  return Math.round((counts.protected / denominator) * 10000) / 10000;
}

function percentagesFromCounts(counts, total) {
  const percentages = {};
  for (const key of STATUS_KEYS) {
    percentages[key] = total === 0 ? 0 : Math.round((counts[key] / total) * 10000) / 100;
  }
  return percentages;
}

function toUtcDateKey(isoString) {
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString().slice(0, 10);
}

function addDaysUtc(dateKey, days) {
  const date = new Date(`${dateKey}T00:00:00.000Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

function buildDailyDateKeys(windowDays = 90, now = new Date()) {
  const endKey = now.toISOString().slice(0, 10);
  const keys = [];
  for (let i = windowDays - 1; i >= 0; i -= 1) {
    keys.push(addDaysUtc(endKey, -i));
  }
  return keys;
}

function indexSnapshotsByAsset(snapshots = []) {
  const byAsset = new Map();
  for (const snapshot of snapshots) {
    if (!snapshot?.waf_asset_id) continue;
    const existing = byAsset.get(snapshot.waf_asset_id) ?? [];
    existing.push(snapshot);
    byAsset.set(snapshot.waf_asset_id, existing);
  }
  for (const records of byAsset.values()) records.sort((a, b) => String(snapshotObservedAt(a)).localeCompare(String(snapshotObservedAt(b))) || String(a.created_at).localeCompare(String(b.created_at)));
  return byAsset;
}

function cutoffForDay(dayKey, now) {
  const end = Date.parse(`${dayKey}T23:59:59.999Z`);
  return new Date(Math.min(end, new Date(now).getTime()));
}

function historicalBucket({ assets, snapshots, dayKey, now }) {
  const cutoff = cutoffForDay(dayKey, now);
  const byAsset = indexSnapshotsByAsset(snapshots);
  const counts = emptyStatusCounts();
  let total = 0;
  let unknownCohort = 0;
  for (const asset of assets) {
    const records = byAsset.get(asset.id) ?? [];
    const firstKnown = records.filter((record) => snapshotAvailableAsOf(record, cutoff)).map((record) => record.created_at ?? snapshotObservedAt(record)).sort()[0] ?? null;
    if (!asset.created_at) unknownCohort += 1;
    if (!assetInCohortAsOf(asset, cutoff, firstKnown)) continue;
    total += 1;
    // Observation and availability both precede cutoff. Never consult current asset.status.
    const snapshot = records.filter((record) => snapshotAvailableAsOf(record, cutoff)).at(-1) ?? null;
    const status = snapshot ? assessPostureAssurance({ snapshot, asOf: cutoff }).status : 'unknown';
    counts[STATUS_KEYS.includes(status) ? status : 'unknown'] += 1;
  }
  return { date: dayKey, total_assets: total, ...counts, coverage_ratio: coverageRatioFromCounts(counts, total), cutoff_at: cutoff.toISOString(), cohort_rule: 'declared_before_cutoff_not_retired_at_cutoff', unknown_cohort_count: unknownCohort, semantics_version: 'waf-coverage-history.v2', assurance_claim: 'observations_available_at_cutoff_only' };
}

export function buildCoverageTrend({ assets = [], historicalSnapshots = [], currentSnapshotsByAsset = new Map(), windowDays = 90, now = new Date() } = {}) {
  const snapshots = [...(Array.isArray(historicalSnapshots) ? historicalSnapshots : []), ...currentSnapshotsByAsset.values()];
  return buildDailyDateKeys(windowDays, now).map((dayKey) => historicalBucket({ assets, snapshots, dayKey, now }));
}

function normalizeCoverageRollupTrend(coverageRollups = []) {
  return coverageRollups
    .map((row) => {
      const date = row.rollup_date ?? row.date;
      if (!date) return null;
      return {
        date: String(date).slice(0, 10),
        coverage_ratio: Number(row.coverage_ratio ?? 0),
        protected: Number(row.protected ?? 0),
        edge_protected: Number(row.edge_protected ?? 0),
        underprotected: Number(row.underprotected ?? 0),
        unprotected: Number(row.unprotected ?? 0),
        unknown: Number(row.unknown ?? 0),
        excluded: Number(row.excluded ?? 0),
        total_assets: Number(row.total_assets ?? row.total ?? 0),
      };
    })
    .filter(Boolean)
    .sort((a, b) => a.date.localeCompare(b.date));
}

export function validCoverageRollupDate(rollupDate, now = new Date()) {
  const parsed = typeof rollupDate === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(rollupDate) ? new Date(`${rollupDate}T00:00:00.000Z`) : null;
  return Boolean(parsed && Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === rollupDate && rollupDate <= new Date(now).toISOString().slice(0, 10));
}

export function computeCoverageDailyRollup({ assets = [], currentSnapshotsByAsset = new Map(), historicalSnapshots = [], rollupDate = new Date().toISOString().slice(0, 10), now = new Date() } = {}) {
  if (!validCoverageRollupDate(rollupDate, now)) throw new RangeError('invalid_or_future_rollup_date');
  const bucket = historicalBucket({ assets, snapshots: [...(Array.isArray(historicalSnapshots) ? historicalSnapshots : []), ...currentSnapshotsByAsset.values()], dayKey: rollupDate, now });
  return { ...bucket, rollup_date: rollupDate };
}

export function buildCoverageSummary({
  assets = [],
  currentSnapshotsByAsset = new Map(),
  historicalSnapshots = [],
  coverageRollups = [],
  windowDays = 90,
  now = new Date(),
} = {}) {
  const counts = emptyStatusCounts();
  for (const asset of assets) {
    const snapshot = currentSnapshotsByAsset.get(asset.id) ?? null;
    const status = statusForAsset(asset, snapshot, now);
    counts[status] += 1;
  }
  const total = assets.length;
  const coverage_ratio = coverageRatioFromCounts(counts, total);
  const percentages = percentagesFromCounts(counts, total);
  const rollupTrend = normalizeCoverageRollupTrend(coverageRollups).filter((row) => row.date >= addDaysUtc(now.toISOString().slice(0, 10), -windowDays + 1) && row.date <= now.toISOString().slice(0, 10)).map((row) => ({ ...row, semantics_version: 'legacy_persisted_rollup', assurance_claim: 'historical_rollup_not_current_assurance' }));
  const trend = rollupTrend.length > 0
    ? rollupTrend
    : buildCoverageTrend({
      assets,
      historicalSnapshots,
      currentSnapshotsByAsset,
      windowDays,
      now,
    });

  return {
    total,
    total_assets: total,
    ...counts,
    coverage_ratio,
    percentages,
    trend,
    window_days: windowDays,
    assurance_version: 'waf-posture-assurance.v2',
    assessment_scope: 'tested_scenarios_only_not_origin_lockdown',
  };
}

function vendorKey(snapshot, asset) {
  const vendor = snapshot?.detected_vendor ?? asset?.expected_vendor_hint ?? 'unknown';
  const product = snapshot?.detected_product ?? 'unknown';
  return `${vendor}::${product}`;
}

export function buildVendorBreakdown({
  assets = [],
  currentSnapshotsByAsset = new Map(),
  now = new Date(),
} = {}) {
  const buckets = new Map();
  for (const asset of assets) {
    const snapshot = currentSnapshotsByAsset.get(asset.id) ?? null;
    const status = statusForAsset(asset, snapshot, now);
    const key = vendorKey(snapshot, asset);
    const [vendor, product] = key.split('::');
    const bucket = buckets.get(key) ?? {
      vendor,
      product,
      asset_count: 0,
      protected_count: 0,
      edge_protected_count: 0,
      underprotected_count: 0,
      unprotected_count: 0,
      unknown_count: 0,
    };
    bucket.asset_count += 1;
    if (status === 'protected') bucket.protected_count += 1;
    if (status === 'edge_protected') bucket.edge_protected_count += 1;
    if (status === 'underprotected') bucket.underprotected_count += 1;
    if (status === 'unprotected') bucket.unprotected_count += 1;
    if (status === 'unknown') bucket.unknown_count += 1;
    buckets.set(key, bucket);
  }

  const items = [...buckets.values()].sort((a, b) => b.asset_count - a.asset_count);
  const protectedTotal = items.reduce((sum, item) => sum + item.protected_count, 0);
  const vendor_mix = items.map((item) => ({
    vendor: item.vendor,
    product: item.product,
    protected_share_pct:
      protectedTotal === 0
        ? 0
        : Math.round((item.protected_count / protectedTotal) * 10000) / 100,
    asset_count: item.asset_count,
    protected_count: item.protected_count,
  }));

  return { items, vendor_mix };
}

function mapEntityType(entityType) {
  const normalized = String(entityType ?? '').trim();
  const mapping = {
    parent_organization: 'parent',
    subsidiary: 'subsidiary',
    brand: 'brand',
    region_business_unit: 'region',
    vendor_managed_property: 'vendor_managed',
  };
  return mapping[normalized] ?? (normalized || 'business_unit');
}

function resolveEntityForAsset(asset, entities = [], targetGroups = []) {
  const ownerHint = typeof asset.owner_hint === 'string' ? asset.owner_hint.trim() : '';
  if (ownerHint) {
    const matched = entities.find(
      (entity) =>
        entity.name === ownerHint
        || entity.display_name === ownerHint
        || entity.entity_id === ownerHint,
    );
    if (matched) {
      return {
        entity_id: matched.entity_id ?? matched.id,
        entity_type: mapEntityType(matched.entity_type),
        name: matched.display_name ?? matched.name ?? ownerHint,
      };
    }
    return {
      entity_id: `owner:${ownerHint}`,
      entity_type: 'business_unit',
      name: ownerHint,
    };
  }

  const targetGroup = targetGroups.find((group) => group.id === asset.target_group_id);
  if (targetGroup) {
    const settings = targetGroup.settings_json ?? {};
    const businessUnit = settings.business_unit ?? settings.entity_name ?? targetGroup.name;
    return {
      entity_id: settings.entity_id ?? `tg:${targetGroup.id}`,
      entity_type: settings.entity_type ? mapEntityType(settings.entity_type) : 'business_unit',
      name: businessUnit,
    };
  }

  return {
    entity_id: 'unassigned',
    entity_type: 'business_unit',
    name: 'Unassigned',
  };
}

function isCriticalGap(asset, snapshot, now) {
  const status = statusForAsset(asset, snapshot, now);
  if (!['unprotected', 'underprotected'].includes(status)) return false;
  const criticality = String(asset.business_criticality ?? '').trim().toLowerCase();
  return CRITICAL_BUSINESS_VALUES.has(criticality);
}

export function buildEntityRollup({
  assets = [],
  currentSnapshotsByAsset = new Map(),
  entities = [],
  targetGroups = [],
  entityTypeFilter = null,
  now = new Date(),
} = {}) {
  const buckets = new Map();
  for (const asset of assets) {
    const snapshot = currentSnapshotsByAsset.get(asset.id) ?? null;
    const status = statusForAsset(asset, snapshot, now);
    const entity = resolveEntityForAsset(asset, entities, targetGroups);
    if (entityTypeFilter && entity.entity_type !== entityTypeFilter) continue;

    const bucket = buckets.get(entity.entity_id) ?? {
      entity_id: entity.entity_id,
      entity_type: entity.entity_type,
      name: entity.name,
      protected: 0,
      edge_protected: 0,
      underprotected: 0,
      unprotected: 0,
      unknown: 0,
      excluded: 0,
      critical_gap_count: 0,
      asset_count: 0,
    };
    bucket.asset_count += 1;
    bucket[status] += 1;
    if (isCriticalGap(asset, snapshot, now)) bucket.critical_gap_count += 1;
    buckets.set(entity.entity_id, bucket);
  }

  const items = [...buckets.values()]
    .map((bucket) => {
      const counts = {
        protected: bucket.protected,
        edge_protected: bucket.edge_protected,
        underprotected: bucket.underprotected,
        unprotected: bucket.unprotected,
        unknown: bucket.unknown,
        excluded: bucket.excluded,
      };
      return {
        entity_id: bucket.entity_id,
        entity_type: bucket.entity_type,
        name: bucket.name,
        coverage_ratio: coverageRatioFromCounts(counts, bucket.asset_count),
        protected: bucket.protected,
        edge_protected: bucket.edge_protected,
        underprotected: bucket.underprotected,
        unprotected: bucket.unprotected,
        critical_gap_count: bucket.critical_gap_count,
        asset_count: bucket.asset_count,
      };
    })
    .sort((a, b) => b.critical_gap_count - a.critical_gap_count || a.name.localeCompare(b.name));

  return { items };
}

function resolveRegionForAsset(asset, targetGroups = [], environments = [], entities = []) {
  const targetGroup = targetGroups.find((group) => group.id === asset.target_group_id);
  const settings = targetGroup?.settings_json ?? {};
  const regionCode =
    settings.region_code
    ?? settings.geography_tag
    ?? settings.country
    ?? null;
  if (regionCode) {
    return {
      region_code: String(regionCode).trim(),
      region_label: settings.region_label ?? String(regionCode).trim(),
    };
  }

  const environment = environments.find((env) => env.id === (asset.environment_id ?? targetGroup?.environment_id));
  if (environment?.data_region) {
    return {
      region_code: environment.data_region,
      region_label: environment.name ?? environment.data_region,
    };
  }

  const ownerHint = typeof asset.owner_hint === 'string' ? asset.owner_hint.trim() : '';
  const entity = entities.find(
    (row) => row.name === ownerHint || row.display_name === ownerHint || row.entity_id === ownerHint,
  );
  if (entity?.country) {
    return {
      region_code: entity.country,
      region_label: entity.country,
    };
  }

  return {
    region_code: 'undeclared',
    region_label: 'Undeclared geography',
  };
}

function normalizeBusinessCriticality(asset) {
  const value = String(asset.business_criticality ?? '').trim().toLowerCase();
  return value || 'unknown';
}

export function buildCriticalityRollup({
  assets = [],
  currentSnapshotsByAsset = new Map(),
  criticalityFilter = null,
  now = new Date(),
} = {}) {
  const buckets = new Map();
  for (const asset of assets) {
    const businessCriticality = normalizeBusinessCriticality(asset);
    if (
      criticalityFilter
      && businessCriticality !== String(criticalityFilter).trim().toLowerCase()
    ) {
      continue;
    }

    const snapshot = currentSnapshotsByAsset.get(asset.id) ?? null;
    const status = statusForAsset(asset, snapshot, now);

    const bucket = buckets.get(businessCriticality) ?? {
      business_criticality: businessCriticality,
      protected: 0,
      edge_protected: 0,
      underprotected: 0,
      unprotected: 0,
      unknown: 0,
      excluded: 0,
      critical_gap_count: 0,
      asset_count: 0,
    };
    bucket.asset_count += 1;
    bucket[status] += 1;
    if (isCriticalGap(asset, snapshot, now)) bucket.critical_gap_count += 1;
    buckets.set(businessCriticality, bucket);
  }

  const items = [...buckets.values()]
    .map((bucket) => {
      const counts = {
        protected: bucket.protected,
        edge_protected: bucket.edge_protected,
        underprotected: bucket.underprotected,
        unprotected: bucket.unprotected,
        unknown: bucket.unknown,
        excluded: bucket.excluded,
      };
      return {
        business_criticality: bucket.business_criticality,
        asset_count: bucket.asset_count,
        coverage_ratio: coverageRatioFromCounts(counts, bucket.asset_count),
        protected: bucket.protected,
        edge_protected: bucket.edge_protected,
        underprotected: bucket.underprotected,
        unprotected: bucket.unprotected,
        critical_gap_count: bucket.critical_gap_count,
      };
    })
    .sort(
      (a, b) =>
        b.critical_gap_count - a.critical_gap_count
        || b.asset_count - a.asset_count
        || a.business_criticality.localeCompare(b.business_criticality),
    );

  return { items };
}

export function buildGeographyRollup({
  assets = [],
  currentSnapshotsByAsset = new Map(),
  targetGroups = [],
  environments = [],
  entities = [],
  regionCodeFilter = null,
  now = new Date(),
} = {}) {
  const buckets = new Map();
  for (const asset of assets) {
    const snapshot = currentSnapshotsByAsset.get(asset.id) ?? null;
    const status = statusForAsset(asset, snapshot, now);
    const region = resolveRegionForAsset(asset, targetGroups, environments, entities);
    if (regionCodeFilter && region.region_code !== regionCodeFilter) continue;

    const bucket = buckets.get(region.region_code) ?? {
      region_code: region.region_code,
      region_label: region.region_label,
      protected: 0,
      edge_protected: 0,
      underprotected: 0,
      unprotected: 0,
      unknown: 0,
      excluded: 0,
      unprotected_critical_count: 0,
      asset_count: 0,
    };
    bucket.asset_count += 1;
    bucket[status] += 1;
    if (status === 'unprotected' && CRITICAL_BUSINESS_VALUES.has(String(asset.business_criticality ?? '').toLowerCase())) {
      bucket.unprotected_critical_count += 1;
    }
    buckets.set(region.region_code, bucket);
  }

  const items = [...buckets.values()]
    .map((bucket) => {
      const counts = {
        protected: bucket.protected,
        edge_protected: bucket.edge_protected,
        underprotected: bucket.underprotected,
        unprotected: bucket.unprotected,
        unknown: bucket.unknown,
        excluded: bucket.excluded,
      };
      return {
        region_code: bucket.region_code,
        region_label: bucket.region_label,
        asset_count: bucket.asset_count,
        coverage_ratio: coverageRatioFromCounts(counts, bucket.asset_count),
        edge_protected: bucket.edge_protected,
        unprotected_critical_count: bucket.unprotected_critical_count,
      };
    })
    .sort((a, b) => b.unprotected_critical_count - a.unprotected_critical_count || a.region_code.localeCompare(b.region_code));

  return { items };
}

function primaryReasonCodes(assessment, snapshot) {
  const codes = new Set(snapshot?.reason_codes ?? []);
  for (const factor of assessment.factors ?? []) {
    if (factor.factor === 'origin_bypass' && Number(factor.contribution) > 0) {
      codes.add('origin_bypass_confirmed');
    }
    if (factor.factor === 'protection_state' && factor.value === 'unprotected') {
      codes.add('coverage_gap');
    }
    if (factor.factor === 'validation_result' && factor.value === 'failed') {
      codes.add('validation_failed');
    }
    if (factor.factor === 'known_vulnerabilities') codes.add('cve_exposed');
    if (factor.factor === 'regulatory_scope') codes.add('compliance_in_scope');
  }
  return [...codes];
}

function passesRoadmapFilters({
  asset,
  snapshot,
  assessment,
  targetGroups = [],
  entities = [],
  filters = {},
}) {
  if (filters.vendor) {
    const vendor = snapshot?.detected_vendor ?? asset.expected_vendor_hint ?? 'unknown';
    if (vendor !== filters.vendor) return false;
  }
  if (filters.min_score != null && assessment.risk_score < filters.min_score) return false;
  if (filters.entity_id) {
    const entity = resolveEntityForAsset(asset, entities, targetGroups);
    if (entity.entity_id !== filters.entity_id) return false;
  }
  if (filters.region_code) {
    const region = resolveRegionForAsset(asset, targetGroups, [], entities);
    if (region.region_code !== filters.region_code) return false;
  }
  return true;
}

export function buildRiskRoadmap({
  assets = [],
  currentSnapshotsByAsset = new Map(),
  validationSummaryByAsset = new Map(),
  cveMatchesByAsset = new Map(),
  targetGroups = [],
  entities = [],
  findingsByAsset = new Map(),
  actionItemsByAsset = new Map(),
  filters = {},
  generatedAt = new Date().toISOString(),
} = {}) {
  const tiers = {
    tier_1: [],
    tier_2: [],
    tier_3: [],
    tier_4: [],
  };
  const limitPerTier = Number(filters.limit_per_tier ?? 50);

  const assessments = [];
  for (const asset of assets) {
    const snapshot = currentSnapshotsByAsset.get(asset.id) ?? { status: asset.status ?? 'unknown', waf_asset_id: asset.id };
    const targetGroup = targetGroups.find((group) => group.id === asset.target_group_id) ?? null;
    const assessment = computeAssetRiskAssessment({
      asset,
      snapshot,
      validationSummary: validationSummaryByAsset.get(asset.id) ?? {},
      cveMatches: cveMatchesByAsset.get(asset.id) ?? [],
      targetGroup,
      computedAt: generatedAt,
    });
    if (!passesRoadmapFilters({ asset, snapshot, assessment, targetGroups, entities, filters })) {
      continue;
    }
    assessments.push({ asset, snapshot, assessment });
  }

  assessments.sort((a, b) => b.assessment.risk_score - a.assessment.risk_score);

  for (const { asset, snapshot, assessment } of assessments) {
    const band = assessment.priority_band ?? assignPriorityBand({
      riskScore: assessment.risk_score,
      asset,
      snapshot,
      factors: assessment.factors,
    });
    const item = {
      waf_asset_id: asset.id,
      hostname: hostnameFromCanonicalUrl(asset.canonical_url),
      owner_hint: asset.owner_hint ?? null,
      detected_vendor: snapshot.detected_vendor ?? asset.expected_vendor_hint ?? null,
      risk_score: assessment.risk_score,
      priority_band: band,
      primary_reason_codes: primaryReasonCodes(assessment, snapshot),
      recommended_action:
        assessment.recommended_action
        ?? deriveRecommendedAction({ factors: assessment.factors, snapshot, priorityBand: band }),
      finding_ids: findingsByAsset.get(asset.id) ?? [],
      action_item_ids: actionItemsByAsset.get(asset.id) ?? [],
      posture_status: assessment.current_assurance.status,
      current_assurance: assessment.current_assurance,
    };
    if (!tiers[band]) tiers[band] = [];
    if (tiers[band].length < limitPerTier) tiers[band].push(item);
  }

  return {
    tiers,
    generated_at: generatedAt,
    method: WAF_RISK_METHOD,
  };
}

export function buildVendorConsolidation({
  assets = [],
  currentSnapshotsByAsset = new Map(),
  connectors = [],
  driftEvents = [],
  now = new Date(),
} = {}) {
  const vendorFootprint = new Map();
  const hostVendors = new Map();

  for (const asset of assets) {
    const snapshot = currentSnapshotsByAsset.get(asset.id) ?? null;
    const vendor = snapshot?.detected_vendor ?? asset.expected_vendor_hint ?? 'unknown';
    const product = snapshot?.detected_product ?? 'unknown';
    const key = `${vendor}::${product}`;
    const bucket = vendorFootprint.get(key) ?? {
      vendor,
      product,
      asset_count: 0,
      protected_count: 0,
    };
    bucket.asset_count += 1;
    if (statusForAsset(asset, snapshot, now) === 'protected') bucket.protected_count += 1;
    vendorFootprint.set(key, bucket);

    const hostname = hostnameFromCanonicalUrl(asset.canonical_url) ?? asset.id;
    const vendors = hostVendors.get(hostname) ?? new Set();
    vendors.add(vendor);
    hostVendors.set(hostname, vendors);
  }

  const overlap_candidates = [...hostVendors.entries()]
    .filter(([, vendors]) => vendors.size > 1)
    .map(([hostname, vendors]) => ({
      hostname,
      vendors: [...vendors],
      advisory: 'read_only_overlap_review',
    }));

  const footprintEntries = [...vendorFootprint.values()].sort((a, b) => b.asset_count - a.asset_count);
  const leading = footprintEntries[0] ?? null;
  const consolidation_opportunities = [];
  if (leading && leading.asset_count >= 2) {
    consolidation_opportunities.push({
      advisory: 'non_prescriptive',
      leading_vendor: leading.vendor,
      leading_product: leading.product,
      covered_asset_count: leading.asset_count,
      suggestion:
        'Majority vendor footprint detected; review duplicate edge policies during planned change windows only.',
    });
  }

  const activeConnectors = connectors.filter((connector) => connector.status === 'active');
  const operating_cost_signals = footprintEntries.map((entry) => {
    const vendorConnectors = activeConnectors.filter((connector) => connector.provider === entry.vendor);
    const staleDrift = driftEvents.filter(
      (event) =>
        event.status === 'open'
        && ['vendor_change', 'rule_mode_changed', 'rule_count_decreased', 'rule_update_stale'].includes(event.drift_type)
        && currentSnapshotsByAsset.get(event.waf_asset_id)?.detected_vendor === entry.vendor,
    );
    return {
      vendor: entry.vendor,
      product: entry.product,
      active_connector_count: vendorConnectors.length,
      stale_rule_drift_events: staleDrift.length,
      duplicate_policy_drift_events: staleDrift.length,
      advisory: 'read_only_operating_cost_signal',
    };
  });

  return {
    vendor_footprint: footprintEntries,
    overlap_candidates,
    consolidation_opportunities,
    operating_cost_signals,
  };
}
