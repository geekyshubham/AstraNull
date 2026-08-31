import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
  type ReactNode
} from 'react';
import { Activity, Bot, CalendarClock, Check, Globe, Plus, Search, ShieldHalf, Target, Trash2, TriangleAlert } from 'lucide-react';
import { requestJson } from '../lib/api';
import { buildDetailHref } from '../lib/route-params';
// @ts-ignore Plain ESM keeps these UI decisions directly executable by node:test.
import { apiErrorCode, isActiveDnsChallenge, isLoaScopeEligible, isSignedLoaState, parseOptionalPort, targetDeclarationProvenanceLabel, targetDisplayValue } from '../lib/target-detail.mjs';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { formatDate } from '../lib/utils';
import { VerifyChip, resolveTargetVerificationProvenance } from '../lib/verify-chip';
import { emptyStateFromApi, PortalLoadingSkeleton } from '../lib/empty-from-api';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Badge } from '../components/ui/badge';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Tabs, type TabOption } from '../components/ui/tabs';
import {
  effectivePolicyTargetKind,
  isPolicyTargetCompatible,
  policySupportedTargetKinds,
} from '../components/policies/target-group-picker';

type OnboardTab = 'fqdn' | 'ip' | 'cloud';

const ONBOARD_TAB_OPTIONS: TabOption<OnboardTab>[] = [
  { id: 'fqdn', label: 'Domain · DNS TXT' },
  { id: 'ip', label: 'IP address · Agent callback' },
  { id: 'cloud', label: 'Cloud provider · pull inventory' }
];

/** §7.1 verification states that unlock the per-row Run test action. */
const RUN_ENABLED_STATES = new Set(['dns_verified', 'provider_verified', 'agent_verified', 'user_confirmed']);
const DNS_INVENTORY_PROVIDERS = new Set(['cloudflare', 'akamai_edgedns', 'namecheap', 'godaddy', 'ibm_ns1']);
const DNS_POLL_INTERVAL_MS = 30_000;
const DNS_POLL_MAX_MS = 15 * 60 * 1000;
const EDGE_DETECTION_POLL_INTERVAL_MS = 2_000;
const EDGE_DETECTION_POLL_MAX_MS = 2 * 60 * 1000;
const EDGE_DETECTION_CHECK_ID = 'waf.fingerprint.safe';
const EDGE_ACTIVE_RUN_STATUSES = new Set(['pending', 'planned', 'queued', 'running', 'collecting']);

const DETAIL_MODAL_STYLES_ID = 'detail-modal-primitive-styles';
const detailModalStyles = `
.detail-modal.modal-confirm {
  padding: 0;
  max-width: min(560px, calc(100% - 32px));
  width: min(560px, calc(100% - 32px));
  max-height: min(88vh, 920px);
  display: flex;
  flex-direction: column;
}
.detail-modal.detail-modal-wide.modal-confirm {
  max-width: min(920px, calc(100% - 32px));
  width: min(920px, calc(100% - 32px));
}
.detail-modal .detail-modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3);
  padding: 16px 20px;
  border-bottom: 1px solid var(--border-soft);
}
.detail-modal .detail-modal-head h3 {
  margin: 0;
  font-family: var(--font-display);
  font-size: 16px;
  font-weight: 600;
  color: var(--fg);
}
.detail-modal .detail-modal-body {
  padding: 18px 20px;
  overflow-y: auto;
  overscroll-behavior: contain;
  max-height: calc(min(88vh, 920px) - 64px);
}
.detail-modal .detail-modal-body .tabs {
  margin-bottom: var(--space-4);
}
`;

const TG_DETAIL_STYLES_ID = 'tg-detail-view-styles';
// Token-only styling for the prototype's DNS/link-button primitives, scoped to this page so it
// cannot collide with styles injected by sibling detail pages. No literal colors (tokens only).
const tgDetailStyles = `
.tg-detail-view { gap: var(--space-6); }
.tg-detail-view .vl-num svg { display: block; color: var(--success); }
.tg-detail-view .dns-field { display: flex; flex-direction: column; gap: 4px; align-items: flex-start; }
.tg-detail-view .dns-key { font-family: var(--font-mono); font-size: 10.5px; letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--fg-2); }
.tg-detail-view .dns-val { color: var(--fg); font-size: var(--text-sm); word-break: break-all; }
.tg-detail-view .dns-head { display: flex; align-items: center; gap: 10px; }
.tg-detail-view .dns-head .spacer { flex: 1 1 auto; }
.tg-detail-view .dns-footer { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.tg-detail-view .dns-footer .btn-loading { display: inline-flex; align-items: center; gap: 8px; }
.tg-detail-view .dns-target-actions { display: flex; align-items: flex-end; justify-content: flex-end; gap: var(--space-2); flex-wrap: wrap; }
.tg-detail-view .dns-target-picker { display: flex; min-width: min(320px, 100%); flex-direction: column; gap: var(--space-1); color: var(--fg-2); font-size: var(--text-xs); }
.tg-detail-view .dns-target-picker select { min-width: 0; }
.tg-detail-view .dns-selected-target { margin-top: var(--space-2); color: var(--fg-2); font-size: var(--text-xs); }
.tg-detail-view .dns-fields { align-items: start; }
.tg-detail-view .dns-history { margin-top: 16px; }
.tg-detail-view .dns-history-title { font-family: var(--font-mono); font-size: 10.5px; letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--fg-2); margin: 0 0 8px; }
.tg-detail-view .link-btn { background: none; border: 0; padding: 0; font: inherit; color: var(--accent); cursor: pointer; font-size: var(--text-xs); text-decoration: underline; text-underline-offset: 2px; }
.tg-detail-view .link-btn:hover { color: var(--fg); }
.tg-detail-view .link-btn:focus-visible { outline: none; box-shadow: var(--focus-ring); border-radius: var(--radius-sm); }
/* Light theme: brand orange (--accent) resolves to ~2.5:1 on the white surface and fails WCAG AA
   4.5:1 for this small link text. Scope an AA-safe ink token to light only; dark theme keeps the
   orange link (~9:1 on black). The underline carries the affordance in both themes. */
:root[data-theme="light"] .tg-detail-view .link-btn { color: var(--fg-2); }
:root[data-theme="light"] .tg-detail-view .link-btn:hover { color: var(--fg); }
/* A signed LOA is a success state: realize the documented "green when signed" intent so the
   callout no longer wears the unsigned warn border. Border + icon tone only, token-driven. */
.tg-detail-view .callout-loa[data-loa-state="signed"] { border-color: color-mix(in oklab, var(--success), transparent 48%); background: color-mix(in oklab, var(--surface), var(--success) 8%); }
.tg-detail-view .callout-loa[data-loa-state="signed"] .callout-icon { color: var(--success); border-color: color-mix(in oklab, var(--success), transparent 48%); background: color-mix(in oklab, var(--surface), var(--success) 12%); }
.tg-detail-view .callout-loa[data-loa-state="signed"] .callout-title { color: var(--success); }
.tg-detail-view .tg-page-head { align-items: flex-start; gap: var(--space-4); }
.tg-detail-view .tg-page-copy { min-width: 0; }
.tg-detail-view .tg-page-summary { margin: var(--space-2) 0 0; color: var(--fg-2); }
.tg-detail-view .tg-title-meta { display: flex; align-items: center; gap: var(--space-2); flex-wrap: wrap; margin-top: var(--space-2); }
.tg-detail-view .tg-head-actions { display: flex; align-items: center; justify-content: flex-end; gap: var(--space-2); flex-wrap: wrap; }
.tg-detail-view .tg-head-actions .btn { display: inline-flex; align-items: center; gap: var(--space-2); }
.tg-detail-view .kpi-value--status { font-size: var(--text-lg); }
.tg-detail-view .target-primary { display: flex; align-items: flex-start; gap: var(--space-3); min-width: 0; }
.tg-detail-view .target-primary-copy { display: flex; flex-direction: column; gap: var(--space-1); min-width: 0; }
.tg-detail-view .target-primary-copy strong { color: var(--fg); font-size: var(--text-sm); overflow-wrap: anywhere; }
.tg-detail-view .target-primary-copy .target-id { color: var(--muted); font-size: var(--text-xs); overflow-wrap: anywhere; }
.tg-detail-view .target-status-stack { display: flex; flex-direction: column; align-items: flex-start; gap: var(--space-1); }
.tg-detail-view .target-status-note { color: var(--muted); font-size: var(--text-xs); }
.tg-detail-view .target-actions { justify-content: flex-end; flex-wrap: wrap; gap: var(--space-1); }
.tg-detail-view .target-actions .btn { display: inline-flex; align-items: center; gap: var(--space-1); }
.tg-detail-view .safety-boundary { display: flex; align-items: flex-start; gap: var(--space-3); margin-bottom: var(--space-4); padding: var(--space-3) var(--space-4); border: 1px solid var(--border); border-radius: var(--radius-md); background: color-mix(in oklab, var(--surface), var(--accent) 4%); color: var(--fg-2); }
.tg-detail-view .safety-boundary svg { flex: 0 0 auto; color: var(--accent); margin-top: var(--space-1); }
.tg-detail-view .edge-detection-result { display: flex; flex-direction: column; gap: var(--space-3); margin-bottom: var(--space-4); }
.tg-detail-view .edge-detection-head { display: flex; align-items: center; justify-content: space-between; gap: var(--space-3); flex-wrap: wrap; }
.tg-detail-view .edge-detection-result p { margin: 0; }
.tg-detail-view .edge-evidence-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-3); }
.tg-detail-view .edge-evidence-card { min-width: 0; padding: var(--space-3); border: 1px solid var(--border-soft); border-radius: var(--radius-md); background: var(--surface); }
.tg-detail-view .edge-evidence-card-head { display: flex; align-items: center; justify-content: space-between; gap: var(--space-2); margin-bottom: var(--space-2); }
.tg-detail-view .edge-evidence-card dl { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: var(--space-1) var(--space-3); margin: 0; }
.tg-detail-view .edge-evidence-card dt { color: var(--muted); }
.tg-detail-view .edge-evidence-card dd { min-width: 0; margin: 0; color: var(--fg); overflow-wrap: anywhere; }
.tg-detail-view .edge-evidence-meta { display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap; color: var(--muted); font-size: var(--text-xs); }
.tg-detail-view .safety-boundary strong { display: block; margin-bottom: var(--space-1); color: var(--fg); }
.tg-detail-view .safety-boundary p { margin: 0; }
.tg-detail-view .check-choice { display: inline-flex; min-width: 44px; min-height: 44px; align-items: center; justify-content: center; cursor: pointer; }
.tg-detail-view .check-choice input { accent-color: var(--accent); cursor: pointer; }
.tg-detail-view .rule-discovery { display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap; margin-bottom: var(--space-4); }
.tg-detail-view .rule-search { display: flex; min-width: min(100%, 320px); flex: 1 1 280px; align-items: center; gap: var(--space-2); min-height: 42px; border: 1px solid var(--border); border-radius: var(--radius-pill); background: var(--surface); padding: 0 var(--space-3); }
.tg-detail-view .rule-search input { width: 100%; min-width: 0; border: 0; outline: 0; background: transparent; color: var(--fg); }
.tg-detail-view .rule-results { color: var(--muted); font-size: var(--text-xs); }
.tg-detail-view .rule-more { display: flex; align-items: center; justify-content: space-between; gap: var(--space-3); flex-wrap: wrap; margin-top: var(--space-3); }
.tg-detail-view .check-primary { display: flex; flex-direction: column; gap: var(--space-1); min-width: 0; }
.tg-detail-view .check-primary strong { color: var(--fg); font-size: var(--text-sm); }
.tg-detail-view .check-primary .check-description { color: var(--fg-2); font-size: var(--text-xs); text-wrap: pretty; }
.tg-detail-view .check-primary .check-id { color: var(--muted); font-size: var(--text-xs); overflow-wrap: anywhere; }
.tg-detail-view .check-policy-stack { display: flex; flex-direction: column; align-items: flex-start; gap: var(--space-2); }
.tg-detail-view .check-policy-binding { display: flex; align-items: center; gap: var(--space-2); flex-wrap: wrap; }
.tg-detail-view .schedule-builder { margin-top: var(--space-5); padding-top: var(--space-5); border-top: 1px solid var(--border-soft); }
.tg-detail-view .schedule-builder-head { display: flex; align-items: flex-start; justify-content: space-between; gap: var(--space-3); }
.tg-detail-view .schedule-builder-head h3 { margin: 0; color: var(--fg); font-family: var(--font-display); font-size: var(--text-base); }
.tg-detail-view .schedule-builder-head p { margin: var(--space-1) 0 0; color: var(--fg-2); }
.tg-detail-view .schedule-fields { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--space-3); width: 100%; margin: 0; padding: 0; border: 0; }
.tg-detail-view .schedule-fields label { min-width: 0; }
.tg-detail-view .schedule-selected { margin: 0; color: var(--fg-2); }
.tg-detail-view .schedule-role-note { display: flex; flex-direction: column; gap: var(--space-1); margin-top: var(--space-4); padding-top: var(--space-4); border-top: 1px solid var(--border-soft); color: var(--fg-2); }
.tg-detail-view .schedule-role-note strong { color: var(--fg); }
.tg-detail-view .target-run-selection { display: flex; align-items: center; gap: var(--space-2); flex-wrap: wrap; margin-bottom: var(--space-4); padding: var(--space-3) var(--space-4); border: 1px solid var(--border-soft); border-radius: var(--radius-md); background: color-mix(in oklab, var(--surface), var(--fg) 2%); color: var(--fg-2); }
.tg-detail-view .target-run-selection strong { color: var(--fg); }
.tg-detail-view .loa-scope-list { display: grid; gap: var(--space-2); margin-top: var(--space-2); }
.tg-detail-view .loa-scope-row { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: center; gap: var(--space-3); padding: var(--space-2) var(--space-3); border: 1px solid var(--border-soft); border-radius: var(--radius-sm); }
.tg-detail-view .loa-scope-row[data-eligible="false"] { color: var(--muted); background: color-mix(in oklab, var(--surface), var(--fg) 2%); }
.tg-detail-view .loa-contact-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-3); }
.tg-detail-view .custody-note { margin: 0; padding: var(--space-3); border: 1px solid var(--border-soft); border-radius: var(--radius-sm); color: var(--fg-2); font-size: var(--text-xs); }
@media (max-width: 900px) {
  .tg-detail-view .schedule-fields { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 640px) {
  .tg-detail-view .btn { min-height: 44px; }
  .tg-detail-view .tg-page-head, .tg-detail-view .schedule-builder-head { flex-direction: column; }
  .tg-detail-view .tg-head-actions, .tg-detail-view .dns-target-actions { width: 100%; justify-content: flex-start; }
  .tg-detail-view .dns-target-picker { width: 100%; }
  .tg-detail-view .schedule-fields, .tg-detail-view .edge-evidence-grid, .tg-detail-view .loa-contact-grid { grid-template-columns: minmax(0, 1fr); }
  .tg-detail-view .loa-scope-row { grid-template-columns: auto minmax(0, 1fr); }
  .tg-detail-view .loa-scope-row .badge { grid-column: 2; }
}
`;

function ensureStyles(id: string, css: string) {
  if (typeof document === 'undefined') return;
  if (document.getElementById(id)) return;
  const node = document.createElement('style');
  node.id = id;
  node.textContent = css;
  document.head.appendChild(node);
}

function ensureDetailModalStyles() {
  ensureStyles(DETAIL_MODAL_STYLES_ID, detailModalStyles);
}

function ensureTgDetailStyles() {
  ensureStyles(TG_DETAIL_STYLES_ID, tgDetailStyles);
}

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function asDataItem(value: unknown): DataItem | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : null;
}

function boundedEdgeString(value: unknown, maxLength = 160) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLength);
}

function finiteEdgeNumber(value: unknown) {
  if (value === null || value === undefined || value === '') return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function firstDataItem(value: unknown) {
  return Array.isArray(value) ? value.map(asDataItem).find(Boolean) ?? null : null;
}

function explicitEdgeBoolean(values: unknown[]) {
  const observed = values.filter((value): value is boolean => typeof value === 'boolean');
  return {
    observed: observed.length > 0,
    value: observed.includes(true),
    conflict: observed.includes(true) && observed.includes(false)
  };
}

function findEdgeProviderMatch(edgeSignature: DataItem, family: 'waf' | 'cdn') {
  const collections = [
    { values: edgeSignature.address_matches, discriminator: 'family', type: 'address_range' },
    { values: edgeSignature.cname_matches, discriminator: 'type', type: 'cname_suffix' }
  ];
  for (const collection of collections) {
    const values = Array.isArray(collection.values) ? collection.values : [];
    for (const value of values) {
      const match = asDataItem(value);
      if (!match || getString(match, [collection.discriminator], '').toLowerCase() !== family) continue;
      const provider = boundedEdgeString(match.provider);
      if (provider) return { provider, type: collection.type };
    }
  }
  return null;
}

function findTrustedEdgeProbeEvent(events: DataItem[], run: DataItem) {
  const correlation = asDataItem(run.correlation);
  const runNonce = getString(correlation, ['nonce_hash'], '');
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = asDataItem(events[index]);
    if (!event || getString(event, ['signal_type'], '') !== 'probe_result') continue;
    if (getString(event, ['check_id'], '') !== EDGE_DETECTION_CHECK_ID) continue;
    const source = getString(event, ['source'], '');
    if (source !== 'probe_worker' && source !== 'probe_simulation_stub') continue;
    if (runNonce && getString(event, ['nonce_hash'], '') !== runNonce) continue;
    return event;
  }
  return null;
}

function edgeSignalProjection(
  signal: { observed: boolean; value: boolean; conflict: boolean },
  details: { provider?: string; type?: string } = {}
): DataItem {
  const status = signal.conflict
    ? 'inconclusive'
    : signal.observed
      ? signal.value ? 'detected' : 'not_detected'
      : 'inconclusive';
  return {
    status,
    ...(status === 'detected' && details.provider ? { provider: details.provider } : {}),
    ...(status === 'detected' && details.type ? { type: details.type } : {}),
    ...(signal.conflict ? { reason: 'conflicting_edge_signals' } : {}),
    ...(!signal.observed ? { reason: 'signal_not_reported' } : {})
  };
}

/** Build a display-only projection from the canonical tenant-scoped run and event APIs. */
export function projectEdgeDetectionResult(requestState: DataItem, runValue: unknown, eventEnvelopeValue: unknown): DataItem {
  const run = asDataItem(runValue);
  const eventEnvelope = asDataItem(eventEnvelopeValue);
  const events = Array.isArray(eventEnvelope?.items) ? eventEnvelope.items as DataItem[] : [];
  const expectedRunId = getString(requestState, ['test_run_id'], '');
  if (
    !run
    || getString(run, ['id'], '') !== expectedRunId
    || getString(run, ['check_id'], '') !== EDGE_DETECTION_CHECK_ID
    || getString(run, ['target_group_id'], '') !== getString(requestState, ['target_group_id'], '')
    || getString(run, ['target_id'], '') !== getString(requestState, ['target_id'], '')
  ) {
    return { ...requestState, status: 'error', reason: 'unexpected_test_run' };
  }

  const runStatus = getString(run, ['status'], 'unknown');
  const base = { ...requestState, run_status: runStatus };
  const event = findTrustedEdgeProbeEvent(events, run);
  if (!event) {
    if (EDGE_ACTIVE_RUN_STATUSES.has(runStatus.toLowerCase())) {
      return { ...base, status: 'pending', reason: 'worker_result_pending', detection: null };
    }
    if (runStatus.toLowerCase() === 'failed' || runStatus.toLowerCase() === 'error') {
      return { ...base, status: 'error', reason: 'test_run_failed', detection: null };
    }
    return { ...base, status: 'not_observed', reason: 'worker_result_not_observed', detection: null };
  }

  const metadata = asDataItem(event.metadata) ?? {};
  const source = getString(event, ['source'], '');
  if (source === 'probe_simulation_stub' || metadata.simulation === 'SAFE_PROBE_SIMULATION') {
    return { ...base, status: 'inconclusive', reason: 'simulation_not_detection', detection: null };
  }
  if (getString(metadata, ['probe_kind'], '') !== 'outside_in_waf_scan') {
    return { ...base, status: 'inconclusive', reason: 'unexpected_worker_result', detection: null };
  }

  const externalResult = getString(metadata, ['external_result'], '').toLowerCase();
  const errorClass = boundedEdgeString(metadata.error_class);
  if (externalResult === 'error' || externalResult === 'timeout' || errorClass) {
    return {
      ...base,
      status: 'error',
      reason: 'worker_result_error',
      detection: null,
      ...(errorClass ? { error_class: errorClass } : {})
    };
  }
  if (externalResult !== 'blocked' && externalResult !== 'connected') {
    return { ...base, status: 'inconclusive', reason: 'worker_result_incomplete', detection: null };
  }

  const edgeSignature = asDataItem(metadata.edge_signature) ?? {};
  const bestVendor = asDataItem(edgeSignature.best_vendor);
  const candidate = firstDataItem(metadata.vendor_candidates);
  const conflictingVendorSignals = edgeSignature.conflicting_vendor_signals === true;
  // The nested classifier result is authoritative. Legacy posture summaries can be recomputed
  // without the nested CDN/WAF input during ingestion, so use them only when it is absent.
  const wafSignal = explicitEdgeBoolean(typeof edgeSignature.waf_present === 'boolean'
    ? [edgeSignature.waf_present]
    : [metadata.waf_fingerprint_detected, metadata.waf_detected]);
  const cdnSignal = explicitEdgeBoolean(typeof edgeSignature.cdn_detected === 'boolean'
    ? [edgeSignature.cdn_detected]
    : [metadata.cdn_detected]);
  const wafMatch = findEdgeProviderMatch(edgeSignature, 'waf');
  const cdnMatch = findEdgeProviderMatch(edgeSignature, 'cdn');
  const responseProvider = boundedEdgeString(metadata.detected_vendor)
    || boundedEdgeString(candidate?.vendor)
    || boundedEdgeString(bestVendor?.vendor);
  const responseType = boundedEdgeString(metadata.detected_product)
    || boundedEdgeString(candidate?.product);
  const wafDetails = conflictingVendorSignals ? {} : {
    provider: responseProvider || wafMatch?.provider,
    type: responseType || (responseProvider ? 'response_fingerprint' : wafMatch?.type)
  };
  const cdnDetails = {
    provider: cdnMatch?.provider,
    type: cdnMatch?.type
  };
  const waf = edgeSignalProjection(wafSignal, wafDetails);
  const cdn = edgeSignalProjection(cdnSignal, cdnDetails);
  const trustedPositive = (wafSignal.value && !wafSignal.conflict) || (cdnSignal.value && !cdnSignal.conflict);
  const completeNoMatch = wafSignal.observed
    && cdnSignal.observed
    && !wafSignal.conflict
    && !cdnSignal.conflict
    && !wafSignal.value
    && !cdnSignal.value;
  const status = trustedPositive ? 'detected' : completeNoMatch ? 'not_detected' : 'inconclusive';
  const reason = status === 'inconclusive'
    ? (wafSignal.conflict || cdnSignal.conflict ? 'conflicting_edge_signals' : 'edge_signature_incomplete')
    : null;
  const corpusVersion = boundedEdgeString(metadata.edge_signature_corpus_version);
  const requestsSent = finiteEdgeNumber(metadata.requests_sent);

  return {
    ...base,
    status,
    reason,
    detection: {
      waf,
      cdn,
      ...(conflictingVendorSignals ? { conflicting_vendor_signals: true } : {}),
      ...(corpusVersion ? { corpus_version: corpusVersion } : {}),
      ...(requestsSent !== null ? { requests_sent: requestsSent } : {}),
      observed_at: boundedEdgeString(event.timestamp ?? event.created_at)
    }
  };
}

function edgeStatusTone(status: string): 'success' | 'warn' | 'danger' | 'info' | 'muted' {
  if (status === 'detected') return 'success';
  if (status === 'not_detected') return 'muted';
  if (status === 'error') return 'danger';
  if (status === 'inconclusive') return 'warn';
  if (status === 'pending' || status === 'queued') return 'info';
  return 'muted';
}

function edgeStatusSummary(state: DataItem) {
  const status = getString(state, ['status'], 'inconclusive');
  if (status === 'pending' || status === 'queued') return 'The governed test run is pending signed-worker evidence.';
  if (status === 'not_observed') return 'No trusted worker result was observed during the bounded wait. The test-run page remains authoritative.';
  if (status === 'error') {
    const errorClass = getString(state, ['error_class'], '');
    return errorClass ? `The worker reported ${humanizeLabel(errorClass).toLowerCase()}.` : 'The edge detection run could not produce a usable result.';
  }
  if (status === 'not_detected') return 'The signed worker completed successfully and explicitly reported no WAF or CDN fingerprint.';
  if (status === 'detected') return 'The signed worker observed one or more positive edge fingerprints.';
  return `${humanizeLabel(getString(state, ['reason'], 'edge_signature_incomplete'))}. The available evidence cannot support a detection or no-match result.`;
}

/** Nested verification envelope (Postgres target payload) when present. */
function targetVerificationEnvelope(item: DataItem): DataItem | null {
  const nested = item.verification;
  return nested && typeof nested === 'object' && !Array.isArray(nested) ? (nested as DataItem) : null;
}

/** Authoritative verification state across dev (flat) and Postgres (nested) target shapes. */
function targetVerificationState(item: DataItem) {
  const nested = targetVerificationEnvelope(item);
  if (nested) {
    const state = getString(nested, ['state'], '');
    if (state !== '—' && state) return state;
  }
  return getString(item, ['verification_state', 'verify_state', 'state'], 'unverified');
}

function canRunTest(state: string) {
  return RUN_ENABLED_STATES.has(state.trim().toLowerCase());
}

function humanizeLabel(value: string, fallback = '—') {
  const normalized = value.trim();
  if (!normalized) return fallback;
  const label = normalized.replace(/[_-]+/g, ' ');
  return `${label.charAt(0).toUpperCase()}${label.slice(1)}`;
}

function isCustomerRunnableCheck(check: DataItem) {
  const constraints = check.safety_constraints
    && typeof check.safety_constraints === 'object'
    && !Array.isArray(check.safety_constraints)
    ? check.safety_constraints as DataItem
    : null;
  return getString(check, ['safety_class'], '').toLowerCase() === 'safe'
    && getString(check, ['risk_class'], '').toLowerCase() !== 'soc_gated'
    && constraints?.customer_runnable !== false;
}

function checkSafetySummary(check: DataItem) {
  const constraints = check.safety_constraints
    && typeof check.safety_constraints === 'object'
    && !Array.isArray(check.safety_constraints)
    ? check.safety_constraints as DataItem
    : null;
  const maxEvents = getString(constraints, ['max_events', 'max_requests'], '');
  const maxDuration = getString(constraints, ['max_duration_seconds'], '');
  const parts: string[] = [];
  if (maxEvents) parts.push(`≤ ${maxEvents} events`);
  if (maxDuration) parts.push(`≤ ${maxDuration}s`);
  return parts.join(' · ') || 'Catalog-defined';
}

function formatPolicySafeWindow(policy: DataItem) {
  const windows = Array.isArray(policy.safe_windows) ? policy.safe_windows as DataItem[] : [];
  const first = windows[0];
  if (!first || typeof first !== 'object' || Array.isArray(first)) return 'Window not declared';
  const day = getString(first, ['day'], '');
  const start = getString(first, ['start'], '');
  const end = getString(first, ['end'], '');
  const timezone = getString(first, ['timezone'], 'UTC');
  const range = start && end ? `${start}–${end}` : start || end;
  return [day, range, timezone].filter(Boolean).join(' ') || 'Window not declared';
}

/** Map a DNS challenge record onto a §7.1 verification-chip state. */
function challengeChipState(challenge: DataItem | null, verified?: boolean) {
  if (!challenge) return verified === true ? 'dns_verified' : 'unverified';
  const state = getString(challenge, ['state'], '').toLowerCase();
  if (state === 'pending') return isActiveDnsChallenge(challenge) ? 'pending' : 'expired';
  if (state === 'resolved' || verified === true) return 'dns_verified';
  if (state === 'expired' || state === '—' || !state) return 'unverified';
  return state;
}

function pickActiveChallenge(list: DataItem[]): DataItem | null {
  if (list.length === 0) return null;
  const newestFirst = [...list].sort((a, b) =>
    String(getString(b, ['issued_at'], '')).localeCompare(String(getString(a, ['issued_at'], '')))
  );
  return newestFirst.find((row) => isActiveDnsChallenge(row)) ?? newestFirst[0] ?? null;
}

function DetailStatusBanners({ loadError, message, error }: { loadError: string; message: string; error: string }) {
  return (
    <>
      {loadError ? <div className="form-banner error" role="alert">{loadError}</div> : null}
      {(message || error) && !loadError ? (
        <div className={error ? 'form-banner error' : 'form-banner'} role={error ? 'alert' : 'status'}>
          {error || message}
        </div>
      ) : null}
    </>
  );
}

function DetailModal({
  title,
  onClose,
  children,
  error,
  wide = true
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  error?: string;
  wide?: boolean;
}) {
  const titleId = useId();
  const dialogRef = useRef<HTMLDialogElement>(null);
  const invokerRef = useRef<HTMLElement | null>(null);
  ensureDetailModalStyles();

  useEffect(() => {
    const activeElement = document.activeElement;
    invokerRef.current = activeElement instanceof HTMLElement ? activeElement : null;
    const dialog = dialogRef.current;
    if (dialog && !dialog.open) dialog.showModal();
    return () => {
      if (dialog?.open) dialog.close();
      const invoker = invokerRef.current;
      if (invoker?.isConnected) invoker.focus({ preventScroll: true });
    };
  }, []);

  return (
    <dialog
      ref={dialogRef}
      className={`modal-confirm detail-modal${wide ? ' detail-modal-wide' : ''}`}
      aria-labelledby={titleId}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <div className="detail-modal-head">
        <h3 id={titleId}>{title}</h3>
        <Button size="sm" variant="ghost" onClick={onClose} aria-label="Close dialog">
          Close
        </Button>
      </div>
      <div className="detail-modal-body">
        {/* In-modal error banner: the page-level DetailStatusBanners sit behind the
            native <dialog>'s top-layer backdrop, so validation/request errors raised
            while the modal is open were invisible. Surface them here instead. */}
        {error ? <div className="form-banner error" role="alert">{error}</div> : null}
        {children}
      </div>
    </dialog>
  );
}

export function TargetGroupDetailView({
  entity,
  entityId,
  data,
  config,
  session,
  onRefresh,
  loading,
  loadError
}: {
  entity: DataItem;
  entityId: string;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  loading: boolean;
  loadError: string;
}) {
  ensureTgDetailStyles();

  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [dnsError, setDnsError] = useState('');
  const [selectedDnsTargetId, setSelectedDnsTargetId] = useState('');
  const [dnsChallenge, setDnsChallenge] = useState<DataItem | null>(null);
  const [dnsVerifyResult, setDnsVerifyResult] = useState<DataItem | null>(null);
  const [dnsChallenges, setDnsChallenges] = useState<DataItem[]>([]);
  const dnsChallengesRef = useRef<DataItem[]>([]);
  const dnsIssueInFlightTargetRef = useRef('');
  const [copiedField, setCopiedField] = useState('');
  const [ladder, setLadder] = useState<DataItem | null>(null);
  const [ladderLoading, setLadderLoading] = useState(true);
  const [ladderError, setLadderError] = useState('');
  const [connectors, setConnectors] = useState<DataItem[]>([]);
  const [connectorsMeta, setConnectorsMeta] = useState<DataItem | null>(null);
  const [inventoryProvider, setInventoryProvider] = useState<string | null>(null);
  const [inventoryRows, setInventoryRows] = useState<DataItem[]>([]);
  const [inventoryMeta, setInventoryMeta] = useState<DataItem | null>(null);
  const [selectedInventory, setSelectedInventory] = useState<Set<string>>(new Set());
  const [edgeDetection, setEdgeDetection] = useState<DataItem | null>(null);
  const [showLoaModal, setShowLoaModal] = useState(false);
  const [showOnboardModal, setShowOnboardModal] = useState(false);
  const [onboardTab, setOnboardTab] = useState<OnboardTab>('fqdn');
  const [selectedPolicyCheckId, setSelectedPolicyCheckId] = useState('');
  const [selectedPolicyTargetId, setSelectedPolicyTargetId] = useState('');
  const [ruleQuery, setRuleQuery] = useState('');
  const [ruleLimit, setRuleLimit] = useState(12);

  const onRefreshRef = useRef(onRefresh);
  useEffect(() => { onRefreshRef.current = onRefresh; }, [onRefresh]);

  const targets = Array.isArray(entity.targets) ? entity.targets as DataItem[] : [];
  const fqdnTargets = targets.filter((target) => getString(target, ['kind'], '').toLowerCase() === 'fqdn');
  const selectedDnsTarget = fqdnTargets.find((target) => getString(target, ['id'], '') === selectedDnsTargetId) ?? null;
  const agents = Array.isArray(data.agents) ? data.agents as DataItem[] : [];
  const checks = Array.isArray(data.checks) ? data.checks as DataItem[] : [];
  const policyItems = Array.isArray(data.testPolicies) ? data.testPolicies as DataItem[] : [];
  const relatedRuns = Array.isArray(entity.runs_recent) ? entity.runs_recent as DataItem[] : [];
  const relatedFindings = Array.isArray(entity.findings_on_group) ? entity.findings_on_group as DataItem[] : [];
  const groupMeta = entity.meta && typeof entity.meta === 'object' && !Array.isArray(entity.meta) ? entity.meta as DataItem : null;
  const targetCount = String(entity.target_count ?? targets.length);
  const loaState = getString(entity, ['loa_state', 'loa_status'], getString(entity.loa as DataItem | undefined, ['state'], 'required'));
  const loaSigned = isSignedLoaState(loaState);
  // KPI row (matches prototype screen-target-group-detail): ownership + validation mode read
  // straight off the target-group API entity (both fields exist in the dev store and Postgres,
  // defaulting to 'unverified'/'external_only').
  const ownershipStatus = getString(entity, ['ownership_status'], 'unverified');
  const ownershipTone = ['agent_verified', 'dns_verified', 'provider_verified', 'user_confirmed', 'verified'].includes(ownershipStatus.trim().toLowerCase())
    ? 'success'
    : ownershipStatus.trim().toLowerCase().includes('pending')
      ? 'warn'
      : 'muted';
  const validationMode = getString(entity, ['validation_mode'], 'external_only');
  const ladderSteps = Array.isArray(ladder?.steps) ? ladder.steps as DataItem[] : [];
  const customerRunnableChecks = checks.filter(isCustomerRunnableCheck);
  const normalizedRuleQuery = ruleQuery.trim().toLowerCase();
  const filteredRuleChecks = normalizedRuleQuery
    ? customerRunnableChecks.filter((check) => [
      getString(check, ['name'], ''),
      getString(check, ['check_id', 'id'], ''),
      getString(check, ['description', 'summary'], ''),
      getString(check, ['vector_family'], '')
    ].some((value) => value.toLowerCase().includes(normalizedRuleQuery)))
    : customerRunnableChecks;
  const visibleRuleChecks = filteredRuleChecks.slice(0, ruleLimit);
  const relatedPolicies = policyItems.filter(
    (policy) => getString(policy, ['target_group_id'], '') === entityId
  );
  const policiesByCheckId = new Map<string, DataItem[]>();
  for (const policy of relatedPolicies) {
    const checkId = getString(policy, ['check_id'], '');
    if (!checkId) continue;
    policiesByCheckId.set(checkId, [...(policiesByCheckId.get(checkId) ?? []), policy]);
  }
  const effectiveSelectedPolicyCheckId = customerRunnableChecks.some(
    (check) => getString(check, ['check_id', 'id'], '') === selectedPolicyCheckId
  ) ? selectedPolicyCheckId : '';
  const selectedPolicyCheck = customerRunnableChecks.find(
    (check) => getString(check, ['check_id', 'id'], '') === effectiveSelectedPolicyCheckId
  ) ?? null;
  const compatiblePolicyTargets = selectedPolicyCheck
    ? targets.filter((target) => isPolicyTargetCompatible(selectedPolicyCheck, target))
    : [];
  const effectiveSelectedPolicyTargetId = compatiblePolicyTargets.some(
    (target) => getString(target, ['id'], '') === selectedPolicyTargetId
  ) ? selectedPolicyTargetId : '';
  const selectedPolicyTarget = compatiblePolicyTargets.find(
    (target) => getString(target, ['id'], '') === effectiveSelectedPolicyTargetId
  ) ?? null;
  const canCreateScheduledPolicy = ['owner', 'admin', 'engineer'].includes(
    String(session.role ?? '').trim().toLowerCase()
  );
  const wafEdgeDetectionEnabled = data.deploymentFeatures?.waf_posture === true;

  const verifiedTargetCount = targets.filter((target) => canRunTest(targetVerificationState(target))).length;
  const loaScopeTargetCount = targets.filter((target) => isLoaScopeEligible(targetVerificationState(target))).length;

  // Every displayed challenge is bound to the domain the operator explicitly selected.
  const selectedChallengeHistory = selectedDnsTargetId
    ? dnsChallenges.filter((challenge) => getString(challenge, ['target_id'], '') === selectedDnsTargetId)
    : [];
  const verifiedChallenge = asDataItem(dnsVerifyResult?.challenge);
  const selectedVerifiedChallenge = verifiedChallenge
    && getString(verifiedChallenge, ['target_id'], '') === selectedDnsTargetId
    ? verifiedChallenge
    : null;
  const selectedChallengeCandidates = [
    ...(selectedVerifiedChallenge ? [selectedVerifiedChallenge] : []),
    ...(dnsChallenge && getString(dnsChallenge, ['target_id'], '') === selectedDnsTargetId ? [dnsChallenge] : []),
    ...selectedChallengeHistory
  ];
  const activeChallenge = selectedDnsTargetId ? pickActiveChallenge(selectedChallengeCandidates) : null;
  const selectedTargetOwnershipState = selectedDnsTarget
    ? targetVerificationState(selectedDnsTarget).trim().toLowerCase()
    : 'unverified';
  const targetOwnershipDnsVerified = selectedTargetOwnershipState === 'dns_verified';
  const activeChallengeId = getString(activeChallenge, ['id', 'challenge_id'], '');
  const activeChallengeState = getString(activeChallenge, ['state'], '').toLowerCase();
  const activeChallengeVerifiedByResponse = selectedVerifiedChallenge !== null
    && getString(selectedVerifiedChallenge, ['id', 'challenge_id'], '') === activeChallengeId
    && dnsVerifyResult?.verified === true;
  const challengeResolved = activeChallengeState === 'resolved' || activeChallengeVerifiedByResponse;
  const dnsOwnershipConfirmed = targetOwnershipDnsVerified || challengeResolved;
  const dnsChipState = challengeChipState(activeChallenge, challengeResolved);
  const activeChallengeIsPending = isActiveDnsChallenge(activeChallenge);
  const dnsIssueBlocked = !selectedDnsTargetId
    || activeChallengeIsPending
    || dnsOwnershipConfirmed
    || busy.startsWith('dns-');
  // §7.2 cycle: surface the transient "checking…" chip while a verify request is in flight.
  const displayedDnsChipState = busy === `dns-verify-${entityId}` && dnsChipState === 'pending' ? 'checking' : dnsChipState;

  const loadDnsChallenges = useCallback(async (surfaceError = true): Promise<DataItem[]> => {
    try {
      const payload = await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/dns-ownership`) as DataItem;
      const items = Array.isArray(payload.items) ? payload.items as DataItem[] : [];
      dnsChallengesRef.current = items;
      setDnsChallenges(items);
      if (surfaceError) setDnsError('');
      return items;
    } catch (err) {
      if (surfaceError) {
        setDnsError(err instanceof Error ? `Could not refresh DNS challenges — ${err.message}. Previously confirmed challenge state is retained.` : 'Could not refresh DNS challenges. Previously confirmed challenge state is retained.');
      }
      return dnsChallengesRef.current;
    }
  }, [config, session, entityId]);

  useEffect(() => {
    let cancelled = false;
    setLadderLoading(true);
    setLadderError('');
    requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/verification-ladder`)
      .then((payload) => {
        if (!cancelled) setLadder(payload as DataItem);
      })
      .catch((err) => {
        if (cancelled) return;
        setLadder(null);
        setLadderError(err instanceof Error
          ? `Could not load ownership ladder — ${err.message}`
          : 'Could not load ownership ladder.');
      })
      .finally(() => {
        if (!cancelled) setLadderLoading(false);
      });
    return () => { cancelled = true; };
  }, [config, session, entityId, entity.updated_at]);

  useEffect(() => {
    setSelectedDnsTargetId('');
    setDnsChallenge(null);
    setDnsVerifyResult(null);
    dnsChallengesRef.current = [];
    setDnsChallenges([]);
    setDnsError('');
  }, [entityId]);

  useEffect(() => {
    if (selectedDnsTargetId && !fqdnTargets.some((target) => getString(target, ['id'], '') === selectedDnsTargetId)) {
      setSelectedDnsTargetId('');
      setDnsChallenge(null);
      setDnsVerifyResult(null);
    }
  }, [selectedDnsTargetId, entity.targets]);

  useEffect(() => { void loadDnsChallenges(); }, [loadDnsChallenges]);

  useEffect(() => {
    // Use connectors already loaded by fetchPortalData (gated on the connectorsEnabled
    // deployment feature). Avoids an unconditional GET /v1/connectors that 404s when the
    // connector add-on is disabled for the tenant.
    const loadedConnectors = (Array.isArray(data.connectors) ? (data.connectors as DataItem[]) : [])
      .filter((connector) => DNS_INVENTORY_PROVIDERS.has(getString(connector, ['provider'], '').toLowerCase()));
    setConnectors(loadedConnectors);
    setConnectorsMeta(loadedConnectors.length === 0
      ? { empty_reason: 'No DNS provider integration is configured for this tenant.' }
      : null);
  }, [data.connectors]);

  // §7.2 optional background polling: re-check a pending challenge every 30s until resolved,
  // capped at 15 minutes. This functional network timer does not create visual motion.
  useEffect(() => {
    if (!activeChallengeIsPending || !activeChallengeId) return undefined;

    const startedAt = Date.now();
    const timer = window.setInterval(() => {
      if (Date.now() - startedAt > DNS_POLL_MAX_MS) {
        window.clearInterval(timer);
        return;
      }
      requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/dns-ownership/verify`, {
        method: 'POST',
        body: { challenge_id: activeChallengeId }
      })
        .then(async (payload) => {
          const result = payload as DataItem;
          const challenge = asDataItem(result.challenge);
          if (
            !challenge
            || getString(challenge, ['id', 'challenge_id'], '') !== activeChallengeId
            || getString(challenge, ['target_id'], '') !== selectedDnsTargetId
          ) {
            window.clearInterval(timer);
            setDnsError('Automatic DNS recheck returned a challenge for a different target. Polling stopped; use Check now after reviewing the selected domain.');
            return;
          }
          setDnsVerifyResult(result);
          setDnsError('');
          if (result.verified === true) {
            window.clearInterval(timer);
            await loadDnsChallenges();
            let baselineMessage = wafEdgeDetectionEnabled
              ? ' Bounded WAF/CDN detection was not queued; start it from the target row.'
              : ' WAF/CDN detection is not enabled for this tenant.';
            if (wafEdgeDetectionEnabled) {
              try {
                await requestJson(config, session, '/v1/waf/edge-detection', {
                  method: 'POST',
                  body: { target_group_id: entityId, target_id: selectedDnsTargetId }
                });
                baselineMessage = ' Bounded WAF/CDN detection started through the signed-worker path.';
              } catch {
                // Ownership remains verified even when group-wide concurrency blocks the baseline.
              }
            }
            setMessage(`DNS ownership verified.${baselineMessage}`);
            try {
              await onRefreshRef.current();
            } catch (refreshError) {
              setDnsError(refreshError instanceof Error
                ? `DNS ownership is confirmed, but the automatic target-group refresh failed — ${refreshError.message}. The confirmed state is retained.`
                : 'DNS ownership is confirmed, but the automatic target-group refresh failed. The confirmed state is retained.');
            }
          }
        })
        .catch((err) => {
          setDnsError(err instanceof Error
            ? `Automatic DNS recheck failed — ${err.message}`
            : 'Automatic DNS recheck failed. Use Check now to retry.');
        });
    }, DNS_POLL_INTERVAL_MS);

    return () => window.clearInterval(timer);
  }, [config, session, entityId, selectedDnsTargetId, activeChallengeId, activeChallengeIsPending, loadDnsChallenges, wafEdgeDetectionEnabled]);

  useEffect(() => { setEdgeDetection(null); }, [entityId]);

  // A detection request is a signed-worker test run, not an inline control-plane scan.
  // Poll the canonical run and event APIs; this page keeps only a display projection.
  useEffect(() => {
    if (!['pending', 'queued'].includes(getString(edgeDetection, ['status'], ''))) return undefined;
    const requestState = edgeDetection as DataItem;
    const runId = getString(requestState, ['test_run_id'], '');
    if (!runId) return undefined;

    let cancelled = false;
    let timer: number | undefined;
    const startedAt = Date.now();
    const poll = async () => {
      try {
        const [run, eventEnvelope] = await Promise.all([
          requestJson(config, session, `/v1/test-runs/${encodeURIComponent(runId)}`),
          requestJson(config, session, `/v1/test-runs/${encodeURIComponent(runId)}/events`)
        ]);
        if (cancelled) return;
        const projected = projectEdgeDetectionResult(requestState, run, eventEnvelope);
        if (!['pending', 'queued'].includes(getString(projected, ['status'], ''))) {
          setMessage('');
          setEdgeDetection(projected);
          return;
        }
        if (Date.now() - startedAt >= EDGE_DETECTION_POLL_MAX_MS) {
          setMessage('');
          setEdgeDetection({
            ...projected,
            status: 'not_observed',
            reason: 'worker_result_not_observed_before_poll_timeout'
          });
          return;
        }
      } catch {
        if (cancelled) return;
        if (Date.now() - startedAt >= EDGE_DETECTION_POLL_MAX_MS) {
          setMessage('');
          setEdgeDetection({
            ...requestState,
            status: 'error',
            reason: 'result_read_failed'
          });
          return;
        }
      }
      timer = window.setTimeout(() => { void poll(); }, EDGE_DETECTION_POLL_INTERVAL_MS);
    };

    timer = window.setTimeout(() => { void poll(); }, 500);
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [config, session, edgeDetection]);

  async function runAction(label: string, action: () => Promise<void>, success: string | (() => string)) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      await action();
      setMessage(typeof success === 'function' ? success() : success);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setBusy('');
    }
  }

  function openOnboardModal(tab: OnboardTab = 'fqdn') {
    setOnboardTab(tab);
    setError('');
    setMessage('');
    setShowOnboardModal(true);
  }

  async function addTarget(
    kind: string,
    value: string,
    expectedBehavior: string,
    metadata?: Record<string, string>,
    options: { closeModal?: boolean; successMessage?: string } = {}
  ): Promise<DataItem | null> {
    const trimmed = value.trim();
    if (!trimmed) {
      setError('A target value is required.');
      setMessage('');
      return null;
    }
    // Only send metadata keys that carry a value — keeps the persisted
    // metadata_json clean (no empty agent_id / notes / port entries).
    const cleanedMetadata = metadata
      ? Object.fromEntries(Object.entries(metadata).filter(([, entry]) => entry && entry.trim()))
      : undefined;
    setBusy(`add-target-${kind}`);
    setError('');
    setMessage('');
    try {
      const created = await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/targets`, {
        method: 'POST',
        body: {
          kind,
          value: trimmed,
          expected_behavior: expectedBehavior || null,
          ...(cleanedMetadata && Object.keys(cleanedMetadata).length > 0 ? { metadata: cleanedMetadata } : {})
        }
      }) as DataItem;
      if (!getString(created, ['id'], '')) {
        throw new Error('The target API did not return the created target ID, so no follow-up action was attempted.');
      }
      setMessage(options.successMessage ?? 'Target declared.');
      if (options.closeModal !== false) setShowOnboardModal(false);
      await onRefresh();
      return created;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to declare target.');
      return null;
    } finally {
      setBusy('');
    }
  }

  async function removeTarget(item: DataItem) {
    const targetId = getString(item, ['id'], '');
    if (!targetId) return;
    const targetLabel = getString(item, ['value'], targetId);
    const confirmed = window.confirm(
      `Remove ${targetLabel} from this target group?\n\nThis removes the declaration and stops future scheduled validation for this target. Active runs must finish or be cancelled first. Existing evidence is retained.`
    );
    if (!confirmed) return;
    await runAction(`remove-target-${targetId}`, async () => {
      await requestJson(
        config,
        session,
        `/v1/target-groups/${encodeURIComponent(entityId)}/targets/${encodeURIComponent(targetId)}`,
        { method: 'DELETE' }
      );
    }, `Target ${targetLabel} removed from the declared scope.`);
  }

  async function submitFqdnTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const created = await addTarget(
      'fqdn',
      String(form.get('value') ?? ''),
      String(form.get('expected_behavior') ?? ''),
      { agent_id: String(form.get('agent_id') ?? '') },
      { closeModal: false, successMessage: 'Domain declared. Issuing its target-bound DNS challenge…' }
    );
    const targetId = getString(created, ['id'], '');
    if (!targetId) return;
    setSelectedDnsTargetId(targetId);
    await issueDnsChallenge(targetId, getString(created, ['value'], targetId));
  }

  function submitIpTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const ip = String(form.get('value') ?? '').trim();
    const parsedPort = parseOptionalPort(form.get('port'));
    if (parsedPort.error) {
      setError(parsedPort.error);
      setMessage('');
      return;
    }
    void addTarget(
      'ip',
      ip,
      String(form.get('expected_behavior') ?? ''),
      { port: parsedPort.port, notes: String(form.get('notes') ?? '') }
    );
  }

  async function issueDnsChallenge(targetId: string, createdTargetLabel = '') {
    const selectedTarget = fqdnTargets.find((target) => getString(target, ['id'], '') === targetId);
    const targetLabel = getString(selectedTarget, ['value'], createdTargetLabel || targetId);
    // The just-created target may not be present in parent props until refresh completes. Its
    // create response supplies both the ID and label, so chaining remains explicit and safe.
    if (!targetId || (!selectedTarget && !createdTargetLabel)) {
      setDnsError('Select a declared domain target before issuing a DNS challenge.');
      setMessage('');
      return;
    }

    const locallyVerifiedChallenge = asDataItem(dnsVerifyResult?.challenge);
    const knownChallenge = pickActiveChallenge([
      ...(dnsChallenge && getString(dnsChallenge, ['target_id'], '') === targetId ? [dnsChallenge] : []),
      ...(locallyVerifiedChallenge && getString(locallyVerifiedChallenge, ['target_id'], '') === targetId ? [locallyVerifiedChallenge] : []),
      ...dnsChallengesRef.current.filter((challenge) => getString(challenge, ['target_id'], '') === targetId)
    ]);
    const targetAlreadyDnsVerified = targetVerificationState(selectedTarget ?? {}).trim().toLowerCase() === 'dns_verified'
      || getString(knownChallenge, ['state'], '').toLowerCase() === 'resolved'
      || (dnsVerifyResult?.verified === true && getString(locallyVerifiedChallenge, ['target_id'], '') === targetId);

    setSelectedDnsTargetId(targetId);
    if (targetAlreadyDnsVerified) {
      if (knownChallenge) setDnsChallenge(knownChallenge);
      setDnsError('');
      setMessage(`DNS ownership is already confirmed for ${targetLabel}. No new challenge was issued.`);
      return;
    }
    if (isActiveDnsChallenge(knownChallenge)) {
      setDnsChallenge(knownChallenge);
      setDnsError('');
      setMessage(`An active challenge already exists for ${targetLabel}. Reuse it or wait until it expires; no replacement was issued.`);
      return;
    }
    if (busy.startsWith('dns-') || dnsIssueInFlightTargetRef.current) return;
    dnsIssueInFlightTargetRef.current = targetId;

    setBusy(`dns-issue-${entityId}`);
    setDnsError('');
    setError('');
    setMessage('');
    try {
      const result = await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/dns-ownership/issue`, {
        method: 'POST',
        body: { target_id: targetId }
      }) as DataItem;
      const challenge = asDataItem(result.challenge) ?? result;
      if (getString(challenge, ['target_id'], '') !== targetId) {
        throw new Error('The DNS service did not bind the challenge to the selected target. Nothing was displayed; contact an operator.');
      }
      setDnsChallenge(challenge);
      setDnsVerifyResult(null);
      await loadDnsChallenges();
      setMessage(`DNS TXT challenge issued for ${targetLabel}.`);
      try {
        await onRefresh();
      } catch (refreshError) {
        setDnsError(refreshError instanceof Error
          ? `The challenge was issued, but the target-group refresh failed — ${refreshError.message}. Keep using the displayed challenge; do not reissue it.`
          : 'The challenge was issued, but the target-group refresh failed. Keep using the displayed challenge; do not reissue it.');
      }
    } catch (err) {
      if (apiErrorCode(err) === 'challenge_active') {
        const items = await loadDnsChallenges();
        const pending = items
          .filter((challenge) => getString(challenge, ['target_id'], '') === targetId)
          .find((challenge) => isActiveDnsChallenge(challenge));
        if (pending) {
          setDnsChallenge(pending);
          setDnsVerifyResult(null);
          setMessage(`An active challenge already exists for ${targetLabel}. Reuse it or wait until it expires; no replacement was issued.`);
          return;
        }
        setDnsError('The DNS service reports an active challenge, but the target-bound challenge could not be loaded. No replacement was issued.');
      } else {
        setDnsError(err instanceof Error ? `Could not issue DNS challenge — ${err.message}` : 'Could not issue DNS challenge.');
      }
    } finally {
      if (dnsIssueInFlightTargetRef.current === targetId) dnsIssueInFlightTargetRef.current = '';
      setBusy('');
    }
  }

  async function verifyDnsChallenge(explicitChallengeId: string, explicitTargetId = selectedDnsTargetId) {
    const challengeId = explicitChallengeId.trim();
    const targetId = explicitTargetId.trim();
    if (!challengeId || !targetId) {
      setDnsError('Select a domain with an issued challenge before checking DNS.');
      setMessage('');
      return;
    }

    setBusy(`dns-verify-${entityId}`);
    setDnsError('');
    setError('');
    setMessage('');
    try {
      const result = await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/dns-ownership/verify`, {
        method: 'POST',
        body: { challenge_id: challengeId }
      }) as DataItem;
      const challenge = asDataItem(result.challenge);
      if (!challenge || getString(challenge, ['id', 'challenge_id'], '') !== challengeId) {
        throw new Error('The DNS service returned a different challenge than the one checked.');
      }
      if (getString(challenge, ['target_id'], '') !== targetId) {
        throw new Error('The DNS service returned a challenge for a different target.');
      }
      setDnsVerifyResult(result);
      setDnsChallenge(challenge);
      await loadDnsChallenges();
      if (result.verified === true) {
        const verifiedTarget = fqdnTargets.find((target) => getString(target, ['id'], '') === targetId);
        const verifiedLabel = getString(verifiedTarget, ['value'], targetId);
        let baselineMessage = wafEdgeDetectionEnabled
          ? ' Bounded WAF/CDN detection was not queued; start it from the target row.'
          : ' WAF/CDN detection is not enabled for this tenant.';
        if (wafEdgeDetectionEnabled) {
          try {
            await requestJson(config, session, '/v1/waf/edge-detection', {
              method: 'POST',
              body: { target_group_id: entityId, target_id: targetId }
            });
            baselineMessage = ' Bounded WAF/CDN detection started through the signed-worker path.';
          } catch {
            // Ownership remains verified even when group-wide run concurrency blocks the baseline.
          }
        }
        setMessage(`DNS ownership verified for ${verifiedLabel}.${baselineMessage}`);
        try {
          await onRefresh();
        } catch (refreshError) {
          setDnsError(refreshError instanceof Error
            ? `DNS ownership is confirmed, but the target-group refresh failed — ${refreshError.message}. The confirmed state is retained.`
            : 'DNS ownership is confirmed, but the target-group refresh failed. The confirmed state is retained.');
        }
      } else if (asDataItem(result.meta)?.timeout === true) {
        setDnsError('The DNS lookup timed out. The challenge remains pending; retry Check now.');
      } else {
        setMessage('The expected TXT value was not observed. The challenge remains pending.');
      }
    } catch (err) {
      setDnsError(err instanceof Error ? `Could not check DNS ownership — ${err.message}` : 'Could not check DNS ownership.');
    } finally {
      setBusy('');
    }
  }

  function copyField(field: string, value: string) {
    if (!value || value === '—') return;
    const flash = () => {
      setCopiedField(field);
      window.setTimeout(() => setCopiedField((current) => (current === field ? '' : current)), 1600);
    };
    try {
      if (navigator?.clipboard?.writeText) {
        navigator.clipboard.writeText(value).then(flash).catch(() => undefined);
      } else {
        flash();
      }
    } catch {
      // Clipboard API unavailable — no-op.
    }
  }

  // Per-row Verify: for a domain, issue (or re-check) a scoped DNS TXT challenge in place; for an
  // IP/agent-bound target, jump to target detail where the agent-binding flow lives (§4.5).
  function verifyTarget(item: DataItem) {
    const id = getString(item, ['id'], '');
    if (!id) return;
    const kind = getString(item, ['kind'], '').toLowerCase();
    if (kind !== 'fqdn') {
      window.location.hash = `target-detail?id=${encodeURIComponent(id)}`;
      return;
    }
    setSelectedDnsTargetId(id);
    setDnsError('');
    const existing = pickActiveChallenge(
      dnsChallengesRef.current.filter((row) => getString(row, ['target_id'], '') === id)
    );
    const verificationState = targetVerificationState(item).trim().toLowerCase();
    const alreadyVerified = canRunTest(verificationState)
      || getString(existing, ['state'], '').toLowerCase() === 'resolved';
    if (alreadyVerified) {
      if (existing) {
        setDnsChallenge(existing);
        setDnsVerifyResult(getString(existing, ['state'], '').toLowerCase() === 'resolved'
          ? { verified: true, challenge: existing }
          : null);
      }
      setMessage(`Ownership is already confirmed for ${getString(item, ['value'], id)} (${humanizeLabel(verificationState)}). No new DNS challenge was issued.`);
    } else if (isActiveDnsChallenge(existing)) {
      setDnsChallenge(existing);
      void verifyDnsChallenge(getString(existing, ['id', 'challenge_id'], ''), id);
    } else {
      void issueDnsChallenge(id);
    }
  }

  async function openInventory(connectorId: string) {
    setInventoryProvider(connectorId);
    setBusy(`inventory-${connectorId}`);
    try {
      const payload = await requestJson(config, session, `/v1/connectors/${encodeURIComponent(connectorId)}/inventory`) as DataItem;
      setInventoryRows(Array.isArray(payload.items) ? payload.items as DataItem[] : []);
      setInventoryMeta(payload.meta && typeof payload.meta === 'object' ? payload.meta as DataItem : null);
      setSelectedInventory(new Set());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Inventory request failed.');
      setInventoryRows([]);
      setInventoryMeta({ empty_reason: err instanceof Error ? err.message : 'Inventory request failed.' });
    } finally {
      setBusy('');
    }
  }

  async function importInventory() {
    if (!inventoryProvider || selectedInventory.size === 0) return;
    let importedCount = 0;
    let skippedCount = 0;
    let skippedDetails = '';
    let baselineLabel = '';
    let baselineDeferredCount = 0;
    let baselineStartFailed = false;
    await runAction(`import-${inventoryProvider}`, async () => {
      const items = [...selectedInventory]
        .map((rowId) => inventoryRows.find((item) => getString(item, ['id', 'value'], '') === rowId))
        .filter((row): row is DataItem => Boolean(row))
        .map((row) => ({
          kind: getString(row, ['kind'], 'fqdn'),
          value: getString(row, ['value', 'name'], ''),
          expected_behavior: getString(row, ['expected_behavior'], '') || null
        }));
      const result = await requestJson(
        config,
        session,
        `/v1/target-groups/${encodeURIComponent(entityId)}/targets:bulk-import`,
        {
          method: 'POST',
          body: { connector_id: inventoryProvider, source: 'provider_inventory', items }
        }
      ) as DataItem;
      importedCount = typeof result.count === 'number'
        ? result.count
        : Array.isArray(result.imported) ? result.imported.length : 0;
      const skippedRows = Array.isArray(result.skipped) ? result.skipped as DataItem[] : [];
      skippedCount = skippedRows.length;
      skippedDetails = skippedRows.slice(0, 5).map((row) => {
        const value = getString(row, ['value'], 'unnamed row');
        const reason = getString(row, ['reason', 'message'], 'not imported').replaceAll('_', ' ');
        return `${value}: ${reason}`;
      }).join('; ');
      const importedTargets = Array.isArray(result.imported) ? result.imported as DataItem[] : [];
      const baselineTargets = importedTargets.filter((target) => canRunTest(targetVerificationState(target)));
      baselineDeferredCount = Math.max(0, baselineTargets.length - 1);
      const baselineTarget = baselineTargets[0];
      const baselineTargetId = getString(baselineTarget, ['id'], '');
      if (baselineTargetId && wafEdgeDetectionEnabled) {
        baselineLabel = getString(baselineTarget, ['value'], baselineTargetId);
        try {
          await requestJson(config, session, '/v1/waf/edge-detection', {
            method: 'POST',
            body: { target_group_id: entityId, target_id: baselineTargetId }
          });
        } catch {
          baselineStartFailed = true;
          baselineDeferredCount = baselineTargets.length;
        }
      }
      setInventoryProvider(null);
      setInventoryRows([]);
      setSelectedInventory(new Set());
    }, () => {
      const skippedSummary = skippedCount
        ? `; ${skippedCount} skipped${skippedDetails ? ` (${skippedDetails}${skippedCount > 5 ? '; more omitted' : ''})` : ''}`
        : '';
      const importSummary = `${importedCount} exact ${importedCount === 1 ? 'target' : 'targets'} imported through provider inventory validation${skippedSummary}.`;
      if (baselineStartFailed) return `${importSummary} The immediate WAF/CDN baseline could not start; no baseline was queued. Start detection from the target row.`;
      if (baselineLabel) {
        return `${importSummary} Bounded WAF/CDN detection started for ${baselineLabel}${baselineDeferredCount ? `; ${baselineDeferredCount} remaining ${baselineDeferredCount === 1 ? 'target is' : 'targets are'} not queued because concurrency is group-wide` : ''}.`;
      }
      return importSummary;
    });
  }

  async function runBoundedTest(targetId: string) {
    if (!effectiveSelectedPolicyCheckId || !selectedPolicyCheck) {
      setError('Select a customer-runnable rule in Rules & schedule before starting a bounded run.');
      setMessage('');
      return;
    }
    const checkName = getString(selectedPolicyCheck, ['name', 'check_id'], effectiveSelectedPolicyCheckId);
    await runAction(`run-test-${targetId}`, async () => {
      await requestJson(config, session, '/v1/test-runs', {
        method: 'POST',
        body: { check_id: effectiveSelectedPolicyCheckId, target_group_id: entityId, target_id: targetId }
      });
    }, `${checkName} run started for the selected target.`);
  }

  // Queue the fixed safe scanner for an already-declared target. The API resolves the
  // tenant-owned binding inside startTestRun; target values never leave this page as input.
  async function runEdgeDetection(item: DataItem) {
    const targetId = getString(item, ['id'], '');
    if (!targetId) {
      setError('This target does not have a valid identifier.');
      setMessage('');
      return;
    }
    if (!canRunTest(targetVerificationState(item))) {
      setError('Verify target ownership before starting WAF/CDN detection.');
      setMessage('');
      return;
    }
    setBusy(`edge-detect-${targetId}`);
    setError('');
    setMessage('');
    setEdgeDetection(null);
    try {
      const payload = await requestJson(config, session, '/v1/waf/edge-detection', {
        method: 'POST',
        body: { target_group_id: entityId, target_id: targetId }
      }) as DataItem;
      const requestState = asDataItem(payload.detection_request);
      const runId = getString(requestState, ['test_run_id'], '');
      if (
        !requestState
        || !['pending', 'queued'].includes(getString(requestState, ['status'], ''))
        || getString(requestState, ['check_id'], '') !== EDGE_DETECTION_CHECK_ID
        || getString(requestState, ['target_group_id'], '') !== entityId
        || getString(requestState, ['target_id'], '') !== targetId
        || !runId
      ) {
        throw new Error('Detection was not queued. Try again.');
      }
      setEdgeDetection({
        status: 'pending',
        reason: 'worker_result_pending',
        test_run_id: runId,
        target_group_id: entityId,
        target_id: targetId,
        check_id: EDGE_DETECTION_CHECK_ID,
        run_status: getString(requestState, ['run_status'], 'running'),
        test_run_url: `/v1/test-runs/${encodeURIComponent(runId)}`,
        events_url: `/v1/test-runs/${encodeURIComponent(runId)}/events`,
        detection: null
      });
      setMessage('WAF/CDN detection accepted. Signed-worker evidence is pending.');
      await onRefresh().catch(() => undefined);
    } catch (err) {
      setEdgeDetection({
        status: 'error',
        reason: 'request_failed',
        target_group_id: entityId,
        target_id: targetId,
        check_id: EDGE_DETECTION_CHECK_ID
      });
      setError(err instanceof Error ? err.message : 'Edge detection could not be queued.');
    } finally {
      setBusy('');
    }
  }

  async function submitScheduledPolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    if (!canCreateScheduledPolicy) {
      setError('Your role cannot create test policies. Ask an organization owner or administrator.');
      setMessage('');
      return;
    }
    if (!effectiveSelectedPolicyCheckId || !selectedPolicyCheck) {
      setError('Select a customer-runnable check before creating a schedule.');
      setMessage('');
      return;
    }
    if (!effectiveSelectedPolicyTargetId || !selectedPolicyTarget) {
      setError('Select the exact target this schedule may validate.');
      setMessage('');
      return;
    }
    const cadence = String(form.get('cadence') ?? 'weekly').trim();
    const expectedVerdict = String(form.get('expected_verdict') ?? 'pass').trim();
    const day = String(form.get('safe_window_day') ?? '').trim();
    const start = String(form.get('safe_window_start') ?? '').trim();
    const end = String(form.get('safe_window_end') ?? '').trim();
    const timezone = String(form.get('safe_window_timezone') ?? 'UTC').trim() || 'UTC';
    if (!day || !start || !end) {
      setError('A day, start time, and end time are required for the schedule window.');
      setMessage('');
      return;
    }
    if (start >= end) {
      setError('Safe window end time must be later than its start time.');
      setMessage('');
      return;
    }

    setBusy('create-test-policy');
    setError('');
    setMessage('');
    try {
      await requestJson(config, session, '/v1/test-policies', {
        method: 'POST',
        body: {
          target_group_id: entityId,
          target_id: effectiveSelectedPolicyTargetId,
          check_id: effectiveSelectedPolicyCheckId,
          cadence,
          expected_verdict: expectedVerdict,
          safe_windows: [{ day, start, end, timezone }]
        }
      });
      const checkName = getString(selectedPolicyCheck, ['name', 'check_id'], effectiveSelectedPolicyCheckId);
      setMessage(
        `${checkName} scheduled ${humanizeLabel(cadence).toLowerCase()} for ${getString(selectedPolicyTarget, ['value'], effectiveSelectedPolicyTargetId)} inside ${day} ${start}–${end} ${timezone}.`
      );
      formElement.reset();
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create the test policy.');
    } finally {
      setBusy('');
    }
  }

  async function submitLoa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (form.get('attested') !== 'on') {
      setError('Attestation is required before signing the LOA.');
      return;
    }
    const requestedScope = form.getAll('scope_ack').map(String).filter(Boolean);
    const eligibleScopeIds = new Set(
      targets
        .filter((target) => isLoaScopeEligible(targetVerificationState(target)))
        .map((target) => getString(target, ['id'], ''))
        .filter(Boolean)
    );
    const scopeAck = requestedScope.filter((targetId) => eligibleScopeIds.has(targetId));
    if (scopeAck.length !== requestedScope.length) {
      setError('The submitted LOA scope includes a target that is no longer eligible. Refresh and review the scope.');
      return;
    }
    if (scopeAck.length === 0) {
      setError('Select at least one agent-verified target for the authorization scope.');
      return;
    }

    setBusy(`loa-${entityId}`);
    setError('');
    setMessage('');
    try {
      const result = await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/loa`, {
        method: 'POST',
        body: {
          attested: true,
          signer_name: String(form.get('signer_name') ?? '').trim(),
          signer_title: String(form.get('signer_title') ?? '').trim(),
          signer_email: String(form.get('signer_email') ?? '').trim(),
          scope_ack: scopeAck,
          emergency_contact: {
            name: String(form.get('emergency_name') ?? '').trim(),
            role: String(form.get('emergency_role') ?? '').trim(),
            phone: String(form.get('emergency_phone') ?? '').trim(),
            email: String(form.get('emergency_email') ?? '').trim()
          }
        }
      }) as DataItem;
      const signedLoa = asDataItem(result.loa);
      const custodyArtifactId = getString(result, ['custody_artifact_id'], getString(signedLoa, ['custody_artifact_id'], ''));
      const custodyDigest = getString(result, ['custody_digest_sha256'], getString(signedLoa, ['custody_digest_sha256'], ''));
      if (!signedLoa || !isSignedLoaState(getString(signedLoa, ['state'], '')) || !custodyArtifactId || !custodyDigest) {
        throw new Error('The LOA response did not include a signed state and custody receipt.');
      }
      setShowLoaModal(false);
      setMessage(`LOA signed for ${scopeAck.length} target${scopeAck.length === 1 ? '' : 's'} and sealed as ${custodyArtifactId}.`);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to sign the LOA.');
    } finally {
      setBusy('');
    }
  }

  const targetColumns: TableColumn<DataItem>[] = [
    {
      key: 'target',
      label: 'Target',
      render: (item) => (
        <div className="target-primary">
          <Badge tone="muted" mono>{getString(item, ['kind'], 'target')}</Badge>
          <span className="target-primary-copy">
            <strong className="mono">{targetDisplayValue(item)}</strong>
            <span className="target-id mono">{getString(item, ['id'], '—')}</span>
          </span>
        </div>
      )
    },
    {
      key: 'source',
      label: 'Source',
      render: (item) => <Badge tone="muted" title="Declaration provenance from target API metadata">{targetDeclarationProvenanceLabel(item)}</Badge>
    },
    {
      key: 'expected',
      label: 'Expected behavior',
      render: (item) => <span>{humanizeLabel(getString(item, ['expected_behavior', 'expected'], ''))}</span>
    },
    {
      key: 'status',
      label: 'Status',
      render: (item) => {
        const state = targetVerificationState(item);
        const provenance = resolveTargetVerificationProvenance(item, targetVerificationEnvelope(item));
        return (
          <span className="target-status-stack">
            <VerifyChip state={state} provenance={provenance} />
            <span className="target-status-note">{canRunTest(state) ? 'Checks enabled' : 'Verify before testing'}</span>
          </span>
        );
      }
    },
    {
      key: 'last_probe',
      label: 'Last result',
      render: (item) => {
        // The target-group API does not always expose a per-target correlated verdict. Keep
        // missing evidence explicit rather than fabricating a success state.
        const probe = getString(item, ['last_probe', 'last_verdict'], '');
        if (!probe) return <span className="muted">—</span>;
        const key = probe.trim().toLowerCase();
        const tone = key === 'pass' ? 'success' : key === 'gap' || key === 'fail' ? 'danger' : 'warn';
        return <Badge tone={tone} title={`Last probe verdict ${probe} from target API`}>{humanizeLabel(probe)}</Badge>;
      }
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const runnable = canRunTest(targetVerificationState(item));
        const runReady = runnable && Boolean(effectiveSelectedPolicyCheckId);
        const removing = busy === `remove-target-${id}`;
        const runTitle = !runnable
          ? 'Verify ownership to enable testing'
          : effectiveSelectedPolicyCheckId
            ? `Run selected rule ${effectiveSelectedPolicyCheckId}`
            : 'Select a rule in Rules & schedule before running';
        return (
          <div className="row-end-actions target-actions">
            <AnchorButton
              size="sm"
              variant="ghost"
              href={buildDetailHref('target-detail', id)}
              aria-label={`Open target ${getString(item, ['value'], id)}`}
            >
              Open target
            </AnchorButton>
            <Button
              size="sm"
              variant="ghost"
              disabled={!id || removing || busy.startsWith('dns-')}
              onClick={() => verifyTarget(item)}
            >
              Verify
            </Button>
            {wafEdgeDetectionEnabled ? (
              <Button
                size="sm"
                variant="ghost"
                className={runnable ? undefined : 'is-locked'}
                disabled={!id || !runnable || busy === `edge-detect-${id}` || removing}
                title={runnable
                  ? 'Queue bounded WAF/CDN detection through the signed probe-worker path'
                  : 'Verify ownership before detecting the edge'}
                loading={busy === `edge-detect-${id}`}
                onClick={() => void runEdgeDetection(item)}
              >
                Detect edge
              </Button>
            ) : null}
            <Button
              size="sm"
              variant="ghost"
              className={runReady ? undefined : 'is-locked'}
              disabled={!runReady || busy === `run-test-${id}` || removing}
              title={runTitle}
              loading={busy === `run-test-${id}`}
              onClick={() => void runBoundedTest(id)}
            >
              Run test
            </Button>
            <Button
              size="sm"
              variant="danger"
              disabled={!id || busy === `run-test-${id}`}
              loading={removing}
              aria-label={`Remove target ${getString(item, ['value'], id)}`}
              onClick={() => void removeTarget(item)}
            >
              <Trash2 size={13} /> Remove
            </Button>
          </div>
        );
      }
    }
  ];

  const checkColumns: TableColumn<DataItem>[] = [
    {
      key: 'select',
      label: 'Select',
      render: (item) => {
        const checkId = getString(item, ['check_id', 'id'], '');
        const checkName = getString(item, ['name', 'check_id'], checkId);
        return (
          <label className="check-choice">
            <input
              type="radio"
              name="target-group-policy-check"
              value={checkId}
              checked={effectiveSelectedPolicyCheckId === checkId}
              onChange={() => {
                setSelectedPolicyCheckId(checkId);
                setSelectedPolicyTargetId((current) => {
                  const selectedTarget = targets.find((target) => getString(target, ['id'], '') === current);
                  return selectedTarget && isPolicyTargetCompatible(item, selectedTarget) ? current : '';
                });
              }}
              aria-label={`Select ${checkName} for bounded runs and the scheduled policy`}
            />
          </label>
        );
      }
    },
    {
      key: 'check',
      label: 'Customer-runnable check',
      render: (item) => {
        const checkId = getString(item, ['check_id', 'id'], '—');
        const description = getString(item, ['description', 'summary'], '');
        return (
          <span className="check-primary">
            <strong>{getString(item, ['name'], checkId)}</strong>
            {description ? <span className="check-description">{description}</span> : null}
            <span className="check-id mono">{checkId}</span>
          </span>
        );
      }
    },
    {
      key: 'family',
      label: 'Family',
      render: (item) => <Badge tone="muted">{humanizeLabel(getString(item, ['vector_family'], 'other'))}</Badge>
    },
    {
      key: 'bounds',
      label: 'Catalog bounds',
      render: (item) => <span className="mono small">{checkSafetySummary(item)}</span>
    },
    {
      key: 'policy',
      label: 'Current schedule',
      render: (item) => {
        const checkId = getString(item, ['check_id', 'id'], '');
        const boundPolicies = policiesByCheckId.get(checkId) ?? [];
        if (boundPolicies.length === 0) return <span className="muted small">Not scheduled in hydrated data</span>;
        return (
          <span className="check-policy-stack">
            {boundPolicies.map((policy, index) => {
              const state = getString(policy, ['state'], 'active').toLowerCase();
              const cadence = humanizeLabel(getString(policy, ['cadence'], 'manual'));
              return (
                <span className="check-policy-binding" key={getString(policy, ['id', 'policy_id'], `${checkId}-${index}`)}>
                  <Badge tone={state === 'paused' ? 'warn' : 'success'} title={`Policy ${state}`}>{cadence}</Badge>
                  <span className="mono small">{getString(policy.target as DataItem | undefined, ['value'], getString(policy, ['target_id'], 'Unbound legacy policy'))}</span>
                  <span className="mono muted small">{formatPolicySafeWindow(policy)}</span>
                </span>
              );
            })}
          </span>
        );
      }
    }
  ];

  const findingColumns: TableColumn<DataItem>[] = [
    {
      key: 'target',
      label: 'Target',
      render: (item) => {
        const targetId = getString(item, ['target_id'], '');
        return targetId
          ? <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-detail', targetId)}>{targetId}</AnchorButton>
          : <span className="muted">group-level</span>;
      }
    },
    {
      key: 'finding',
      label: 'Finding',
      render: (item) => <AnchorButton size="sm" variant="ghost" href={buildDetailHref('finding-detail', getString(item, ['id'], ''))}>{getString(item, ['title', 'id'], '')}</AnchorButton>
    },
    { key: 'severity', label: 'Severity', render: (item) => getString(item, ['severity'], 'unknown') },
    { key: 'status', label: 'Status', render: (item) => getString(item, ['status'], 'open') }
  ];

  const runColumns: TableColumn<DataItem>[] = [
    { key: 'run', label: 'Run', render: (item) => <AnchorButton size="sm" variant="ghost" href={buildDetailHref('run-detail', getString(item, ['id'], ''))}>{getString(item, ['id'], '')}</AnchorButton> },
    { key: 'policy', label: 'Policy', render: (item) => getString(item, ['policy_id', 'test_policy_id'], '—') },
    { key: 'checks', label: 'Checks', render: (item) => String(item.check_count ?? getString(item, ['check_id'], '—')) },
    { key: 'verdict', label: 'Verdict', render: (item) => getString(item, ['verdict', 'status'], 'pending') },
    { key: 'started', label: 'Started', render: (item) => formatDate(item.started_at ?? item.created_at) },
    { key: 'agent', label: 'Agent', render: (item) => getString(item, ['agent_id'], '—') }
  ];

  const dnsHistoryColumns: TableColumn<DataItem>[] = [
    { key: 'target', label: 'Target', render: (item) => <span className="mono">{getString(fqdnTargets.find((target) => getString(target, ['id'], '') === getString(item, ['target_id'], '')), ['value'], getString(item, ['target_id'], '—'))}</span> },
    { key: 'record', label: 'Record name', render: (item) => <span className="mono">{getString(item, ['record_name', 'name'], '—')}</span> },
    {
      key: 'state',
      label: 'State',
      render: (item) => <VerifyChip state={challengeChipState(item)} provenance={`DNS challenge ${getString(item, ['id'], '')} · ${getString(item, ['state'], 'pending')} per ownership API`} />
    },
    { key: 'issued', label: 'Issued', render: (item) => formatDate(item.issued_at) },
    { key: 'checked', label: 'Last checked', render: (item) => (item.last_checked_at ? formatDate(item.last_checked_at) : '—') }
  ];

  const dnsProvenance = dnsChipState === 'dns_verified'
    ? `TXT record resolved for ${getString(selectedDnsTarget, ['value'], selectedDnsTargetId)} via challenge ${activeChallengeId}`
    : activeChallengeId
      ? `Challenge ${activeChallengeId} is ${humanizeLabel(dnsChipState).toLowerCase()} for ${getString(selectedDnsTarget, ['value'], selectedDnsTargetId)}.${targetOwnershipDnsVerified ? ' Target ownership remains DNS verified from prior target evidence.' : ''}`
      : targetOwnershipDnsVerified
        ? `${getString(selectedDnsTarget, ['value'], selectedDnsTargetId)} is DNS verified by the target API; challenge details are unavailable`
        : selectedDnsTargetId
          ? `No DNS challenge is active for ${getString(selectedDnsTarget, ['value'], selectedDnsTargetId)}`
          : 'Select a domain target to inspect its DNS ownership state';
  const edgeDetectionStatus = getString(edgeDetection, ['status'], '');
  const edgeDetectionRunId = getString(edgeDetection, ['test_run_id'], '');
  const edgeDetectionEvidence = asDataItem(edgeDetection?.detection);
  const edgeWaf = asDataItem(edgeDetectionEvidence?.waf);
  const edgeCdn = asDataItem(edgeDetectionEvidence?.cdn);

  return (
    <div className="content tg-detail-view" aria-busy={loading || undefined}>
      <div className="page-head tg-page-head">
        <div className="tg-page-copy">
          <p className="eyebrow">Declared business service</p>
          <h1 className="page-title">{getString(entity, ['name'], entityId)}</h1>
          <p className="tg-page-summary">{getString(entity, ['description'], 'Manage declared scope, prove ownership, and schedule readiness checks.')}</p>
          <div className="tg-title-meta">
            <span className="muted mono">{entityId}</span>
            <Badge tone="muted">Environment {getString(entity, ['environment_id'], '—')}</Badge>
          </div>
        </div>
        <div className="tg-head-actions">
          <Button size="sm" onClick={() => openOnboardModal()}><Plus size={14} /> Add target</Button>
          <AnchorButton size="sm" variant="secondary" href="#target-groups">All groups</AnchorButton>
        </div>
      </div>

      {loading ? <PortalLoadingSkeleton rows={2} /> : null}
      <DetailStatusBanners loadError={loadError} message={message} error={error} />

      {/* (1) Ownership ladder — Declared → DNS verified → Agent verified → User confirmed. */}
      {ladderError ? <div className="form-banner error" role="alert">{ladderError}</div> : null}
      {ladderLoading ? <PortalLoadingSkeleton rows={1} /> : null}
      {!ladderLoading && ladderSteps.length === 0 ? (
        emptyStateFromApi({
          loading: ladderLoading,
          icon: Target,
          meta: ladder?.meta && typeof ladder.meta === 'object' ? ladder.meta as DataItem : null,
        })
      ) : null}
      {!ladderLoading && ladderSteps.length > 0 ? (
      <ol className="verify-ladder" aria-label="Ownership verification ladder">
        {ladderSteps.map((step, index) => {
          const done = step.done === true;
          const now = !done && ladderSteps.slice(0, index).every((entry) => entry.done === true);
          return (
            <li key={getString(step, ['id'], String(index))} className={`vl-step${done ? ' is-done' : ''}${now ? ' is-now' : ''}`}>
              <span className="vl-num" aria-hidden="true">{done ? <Check size={13} strokeWidth={2.6} /> : index + 1}</span>
              <div className="vl-body">
                <strong>{getString(step, ['label'], 'Step')}</strong>
                <span className="vl-meta">{getString(step, ['count'], '0')} of {getString(step, ['total'], '0')}</span>
              </div>
            </li>
          );
        })}
      </ol>
      ) : null}

      {/* (2) KPI row — Targets · Ownership · LOA · Validation mode (matches prototype screen-target-group-detail). */}
      <div className="kpi-row">
        <div className="kpi-cell">
          <div className="kpi-label">Targets</div>
          <div className="kpi-value">{targetCount}</div>
          <div className="kpi-delta">{verifiedTargetCount} verified · {Math.max(0, targets.length - verifiedTargetCount)} unverified</div>
        </div>
        <div className="kpi-cell">
          <div className="kpi-label">Ownership</div>
          <div className="kpi-value kpi-value--status">
            <Badge tone={ownershipTone} title={`Ownership status ${ownershipStatus} from target group API`}>{ownershipStatus}</Badge>
          </div>
        </div>
        <div className="kpi-cell">
          <div className="kpi-label">LOA</div>
          <div className="kpi-value kpi-value--status">
            <Badge tone={loaSigned ? 'success' : 'warn'} title={`LOA state ${loaState} from target group API`}>{loaSigned ? 'Signed' : 'Required'}</Badge>
          </div>
        </div>
        <div className="kpi-cell">
          <div className="kpi-label">Validation mode</div>
          <div className="kpi-value kpi-value--status">{humanizeLabel(validationMode)}</div>
        </div>
      </div>

      {/* (3) LOA callout — orange warn when unsigned, green success (signer + digest + date) when signed. */}
      <div className="callout callout-loa" data-loa-state={loaSigned ? 'signed' : 'required'}>
        <span className="callout-icon" aria-hidden="true"><ShieldHalf size={16} /></span>
        <div className="callout-body">
          <p className="callout-title">{loaSigned ? 'LOA signed' : 'Letter of Authorization required'}</p>
          <p className="callout-desc">
            {loaSigned
              ? `${getString(entity.loa as DataItem | undefined, ['signer_name'], getString(entity, ['loa_signer'], '—'))} · ${getString(entity.loa as DataItem | undefined, ['custody_digest_sha256', 'digest'], getString(entity, ['loa_digest'], '—'))} · ${formatDate((entity.loa as DataItem | undefined)?.signed_at ?? entity.loa_signed_at)}`
              : 'A scoped LOA records authorization and custody for governed workflows. Bounded safe checks still require verified ownership; SOC-gated execution additionally requires an active LOA.'}
          </p>
        </div>
        <div className="callout-actions">
          {!loaSigned ? (
            <>
              <Button size="sm" onClick={() => setShowLoaModal(true)}>Open target group &amp; sign LOA</Button>
              <Button size="sm" variant="ghost" onClick={() => void verifyDnsChallenge(activeChallengeId)} loading={busy === `dns-verify-${entityId}`} disabled={!activeChallengeId}>Review DNS status</Button>
            </>
          ) : null}
        </div>
      </div>

      {/* (4) DNS TXT verification panel — every challenge is explicitly target-bound. */}
      <Card>
        <CardHeader>
          <div>
            <CardTitle>DNS TXT verification</CardTitle>
            <CardDescription>Select the exact declared FQDN, then publish its one-time <span className="mono">_astranull-challenge</span> TXT record. No first-domain fallback is used.</CardDescription>
            {selectedDnsTarget ? (
              <p className="dns-selected-target">Selected target: <strong className="mono">{getString(selectedDnsTarget, ['value'], selectedDnsTargetId)}</strong> · <span className="mono">{selectedDnsTargetId}</span> · Target ownership: <strong>{humanizeLabel(selectedTargetOwnershipState)}</strong></p>
            ) : null}
          </div>
          <div className="dns-target-actions">
            <label className="dns-target-picker">
              <span>Domain target</span>
              <select
                value={selectedDnsTargetId}
                disabled={fqdnTargets.length === 0 || busy.startsWith('dns-')}
                onChange={(event) => {
                  setSelectedDnsTargetId(event.target.value);
                  setMessage('');
                }}
              >
                <option value="">Select a declared FQDN</option>
                {fqdnTargets.map((target) => {
                  const id = getString(target, ['id'], '');
                  return <option key={id} value={id}>{getString(target, ['value'], id)}</option>;
                })}
              </select>
            </label>
            <Button
              size="sm"
              onClick={() => void issueDnsChallenge(selectedDnsTargetId)}
              loading={busy === `dns-issue-${entityId}`}
              disabled={dnsIssueBlocked}
              title={activeChallengeIsPending
                ? 'This target already has an unexpired pending challenge'
                : dnsOwnershipConfirmed
                  ? 'DNS ownership is already confirmed for this target'
                  : busy.startsWith('dns-')
                    ? 'Wait for the current DNS action to finish'
                    : 'Issue a challenge for the selected target'}
            >
              {activeChallengeIsPending ? 'Challenge active' : dnsOwnershipConfirmed ? 'Ownership confirmed' : activeChallenge ? 'Issue new challenge' : 'Issue DNS challenge'}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {dnsError ? <div className="form-banner error" role="alert">{dnsError}</div> : null}
          {activeChallenge ? (
            <div className="dns-challenge" data-state={dnsChipState}>
              <div className="dns-head">
                <span className="eyebrow">Publish this target-bound TXT record</span>
                <span className="spacer" />
                <VerifyChip state={displayedDnsChipState} provenance={dnsProvenance} />
              </div>
              <div className="dns-fields">
                <div className="dns-field">
                  <span className="dns-key">Selected target</span>
                  <span className="dns-val mono">{getString(selectedDnsTarget, ['value'], selectedDnsTargetId)}</span>
                  <span className="muted small mono">{selectedDnsTargetId}</span>
                </div>
                <div className="dns-field">
                  <span className="dns-key">Record type</span>
                  <span className="dns-val mono">TXT</span>
                </div>
                <div className="dns-field">
                  <span className="dns-key">Record name</span>
                  <span className="dns-val mono">{getString(activeChallenge, ['record_name', 'name'], '—')}</span>
                  <button type="button" className="link-btn" onClick={() => copyField('dns-name', getString(activeChallenge, ['record_name', 'name'], ''))} aria-label="Copy record name">
                    {copiedField === 'dns-name' ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <div className="dns-field">
                  <span className="dns-key">Record value</span>
                  <span className="dns-val mono">{getString(activeChallenge, ['record_value', 'value'], '—')}</span>
                  <button type="button" className="link-btn" onClick={() => copyField('dns-value', getString(activeChallenge, ['record_value', 'value'], ''))} aria-label="Copy record value">
                    {copiedField === 'dns-value' ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <div className="dns-field">
                  <span className="dns-key">TTL</span>
                  <span className="dns-val mono">{getString(activeChallenge, ['ttl_seconds', 'ttl'], '—')} seconds</span>
                </div>
                <div className="dns-field">
                  <span className="dns-key">Expires</span>
                  <span className="dns-val">{formatDate(activeChallenge.expires_at)}</span>
                </div>
              </div>
              <div className="dns-footer">
                <Button size="sm" onClick={() => void verifyDnsChallenge(activeChallengeId)} loading={busy === `dns-verify-${entityId}`} disabled={!activeChallengeId || dnsChipState === 'dns_verified'}>
                  Check now
                </Button>
                <span className="muted small">
                  {dnsChipState === 'dns_verified'
                    ? `Resolved ${formatDate(getString(activeChallenge, ['resolved_at'], '') || undefined)}`
                    : getString(activeChallenge, ['last_checked_at'], '') !== '—' && getString(activeChallenge, ['last_checked_at'], '')
                      ? `Last checked ${formatDate(activeChallenge?.last_checked_at)}`
                      : 'Last checked: not yet'}
                </span>
                {activeChallengeIsPending ? <span className="muted small">Auto-rechecks every 30s until resolved or expired.</span> : null}
              </div>
            </div>
          ) : selectedDnsTarget && dnsOwnershipConfirmed ? (
            <EmptyState
              icon={ShieldHalf}
              title="DNS ownership confirmed"
              body={`The target API reports ${getString(selectedDnsTarget, ['value'], selectedDnsTargetId)} as DNS verified. Challenge details are unavailable, so AstraNull will not issue a replacement.`}
            />
          ) : selectedDnsTarget ? (
            <EmptyState
              icon={Globe}
              title="No challenge for the selected domain"
              body={`Issue a challenge for ${getString(selectedDnsTarget, ['value'], selectedDnsTargetId)}. AstraNull will send that exact target ID to the ownership API.`}
              actionLabel={busy.startsWith('dns-') ? undefined : 'Issue DNS challenge'}
              onAction={busy.startsWith('dns-') ? undefined : () => void issueDnsChallenge(selectedDnsTargetId)}
            />
          ) : fqdnTargets.length > 0 ? (
            <EmptyState
              icon={Globe}
              title="Select a domain target"
              body="Choose the exact declared FQDN above. AstraNull will not choose the first domain in the group."
            />
          ) : (
            <EmptyState
              icon={Globe}
              title="No domain targets declared"
              body="Add a domain first. Its create response will supply the target ID used to issue the DNS challenge."
              actionLabel="Add domain"
              onAction={() => openOnboardModal('fqdn')}
            />
          )}
          {selectedChallengeHistory.length > 0 ? (
            <div className="dns-history">
              <p className="dns-history-title">Challenge history for selected target</p>
              <DataTable
                columns={dnsHistoryColumns}
                items={selectedChallengeHistory}
                getRowId={(item, index) => getString(item, ['id'], String(index))}
                empty={<span className="muted small">No challenges recorded for this target.</span>}
              />
            </div>
          ) : null}
        </CardContent>
      </Card>

      {/* (5) Declared targets — clickable rows deep-link to target detail; actions stay explicit. */}
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Declared targets</CardTitle>
            <CardDescription>Customer-declared scope only. Verify each target before any check can run.</CardDescription>
          </div>
          <Button size="sm" onClick={() => openOnboardModal()}><Plus size={14} /> Add target</Button>
        </CardHeader>
        <CardContent>
          {edgeDetection ? (
            <div
              className={`form-banner ${edgeDetectionStatus === 'error' ? 'error' : 'info'} edge-detection-result`}
              role={edgeDetectionStatus === 'error' ? 'alert' : 'status'}
            >
              <div className="edge-detection-head">
                <strong>WAF/CDN detection</strong>
                <Badge
                  tone={edgeStatusTone(edgeDetectionStatus)}
                  title={`${humanizeLabel(edgeDetectionStatus)} from governed test run ${edgeDetectionRunId || 'not created'}`}
                >
                  {humanizeLabel(edgeDetectionStatus)}
                </Badge>
              </div>
              <p>{edgeStatusSummary(edgeDetection)}</p>
              {edgeDetectionEvidence && edgeWaf && edgeCdn ? (
                <div className="edge-evidence-grid" aria-label="Independent WAF and CDN evidence">
                  <section className="edge-evidence-card" aria-labelledby="edge-waf-evidence-title">
                    <div className="edge-evidence-card-head">
                      <strong id="edge-waf-evidence-title">WAF</strong>
                      <Badge
                        tone={edgeStatusTone(getString(edgeWaf, ['status'], 'inconclusive'))}
                        title={`WAF fingerprint status from signed-worker event for ${edgeDetectionRunId}`}
                      >
                        {humanizeLabel(getString(edgeWaf, ['status'], 'inconclusive'))}
                      </Badge>
                    </div>
                    <dl>
                      {getString(edgeWaf, ['provider'], '') ? <><dt>Provider</dt><dd>{getString(edgeWaf, ['provider'], '')}</dd></> : null}
                      {getString(edgeWaf, ['type'], '') ? <><dt>Type</dt><dd>{humanizeLabel(getString(edgeWaf, ['type'], ''))}</dd></> : null}
                    </dl>
                  </section>
                  <section className="edge-evidence-card" aria-labelledby="edge-cdn-evidence-title">
                    <div className="edge-evidence-card-head">
                      <strong id="edge-cdn-evidence-title">CDN</strong>
                      <Badge
                        tone={edgeStatusTone(getString(edgeCdn, ['status'], 'inconclusive'))}
                        title={`CDN fingerprint status from signed-worker event for ${edgeDetectionRunId}`}
                      >
                        {humanizeLabel(getString(edgeCdn, ['status'], 'inconclusive'))}
                      </Badge>
                    </div>
                    <dl>
                      {getString(edgeCdn, ['provider'], '') ? <><dt>Provider</dt><dd>{getString(edgeCdn, ['provider'], '')}</dd></> : null}
                      {getString(edgeCdn, ['type'], '') ? <><dt>Type</dt><dd>{humanizeLabel(getString(edgeCdn, ['type'], ''))}</dd></> : null}
                    </dl>
                  </section>
                </div>
              ) : null}
              {edgeDetectionEvidence ? (
                <div className="edge-evidence-meta">
                  {getString(edgeDetectionEvidence, ['corpus_version'], '') ? <span>Corpus v{getString(edgeDetectionEvidence, ['corpus_version'], '')}</span> : null}
                  {getString(edgeDetectionEvidence, ['requests_sent'], '') ? <span>{getString(edgeDetectionEvidence, ['requests_sent'], '')} bounded requests</span> : null}
                  {getString(edgeDetectionEvidence, ['observed_at'], '') ? <span>Observed {formatDate(edgeDetectionEvidence.observed_at)}</span> : null}
                  {edgeDetectionEvidence.conflicting_vendor_signals === true ? <span>Provider signals conflict; no WAF provider is asserted.</span> : null}
                </div>
              ) : null}
              <p className="muted small">Fingerprint detection is not a protection verdict. A successful no-match does not prove that no edge control exists.</p>
              {edgeDetectionRunId ? (
                <p><a href={buildDetailHref('run-detail', edgeDetectionRunId)}>Open test run {edgeDetectionRunId}</a></p>
              ) : null}
            </div>
          ) : null}
          <div className="target-run-selection" role="note">
            <span>Bounded run rule:</span>
            <strong>{getString(selectedPolicyCheck, ['name', 'check_id'], 'None selected')}</strong>
            {effectiveSelectedPolicyCheckId ? <span className="mono muted small">{effectiveSelectedPolicyCheckId}</span> : <a href="#target-group-rules">Choose a rule below</a>}
          </div>
          <DataTable
            columns={targetColumns}
            items={targets}
            className="tg-targets-table"
            getRowId={(item, index) => getString(item, ['id'], String(index))}
            empty={
              <EmptyState
                icon={Target}
                title="No targets declared yet"
                body="Declare a domain, IP, or cloud inventory selection to start validating this group. Nothing runs until a target is verified."
                actionLabel="Add target"
                onAction={() => openOnboardModal()}
              />
            }
          />
        </CardContent>
      </Card>

      {/* (6) Customer-runnable checks and schedule creation. */}
      <div id="target-group-rules">
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Rules &amp; schedule</CardTitle>
            <CardDescription>Select the exact customer-runnable rule used by per-target bounded runs and any new schedule. Nothing is selected implicitly.</CardDescription>
          </div>
          <Badge tone="info">{customerRunnableChecks.length} customer-runnable {customerRunnableChecks.length === 1 ? 'check' : 'checks'}</Badge>
        </CardHeader>
        <CardContent>
          <div className="safety-boundary" role="note" aria-label="Scheduling boundary">
            <CalendarClock size={18} aria-hidden="true" />
            <div>
              <strong>Authorized validation only</strong>
              <p>Schedules dispatch only the selected customer-runnable check under catalog limits, the declared schedule window, authorization gates, and the tenant kill switch. High-scale scenarios remain SOC-gated. They do not authorize or launch unmanaged DDoS traffic.</p>
            </div>
          </div>
          {data.loadErrors.testPolicies ? (
            <div className="form-banner error" role="alert">Scheduled policy data could not be hydrated — {data.loadErrors.testPolicies}</div>
          ) : null}
          <div className="rule-discovery">
            <label className="rule-search">
              <Search size={16} aria-hidden="true" />
              <span className="sr-only">Search customer-runnable rules</span>
              <input
                value={ruleQuery}
                onChange={(event) => { setRuleQuery(event.target.value); setRuleLimit(12); }}
                placeholder="Search rule name, family, or check ID"
              />
            </label>
            <span className="rule-results" role="status">
              Showing {Math.min(visibleRuleChecks.length, filteredRuleChecks.length)} of {filteredRuleChecks.length} matching rules
            </span>
          </div>
          <DataTable
            columns={checkColumns}
            items={visibleRuleChecks}
            className="rules-table"
            selectedId={effectiveSelectedPolicyCheckId}
            getRowId={(item, index) => getString(item, ['check_id', 'id'], String(index))}
            loadError={data.loadErrors.checks}
            empty={
              <EmptyState
                icon={ShieldHalf}
                title="No customer-runnable checks"
                body="The hydrated check catalog does not currently contain a check that can be scheduled by a customer. SOC-gated checks are intentionally excluded."
              />
            }
          />
          {filteredRuleChecks.length > visibleRuleChecks.length ? (
            <div className="rule-more">
              <span className="rule-results">{filteredRuleChecks.length - visibleRuleChecks.length} more matching rules are available.</span>
              <Button type="button" size="sm" variant="secondary" onClick={() => setRuleLimit((current) => current + 12)}>
                Show 12 more
              </Button>
            </div>
          ) : null}
          {!data.loadErrors.testPolicies && relatedPolicies.length === 0 ? (
            <p className="muted small">No existing schedule is present in hydrated policy data for this target group.</p>
          ) : null}

          {canCreateScheduledPolicy ? (
            <form className="product-form schedule-builder" onSubmit={(event) => void submitScheduledPolicy(event)}>
              <div className="schedule-builder-head full">
                <div>
                  <h3>Create a schedule</h3>
                  <p>Cadence repeats eligibility only. Every dispatch is still checked against ownership, LOA, catalog bounds, rate limits, safe window, and kill switch.</p>
                </div>
                <Badge tone={effectiveSelectedPolicyCheckId && effectiveSelectedPolicyTargetId ? 'success' : 'warn'}>
                  {effectiveSelectedPolicyCheckId && effectiveSelectedPolicyTargetId ? 'Check + target selected' : 'Select check + target'}
                </Badge>
              </div>
              <p className="schedule-selected full">
                Selected rule: <strong>{getString(selectedPolicyCheck, ['name', 'check_id'], 'None')}</strong>
                {effectiveSelectedPolicyCheckId ? <span className="mono muted"> · {effectiveSelectedPolicyCheckId}</span> : null}
              </p>
              <fieldset className="schedule-fields full" disabled={busy === 'create-test-policy'}>
                <legend className="sr-only">Scheduled policy settings</legend>
                <label>
                  <span>Exact target</span>
                  <select
                    name="target_id"
                    value={effectiveSelectedPolicyTargetId}
                    onChange={(event) => setSelectedPolicyTargetId(event.target.value)}
                    disabled={!selectedPolicyCheck || compatiblePolicyTargets.length === 0}
                    required
                  >
                    <option value="" disabled>
                      {selectedPolicyCheck && compatiblePolicyTargets.length === 0 ? 'No compatible targets' : 'Choose target'}
                    </option>
                    {compatiblePolicyTargets.map((target) => {
                      const targetId = getString(target, ['id'], '');
                      const state = humanizeLabel(targetVerificationState(target));
                      const kind = humanizeLabel(effectivePolicyTargetKind(target));
                      return <option key={targetId} value={targetId}>{getString(target, ['value'], targetId)} · {kind} · {state}</option>;
                    })}
                  </select>
                </label>
                <label>
                  <span>Cadence</span>
                  <select name="cadence" defaultValue="weekly" required>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </label>
                <label>
                  <span>Expected verdict</span>
                  <select name="expected_verdict" defaultValue="pass" required>
                    <option value="pass">Pass</option>
                    <option value="warn">Warn</option>
                    <option value="manual_review">Manual review</option>
                  </select>
                </label>
                <label>
                  <span>Safe window day</span>
                  <select name="safe_window_day" defaultValue="" required>
                    <option value="" disabled>Choose day</option>
                    <option value="Mon">Monday</option>
                    <option value="Tue">Tuesday</option>
                    <option value="Wed">Wednesday</option>
                    <option value="Thu">Thursday</option>
                    <option value="Fri">Friday</option>
                    <option value="Sat">Saturday</option>
                    <option value="Sun">Sunday</option>
                  </select>
                </label>
                <label>
                  <span>Safe window start</span>
                  <input name="safe_window_start" type="time" required />
                </label>
                <label>
                  <span>Safe window end</span>
                  <input name="safe_window_end" type="time" required />
                </label>
                <label>
                  <span>Window timezone</span>
                  <input
                    name="safe_window_timezone"
                    defaultValue={getString(entity, ['timezone'], getString(data.tenant, ['timezone'], 'UTC'))}
                    placeholder="UTC"
                    autoComplete="off"
                    spellCheck={false}
                    required
                  />
                </label>
              </fieldset>
              {selectedPolicyCheck && compatiblePolicyTargets.length === 0 ? (
                <p className="form-banner neutral full" role="status">
                  This group has no exact target compatible with {getString(selectedPolicyCheck, ['name', 'check_id'], effectiveSelectedPolicyCheckId)}. This check supports {policySupportedTargetKinds(selectedPolicyCheck).join(', ') || 'any declared target kind'}; choose another check or add a compatible target.
                </p>
              ) : null}
              <div className="form-actions full">
                <Button
                  type="submit"
                  loading={busy === 'create-test-policy'}
                  disabled={!effectiveSelectedPolicyCheckId || !effectiveSelectedPolicyTargetId || customerRunnableChecks.length === 0}
                >
                  Create schedule
                </Button>
                <AnchorButton size="sm" variant="secondary" href="#test-policies">Open all policies</AnchorButton>
              </div>
            </form>
          ) : (
            <div className="schedule-role-note" role="note">
              <strong>Read-only schedule view</strong>
              <span>An organization owner, administrator, or engineer can create validation policies. SOC-gated scenarios continue through the governed SOC workflow.</span>
            </div>
          )}
        </CardContent>
      </Card>
      </div>

      {/* (7) Findings on this group — Target column deep-links target detail. */}
      <Card>
        <CardHeader><CardTitle>Findings on this group</CardTitle></CardHeader>
        <CardContent>
          <DataTable columns={findingColumns} items={relatedFindings} empty={emptyStateFromApi({ icon: TriangleAlert, meta: groupMeta ? { empty_reason: getString(groupMeta, ['findings_empty_reason'], '') } : null })} />
        </CardContent>
      </Card>

      {/* (7) Recent runs — 6-column run history. */}
      <Card>
        <CardHeader><CardTitle>Recent runs</CardTitle></CardHeader>
        <CardContent>
          <DataTable columns={runColumns} items={relatedRuns} empty={emptyStateFromApi({ icon: Activity, meta: groupMeta ? { empty_reason: getString(groupMeta, ['runs_empty_reason'], '') } : null, actionHref: '#runs', actionLabel: 'Open test runs' })} />
        </CardContent>
      </Card>

      {inventoryProvider ? (
        <DetailModal title={`Provider inventory · ${inventoryProvider}`} onClose={() => setInventoryProvider(null)} error={error}>
            <div className="inv-body">
              <DataTable
                columns={[
                  { key: 'select', label: 'Select', render: (item) => {
                    const id = getString(item, ['id', 'value'], '');
                    const label = getString(item, ['value', 'name'], id);
                    return (
                      <input
                        type="checkbox"
                        checked={selectedInventory.has(id)}
                        aria-label={`Select ${label}`}
                        onChange={(event) => {
                      setSelectedInventory((current) => {
                        const next = new Set(current);
                        if (event.target.checked) next.add(id);
                        else next.delete(id);
                        return next;
                      });
                    }}
                      />
                    );
                  } },
                  { key: 'kind', label: 'Kind', render: (item) => getString(item, ['kind'], '—') },
                  { key: 'value', label: 'Value', render: (item) => getString(item, ['value', 'name'], '—') }
                ]}
                items={inventoryRows}
                empty={emptyStateFromApi({ icon: Bot, meta: inventoryMeta })}
              />
              <div className="row-actions">
                <Button size="sm" disabled={selectedInventory.size === 0 || busy !== ''} loading={busy.startsWith('import-')} onClick={() => void importInventory()}>Import selected</Button>
              </div>
            </div>
        </DetailModal>
      ) : null}

      {showOnboardModal ? (
        <DetailModal title="Onboard a target" onClose={() => setShowOnboardModal(false)} error={onboardTab === 'fqdn' ? dnsError || error : error}>
          <Tabs
            value={onboardTab}
            options={ONBOARD_TAB_OPTIONS}
            onChange={(value) => setOnboardTab(value)}
            ariaLabel="Target onboarding method"
          />
          {onboardTab === 'fqdn' ? (
            <div className="stack-tight">
              <p className="muted">Prove you control the domain by publishing a one-time TXT record. Verification is required before any probe runs.</p>
              <form className="product-form" onSubmit={(event) => void submitFqdnTarget(event)}>
                <label className="full"><span>Domain</span><input name="value" className="mono" placeholder="origin.example.com" required /></label>
                <label>
                  <span>Expected behavior</span>
                  <select name="expected_behavior" defaultValue="block_at_edge">
                    <option value="block_at_edge">block_at_edge</option>
                    <option value="absorb_at_origin">absorb_at_origin</option>
                    <option value="rate_shape">rate_shape</option>
                  </select>
                </label>
                <label>
                  <span>Bind to agent (optional)</span>
                  <select name="agent_id" defaultValue="">
                    <option value="">any agent in {getString(entity, ['environment_id'], 'this environment')}</option>
                    {agents.map((agent) => {
                      const optId = getString(agent, ['id'], '');
                      return <option key={optId} value={optId}>{optId} · {getString(agent, ['hostname', 'name'], optId)}</option>;
                    })}
                  </select>
                </label>
                <div className="form-actions full">
                  <Button type="submit" loading={busy === 'add-target-fqdn' || busy === `dns-issue-${entityId}`}>Add &amp; issue target-bound challenge</Button>
                </div>
              </form>
              <div className="dns-challenge">
                <div className="dns-head">
                  <span className="eyebrow">Challenge state</span>
                  <span className="spacer" />
                  <VerifyChip
                    state={displayedDnsChipState}
                    provenance={dnsProvenance}
                  />
                </div>
                <div className="dns-fields">
                  <div className="dns-field"><span className="dns-key">Target</span><span className="dns-val mono">{getString(selectedDnsTarget, ['value'], selectedDnsTargetId || '—')}</span></div>
                  <div className="dns-field"><span className="dns-key">Name</span><span className="dns-val mono">{getString(activeChallenge, ['record_name', 'name'], '—')}</span></div>
                  <div className="dns-field"><span className="dns-key">Value</span><span className="dns-val mono">{getString(activeChallenge, ['record_value', 'value'], '—')}</span></div>
                  <div className="dns-field"><span className="dns-key">TTL</span><span className="dns-val mono">{getString(activeChallenge, ['ttl_seconds', 'ttl'], '—')}</span></div>
                </div>
                <div className="dns-footer row-actions">
                  <Button size="sm" variant="ghost" loading={busy === `dns-verify-${entityId}`} disabled={!activeChallengeId} onClick={() => void verifyDnsChallenge(activeChallengeId)}>Check now</Button>
                  {dnsVerifyResult?.verified === false ? <span className="muted small">Last checked {formatDate(dnsVerifyResult.checked_at ?? dnsVerifyResult.updated_at)}</span> : null}
                </div>
              </div>
            </div>
          ) : null}
          {onboardTab === 'ip' ? (
            <div className="stack-tight">
              <p className="muted">You cannot prove control of an IP with DNS. Install an agent inside that instance. When the agent registers, its outbound call reveals the public IP and binds the target to a verified agent.</p>
              <form className="product-form" onSubmit={submitIpTarget}>
                <label><span>IP address</span><input name="value" className="mono" placeholder="203.0.113.10" required /></label>
                <label><span>Port (optional)</span><input name="port" className="mono" inputMode="numeric" pattern="[0-9]*" placeholder="443" aria-describedby="ip-port-storage-note" /></label>
                <label>
                  <span>Expected behavior</span>
                  <select name="expected_behavior" defaultValue="absorb_at_origin">
                    <option value="absorb_at_origin">absorb_at_origin</option>
                    <option value="block_at_edge">block_at_edge</option>
                    <option value="rate_shape">rate_shape</option>
                  </select>
                </label>
                <label className="full"><span>Notes (optional)</span><input name="notes" placeholder="Origin behind CDN · single-AZ · IPv4 only" /></label>
                <p id="ip-port-storage-note" className="muted small full">The target remains a canonical bare IP. Port is retained separately as target metadata.</p>
                <div className="form-actions full">
                  <Button type="submit" loading={busy === 'add-target-ip'}>Register &amp; wait for agent</Button>
                  <AnchorButton size="sm" variant="secondary" href="#agents">Open agent install</AnchorButton>
                </div>
              </form>
              <div className="dns-challenge">
                <div className="dns-head">
                  <span className="eyebrow">Agent callback</span>
                  <span className="spacer" />
                  <VerifyChip state="awaiting_heartbeat" provenance="Awaiting agent heartbeat from this IP" />
                </div>
                <ol className="muted small">
                  <li>Install an agent on any host that can reach the target IP (container image, Helm chart, or native package from the Agents screen).</li>
                  <li>Bind it at deploy time with <span className="mono">ASTRANULL_TARGET_GROUP={entityId}</span>. No inbound port needed.</li>
                  <li>When the agent heartbeats, AstraNull records its <span className="mono">discovered_public_ip</span> and matches it against the IP you registered.</li>
                  <li>Verified after a probe + agent correlation on the same nonce.</li>
                </ol>
              </div>
            </div>
          ) : null}
          {onboardTab === 'cloud' ? (
            <div className="stack-tight">
              <p className="muted">Connect a DNS provider once, then select exact zones for this target group. A current vault-backed server poll can verify the imported zone from durable provider API evidence; manual or prefetched metadata remains pending and still requires DNS proof.</p>
              {connectors.length === 0 ? (
                <EmptyState
                  icon={Bot}
                  title="No DNS provider connected"
                  body={getString(connectorsMeta, ['empty_reason'], 'Add a provider integration to load bounded DNS zone inventory.')}
                  actionLabel="Add provider"
                  actionHref="#integrations"
                />
              ) : null}
              <div className="provider-grid">
                {connectors.map((connector) => {
                  const connectorId = getString(connector, ['id'], '');
                  const providerLabel = getString(connector, ['name', 'provider'], connectorId);
                  const scope = getString(connector, ['scope', 'config_json.scope'], getString(connector.config_json as DataItem | undefined, ['scope'], '—'));
                  return (
                    <div className="provider-card" key={connectorId}>
                      <div className="pc-head">
                        <span className="pc-mark">{providerLabel.slice(0, 2).toUpperCase()}</span>
                        <h3>{providerLabel}</h3>
                      </div>
                      <p>Scope required: <span className="mono">{scope}</span></p>
                      <p className="muted small">Status: {getString(connector, ['status', 'state'], 'unknown')}</p>
                      <div className="pc-actions">
                        <Button size="sm" variant="ghost" loading={busy === `inventory-${connectorId}`} onClick={() => void openInventory(connectorId)}>Open inventory</Button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : null}
        </DetailModal>
      ) : null}

      {showLoaModal ? (
        <DetailModal title={`Sign LOA · ${getString(entity, ['name'], entityId)}`} onClose={() => setShowLoaModal(false)} error={error}>
            <form className="loa-body product-form" onSubmit={(event) => void submitLoa(event)}>
              <div className="loa-doc">
                <h4>Authorization artifact</h4>
                <dl className="loa-meta">
                  <dt>Customer</dt><dd>{getString(data.tenant, ['name', 'display_name'], session.tenant_id ?? '—')}</dd>
                  <dt>Tenant</dt><dd className="mono">{session.tenant_id ?? getString(data.state, ['tenant_id'], '—')}</dd>
                  <dt>Target group</dt><dd>{getString(entity, ['name'], entityId)}</dd>
                  <dt>Eligible scope</dt><dd>{loaScopeTargetCount} agent-verified target{loaScopeTargetCount === 1 ? '' : 's'}</dd>
                </dl>
              </div>

              <div className="full">
                <strong>Authorized target scope</strong>
                <p className="muted small">Select every target you intend to authorize; none are selected automatically. Only agent-verified or user-confirmed targets are eligible. The server records the submitted IDs as the custody-bound scope snapshot.</p>
                <div className="loa-scope-list">
                  {targets.map((target) => {
                    const id = getString(target, ['id'], '');
                    const state = targetVerificationState(target);
                    const eligible = isLoaScopeEligible(state);
                    return (
                      <label className="loa-scope-row" data-eligible={String(eligible)} key={id}>
                        <input type="checkbox" name="scope_ack" value={id} disabled={!eligible} />
                        <span><strong className="mono">{targetDisplayValue(target)}</strong><span className="muted small mono"> · {id}</span></span>
                        <Badge tone={eligible ? 'success' : 'muted'}>{humanizeLabel(state)}</Badge>
                      </label>
                    );
                  })}
                </div>
                {loaScopeTargetCount === 0 ? <div className="form-banner error" role="alert">No target is eligible for LOA scope yet. Complete agent verification first.</div> : null}
              </div>

              <label className="checkrow full"><input type="checkbox" name="attested" required /><span>I attest that every selected target is owned or explicitly authorized for AstraNull validation.</span></label>
              <label><span>Signer name</span><input name="signer_name" autoComplete="name" required /></label>
              <label><span>Signer title</span><input name="signer_title" required /></label>
              <label className="full"><span>Signer email</span><input name="signer_email" type="email" autoComplete="email" required /></label>

              <div className="loa-contact-grid full">
                <label><span>Emergency contact name</span><input name="emergency_name" required /></label>
                <label><span>Emergency contact role</span><input name="emergency_role" required /></label>
                <label><span>Emergency contact phone</span><input name="emergency_phone" type="tel" autoComplete="tel" required /></label>
                <label><span>Emergency contact email</span><input name="emergency_email" type="email" autoComplete="email" required /></label>
              </div>

              <p className="custody-note full">Signing time is assigned by the server. The response must include a signed LOA, custody artifact ID, SHA-256 custody digest, and audit entry before this UI reports success.</p>
              <div className="form-actions full">
                <Button type="submit" loading={busy === `loa-${entityId}`} disabled={loaScopeTargetCount === 0}>Sign &amp; seal LOA</Button>
              </div>
            </form>
        </DetailModal>
      ) : null}

    </div>
  );
}
