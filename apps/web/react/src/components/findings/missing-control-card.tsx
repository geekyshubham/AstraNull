import { useId, useMemo, useState } from 'react';
import { Badge } from '../ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Tabs } from '../ui/tabs';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { ProviderFixPack } from './provider-fix-pack';
import './missing-control-card.css';

export type ProviderGuidance = {
  provider: string;
  provider_label: string;
  source: 'detected_edge' | 'generic' | 'catalog';
  detected_as: string | null;
  detection_layer: string | null;
  control: string;
  steps: string[];
  docs: string[];
};

export type MissingControl = {
  control_family: string;
  control_label: string;
  layer: string;
  status: 'missing' | 'not_established';
  headline: string;
  missing_control: string;
  required_policy: string;
  observed: string | null;
  provider_guidance: ProviderGuidance[];
  other_provider_guidance: ProviderGuidance[];
  detected_without_guidance: string[];
};

const LAYER_LABELS: Record<string, string> = {
  network: 'Network firewall layer',
  edge_waf: 'Edge WAF layer',
  edge_cdn: 'Edge CDN layer',
  dns: 'DNS layer',
  origin: 'Origin layer',
  operations: 'Operations',
};

const DETECTION_LAYER_LABELS: Record<string, string> = {
  waf: 'WAF',
  cdn: 'CDN',
  cloud: 'cloud hosting',
};

function isGuidance(value: unknown): value is ProviderGuidance {
  if (!value || typeof value !== 'object') return false;
  const row = value as DataItem;
  return typeof row.provider === 'string' && typeof row.control === 'string'
    && Array.isArray(row.steps) && Array.isArray(row.docs);
}

function normalizeGuidance(row: ProviderGuidance): ProviderGuidance {
  return {
    ...row,
    provider_label: typeof row.provider_label === 'string' ? row.provider_label : row.provider,
    steps: row.steps.filter((step): step is string => typeof step === 'string' && step.trim() !== ''),
    docs: [...new Set(row.docs.filter((doc): doc is string => typeof doc === 'string'))],
  };
}

export function readMissingControl(finding: DataItem | null | undefined): MissingControl | null {
  const value = finding?.missing_control;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as DataItem;
  if (typeof row.missing_control !== 'string' || typeof row.required_policy !== 'string' || typeof row.control_label !== 'string') return null;
  return {
    control_family: String(row.control_family ?? ''),
    control_label: row.control_label,
    layer: String(row.layer ?? ''),
    status: row.status === 'missing' ? 'missing' : 'not_established',
    headline: typeof row.headline === 'string' ? row.headline : `Missing control: ${row.control_label}`,
    missing_control: row.missing_control,
    required_policy: row.required_policy,
    observed: typeof row.observed === 'string' && row.observed.trim() ? row.observed : null,
    provider_guidance: Array.isArray(row.provider_guidance) ? row.provider_guidance.filter(isGuidance).map(normalizeGuidance) : [],
    other_provider_guidance: Array.isArray(row.other_provider_guidance) ? row.other_provider_guidance.filter(isGuidance).map(normalizeGuidance) : [],
    detected_without_guidance: Array.isArray(row.detected_without_guidance)
      ? row.detected_without_guidance.filter((item): item is string => typeof item === 'string')
      : [],
  };
}

function safeDocUrl(value: unknown) {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url.toString() : null;
  } catch {
    return null;
  }
}

function docLabel(url: string) {
  const parsed = new URL(url);
  return `${parsed.hostname}${parsed.pathname.length > 1 ? parsed.pathname : ''}`;
}

function sourceLabel(row: ProviderGuidance) {
  if (row.source === 'detected_edge') {
    const layer = row.detection_layer ? DETECTION_LAYER_LABELS[row.detection_layer] ?? row.detection_layer : 'edge';
    return `Detected as your ${layer} provider${row.detected_as && row.detected_as.toLowerCase() !== row.provider ? ` (${row.detected_as})` : ''}`;
  }
  if (row.source === 'generic') return 'Vendor-neutral steps';
  return 'Not detected on this target';
}

function StepText({ text }: { text: string }) {
  const parts = text.split('`');
  if (parts.length < 3 || parts.length % 2 === 0) return <>{text}</>;
  return <>{parts.map((part, index) => (index % 2 === 1 ? <code key={index}>{part}</code> : <span key={index}>{part}</span>))}</>;
}

function GuidancePanel({ row, id, labelledBy }: { row: ProviderGuidance; id: string; labelledBy?: string }) {
  const docs = [...new Set(row.docs.map(safeDocUrl).filter((url): url is string => Boolean(url)))];
  return (
    <div className="missing-control-guidance" id={id} role={labelledBy ? 'tabpanel' : undefined} aria-labelledby={labelledBy} tabIndex={labelledBy ? 0 : undefined}>
      <p className="missing-control-guidance-source muted small">{sourceLabel(row)}</p>
      <p className="missing-control-guidance-control"><strong>{row.control}</strong></p>
      <ol className="missing-control-steps">
        {row.steps.map((step, index) => <li key={`${row.provider}-${index}`}><StepText text={step} /></li>)}
      </ol>
      {docs.length ? (
        <ul className="missing-control-docs" aria-label={`${row.provider_label} documentation`}>
          {docs.map((url) => (
            <li key={url}>
              <a href={url} target="_blank" rel="noopener noreferrer">
                {docLabel(url)}
                <span className="sr-only"> (opens in a new tab)</span>
              </a>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

export function MissingControlCard({ finding, config, session }: { finding: DataItem | null | undefined; config?: PortalConfig; session?: Session }) {
  const control = useMemo(() => readMissingControl(finding), [finding]);
  const baseId = useId();
  const guidance = control?.provider_guidance ?? [];
  const [selected, setSelected] = useState('');
  if (!control) return null;
  const active = guidance.find((row) => row.provider === selected) ?? guidance[0] ?? null;
  const panelId = (provider: string) => `${baseId}-panel-${provider}`;
  const tabId = (provider: string) => `${baseId}-tab-${provider}`;
  const missing = control.status === 'missing';
  return (
    <Card className="missing-control-card" role="region" aria-labelledby={`${baseId}-title`}>
      <CardHeader>
        <div>
          <CardTitle id={`${baseId}-title`}>{missing ? 'What is missing in your environment' : 'Control this check validates'}</CardTitle>
          <CardDescription>{control.headline}</CardDescription>
        </div>
        <div className="missing-control-badges">
          <Badge tone={missing ? 'danger' : 'muted'}>{missing ? 'Control missing' : 'Not established'}</Badge>
          <Badge tone="muted">{LAYER_LABELS[control.layer] ?? control.layer}</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <dl className="missing-control-facts">
          <div className="missing-control-fact missing-control-fact--primary">
            <dt>What is missing</dt>
            <dd>{control.missing_control}</dd>
          </div>
          {control.observed ? (
            <div className="missing-control-fact">
              <dt>What AstraNull observed</dt>
              <dd>{control.observed}</dd>
            </div>
          ) : null}
          <div className="missing-control-fact">
            <dt>Policy you need</dt>
            <dd>{control.required_policy}</dd>
          </div>
        </dl>
        {guidance.length ? (
          <section className="missing-control-providers" aria-labelledby={`${baseId}-providers`}>
            <h3 id={`${baseId}-providers`}>How to add it on your provider</h3>
            {guidance.length > 1 ? (
              <Tabs
                value={active?.provider ?? ''}
                options={guidance.map((row) => ({ id: row.provider, label: row.source === 'detected_edge' ? `${row.provider_label} · detected` : row.provider_label }))}
                onChange={setSelected}
                ariaLabel="Provider remediation guidance"
                getPanelId={panelId}
                getTabId={tabId}
              />
            ) : null}
            {active ? (
              <>
                <GuidancePanel row={active} id={panelId(active.provider)} labelledBy={guidance.length > 1 ? tabId(active.provider) : undefined} />
                {config && session && typeof finding?.id === 'string' ? <ProviderFixPack config={config} session={session} scope={{ findingId: finding.id, provider: active.provider, controlFamily: control.control_family, docs: active.docs }} /> : null}
              </>
            ) : null}
            {control.detected_without_guidance.length ? (
              <p className="muted small">
                Also detected: {control.detected_without_guidance.join(', ')}. AstraNull has no provider-specific guide for it yet, so use the vendor-neutral steps with that vendor&apos;s documentation.
              </p>
            ) : null}
          </section>
        ) : null}
        {control.other_provider_guidance.length ? (
          <details className="missing-control-other">
            <summary>Guidance for other providers</summary>
            <div className="missing-control-other-list">
              {control.other_provider_guidance.map((row) => (
                <section key={row.provider} aria-labelledby={`${baseId}-other-${row.provider}`}>
                  <h4 id={`${baseId}-other-${row.provider}`}>{row.provider_label}</h4>
                  <GuidancePanel row={row} id={`${baseId}-other-panel-${row.provider}`} />
                  {config && session && typeof finding?.id === 'string' ? <ProviderFixPack config={config} session={session} scope={{ findingId: finding.id, provider: row.provider, controlFamily: control.control_family, docs: row.docs }} /> : null}
                </section>
              ))}
            </div>
          </details>
        ) : null}
        <p className="missing-control-note muted small">
          Provider guidance follows the provider detected for this target. It is advice for that provider, not proof of which control failed; confirm the change, then retest this finding.
        </p>
      </CardContent>
    </Card>
  );
}
