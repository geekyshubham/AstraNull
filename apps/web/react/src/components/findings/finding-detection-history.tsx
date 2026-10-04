import { useEffect, useMemo, useState } from 'react';
import { Check, Copy, ExternalLink, Eye, History, ShieldAlert } from 'lucide-react';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { formatDate, formatSeverityLabel } from '../../lib/utils';
import { buildDetailHref } from '../../lib/route-params';
import { requestJson } from '../../lib/api';
import { findingRuleKey, parseFindingTimestamp } from '../../lib/findings-helpers';
import { plainFindingTitle } from '../../lib/plain-language.mjs';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import './finding-detection-history.css';

function formatLabel(value: string, fallback = 'Not reported') {
  if (!value) return fallback;
  return value.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function severityTone(severity: string) {
  const key = severity.toLowerCase();
  if (['critical', 'high', 's1', 's2'].includes(key)) return 'danger' as const;
  if (['medium', 's3'].includes(key)) return 'warn' as const;
  return 'muted' as const;
}

export function FindingDetectionHistory({
  entity,
  entityId,
  targetId,
  targetDisplay,
  checkId,
  checks = [],
  dataFindings = [],
  config,
  session,
  onInspectFinding,
  onInspectRun,
}: {
  entity: DataItem;
  entityId: string;
  targetId: string;
  targetDisplay: string;
  checkId: string;
  checks?: DataItem[];
  dataFindings?: DataItem[];
  config: PortalConfig;
  session: Session;
  onInspectFinding: (finding: DataItem) => void;
  onInspectRun?: (runId: string, checkId: string) => void;
}) {
  const [fetchedDetections, setFetchedDetections] = useState<DataItem[]>([]);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    if (!targetId) return;
    let active = true;
    requestJson(config, session, `/v1/findings?target_id=${encodeURIComponent(targetId)}`)
      .then((payload) => {
        if (!active) return;
        const items = Array.isArray(payload)
          ? payload
          : Array.isArray((payload as { items?: DataItem[] })?.items)
          ? (payload as { items: DataItem[] }).items
          : [];
        setFetchedDetections(items);
      })
      .catch(() => {
        // Fallback gracefully to dataFindings if API request fails
      });
    return () => {
      active = false;
    };
  }, [config, session, targetId]);

  const allDetections = useMemo(() => {
    const ruleKey = findingRuleKey(entity);
    const pool = new Map<string, DataItem>();

    // Seed with current entity
    if (entity && entityId) {
      pool.set(entityId, entity);
    }

    // Merge from dataFindings
    (dataFindings || []).forEach((f) => {
      const id = getString(f, ['id'], '');
      if (id) pool.set(id, f);
    });

    // Merge from fetchedDetections
    (fetchedDetections || []).forEach((f) => {
      const id = getString(f, ['id'], '');
      if (id) pool.set(id, f);
    });

    // Filter to those that match the current finding's scope:
    // Same target AND (same check OR same rule title/key)
    const matching = [...pool.values()].filter((item) => {
      const itemTargetId = getString(item, ['target_id'], '');
      if (targetId && itemTargetId && itemTargetId !== targetId) return false;
      const itemCheckId = getString(item, ['check_id', 'check'], '');
      const itemRuleKey = findingRuleKey(item);
      const isSameCheck = Boolean(checkId && itemCheckId === checkId);
      const isSameRule = Boolean(ruleKey && itemRuleKey === ruleKey);
      return isSameCheck || isSameRule || getString(item, ['id'], '') === entityId;
    });

    // Sort newest to oldest
    matching.sort((a, b) => {
      const timeA = parseFindingTimestamp(a.opened_at ?? a.created_at) ?? 0;
      const timeB = parseFindingTimestamp(b.opened_at ?? b.created_at) ?? 0;
      return timeB - timeA || String(b.id ?? '').localeCompare(String(a.id ?? ''));
    });

    return matching;
  }, [entity, entityId, targetId, checkId, dataFindings, fetchedDetections]);

  const newest = allDetections[0] ?? entity;
  const oldest = allDetections[allDetections.length - 1] ?? entity;
  const detectionCount = allDetections.length;
  const isRecurring = detectionCount > 1;

  function copyFindingId(id: string) {
    if (!navigator?.clipboard?.writeText) return;
    navigator.clipboard.writeText(id).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId((curr) => (curr === id ? null : curr)), 1800);
    });
  }

  return (
    <Card className="finding-history-card" data-od-id="finding-detection-history">
      <CardHeader>
        <div className="finding-history-head">
          <div className="finding-history-title-wrap">
            <History size={18} className="finding-history-icon" aria-hidden="true" />
            <div>
              <CardTitle id="finding-detection-history-title">Detection history</CardTitle>
              <CardDescription>
                Chronological record of outside-in probe detections for this condition on{' '}
                <strong>{targetDisplay || 'this target'}</strong>.
              </CardDescription>
            </div>
          </div>
          <Badge tone={isRecurring ? 'warn' : 'default'}>
            {detectionCount} recorded detection{detectionCount === 1 ? '' : 's'}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <dl className="finding-history-metrics">
          <div className="finding-history-metric">
            <dt>Total detections</dt>
            <dd>
              <strong>{detectionCount}</strong>
              <small>{isRecurring ? 'Recurring across scans' : 'Single observation'}</small>
            </dd>
          </div>
          <div className="finding-history-metric">
            <dt>First detected</dt>
            <dd>
              <strong>{formatDate(oldest.opened_at ?? oldest.created_at)}</strong>
              <small>Initial observation</small>
            </dd>
          </div>
          <div className="finding-history-metric">
            <dt>Latest detected</dt>
            <dd>
              <strong>{formatDate(newest.opened_at ?? newest.created_at)}</strong>
              <small>Most recent confirmation</small>
            </dd>
          </div>
          <div className="finding-history-metric">
            <dt>Current lifecycle</dt>
            <dd>
              <Badge tone={severityTone(getString(entity, ['severity'], 'medium'))}>
                {formatLabel(getString(entity, ['status', 'state'], 'open'))}
              </Badge>
              <small>{formatSeverityLabel(getString(entity, ['severity'], 'medium'))}</small>
            </dd>
          </div>
        </dl>

        <div className="finding-history-timeline-section">
          <h4 className="finding-history-timeline-title">Detection events ({detectionCount})</h4>
          <div className="finding-history-timeline" role="list">
            {allDetections.map((detection, index) => {
              const detId = getString(detection, ['id'], '');
              const runId = getString(detection, ['test_run_id', 'testRunId'], '');
              const isCurrent = detId === entityId;
              const isLatest = index === 0;
              const isInitial = index === allDetections.length - 1 && isRecurring;
              const openedDate = detection.opened_at ?? detection.created_at;
              const detSeverity = getString(detection, ['severity'], 'medium');
              const detTitle = plainFindingTitle(detection, [], checks);

              return (
                <div
                  key={detId || index}
                  className={`finding-history-entry ${isCurrent ? 'is-current' : ''}`}
                  role="listitem"
                >
                  <div className="finding-history-entry-marker">
                    <span className={`finding-history-dot ${isLatest ? 'is-latest' : ''}`} />
                    {index < allDetections.length - 1 ? <span className="finding-history-line" /> : null}
                  </div>
                  <div className="finding-history-entry-content">
                    <div className="finding-history-entry-head">
                      <div className="finding-history-entry-chips">
                        <span className="finding-history-timestamp">{formatDate(openedDate)}</span>
                        {isLatest ? (
                          <Badge tone="warn">Latest detection</Badge>
                        ) : isInitial ? (
                          <Badge tone="default">Initial detection</Badge>
                        ) : (
                          <Badge tone="default">Detection #{allDetections.length - index}</Badge>
                        )}
                        <Badge tone={severityTone(detSeverity)}>{formatSeverityLabel(detSeverity)}</Badge>
                        {isCurrent ? <span className="finding-current-pill">Current record</span> : null}
                      </div>
                      <div className="finding-history-entry-actions">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => onInspectFinding(detection)}
                          aria-label={`View evidence for detection ${detId}`}
                        >
                          <Eye size={13} aria-hidden="true" /> View evidence
                        </Button>
                        {!isCurrent ? (
                          <a
                            href={buildDetailHref('finding-detail', detId)}
                            className="btn btn-secondary btn-sm"
                            aria-label={`Open finding detail page for ${detId}`}
                          >
                            <ExternalLink size={12} aria-hidden="true" /> Open record
                          </a>
                        ) : null}
                      </div>
                    </div>

                    <div className="finding-history-entry-details">
                      <div className="finding-history-identity">
                        <span className="finding-history-label">Finding ID:</span>
                        <code className="mono">{detId}</code>
                        <button
                          type="button"
                          className="finding-history-copy-btn"
                          onClick={() => copyFindingId(detId)}
                          aria-label={`Copy finding ID ${detId}`}
                        >
                          {copiedId === detId ? (
                            <Check size={12} className="text-success" aria-hidden="true" />
                          ) : (
                            <Copy size={12} aria-hidden="true" />
                          )}
                        </button>
                      </div>

                      {runId ? (
                        <div className="finding-history-run">
                          <span className="finding-history-label">Run:</span>
                          <code className="mono">{runId}</code>
                          {onInspectRun && checkId ? (
                            <button
                              type="button"
                              className="td-inline-link finding-history-run-link"
                              onClick={() => onInspectRun(runId, checkId)}
                            >
                              Inspect run
                            </button>
                          ) : null}
                        </div>
                      ) : null}
                    </div>

                    {detTitle ? <p className="finding-history-verdict-text">{detTitle}</p> : null}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
