import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { findingSlaDueAt } from '../../apps/web/react/src/lib/findings-helpers.ts';
import {
  AUDIT_ACTION_LABELS,
  AUDIT_ACTIONS,
  formatAuditAction,
  formatDate,
  formatSeverityLabel,
  formatTargetKind,
  formatTimestamp,
  RESOURCE_TYPE_LABELS,
} from '../../apps/web/react/src/lib/utils.ts';

const DATE_OPTIONS = {
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
};

describe('portal date formatting', () => {
  it('formats computed numeric SLA timestamps instead of rendering epoch milliseconds', () => {
    const dueAt = findingSlaDueAt({
      status: 'open',
      severity: 'medium',
      created_at: '2026-09-02T20:02:59.917Z',
    });
    assert.equal(typeof dueAt, 'number');
    assert.equal(formatDate(dueAt), new Date(dueAt).toLocaleString(undefined, DATE_OPTIONS));
    assert.doesNotMatch(formatDate(dueAt), /^\d{13}$/);
  });

  it('preserves ISO timestamp and invalid-value behavior', () => {
    const iso = '2026-09-02T20:02:59.917Z';
    assert.equal(formatDate(iso), new Date(iso).toLocaleString(undefined, DATE_OPTIONS));
    assert.equal(formatDate('not-a-date'), 'not-a-date');
    assert.equal(formatDate(null), 'Not recorded');
  });
});

describe('portal full timestamps', () => {
  it('includes the year and zone so audit records are unambiguous', () => {
    const iso = '2026-09-02T20:02:59.917Z';
    const text = formatTimestamp(iso);
    assert.match(text, /\b2026\b/);
    assert.equal(
      text,
      new Date(iso).toLocaleString(undefined, { ...DATE_OPTIONS, year: 'numeric', timeZoneName: 'short' }),
    );
    assert.match(formatTimestamp(Date.parse(iso)), /\d{4}/);
  });

  it('shares the null and invalid handling of formatDate', () => {
    assert.equal(formatTimestamp(null), 'Not recorded');
    assert.equal(formatTimestamp(''), 'Not recorded');
    assert.equal(formatTimestamp('not-a-date'), 'not-a-date');
  });
});

describe('portal audit action derivation', () => {
  it('derives finding.updated labels from the recorded status', () => {
    assert.equal(formatAuditAction('finding.updated', 'x', { status: 'accepted_risk' }), 'Risk accepted');
    assert.equal(formatAuditAction('finding.updated', 'x', { status: 'closed' }), 'Finding closed');
    assert.equal(formatAuditAction('finding.updated', 'x', { status: 'resolved' }), 'Finding closed');
    assert.equal(formatAuditAction('finding.updated', 'x', { status: 'false_positive' }), 'Marked false positive');
    assert.equal(formatAuditAction('finding.updated', 'x', { status: 'open' }), 'Finding reopened');
    assert.equal(formatAuditAction('finding.updated', 'x', { status: 'in_progress' }), 'Finding in progress');
  });

  it('labels owner changes and falls back to a generic update', () => {
    assert.equal(formatAuditAction('finding.updated', 'x', { assignee: 'usr_1' }), 'Owner assigned');
    assert.equal(formatAuditAction('finding.updated', 'x', { assignee: null }), 'Owner assigned');
    assert.equal(formatAuditAction('finding.updated', 'x', { notes: 'n' }), 'Finding updated');
    assert.equal(formatAuditAction('finding.updated'), 'Finding updated');
    assert.equal(formatAuditAction('finding.updated', 'x', 'status=closed'), 'Finding updated');
  });

  it('labels finding creation and exports the action catalog for filters', () => {
    assert.equal(formatAuditAction('finding.created'), 'Finding opened');
    assert.equal(AUDIT_ACTION_LABELS['finding.created'], 'Finding opened');
    assert.deepEqual(AUDIT_ACTIONS.find((entry) => entry.value === 'finding.created'), {
      value: 'finding.created',
      label: 'Finding opened',
    });
    assert.equal(AUDIT_ACTIONS.length, Object.keys(AUDIT_ACTION_LABELS).length);
    assert.equal(RESOURCE_TYPE_LABELS.test_run, 'Validation run');
  });

  it('reads severity codes as plain words', () => {
    assert.equal(formatSeverityLabel('s1'), 'Critical');
    assert.equal(formatSeverityLabel('S2'), 'High');
    assert.equal(formatSeverityLabel('s3'), 'Medium');
    assert.equal(formatSeverityLabel('s4'), 'Low');
  });
});

describe('portal target kind labels', () => {
  it('names each declared target kind in plain words', () => {
    assert.equal(formatTargetKind('fqdn'), 'Domain name');
    assert.equal(formatTargetKind('hostname'), 'Domain name');
    assert.equal(formatTargetKind('domain'), 'Domain name');
    assert.equal(formatTargetKind('url'), 'URL');
    assert.equal(formatTargetKind('ip', '203.0.113.10'), 'IPv4 address');
    assert.equal(formatTargetKind('ip', '2001:db8::1'), 'IPv6 address');
    assert.equal(formatTargetKind('ip'), 'IPv4 address');
    assert.equal(formatTargetKind('cidr'), 'CIDR range');
    assert.equal(formatTargetKind('tcp'), 'TCP service');
    assert.equal(formatTargetKind('dns_zone'), 'DNS zone');
    assert.equal(formatTargetKind('canary'), 'Canary endpoint');
  });

  it('handles missing and unknown kinds without raw separators', () => {
    assert.equal(formatTargetKind(''), 'Kind not recorded');
    assert.equal(formatTargetKind(undefined), 'Kind not recorded');
    assert.equal(formatTargetKind('edge_service'), 'Edge service');
  });
});
