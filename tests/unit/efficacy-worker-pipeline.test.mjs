import '../helpers/dev-data-dir.mjs';
import test from 'node:test'; import assert from 'node:assert/strict';
import { sanitizeProbeMetadata,buildResultBody } from '../../workers/probe-worker.mjs';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';

const job = { probe_profile: { kind: 'tls_audit' }, target: { kind: 'url' }, check_id: 'tls.full_audit.safe' };
const accounting = { requests_sent: 1, probe_requests_sent: 1, destination_resolver_attempts: 0, total_operations: 1, duration_ms: 25 };

function runCorrelation(externalResult, metadata, acct = accounting) {
  const body = buildResultBody(job, externalResult, metadata, acct);
  return correlateExternalOnlyVerdict({
    externalResult: body.external_result,
    probeKind: 'tls_audit',
    probeIoObserved: body.safety_attestation.probe_requests_sent > 0,
    probeMetadata: body.metadata,
    checkId: 'tls.full_audit.safe',
    expectedBehavior: 'must_block_before_origin',
  });
}

test('sanitizeProbeMetadata removes raw body and headers while preserving nameservers', () => {
  const sanitized = sanitizeProbeMetadata({
    body: 'payload',
    headers: { host: 'target.local' },
    nameservers: ['1.1.1.1', '8.8.8.8'],
  });
  assert.equal(sanitized.body, undefined);
  assert.equal(sanitized.headers, undefined);
  assert.deepEqual(sanitized.nameservers, ['1.1.1.1', '8.8.8.8']);
});

test('buildResultBody preserves metadata arrays and scalars', () => {
  const meta = { nameservers: ['9.9.9.9'], status_code: 200 };
  const body = buildResultBody(job, 'connected', meta, accounting);
  assert.deepEqual(body.metadata.nameservers, ['9.9.9.9']);
  assert.equal(body.metadata.status_code, 200);
  assert.equal(body.external_result, 'connected');
});

test('correlateExternalOnlyVerdict handles tls_audit exposed and inconclusive cases', () => {
  const certExpiredVerdict = runCorrelation('connected', {
    complete: true,
    days_to_expiry: -1,
    tls_issues: ['cert_expired'],
  });
  assert.equal(certExpiredVerdict.verdict, 'exposed');

  const notYetValidVerdict = runCorrelation('connected', {
    complete: true,
    days_to_expiry: -1,
    tls_issues: ['certificate_not_yet_valid'],
  });
  assert.equal(notYetValidVerdict.verdict, 'exposed');

  const emptyIssuesVerdict = runCorrelation('connected', {
    complete: true,
    tls_issues: [],
  });
  assert.equal(emptyIssuesVerdict.verdict, 'inconclusive');

  const timeoutVerdict = runCorrelation('timeout', {
    complete: true,
    days_to_expiry: -1,
    tls_issues: ['cert_expired'],
  });
  assert.equal(timeoutVerdict.verdict, 'inconclusive');

  const ioZeroVerdict = runCorrelation('connected', {
    complete: true,
    days_to_expiry: -1,
    tls_issues: ['cert_expired'],
  }, { ...accounting, requests_sent: 0, probe_requests_sent: 0, total_operations: 0 });
  assert.equal(ioZeroVerdict.verdict, 'inconclusive');
});