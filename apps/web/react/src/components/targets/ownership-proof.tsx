import { useState } from 'react';
import { Check, Copy, ShieldCheck } from 'lucide-react';
import type { OwnershipChallenge } from '../../lib/target-detail-api';
import { formatDate } from '../../lib/utils';
// @ts-ignore Plain ESM keeps truthfulness rules executable in focused node tests.
import { isActiveDnsChallenge } from '../../lib/target-detail.mjs';
import { AnchorButton, Button } from '../ui/button';
import { Badge } from '../ui/badge';

const DNS_TXT_KINDS = new Set(['fqdn', 'url']);
const ORIGIN_PROOF_KINDS = new Set(['ip', 'tcp']);
const INSTRUCTION_TTL_SECONDS = 60;

export function CopyButton({ value, label, text = 'Copy' }: { value: string; label: string; text?: string }) {
  const [copied, setCopied] = useState(false);
  if (!value) return null;
  return (
    <Button
      size="sm"
      variant="ghost"
      aria-label={`Copy ${label}`}
      onClick={async () => {
        try {
          await navigator.clipboard?.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        } catch {
          setCopied(false);
        }
      }}
    >
      {copied ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
      {copied ? 'Copied' : text}
    </Button>
  );
}

function clockTime(value: string) {
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? 'an unrecorded time' : at.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

/** Plain-text hand-off for a DNS team; carries only the public TXT record and its expiry. */
export function dnsTxtInstructions(hostname: string, challenge: NonNullable<OwnershipChallenge>) {
  return [
    `Please publish this DNS record so AstraNull can confirm ownership of ${hostname}:`,
    'Type: TXT',
    `Name: ${challenge.record_name}`,
    `Value: ${challenge.record_value}`,
    `TTL: ${INSTRUCTION_TTL_SECONDS}`,
    `Valid until: ${challenge.expires_at || 'not recorded'}${challenge.expires_at ? ` (${formatDate(challenge.expires_at)})` : ''}`,
  ].join('\n');
}

export type OwnershipProofProps = {
  kind: string;
  hostname: string;
  challenge: OwnershipChallenge;
  now: number;
  compact?: boolean;
  panelId: string;
  canWrite: boolean;
  busy: string;
  error: string;
  watching: boolean;
  watchStopped: boolean;
  onIssue: () => void;
  onCheck: () => void;
};

/** Ownership proof for one target. DNS TXT applies only to hostnames and URLs, never to IP, TCP or zones. */
export function OwnershipProof({ kind, hostname, challenge, now, compact = false, panelId, canWrite, busy, error, watching, watchStopped, onIssue, onCheck }: OwnershipProofProps) {
  const dnsKind = DNS_TXT_KINDS.has(kind);
  const live = dnsKind && Boolean(challenge?.record_name) && (isActiveDnsChallenge(challenge, now) as boolean);
  const expired = dnsKind && Boolean(challenge?.record_name) && !live && ['pending', 'expired'].includes(String(challenge?.state ?? '').toLowerCase());
  const errorBanner = error ? <div className="form-banner" role="alert">{error}</div> : null;
  const dnsIntro = expired
    ? ' Issue a new DNS TXT record and publish its value. We only check the declared hostname.'
    : live
      ? ' Publish the DNS TXT record below, then choose Check now. We only check the declared hostname.'
      : ' Issue a DNS TXT record, publish it at your DNS provider, then check it here. We only check the declared hostname.';
  const intro = !compact ? (
    <p className="td-copy">
      External checks stay blocked until you prove you control this target.
      {dnsKind ? dnsIntro : ''}
    </p>
  ) : null;

  if (!dnsKind) {
    return (
      <div className="td-ownership" id={panelId} tabIndex={-1} data-kind={kind}>
        {intro}
        {ORIGIN_PROOF_KINDS.has(kind) ? (
          <>
            <p className="td-copy">DNS TXT proof applies to hostnames and URLs. IP and TCP targets are checked as the origin of a hostname you have verified: open that hostname and declare this address under Origin relations.</p>
            <div className="td-actions"><AnchorButton size="sm" variant="secondary" href="#targets">Open targets</AnchorButton></div>
          </>
        ) : (
          <p className="td-copy">DNS TXT ownership proof is not available for this target kind yet.</p>
        )}
        {errorBanner}
      </div>
    );
  }

  const expiredAt = expired && challenge?.expires_at && Number.isFinite(Date.parse(challenge.expires_at)) ? challenge.expires_at : '';
  const minutesLeft = live && challenge ? Math.max(1, Math.ceil((Date.parse(challenge.expires_at) - now) / 60_000)) : 0;

  if (challenge && (live || expired)) {
    return (
      <div className="td-ownership" id={panelId} tabIndex={-1} data-kind={kind} data-challenge={live ? 'live' : 'expired'}>
        {intro}
        {expired ? (
          <div className="td-ownership-expired">
            <Badge tone="warn">{expiredAt ? `Expired ${formatDate(expiredAt)}` : 'Expired · no expiry recorded'}</Badge>
            <p className="td-copy">This record expired and can no longer prove ownership. Issue a new record and publish its value.</p>
          </div>
        ) : null}
        <div className="td-dns" data-expired={expired || undefined}>
          <div className="td-dns-row"><span className="td-dns-key">Type</span><span className="td-dns-val">TXT</span><span /></div>
          <div className="td-dns-row">
            <span className="td-dns-key">Name</span>
            <span className="td-dns-val">{challenge.record_name}</span>
            {live ? <CopyButton value={challenge.record_name} label="DNS record name" /> : <span />}
          </div>
          <div className="td-dns-row">
            <span className="td-dns-key">Value</span>
            <span className="td-dns-val">{live ? challenge.record_value : 'Expired value withheld. Issue a new record for a new value.'}</span>
            {live ? <CopyButton value={challenge.record_value} label="DNS record value" /> : <span />}
          </div>
        </div>
        {live ? (
          <>
            <p className="td-muted td-ownership-expiry">
              Valid for 15 minutes · expires <time dateTime={challenge.expires_at}>{clockTime(challenge.expires_at)}</time> (in {minutesLeft} min)
            </p>
            <p className="td-muted">Checks run only while this page is open. If your DNS change needs a ticket, publish the record first and choose Check now when it is live, or issue a new record after this one expires.</p>
          </>
        ) : null}
        <div className="td-actions">
          {canWrite && live ? (
            <Button size="sm" loading={busy === 'verify'} disabled={busy !== ''} onClick={onCheck}>
              <ShieldCheck size={15} aria-hidden="true" />Check now
            </Button>
          ) : null}
          {canWrite && expired ? (
            <Button size="sm" loading={busy === 'issue'} disabled={busy !== ''} onClick={onIssue}>
              <ShieldCheck size={15} aria-hidden="true" />Issue a new record
            </Button>
          ) : null}
          {!canWrite ? <Badge tone="muted">Read-only role</Badge> : null}
          {live ? <CopyButton value={dnsTxtInstructions(hostname, challenge)} label="DNS record instructions for your DNS team" text="Copy instructions" /> : null}
          {live && canWrite ? <span className="td-muted">You can issue a new value after it expires.</span> : null}
          {challenge.last_checked_at ? <span className="td-muted">Last checked {formatDate(challenge.last_checked_at)}</span> : null}
          {live && watching ? <span className="td-muted" role="status">Re-checking every 30 seconds</span> : null}
        </div>
        {live && watchStopped && !watching ? <p className="td-muted" role="status">Stopped re-checking. Choose Check now after your DNS change is live.</p> : null}
        {errorBanner}
      </div>
    );
  }

  return (
    <div className="td-ownership" id={panelId} tabIndex={-1} data-kind={kind}>
      {intro}
      <div className="td-actions">
        {canWrite ? (
          <Button size="sm" loading={busy === 'issue'} disabled={busy !== ''} onClick={onIssue}>
            <ShieldCheck size={15} aria-hidden="true" />Issue DNS TXT record
          </Button>
        ) : <Badge tone="muted">Ask an engineer or admin to prove ownership</Badge>}
      </div>
      {errorBanner}
    </div>
  );
}
