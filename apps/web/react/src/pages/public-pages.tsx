import { FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  Circle,
  CircleDashed,
  CircleDot,
  Copy,
  Eye,
  EyeOff,
  FileQuestion,
  Info,
  LockKeyhole,
  ShieldCheck,
  TriangleAlert,
  type LucideIcon
} from 'lucide-react';
import {
  isOidcJwtMode,
  loadSession,
  resolveOidcLoginRedirect,
  saveSession,
  sessionFromLoginResponse
} from '../lib/api';
import { staffHomePath } from '../lib/portal-auth-policy.mjs';
import { publicApiErrorCode, publicApiErrorMessage } from '../lib/error-messages';
import { DETAIL_ROUTE_ITEMS, ROUTE_BY_ID } from '../lib/navigation';
import { buildEvidenceInspectorHref, isSafeInspectorId, parseInspectorRef } from '../lib/evidence-inspector.mjs';
import type { PortalConfig, RouteId } from '../lib/types';
import { AnchorButton, Button } from '../components/ui/button';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Reveal } from '../components/ui/motion';
import { Select } from '../components/ui/select';
import { BrandMark } from '../components/layout/brand';
import './public-landing.css';

type BadgeTone = NonNullable<BadgeProps['tone']>;

type PublicPageProps = {
  config: PortalConfig;
};

const NETWORK_ERROR_MESSAGE = 'Could not reach AstraNull. Check your connection and try again.';

function isNetworkFailure(error: unknown) {
  return error instanceof TypeError;
}

/* ── Safe return-to-intent contract ────────────────────────────────────
   Sign-in may carry a nonsecret `next` hash and a `reason`. Only real,
   customer-reachable route ids survive, each with the parameters its page
   actually reads (route-scoped below) plus shared evidence-inspector state
   validated by its own schema. Tokens, external URLs, staff routes, free text
   and unknown parameters are dropped. The portal's route guard and the server
   stay authoritative after sign-in. */

export type LoginReturnReason = 'session_expired' | 'signed_out';

const LOGIN_RETURN_REASONS = new Set<LoginReturnReason>(['session_expired', 'signed_out']);
const RETURN_ROUTE_ID = /^[a-z][a-z0-9-]{0,63}$/;
const RETURN_HASH_MAX = 2048;
const RETURN_TAB = /^[a-z][a-z-]{0,31}$/;
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/;
const CREDENTIAL_SHAPE = /\b(?:pwi|pwr)_|\bbearer\s|eyJ[A-Za-z0-9_-]{8,}\./i;
const FINDING_GROUP_KEY_MAX = 640;
const FINDING_GROUP_PART_MAX = 240;
const FINDING_GROUP_ISSUE = /^(?:[vtf]:[\s\S]+|none)$/;

/**
 * Validate a canonical finding-group key: `<URI-encoded check id>|<URI-encoded issue>` as built
 * by findingGroupKey. Each part must decode, re-encode to exactly itself, stay bounded and free
 * of control characters; the check part is a safe id and the issue keeps its v:/t:/f:/none form.
 */
export function parseFindingGroupReturnKey(value: string | null | undefined): string | null {
  const raw = String(value ?? '');
  if (!raw || raw.length > FINDING_GROUP_KEY_MAX) return null;
  const parts = raw.split('|');
  if (parts.length !== 2) return null;
  const decoded: string[] = [];
  for (const part of parts) {
    let plain: string;
    try {
      plain = decodeURIComponent(part);
    } catch {
      return null;
    }
    if (!plain || plain.length > FINDING_GROUP_PART_MAX) return null;
    if (CONTROL_CHARS.test(plain) || encodeURIComponent(plain) !== part) return null;
    decoded.push(plain);
  }
  const [checkId, issue] = decoded;
  if (!isSafeInspectorId(checkId)) return null;
  if (!FINDING_GROUP_ISSUE.test(issue) || CREDENTIAL_SHAPE.test(issue)) return null;
  return raw;
}

export function parseLoginReturnReason(value: string | null | undefined): LoginReturnReason | null {
  const normalized = String(value ?? '').trim() as LoginReturnReason;
  return LOGIN_RETURN_REASONS.has(normalized) ? normalized : null;
}

type ReturnParamRule = (value: string) => string | null;

const safeReturnId: ReturnParamRule = (value) => (isSafeInspectorId(value) ? value : null);
const safeReturnTab: ReturnParamRule = (value) => (RETURN_TAB.test(value) ? value : null);

const DETAIL_RETURN_ROUTES = new Set<string>(DETAIL_ROUTE_ITEMS.map((item) => item.id));

/** Parameters each page reads for selection continuity. Anything not listed is dropped. */
const ROUTE_RETURN_PARAMS: Partial<Record<string, Record<string, ReturnParamRule>>> = {
  'target-detail': { tab: safeReturnTab, check: safeReturnId },
  'check-detail': { policy: safeReturnId, target: safeReturnId },
  'finding-group-detail': { key: parseFindingGroupReturnKey },
  checks: { target: safeReturnId }
};

/** Normalize a requested hash route into `#route?route-scoped=params`, or null when unsafe. */
export function sanitizeReturnHash(next: string | null | undefined): string | null {
  const raw = String(next ?? '').trim();
  if (!raw || raw.length > RETURN_HASH_MAX) return null;
  const hash = raw.startsWith('#') ? raw.slice(1) : raw;
  const queryIndex = hash.indexOf('?');
  const routePart = queryIndex >= 0 ? hash.slice(0, queryIndex) : hash;
  if (!RETURN_ROUTE_ID.test(routePart)) return null;
  const item = ROUTE_BY_ID.get(routePart as RouteId);
  if (!item || item.group === 'staff') return null;

  const params = new URLSearchParams(queryIndex >= 0 ? hash.slice(queryIndex + 1) : '');
  const kept = new URLSearchParams();
  if (DETAIL_RETURN_ROUTES.has(routePart)) {
    const id = safeReturnId(params.get('id') ?? params.get('entity_id') ?? '');
    if (id) kept.set('id', id);
  }
  for (const [name, rule] of Object.entries(ROUTE_RETURN_PARAMS[routePart] ?? {})) {
    const value = params.get(name);
    const safe = value === null ? null : rule(value);
    if (safe) kept.set(name, safe);
  }
  const query = kept.toString();
  const base = `#${routePart}${query ? `?${query}` : ''}`;
  const inspector = parseInspectorRef(`#${hash}`);
  return inspector ? buildEvidenceInspectorHref(inspector, base) || base : base;
}

/** One decoded parameter of a return hash, as the destination page will read it. */
export function returnHashParam(hash: string | null | undefined, name: string): string | null {
  const value = String(hash ?? '');
  const index = value.indexOf('?');
  return index >= 0 ? new URLSearchParams(value.slice(index + 1)).get(name) : null;
}

/** Resolve a post-sign-in destination inside the customer portal, or null. */
export function resolveSafeReturnPath(next: string | null | undefined, portalPath: string): string | null {
  const hash = sanitizeReturnHash(next);
  if (!hash) return null;
  const base = portalPath.startsWith('/') && !portalPath.startsWith('//') ? portalPath : '/app';
  return `${base}${hash}`;
}

export function returnDestinationLabel(next: string | null | undefined): string | null {
  const hash = sanitizeReturnHash(next);
  if (!hash) return null;
  const routeId = hash.slice(1).split('?')[0] as RouteId;
  return ROUTE_BY_ID.get(routeId)?.label ?? null;
}

/**
 * Build the sign-in URL the portal should send an expired or signed-out user to.
 * External identity-provider URLs are returned untouched; they own their own return flow.
 */
export function buildLoginReturnUrl(
  loginUrl: string,
  options: { hash?: string | null; reason?: LoginReturnReason | null } = {}
): string {
  const target = String(loginUrl ?? '').trim() || '/login';
  if (!target.startsWith('/') || target.startsWith('//')) return target;
  const [pathAndQuery, fragment] = target.split('#', 2);
  const [pathname, search = ''] = pathAndQuery.split('?', 2);
  const params = new URLSearchParams(search);
  const hash = sanitizeReturnHash(options.hash);
  if (hash) params.set('next', hash);
  const reason = parseLoginReturnReason(options.reason);
  if (reason) params.set('reason', reason);
  const query = params.toString();
  return `${pathname}${query ? `?${query}` : ''}${fragment ? `#${fragment}` : ''}`;
}

function readLoginContext(portalPath: string) {
  if (typeof window === 'undefined') return { next: null, destination: null, label: null, reason: null };
  const params = new URLSearchParams(window.location.search);
  const next = sanitizeReturnHash(params.get('next'));
  return {
    next,
    destination: resolveSafeReturnPath(next, portalPath),
    label: returnDestinationLabel(next),
    reason: parseLoginReturnReason(params.get('reason'))
  };
}

function withNext(href: string, next: string | null) {
  if (!next || !href.startsWith('/') || href.startsWith('//')) return href;
  const separator = href.includes('?') ? '&' : '?';
  return `${href}${separator}next=${encodeURIComponent(next)}`;
}

/* ── Signup lifecycle: derived only from recorded request state ─────── */

export type LifecycleStageStatus = 'complete' | 'current' | 'upcoming' | 'untracked';

export type LifecycleStage = {
  id: string;
  label: string;
  detail: string;
  status: LifecycleStageStatus;
};

const SIGNUP_STAGES = [
  { id: 'submitted', label: 'Received', detail: 'Your request is recorded. Nobody has reviewed it yet.' },
  { id: 'under_review', label: 'Under review', detail: 'AstraNull is reviewing the organization, contact and intended use.' },
  { id: 'approved', label: 'Approved', detail: 'The request is approved. The workspace has not been created yet.' },
  { id: 'provisioned', label: 'Workspace created', detail: 'Your workspace exists. No invitation is recorded yet.' },
  { id: 'customer_invited', label: 'Invitation issued', detail: 'An invitation is recorded for the contact on this request.' }
] as const;

const SIGNUP_FINAL_STAGE = {
  id: 'password_set',
  label: 'Password set',
  detail: 'Happens when the invited person opens the invitation and sets a password. This page does not track it.'
};

const SIGNUP_STATE_LABELS: Record<string, string> = {
  submitted: 'Received',
  under_review: 'Under review',
  in_review: 'Under review',
  approved: 'Approved',
  provisioned: 'Workspace created',
  customer_invited: 'Invitation issued',
  rejected: 'Not approved'
};

function normalizeSignupState(state: unknown) {
  const normalized = String(state ?? '').trim().toLowerCase();
  return normalized === 'in_review' ? 'under_review' : normalized;
}

export function signupStateLabel(state: unknown) {
  const raw = String(state ?? '').trim();
  return SIGNUP_STATE_LABELS[normalizeSignupState(raw)] ?? (raw ? `Recorded as ${raw}` : 'Not recorded');
}

function signupStateTone(state: unknown): BadgeTone {
  const normalized = normalizeSignupState(state);
  if (normalized === 'customer_invited') return 'success';
  if (normalized === 'rejected') return 'danger';
  if (['under_review', 'approved', 'provisioned'].includes(normalized)) return 'warn';
  if (normalized === 'submitted') return 'info';
  return 'muted';
}

/** Map a recorded state onto the readable journey. Unknown states return no stages. */
export function signupLifecycleStages(state: unknown): LifecycleStage[] {
  const normalized = normalizeSignupState(state);
  if (normalized === 'rejected') return [];
  const index = SIGNUP_STAGES.findIndex((stage) => stage.id === normalized);
  if (index < 0) return [];
  return [
    ...SIGNUP_STAGES.map((stage, position) => ({
      ...stage,
      status: (position < index ? 'complete' : position === index ? 'current' : 'upcoming') as LifecycleStageStatus
    })),
    { ...SIGNUP_FINAL_STAGE, status: 'untracked' as const }
  ];
}

export function signupNextStep(state: unknown): { headline: string; body: string; canSignIn: boolean } {
  switch (normalizeSignupState(state)) {
    case 'submitted':
      return { headline: 'You cannot sign in yet.', body: 'The request is waiting for review. Keep the request ID to check back.', canSignIn: false };
    case 'under_review':
      return { headline: 'You cannot sign in yet.', body: 'Review is in progress. If AstraNull needs more detail, they will use the contact on the request.', canSignIn: false };
    case 'approved':
      return { headline: 'You cannot sign in yet.', body: 'Approval is recorded. The workspace is created next, then an invitation is issued.', canSignIn: false };
    case 'provisioned':
      return { headline: 'You cannot sign in yet.', body: 'The workspace exists. Sign-in opens once an invitation is issued and a password is set.', canSignIn: false };
    case 'customer_invited':
      return {
        headline: 'Set your password from the invitation, then log in.',
        body: 'Open the invitation link sent for this request. If you already set a password, log in now.',
        canSignIn: true
      };
    case 'rejected':
      return { headline: 'This request was not approved.', body: 'No workspace was created. Any message from the reviewer is shown below.', canSignIn: false };
    default:
      return { headline: 'Status recorded.', body: 'This state does not map to a known step. Contact AstraNull if you need help reading it.', canSignIn: false };
  }
}

/* ── Password requirements (mirrors the server policy; the server stays authoritative) ── */

export type PasswordRequirement = { id: 'length' | 'classes'; label: string; met: boolean };

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 200;

export function passwordRequirementStatus(password: string): PasswordRequirement[] {
  const value = String(password ?? '');
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(value)).length;
  return [
    {
      id: 'length',
      label: `At least ${PASSWORD_MIN_LENGTH} characters`,
      met: value.length >= PASSWORD_MIN_LENGTH && value.length <= PASSWORD_MAX_LENGTH
    },
    { id: 'classes', label: 'Three of: lowercase, uppercase, number, symbol', met: classes >= 3 }
  ];
}

const PASSWORD_POLICY_LABELS: Record<string, string> = {
  too_short: `Use at least ${PASSWORD_MIN_LENGTH} characters.`,
  too_long: `Use at most ${PASSWORD_MAX_LENGTH} characters.`,
  invalid_type: 'Enter a password.',
  insufficient_character_classes: 'Mix at least three of: lowercase, uppercase, numbers, symbols.',
  contains_email_local_part: 'Do not include the name part of your email address.',
  common_password: 'This password is too common. Choose something less guessable.'
};

function passwordPolicyMessages(failures: unknown): string[] {
  if (!Array.isArray(failures)) return [];
  return failures.map((code) => PASSWORD_POLICY_LABELS[String(code)] ?? 'Choose a different password.');
}

/* ── Public support contact: only what the deployment actually publishes ── */

type PublicContact = { label: string; href: string };

export function publicSupportContact(siteConfig: Record<string, unknown> | null | undefined): PublicContact | null {
  const source = siteConfig ?? {};
  for (const key of ['support_email', 'support_contact_email', 'contact_email']) {
    const value = String(source[key] ?? '').trim();
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return { label: value, href: `mailto:${value}` };
  }
  for (const key of ['support_url', 'contact_url']) {
    const value = String(source[key] ?? '').trim();
    if (/^https:\/\/[^\s]+$/.test(value) || (value.startsWith('/') && !value.startsWith('//'))) {
      return { label: value.replace(/^https:\/\//, ''), href: value };
    }
  }
  return null;
}

function retryAfterLabel(json: Record<string, unknown>, response: Response) {
  const fromBody = Number(json.retry_after_seconds);
  const fromHeader = Number(response.headers.get('Retry-After'));
  const seconds = Number.isFinite(fromBody) && fromBody > 0
    ? fromBody
    : Number.isFinite(fromHeader) && fromHeader > 0 ? fromHeader : 0;
  if (!seconds) return 'in a few minutes';
  if (seconds < 90) return `in ${Math.ceil(seconds)} seconds`;
  return `in about ${Math.ceil(seconds / 60)} minutes`;
}

/* ── Shared page chrome ─────────────────────────────────────────────── */

function usePageMeta({ title, robots }: { title: string; robots?: string }) {
  useEffect(() => {
    const previousTitle = document.title;
    document.title = title;

    const existingRobots = document.querySelector('meta[name="robots"]') as HTMLMetaElement | null;
    const previousRobots = existingRobots?.content;
    let robotsMeta = existingRobots;

    if (robots) {
      if (!robotsMeta) {
        robotsMeta = document.createElement('meta');
        robotsMeta.name = 'robots';
        document.head.appendChild(robotsMeta);
      }
      robotsMeta.content = robots;
    }

    return () => {
      document.title = previousTitle;
      if (!robots) return;
      if (previousRobots && robotsMeta) {
        robotsMeta.content = previousRobots;
      } else if (robotsMeta) {
        robotsMeta.remove();
      }
    };
  }, [title, robots]);
}

function navigateSpa(destination: string) {
  if (destination.startsWith('/') && !destination.startsWith('//')) {
    window.history.pushState(null, '', destination);
    window.dispatchEvent(new PopStateEvent('popstate'));
    return;
  }
  window.location.href = destination;
}

function enterDemoPortal(portalPath: string) {
  saveSession({
    mode: 'dev-headers',
    principal: 'customer',
    tenant_id: 'ten_demo',
    user_id: 'usr_admin',
    role: 'admin'
  });
  navigateSpa(portalPath);
}

function PublicShell({
  children,
  eyebrow = 'No-access-first · Evidence-backed · SOC-gated',
  activeNav,
  loginHref = '/login',
  signupEnabled = true,
  showAccountNav = true,
  showEyebrow = true
}: {
  children: React.ReactNode;
  eyebrow?: string;
  activeNav?: 'login' | 'signup';
  loginHref?: string;
  signupEnabled?: boolean;
  showAccountNav?: boolean;
  showEyebrow?: boolean;
}) {
  const loginVariant = activeNav === 'login' || !signupEnabled ? 'default' : 'ghost';
  return (
    <div className="public-app">
      <a className="skip-link" href="#public-main">Skip to main content</a>
      <header className="public-topnav">
        <div className="public-topnav-inner">
          <a href="/" className="brand" aria-label="AstraNull home">
            <BrandMark />
            <span>AstraNull</span>
          </a>
          {showEyebrow && eyebrow ? <span className="public-topnav-eyebrow eyebrow">{eyebrow}</span> : null}
          {showAccountNav ? (
            <nav className="public-topnav-actions" aria-label="Account access">
              <AnchorButton
                href={loginHref}
                variant={loginVariant}
                size="sm"
                aria-current={activeNav === 'login' ? 'page' : undefined}
              >
                Log in
              </AnchorButton>
              {signupEnabled ? (
                <AnchorButton
                  href="/signup"
                  variant={activeNav === 'login' ? 'secondary' : 'default'}
                  size="sm"
                  aria-current={activeNav === 'signup' ? 'page' : undefined}
                >
                  Request access
                </AnchorButton>
              ) : null}
            </nav>
          ) : <span className="public-topnav-actions" aria-hidden="true" />}
        </div>
      </header>
      {children}
    </div>
  );
}

/** Two-column frame kept for request access, where context helps before a long form. */
function AuthPageLayout({
  aside,
  children,
  footer,
  wide = false
}: {
  aside: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  wide?: boolean;
}) {
  return (
    <main id="public-main" className={`auth-page public-auth-split${wide ? ' auth-page--wide' : ''}`}>
      <aside className="auth-aside">{aside}</aside>
      <section className="auth-panel">
        {children}
        {footer ? <footer className="auth-footer">{footer}</footer> : null}
      </section>
    </main>
  );
}

/** Single column for sign-in and credential tasks: heading, one sentence, then the form. */
function AuthTaskLayout({
  title,
  lead,
  children,
  links
}: {
  title: string;
  lead?: React.ReactNode;
  children: React.ReactNode;
  links?: React.ReactNode;
}) {
  return (
    <main id="public-main" className="public-auth-task">
      <header className="public-auth-task-head">
        <h1 className="public-auth-task-title">{title}</h1>
        {lead ? <p className="public-auth-task-lead">{lead}</p> : null}
      </header>
      {children}
      {links ? <nav className="public-auth-task-links" aria-label="Other account options">{links}</nav> : null}
    </main>
  );
}

type NoticeTone = 'info' | 'warn' | 'danger' | 'success';

const NOTICE_ICONS: Record<NoticeTone, LucideIcon> = {
  info: Info,
  warn: TriangleAlert,
  danger: TriangleAlert,
  success: CheckCircle2
};

function PublicNotice({
  tone = 'info',
  title,
  children,
  actions,
  role,
  id,
  focusRef
}: {
  tone?: NoticeTone;
  title: string;
  children?: React.ReactNode;
  actions?: React.ReactNode;
  role?: 'alert' | 'status' | 'note';
  id?: string;
  focusRef?: React.Ref<HTMLDivElement>;
}) {
  const Icon = NOTICE_ICONS[tone];
  return (
    <div
      className={`public-notice is-${tone}`}
      role={role}
      aria-live={role === 'status' ? 'polite' : undefined}
      id={id}
      ref={focusRef}
      tabIndex={focusRef ? -1 : undefined}
    >
      <Icon className="public-notice-icon" size={18} aria-hidden="true" />
      <div className="public-notice-body">
        <p className="public-notice-title">{title}</p>
        {children ? <div className="public-notice-text">{children}</div> : null}
        {actions ? <div className="public-notice-actions">{actions}</div> : null}
      </div>
    </div>
  );
}

function FieldError({ id, message }: { id: string; message?: string }) {
  if (!message) return null;
  return (
    <span className="public-field-error" id={id}>
      <TriangleAlert size={14} aria-hidden="true" />
      {message}
    </span>
  );
}

function describedBy(...ids: Array<string | false | null | undefined>) {
  const value = ids.filter(Boolean).join(' ');
  return value || undefined;
}

function AuthRedirectPanel({ lead, help, href }: { lead: string; help?: string; href?: string }) {
  return (
    <div className="success-panel" role="status" aria-live="polite" aria-busy="true">
      <span className="spinner" aria-hidden="true" />
      <p className="success-panel-lead">{lead}</p>
      {help ? <p className="auth-field-help">{help}</p> : null}
      {href ? <AnchorButton href={href} variant="secondary">Continue to your identity provider</AnchorButton> : null}
    </div>
  );
}

function CopyValueButton({ value, label }: { value: string; label: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const timer = useRef<number | null>(null);

  useEffect(() => () => {
    if (timer.current) window.clearTimeout(timer.current);
  }, []);

  async function copy() {
    if (timer.current) window.clearTimeout(timer.current);
    try {
      if (!navigator.clipboard?.writeText) throw new Error('clipboard unavailable');
      await navigator.clipboard.writeText(value);
      setState('copied');
    } catch {
      setState('failed');
    }
    timer.current = window.setTimeout(() => setState('idle'), 2400);
  }

  return (
    <span className="public-copy">
      <Button type="button" variant="secondary" size="sm" onClick={copy}>
        {state === 'copied' ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
        {state === 'copied' ? 'Copied' : label}
      </Button>
      <span className="public-copy-status" role="status" aria-live="polite">
        {state === 'copied' ? 'Request ID copied.' : state === 'failed' ? 'Copy failed. Select the ID and copy it manually.' : ''}
      </span>
    </span>
  );
}

function RequestReference({ id }: { id: string }) {
  return (
    <div className="public-reference">
      <span className="public-reference-label" id="request-reference-label">Request ID</span>
      <code className="public-reference-value" aria-labelledby="request-reference-label">{id}</code>
      <CopyValueButton value={id} label="Copy ID" />
    </div>
  );
}

const STAGE_STATUS_TEXT: Record<LifecycleStageStatus, string> = {
  complete: 'Done',
  current: 'Current step',
  upcoming: 'Not reached',
  untracked: 'Not tracked here'
};

function LifecycleMarker({ status }: { status: LifecycleStageStatus }) {
  if (status === 'complete') return <Check size={14} aria-hidden="true" />;
  if (status === 'current') return <CircleDot size={14} aria-hidden="true" />;
  if (status === 'untracked') return <CircleDashed size={14} aria-hidden="true" />;
  return <Circle size={14} aria-hidden="true" />;
}

function SignupLifecycle({ stages, label }: { stages: LifecycleStage[]; label: string }) {
  return (
    <ol className="public-lifecycle" aria-label={label}>
      {stages.map((stage) => (
        <li key={stage.id} className={`is-${stage.status}`} aria-current={stage.status === 'current' ? 'step' : undefined}>
          <span className="public-lifecycle-marker"><LifecycleMarker status={stage.status} /></span>
          <span className="public-lifecycle-copy">
            <span className="public-lifecycle-label">
              {stage.label}
              <span className="public-lifecycle-status">{STAGE_STATUS_TEXT[stage.status]}</span>
            </span>
            {stage.status === 'current' || stage.status === 'untracked'
              ? <span className="public-lifecycle-detail">{stage.detail}</span>
              : null}
          </span>
        </li>
      ))}
    </ol>
  );
}

function LostReferenceHelp({ contact }: { contact: PublicContact | null | undefined }) {
  if (contact === undefined) return null;
  return (
    <p className="public-help-line">
      {contact ? (
        <>Lost your request ID? Contact <a href={contact.href}>{contact.label}</a>. Status lookup never shows contact details.</>
      ) : (
        <>Lost your request ID? This deployment has not published a support contact. Ask the person who arranged your AstraNull access.</>
      )}
    </p>
  );
}

/* ── Landing ────────────────────────────────────────────────────────── */

type ExampleStep = { id: string; action: string; result: string; detail: string };

/* Synthetic walkthrough. The reserved .example domain and every value are invented. */
const LANDING_EXAMPLE: readonly ExampleStep[] = [
  {
    id: 'declare',
    action: 'Declare a target',
    result: 'checkout.shop.example',
    detail: 'Added by hand as a website, tagged payments. Nothing is discovered for you.'
  },
  {
    id: 'ownership',
    action: 'Prove ownership',
    result: 'DNS TXT record found',
    detail: 'Checks stay locked for this hostname until the record is confirmed.'
  },
  {
    id: 'check',
    action: 'Run one bounded check',
    result: 'Rate-limit response check',
    detail: 'A short, capped request sequence sent from one external probe.'
  },
  {
    id: 'evidence',
    action: 'Read the evidence',
    result: 'Rate limiting observed',
    detail: 'Responses switched to HTTP 429 with a Retry-After header. The result covers this check on this host only.'
  }
];

function LandingExample() {
  const [active, setActive] = useState<number | null>(null);
  const activeStep = active === null ? null : LANDING_EXAMPLE[active];

  function advance() {
    setActive((current) => (current === null || current >= LANDING_EXAMPLE.length - 1 ? 0 : current + 1));
  }

  return (
    <figure className="public-example" aria-labelledby="public-example-title">
      <div className="public-example-head">
        <p id="public-example-title" className="public-example-title">One check, start to finish</p>
        <Badge tone="muted">Example data</Badge>
      </div>
      <ol className="public-example-steps">
        {LANDING_EXAMPLE.map((step, index) => (
          <li
            key={step.id}
            className={active === index ? 'is-active' : active !== null && index < active ? 'is-done' : undefined}
            aria-current={active === index ? 'step' : undefined}
          >
            <span className="public-example-index" aria-hidden="true">{index + 1}</span>
            <div>
              <p className="public-example-action">{step.action}</p>
              <p className="public-example-result">{step.result}</p>
              <p className="public-example-detail">{step.detail}</p>
            </div>
          </li>
        ))}
      </ol>
      <div className="public-example-controls">
        <Button type="button" variant="secondary" size="sm" onClick={advance}>
          {active === null ? 'Walk through the example' : active >= LANDING_EXAMPLE.length - 1 ? 'Start again' : 'Next step'}
          <ArrowRight size={14} aria-hidden="true" />
        </Button>
        <span className="public-example-progress" role="status" aria-live="polite">
          {activeStep ? `Step ${(active ?? 0) + 1} of ${LANDING_EXAMPLE.length}: ${activeStep.action}` : ''}
        </span>
      </div>
      <figcaption>Illustrative example with invented data. It is not a customer result.</figcaption>
    </figure>
  );
}

type LandingBoundary = { label: string; title: string; body: string };

const LANDING_BOUNDARIES: readonly LandingBoundary[] = [
  {
    label: 'Scope',
    title: 'Only the targets you declare.',
    body: 'You list the hostnames, DNS zones and TCP services in scope, by hand or through CSV or API import. AstraNull does not discover IP inventory.'
  },
  {
    label: 'Access',
    title: 'No cloud keys, no agent.',
    body: 'Checks run from outside your network. You do not grant cloud, CDN or WAF credentials, and nothing is installed on your hosts.'
  },
  {
    label: 'Checks',
    title: 'Bounded, and only after ownership.',
    body: 'Each check sends a capped sequence of requests from an external probe, and only to targets whose ownership is proven.'
  },
  {
    label: 'Results',
    title: 'Evidence with stated limits.',
    body: 'A passed check covers that check on that target. It does not certify protection or measure volumetric capacity. Missing evidence stays marked as unknown.'
  }
];

type LandingFlowStep = { id: string; title: string; body: string };

const LANDING_FLOW: readonly LandingFlowStep[] = [
  {
    id: 'declare',
    title: 'Declare the targets',
    body: 'Add the hostnames, DNS zones and TCP services you want validated, and group them with tags. Scope is what you declare, nothing more.'
  },
  {
    id: 'verify',
    title: 'Prove you own them',
    body: 'Publish the DNS TXT challenge for each hostname. Until ownership is confirmed, no probe traffic is sent to it.'
  },
  {
    id: 'check',
    title: 'Run a bounded check',
    body: 'Pick a check suited to the target. Signed, rate-bounded probe jobs observe it from outside, within a fixed request budget.'
  },
  {
    id: 'evidence',
    title: 'Review the evidence',
    body: 'Each result keeps the request, response and the rule it was judged against. A gap or an inconclusive check stays visible, with a next step.'
  }
];

type VerdictRecordField = { field: string; description?: string; vocabulary?: readonly string[] };

/* Field names mirror the verdict record the API returns; values list the allowed vocabulary. */
const VERDICT_RECORD_FIELDS: readonly VerdictRecordField[] = [
  { field: 'target_id', description: 'The declared hostname, DNS zone or TCP service' },
  { field: 'confidence', vocabulary: ['external_only'] },
  { field: 'verdict', vocabulary: ['protected', 'exposed', 'bypassable', 'inconclusive'] },
  { field: 'evidence_ids', description: 'References to the probe evidence behind the verdict' },
  { field: 'reason_codes', description: 'Why correlation reached this verdict' }
];

const LANDING_COMPARE = [
  ['Scope source', 'Targets you declare', 'Whatever the operator scripts', 'Provider resource inventory'],
  ['Cloud credentials', 'Not required', 'Depends on the test setup', 'Required for the provider account'],
  ['Evidence origin', 'External probe evidence only', 'Tool-specific run output', 'Provider telemetry'],
  ['What a result covers', 'One bounded check on one declared target', 'The traffic the operator generated', 'Traffic the provider observed'],
  ['Ownership gate', 'Required before any probe', 'Not inherent', 'Account membership']
];

function VerdictRecordFields() {
  return (
    <dl className="public-record-fields">
      {VERDICT_RECORD_FIELDS.map(({ field, description, vocabulary }) => (
        <div key={field}>
          <dt><code>{field}</code></dt>
          <dd>
            {vocabulary ? (
              <ul className="public-record-vocab" aria-label={`Allowed ${field} values`}>
                {vocabulary.map((value) => (
                  <li key={value}><code>{value}</code></li>
                ))}
              </ul>
            ) : description}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function ValidationFlowSection() {
  return (
    <section className="public-section" id="how" aria-labelledby="how-heading">
      <div className="public-flow-layout">
        <Reveal className="public-flow-intro">
          <h2 id="how-heading">How a check works.</h2>
          <p className="public-section-lead">Four steps, in this order. Each one records what the next is allowed to rely on.</p>
          <details className="public-technical">
            <summary>Fields in every verdict record</summary>
            <VerdictRecordFields />
          </details>
        </Reveal>
        <ol className="public-flow">
          {LANDING_FLOW.map((step, index) => (
            <Reveal as="li" step={index} key={step.id} className="public-flow-step">
              <span className="public-flow-marker" aria-hidden="true">{index + 1}</span>
              <div>
                <h3>{step.title}</h3>
                <p>{step.body}</p>
              </div>
            </Reveal>
          ))}
        </ol>
      </div>
    </section>
  );
}

function BoundariesSection() {
  return (
    <Reveal as="section" className="public-section" id="boundaries" aria-labelledby="boundaries-heading">
      <div className="public-section-head">
        <h2 id="boundaries-heading">What it needs, and what it does not claim.</h2>
      </div>
      <ul className="public-ledger">
        {LANDING_BOUNDARIES.map(({ label, title, body }) => (
          <li key={label}>
            <span className="public-ledger-label">{label}</span>
            <h3>{title}</h3>
            <p>{body}</p>
          </li>
        ))}
      </ul>
      <p className="public-note">
        <ShieldCheck size={18} aria-hidden="true" />
        <span>AstraNull is a defensive validation service. It does not offer self-service attack tooling or unmanaged traffic generation.</span>
      </p>
    </Reveal>
  );
}

export function PublicLandingPage({ config }: PublicPageProps) {
  const productName = String(config.siteConfig.product_name ?? 'AstraNull');
  const signupEnabled = config.siteConfig.signup_enabled !== false;
  const demoEnabled = config.authMode === 'dev-headers';
  const loginUrl = config.loginUrl;

  usePageMeta({
    title: `${productName} · Prove DDoS readiness without handing over your cloud keys`
  });

  return (
    <PublicShell loginHref={loginUrl} signupEnabled={signupEnabled} showEyebrow={false}>
      <main id="public-main" className="public-wrap public-landing">
        <section className="public-hero" aria-labelledby="public-hero-heading">
          <div className="public-hero-grid">
            <div className="public-hero-copy">
              <p className="public-kicker">No-access-first DDoS readiness validation</p>
              <h1 id="public-hero-heading">Prove DDoS readiness without handing over your cloud keys.</h1>
              <p className="public-hero-lead">AstraNull checks customer-declared targets from outside your network, with no required cloud credentials and no automatic IP inventory discovery. Prove ownership, run bounded checks and keep the evidence behind every result.</p>
              <div className="public-actions">
                {signupEnabled ? (
                  <AnchorButton href="/signup">
                    Request access
                    <ArrowRight size={15} aria-hidden="true" />
                  </AnchorButton>
                ) : (
                  <AnchorButton href={loginUrl}>Log in</AnchorButton>
                )}
                <AnchorButton href="#how" variant="secondary">How a check works</AnchorButton>
              </div>
              {!signupEnabled ? (
                <p className="public-hero-note">Access requests are closed on this deployment. Existing customers can log in.</p>
              ) : null}
            </div>
            <LandingExample />
          </div>
        </section>

        <ValidationFlowSection />

        <BoundariesSection />

        <Reveal as="section" className="public-section" id="compare" aria-labelledby="compare-heading">
          <div className="public-section-head">
            <h2 id="compare-heading">Compare the operating model.</h2>
            <p className="public-section-lead">Where scope comes from, what access is needed, and what a result actually covers.</p>
          </div>
          <div
            className="public-compare table-wrap"
            tabIndex={0}
            role="region"
            aria-label="AstraNull capability comparison, scrollable"
          >
            <table>
              <thead>
                <tr>
                  <th scope="col"><span className="sr-only">Capability</span></th>
                  <th scope="col">AstraNull</th>
                  <th scope="col">Self-run load tests</th>
                  <th scope="col">Provider DDoS dashboards</th>
                </tr>
              </thead>
              <tbody>
                {LANDING_COMPARE.map(([label, anull, legacy, cloud]) => (
                  <tr key={label}>
                    <th scope="row">{label}</th>
                    <td className="public-compare-yes" data-label="AstraNull">{anull}</td>
                    <td data-label="Self-run load tests">{legacy}</td>
                    <td data-label="Provider DDoS dashboards">{cloud}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Reveal>

        <Reveal as="section" className="public-cta-final" aria-labelledby="cta-heading">
          <div>
            <h2 id="cta-heading">Start with one target you need to prove.</h2>
            <p>
              {signupEnabled
                ? 'Every request is reviewed before a workspace is created. Existing customers can log in.'
                : 'Access requests are closed on this deployment. Existing customers can log in.'}
            </p>
          </div>
          <div className="public-actions">
            {signupEnabled ? <AnchorButton href="/signup">Request access</AnchorButton> : null}
            <AnchorButton href={loginUrl} variant={signupEnabled ? 'secondary' : 'default'}>Log in</AnchorButton>
            {demoEnabled ? (
              <Button type="button" variant="ghost" onClick={() => enterDemoPortal(config.portalPath)}>
                Open demo workspace (sample data)
              </Button>
            ) : null}
          </div>
        </Reveal>
      </main>

      <footer className="public-footer">
        <div className="public-footer-inner">
          <span>© {productName}. Defensive DDoS readiness validation.</span>
          <nav aria-label="Public footer">
            <a href={loginUrl}>Log in</a>
            {signupEnabled ? <a href="/signup">Request access</a> : null}
            <a href="/signup-status">Request status</a>
            <a href="#how">How it works</a>
            <a href="#boundaries">Boundaries</a>
            <a href="#compare">Compare</a>
          </nav>
        </div>
      </footer>
    </PublicShell>
  );
}

/* ── Sign-in ────────────────────────────────────────────────────────── */

/**
 * Human copy for the credential lane's documented failures (see docs/api.md).
 *
 * `invalid_credentials` stays deliberately vague: the server returns the same
 * response for an unknown email and a wrong password so the form cannot be used
 * to enumerate accounts, and saying more here would undo that.
 */
function passwordLoginErrorMessage(response: Response, code: string, json: Record<string, unknown>) {
  switch (code) {
    case 'invalid_credentials':
      return 'Email or password is incorrect.';
    case 'validation_failed':
      return 'Enter a valid work email and your account password.';
    case 'tenant_required':
      return 'This email belongs to more than one workspace. Enter the workspace ID to continue.';
    case 'password_setup_required':
      return 'This account has no password yet. Use the invitation link from your administrator to set one.';
    case 'password_change_required':
      return 'Your password must be changed before you can sign in. Use the invitation link from your administrator.';
    case 'account_disabled':
      return 'This account is disabled. Contact your AstraNull administrator.';
    case 'account_locked':
      return `Too many failed attempts. This account is temporarily locked; try again ${retryAfterLabel(json, response)}.`;
    case 'rate_limited':
      return `Too many sign-in attempts. Try again ${retryAfterLabel(json, response)}.`;
    case 'password_login_disabled':
    case 'password_login_unavailable':
      return 'Password sign-in is not available on this deployment. Contact your administrator for the configured sign-in path.';
    default:
      return publicApiErrorMessage(response.status, json, 'Sign-in failed. Check your details and try again.');
  }
}

type LoginFlow = 'sign-in' | 'request-password-reset' | 'password-reset';

function resolveLoginFlow(): LoginFlow {
  if (typeof window === 'undefined') return 'sign-in';
  const flow = new URLSearchParams(window.location.search).get('flow');
  if (flow === 'request-password-reset' || flow === 'password-reset') return flow;
  return 'sign-in';
}

export function LoginPage(props: PublicPageProps) {
  const flow = resolveLoginFlow();
  if (flow === 'request-password-reset') return <RequestPasswordResetPage {...props} />;
  if (flow === 'password-reset') return <ResetPasswordPage {...props} />;
  return <CredentialLoginPage {...props} />;
}

const CUSTOMER_STAGING_ROLES = ['admin', 'engineer', 'soc', 'viewer', 'auditor', 'owner'] as const;

const CUSTOMER_STAGING_ROLE_LABELS: Record<(typeof CUSTOMER_STAGING_ROLES)[number], string> = {
  admin: 'Admin',
  engineer: 'Engineer',
  soc: 'SOC',
  viewer: 'Viewer',
  auditor: 'Auditor',
  owner: 'Owner'
};

function customerStagingRoleLabel(slug: string) {
  return CUSTOMER_STAGING_ROLE_LABELS[slug as (typeof CUSTOMER_STAGING_ROLES)[number]] ?? slug.replace(/_/g, ' ');
}

function LoginReturnNotice({ reason, label }: { reason: LoginReturnReason | null; label: string | null }) {
  if (!reason && !label) return null;
  const title = reason === 'session_expired'
    ? 'Your session ended. Log in again to continue.'
    : reason === 'signed_out'
      ? 'You are signed out.'
      : `Log in to open ${label}.`;
  return (
    <PublicNotice tone="info" title={title} role="status">
      {label && reason ? <p>After you log in, you return to {label}.</p> : null}
    </PublicNotice>
  );
}

function CredentialLoginPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Log in · AstraNull' });

  const context = useMemo(() => readLoginContext(config.portalPath), [config.portalPath]);
  const destination = context.destination ?? config.portalPath;

  const [userId, setUserId] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [totp, setTotp] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [tenantId, setTenantId] = useState('');
  const [tenantRequired, setTenantRequired] = useState(false);
  const [role, setRole] = useState('admin');
  const [error, setError] = useState('');
  const [errorCode, setErrorCode] = useState('');
  const [fieldErrors, setFieldErrors] = useState<{ email?: string; password?: string }>({});
  const [loading, setLoading] = useState(false);
  const [stagingBypass, setStagingBypass] = useState(false);
  const emailRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const errorRef = useRef<HTMLDivElement>(null);

  const isDevHeaders = config.authMode === 'dev-headers';
  const authUnknown = config.authMode === 'unknown';
  const isOidc = isOidcJwtMode(config);
  const idpRedirect = useMemo(() => resolveOidcLoginRedirect(config, 'customer'), [config]);
  // The credential lane is the real one. Dev headers stay ahead of it because that
  // mode has no credential store at all; everything else prefers a password.
  const passwordLane = !isDevHeaders && config.passwordLoginEnabled && !idpRedirect;
  // The old user-id + self-selected-role exchange is a staging bypass, not a login.
  // Once a password lane exists it is demoted behind an explicit disclosure so it
  // can never be mistaken for authentication.
  const stagingLane = isDevHeaders || (config.bundledLoginEnabled && !idpRedirect);
  const showStagingRolePicker = stagingLane && (!passwordLane || stagingBypass);
  const loginDisabled = isOidc && !passwordLane && !config.bundledLoginEnabled && !idpRedirect;
  const signupEnabled = config.siteConfig.signup_enabled !== false;
  const usePasswordLane = passwordLane && !stagingBypass;

  useEffect(() => {
    const existing = loadSession();
    if (existing?.access_token && existing.principal !== 'staff') {
      navigateSpa(destination);
    }
  }, [destination]);

  useEffect(() => {
    if (idpRedirect) window.location.replace(idpRedirect);
  }, [idpRedirect]);

  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);

  const lead = isDevHeaders
    ? 'Local developer mode. Pick an identity and role to preview the customer portal.'
    : passwordLane
      ? 'Use your work email and AstraNull password. We never ask for your cloud credentials.'
      : config.bundledLoginEnabled
        ? 'Staging sign-in for this environment. Production sign-in uses your organization identity provider.'
        : 'Sign-in uses your organization identity provider.';

  /** Submit the staging bypass exchange: no credential, role taken from the picker. */
  async function submitStagingBypass() {
    if (isDevHeaders) {
      saveSession({
        mode: 'dev-headers',
        principal: 'customer',
        tenant_id: 'ten_demo',
        user_id: userId.trim(),
        role
      });
      navigateSpa(destination);
      return;
    }
    const response = await fetch('/v1/auth/bundled-staging-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        principal: 'customer',
        tenant_id: 'ten_demo',
        user_id: userId.trim(),
        role
      })
    });
    const json = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(publicApiErrorMessage(
        response.status,
        json,
        'Sign-in failed. Check the selected staging identity and try again.'
      ));
    }
    saveSession(sessionFromLoginResponse(json as Record<string, unknown>));
    navigateSpa(destination);
  }

  /** Submit real credentials to the password lane. Role/tenant come from the server. */
  async function submitPasswordLogin() {
    const body: Record<string, unknown> = { email: userId.trim(), password };
    const scopedTenant = tenantId.trim();
    if (scopedTenant) body.tenant_id = scopedTenant;
    if (mfaRequired) body.totp = totp.trim();

    const response = await fetch('/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(body)
    });
    const json = (await response.json().catch(() => ({}))) as Record<string, unknown>;

    if (!response.ok) {
      const code = publicApiErrorCode(response.status, json);
      setErrorCode(code);
      if (code === 'tenant_required') setTenantRequired(true);
      if (code === 'mfa_required' || code === 'mfa_invalid') {
        setMfaRequired(true);
        setTotp('');
        throw new Error(code === 'mfa_required'
          ? 'Enter the 6-digit code from your authenticator app to continue.'
          : 'That authenticator code could not be verified. Enter the current 6-digit code.');
      }
      if (code === 'invalid_credentials') setPassword('');
      throw new Error(passwordLoginErrorMessage(response, code, json));
    }
    // Never keep plaintext credentials or a one-time code in component state past success.
    setPassword('');
    setTotp('');
    setMfaRequired(false);
    saveSession(sessionFromLoginResponse(json));
    navigateSpa(destination);
  }

  function clearMfaChallenge() {
    if (!mfaRequired) return;
    setMfaRequired(false);
    setTotp('');
    setError('');
    setErrorCode('');
  }

  function validate() {
    const next: { email?: string; password?: string } = {};
    const email = userId.trim();
    if (!email) next.email = usePasswordLane ? 'Enter your work email.' : 'Enter a user ID or work email.';
    else if (usePasswordLane && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) next.email = 'Enter a full work email, like name@company.com.';
    if (usePasswordLane && !password) next.password = 'Enter your password.';
    setFieldErrors(next);
    if (next.email) emailRef.current?.focus();
    else if (next.password) passwordRef.current?.focus();
    return !next.email && !next.password;
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (loginDisabled || loading) return;
    setError('');
    setErrorCode('');
    if (!validate()) return;
    setLoading(true);

    try {
      if (usePasswordLane) {
        await submitPasswordLogin();
      } else {
        await submitStagingBypass();
      }
    } catch (err) {
      setError(isNetworkFailure(err) ? NETWORK_ERROR_MESSAGE : err instanceof Error ? err.message : 'Sign-in failed.');
      setLoading(false);
    }
  }

  const links = (
    <>
      {passwordLane ? <a href={withNext('/login?flow=request-password-reset', context.next)}>Forgot password?</a> : null}
      {signupEnabled ? <a href="/signup">Request access</a> : null}
      <a href="/signup-status">Check request status</a>
    </>
  );

  let body: React.ReactNode;
  if (authUnknown) {
    body = (
      <PublicNotice
        tone="warn"
        role="alert"
        title="We could not confirm how this deployment signs people in."
        actions={<Button type="button" variant="secondary" onClick={() => window.location.reload()}>Try again</Button>}
      >
        <p>The sign-in service did not return its configuration. Nothing was submitted. Try again in a moment.</p>
      </PublicNotice>
    );
  } else if (idpRedirect) {
    body = (
      <AuthRedirectPanel
        lead="Redirecting to your identity provider…"
        help="You are being sent to your organization's sign-in page. If nothing happens, use the button below."
        href={idpRedirect}
      />
    );
  } else if (loginDisabled) {
    body = (
      <PublicNotice tone="info" role="note" title="Sign-in uses your organization identity provider.">
        <p>This deployment has no sign-in link configured, so there is nothing to submit here. Contact your AstraNull administrator for the correct sign-in address.</p>
      </PublicNotice>
    );
  } else {
    body = (
      <form className="auth-form" onSubmit={submit} aria-busy={loading} noValidate>
        <label htmlFor="login-user-id">
          <span>{usePasswordLane || isDevHeaders || config.bundledLoginEnabled ? 'Work email' : 'User ID'}</span>
          <input
            id="login-user-id"
            ref={emailRef}
            type={usePasswordLane ? 'email' : 'text'}
            value={userId}
            onChange={(event) => {
              setUserId(event.target.value);
              if (fieldErrors.email) setFieldErrors((current) => ({ ...current, email: undefined }));
              clearMfaChallenge();
            }}
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            required
            aria-invalid={fieldErrors.email ? true : undefined}
            aria-describedby={describedBy(fieldErrors.email && 'login-user-id-error')}
          />
          <FieldError id="login-user-id-error" message={fieldErrors.email} />
        </label>
        {usePasswordLane ? (
          <>
            <label htmlFor="login-password">
              <span>Password</span>
              <span className="auth-password-field">
                <input
                  id="login-password"
                  ref={passwordRef}
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(event) => {
                    setPassword(event.target.value);
                    if (fieldErrors.password) setFieldErrors((current) => ({ ...current, password: undefined }));
                    clearMfaChallenge();
                  }}
                  autoComplete="current-password"
                  required
                  maxLength={PASSWORD_MAX_LENGTH}
                  aria-invalid={fieldErrors.password ? true : undefined}
                  aria-describedby={describedBy(fieldErrors.password && 'login-password-error')}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="auth-password-toggle"
                  onClick={() => setShowPassword((current) => !current)}
                  aria-pressed={showPassword}
                >
                  {showPassword ? <EyeOff size={16} aria-hidden="true" /> : <Eye size={16} aria-hidden="true" />}
                  <span className="sr-only">{showPassword ? 'Hide password' : 'Show password'}</span>
                </Button>
              </span>
              <FieldError id="login-password-error" message={fieldErrors.password} />
            </label>
            {tenantRequired ? (
              <label htmlFor="login-tenant-scope">
                <span>Workspace ID</span>
                <input
                  id="login-tenant-scope"
                  value={tenantId}
                  onChange={(event) => {
                    setTenantId(event.target.value);
                    clearMfaChallenge();
                  }}
                  className="mono"
                  autoComplete="off"
                  required
                  aria-describedby="login-tenant-scope-help"
                />
                <span className="auth-field-help" id="login-tenant-scope-help">
                  This email belongs to more than one workspace. Enter the workspace ID you want to open.
                </span>
              </label>
            ) : null}
            {mfaRequired ? (
              <label htmlFor="login-totp">
                <span>Authenticator code</span>
                <input
                  id="login-totp"
                  value={totp}
                  onChange={(event) => setTotp(event.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="mono"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  minLength={6}
                  maxLength={6}
                  required
                  autoFocus
                  aria-describedby="login-totp-help"
                />
                <span className="auth-field-help" id="login-totp-help">
                  Enter the current 6-digit code from your authenticator app.
                </span>
              </label>
            ) : null}
          </>
        ) : null}
        {isDevHeaders ? (
          <label htmlFor="login-tenant-id">
            <span>Workspace</span>
            <input id="login-tenant-id" value="ten_demo" readOnly aria-readonly="true" />
          </label>
        ) : null}
        {showStagingRolePicker ? (
          <div className="auth-field-group">
            <Select
              label={isDevHeaders ? 'Role' : 'Staging role'}
              value={role}
              options={CUSTOMER_STAGING_ROLES.map((item) => ({
                value: item,
                label: customerStagingRoleLabel(item)
              }))}
              onChange={setRole}
            />
            {!isDevHeaders && config.bundledLoginEnabled ? (
              <span className="auth-field-help">Staging only. Production sign-in takes your role from your identity provider.</span>
            ) : null}
          </div>
        ) : null}
        {error ? (
          <div className="form-error public-form-error" role="alert" tabIndex={-1} ref={errorRef}>
            <p>{error}</p>
            {errorCode === 'password_setup_required' || errorCode === 'password_change_required' ? (
              <p><a href="/set-password">Set a password with your invitation</a></p>
            ) : null}
            {errorCode === 'invalid_credentials' && passwordLane ? (
              <p><a href={withNext('/login?flow=request-password-reset', context.next)}>Reset your password</a></p>
            ) : null}
          </div>
        ) : null}
        <div className={`auth-form-actions${isDevHeaders ? ' row-actions' : ''}`}>
          <Button type="submit" loading={loading} loadingText="Signing in…">
            {mfaRequired ? 'Verify and continue' : 'Continue to portal'}
          </Button>
          {isDevHeaders ? (
            <Button type="button" variant="secondary" onClick={() => enterDemoPortal(config.portalPath)}>
              Try demo
            </Button>
          ) : null}
        </div>
        {passwordLane && stagingLane ? (
          <details
            className="auth-bypass"
            open={stagingBypass}
            onToggle={(event) => setStagingBypass((event.currentTarget as HTMLDetailsElement).open)}
          >
            <summary>Staging role bypass</summary>
            <p className="auth-field-help">
              <TriangleAlert size={14} aria-hidden="true" />
              Non-production only. This exchange mints a session from a self-selected role and
              verifies no credential. It exists for staging walkthroughs and is refused on
              production deployments.
            </p>
          </details>
        ) : null}
      </form>
    );
  }

  return (
    <PublicShell activeNav="login" showEyebrow={false} signupEnabled={signupEnabled}>
      <AuthTaskLayout title="Log in to AstraNull" lead={lead} links={links}>
        <LoginReturnNotice reason={context.reason} label={context.label} />
        {isDevHeaders && !authUnknown ? (
          <PublicNotice tone="warn" role="note" title="Developer mode: no password is checked.">
            <p>Identity and role come from this form. Production deployments never show it.</p>
          </PublicNotice>
        ) : null}
        <Card className="auth-card public-auth-card">
          <CardContent>{body}</CardContent>
        </Card>
      </AuthTaskLayout>
    </PublicShell>
  );
}

/** Initiate password recovery without revealing account or delivery state. */
function RequestPasswordResetPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Reset your password · AstraNull', robots: 'noindex, nofollow' });

  const context = useMemo(() => readLoginContext(config.portalPath), [config.portalPath]);
  const backToLogin = withNext(config.loginUrl, context.next);
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError('');
    setSubmitted(false);
    setLoading(true);
    try {
      const response = await fetch('/v1/auth/request-password-reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ email: email.trim() })
      });
      const json = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      if (!response.ok) {
        const code = publicApiErrorCode(response.status, json);
        if (code === 'password_login_disabled' || code === 'password_login_unavailable') {
          throw new Error('Password recovery is not available on this deployment. Contact your administrator for the configured sign-in path.');
        }
        if (code === 'validation_failed') throw new Error('Enter a valid work email.');
        if (code === 'rate_limited') throw new Error(`Too many recovery requests. Try again ${retryAfterLabel(json, response)}.`);
        throw new Error(publicApiErrorMessage(
          response.status,
          json,
          'The recovery request could not be submitted. Try again.'
        ));
      }
      setEmail('');
      setSubmitted(true);
    } catch (err) {
      setError(isNetworkFailure(err) ? NETWORK_ERROR_MESSAGE : err instanceof Error ? err.message : 'The recovery request could not be submitted. Try again.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <PublicShell activeNav="login" showEyebrow={false} loginHref={config.loginUrl} signupEnabled={config.siteConfig.signup_enabled !== false}>
      <AuthTaskLayout
        title="Reset your password"
        lead="Enter your work email. For privacy, the response is the same whether or not an account exists."
        links={(
          <>
            <a href={backToLogin}>Back to log in</a>
            <a href="/login?flow=password-reset">I have a recovery code</a>
          </>
        )}
      >
        <Card className="auth-card public-auth-card">
          <CardContent>
            {submitted ? (
              <div className="success-panel" role="status" aria-live="polite">
                <PublicNotice tone="info" title="Request recorded.">
                  <p className="success-panel-lead">If an account is eligible and recovery delivery is configured and succeeds, instructions may arrive. This response confirms neither condition.</p>
                </PublicNotice>
                <div className="auth-form-actions row-actions">
                  <Button type="button" variant="secondary" onClick={() => setSubmitted(false)}>Use another email</Button>
                  <AnchorButton href={backToLogin}>Back to log in</AnchorButton>
                </div>
              </div>
            ) : (
              <form className="auth-form" onSubmit={submit} aria-busy={loading}>
                <label htmlFor="password-reset-email">
                  <span>Work email</span>
                  <input
                    id="password-reset-email"
                    type="email"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    autoComplete="email"
                    autoCapitalize="none"
                    spellCheck={false}
                    required
                    disabled={loading}
                  />
                </label>
                {error ? <div className="form-error public-form-error" role="alert"><p>{error}</p></div> : null}
                <div className="auth-form-actions">
                  <Button type="submit" loading={loading} loadingText="Submitting request…">Request recovery instructions</Button>
                </div>
              </form>
            )}
          </CardContent>
        </Card>
      </AuthTaskLayout>
    </PublicShell>
  );
}

/* ── Password fields shared by invitation and recovery ─────────────── */

function PasswordFields({
  idPrefix,
  password,
  onPasswordChange,
  confirm,
  onConfirmChange,
  disabled,
  serverFailures,
  confirmError,
  onConfirmBlur,
  passwordRef,
  confirmRef
}: {
  idPrefix: string;
  password: string;
  onPasswordChange: (value: string) => void;
  confirm: string;
  onConfirmChange: (value: string) => void;
  disabled: boolean;
  serverFailures: string[];
  confirmError: string;
  onConfirmBlur: () => void;
  passwordRef: React.Ref<HTMLInputElement>;
  confirmRef: React.Ref<HTMLInputElement>;
}) {
  const [showPassword, setShowPassword] = useState(false);
  const requirements = passwordRequirementStatus(password);
  const allMet = requirements.every((item) => item.met);
  const requirementsId = `${idPrefix}-requirements`;
  const policyErrorId = `${idPrefix}-policy-error`;
  const confirmErrorId = `${idPrefix}-confirm-error`;

  return (
    <>
      <label htmlFor={`${idPrefix}-new`}>
        <span>New password</span>
        <span className="auth-password-field">
          <input
            id={`${idPrefix}-new`}
            ref={passwordRef}
            type={showPassword ? 'text' : 'password'}
            value={password}
            onChange={(event) => onPasswordChange(event.target.value)}
            autoComplete="new-password"
            minLength={PASSWORD_MIN_LENGTH}
            maxLength={PASSWORD_MAX_LENGTH}
            required
            disabled={disabled}
            aria-invalid={serverFailures.length > 0 ? true : undefined}
            aria-describedby={describedBy(requirementsId, serverFailures.length > 0 && policyErrorId)}
          />
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="auth-password-toggle"
            onClick={() => setShowPassword((current) => !current)}
            aria-pressed={showPassword}
          >
            {showPassword ? <EyeOff size={16} aria-hidden="true" /> : <Eye size={16} aria-hidden="true" />}
            <span className="sr-only">{showPassword ? 'Hide passwords' : 'Show passwords'}</span>
          </Button>
        </span>
      </label>
      <div className="public-requirements" id={requirementsId}>
        <ul aria-label="Password requirements">
          {requirements.map((item) => (
            <li key={item.id} className={item.met ? 'is-met' : undefined}>
              {item.met ? <Check size={14} aria-hidden="true" /> : <Circle size={14} aria-hidden="true" />}
              <span className="sr-only">{item.met ? 'Met: ' : 'Not met yet: '}</span>
              {item.label}
            </li>
          ))}
        </ul>
        <p>Must not include the name part of your email or be a common password. Checked when you submit.</p>
        <span className="sr-only" aria-live="polite">{password && allMet ? 'Length and character requirements met.' : ''}</span>
      </div>
      {serverFailures.length > 0 ? (
        <ul className="public-field-error public-field-error-list" id={policyErrorId}>
          {serverFailures.map((message) => <li key={message}>{message}</li>)}
        </ul>
      ) : null}
      <label htmlFor={`${idPrefix}-confirm`}>
        <span>Confirm new password</span>
        <input
          id={`${idPrefix}-confirm`}
          ref={confirmRef}
          type={showPassword ? 'text' : 'password'}
          value={confirm}
          onChange={(event) => onConfirmChange(event.target.value)}
          onBlur={onConfirmBlur}
          autoComplete="new-password"
          maxLength={PASSWORD_MAX_LENGTH}
          required
          disabled={disabled}
          aria-invalid={confirmError ? true : undefined}
          aria-describedby={describedBy(confirmError && confirmErrorId)}
        />
        <FieldError id={confirmErrorId} message={confirmError} />
      </label>
    </>
  );
}

function usePasswordPair() {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [confirmError, setConfirmError] = useState('');
  const [serverFailures, setServerFailures] = useState<string[]>([]);
  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmRef = useRef<HTMLInputElement>(null);

  return {
    password,
    confirm,
    confirmError,
    serverFailures,
    passwordRef,
    confirmRef,
    setServerFailures,
    onPasswordChange(value: string) {
      setPassword(value);
      if (serverFailures.length) setServerFailures([]);
      if (confirmError && value === confirm) setConfirmError('');
    },
    onConfirmChange(value: string) {
      setConfirm(value);
      if (confirmError && value === password) setConfirmError('');
    },
    onConfirmBlur() {
      if (confirm && confirm !== password) setConfirmError('Passwords do not match.');
    },
    /** Client checks before submit; returns false and focuses the first problem. */
    validate() {
      if (!passwordRequirementStatus(password).every((item) => item.met)) {
        passwordRef.current?.focus();
        return 'Your new password does not meet the requirements yet.';
      }
      if (password !== confirm) {
        setConfirmError('Passwords do not match.');
        confirmRef.current?.focus();
        return 'Passwords do not match.';
      }
      return '';
    },
    clear() {
      setPassword('');
      setConfirm('');
      setConfirmError('');
      setServerFailures([]);
    }
  };
}

/** Read a one-time token from the query once, then strip it from the address bar. */
function useTransientUrlToken() {
  const [token, setToken] = useState(() => {
    if (typeof window === 'undefined') return '';
    return new URLSearchParams(window.location.search).get('token')?.trim() ?? '';
  });
  const [fromLink] = useState(() => Boolean(token));

  // The token is a live secret; drop it from the address bar so it does not persist
  // in history or leak through a Referer on the next click.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const url = new URL(window.location.href);
    if (!url.searchParams.has('token')) return;
    url.searchParams.delete('token');
    window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
  }, []);

  return { token, setToken, fromLink };
}

type TerminalTokenState = { title: string; body: string } | null;

/**
 * Consume a one-time password recovery token.
 *
 * Recovery is deliberately a distinct `flow=password-reset` mode on the public
 * login route. Invitation activation below continues to call /v1/auth/set-password.
 */
function ResetPasswordPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Choose a new password · AstraNull', robots: 'noindex, nofollow' });

  const { token, setToken, fromLink } = useTransientUrlToken();
  const [editToken, setEditToken] = useState(!fromLink);
  const pair = usePasswordPair();
  const [totp, setTotp] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [terminal, setTerminal] = useState<TerminalTokenState>(null);
  const errorRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (loading) return;
    setError('');
    pair.setServerFailures([]);
    if (!token.trim()) {
      setError('Enter the recovery code from your recovery message.');
      return;
    }
    const problem = pair.validate();
    if (problem) {
      setError(problem);
      return;
    }

    setLoading(true);
    try {
      const body: Record<string, unknown> = { token: token.trim(), password: pair.password };
      if (mfaRequired) body.totp = totp.trim();
      const response = await fetch('/v1/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', accept: 'application/json' },
        body: JSON.stringify(body)
      });
      const json = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      if (!response.ok) {
        const code = publicApiErrorCode(response.status, json);
        if (code === 'weak_password') {
          pair.setServerFailures(passwordPolicyMessages(json.failures));
          throw new Error('That password does not meet the password policy.');
        }
        if (code === 'mfa_required' || code === 'mfa_invalid') {
          setMfaRequired(true);
          setTotp('');
          throw new Error(code === 'mfa_required'
            ? 'Enter the 6-digit code from your authenticator app to complete recovery.'
            : 'That authenticator code could not be verified. Enter the current 6-digit code.');
        }
        if (code === 'invalid_reset_token' || code === 'reset_token_expired') {
          setToken('');
          pair.clear();
          setTerminal(code === 'reset_token_expired'
            ? { title: 'This recovery link has expired.', body: 'Your password was not changed. Request a new recovery link to continue.' }
            : { title: 'This recovery link cannot be used.', body: 'It may have been used already or replaced by a newer one. Your password was not changed by this attempt.' });
          return;
        }
        if (code === 'rate_limited') {
          throw new Error(`Too many attempts. Try again ${retryAfterLabel(json, response)}.`);
        }
        if (code === 'password_login_disabled' || code === 'password_login_unavailable') {
          throw new Error('Password recovery is not available on this deployment. Contact your administrator for the configured sign-in path.');
        }
        throw new Error(publicApiErrorMessage(
          response.status,
          json,
          'Could not reset the password. Check the recovery details and try again.'
        ));
      }
      pair.clear();
      setTotp('');
      setToken('');
      setMfaRequired(false);
      setDone(true);
    } catch (err) {
      setError(isNetworkFailure(err)
        ? 'We could not confirm whether your password changed. Try logging in with the new password first; if that fails, retry here.'
        : err instanceof Error ? err.message : 'Could not reset the password.');
    } finally {
      setLoading(false);
    }
  }

  let body: React.ReactNode;
  if (done) {
    body = (
      <div className="success-panel" role="status" aria-live="polite">
        <PublicNotice tone="success" title="Password changed.">
          <p>Earlier password sessions are signed out. Log in with your new password.</p>
        </PublicNotice>
        <div className="auth-form-actions">
          <AnchorButton href={config.loginUrl}>Log in</AnchorButton>
        </div>
      </div>
    );
  } else if (terminal) {
    body = (
      <PublicNotice
        tone="warn"
        role="alert"
        title={terminal.title}
        actions={(
          <>
            <AnchorButton href="/login?flow=request-password-reset">Request a new link</AnchorButton>
            <AnchorButton href={config.loginUrl} variant="secondary">Back to log in</AnchorButton>
          </>
        )}
      >
        <p>{terminal.body}</p>
      </PublicNotice>
    );
  } else {
    body = (
      <form className="auth-form" onSubmit={submit} aria-busy={loading} noValidate>
        {editToken ? (
          <label htmlFor="reset-password-token">
            <span>Recovery code</span>
            <input
              id="reset-password-token"
              type="password"
              value={token}
              onChange={(event) => {
                setToken(event.target.value);
                setMfaRequired(false);
                setTotp('');
              }}
              className="mono"
              autoComplete="off"
              spellCheck={false}
              required
              disabled={loading}
              data-1p-ignore="true"
              data-lpignore="true"
              aria-describedby="reset-password-token-help"
            />
            <span className="auth-field-help" id="reset-password-token-help">Paste the code from your recovery message. Opening the link fills it for you.</span>
          </label>
        ) : (
          <PublicNotice tone="info" role="note" title="Recovery link detected.">
            <p>Choose a new password below. The code from your link is kept only on this page.</p>
          </PublicNotice>
        )}
        <PasswordFields
          idPrefix="reset-password"
          password={pair.password}
          onPasswordChange={pair.onPasswordChange}
          confirm={pair.confirm}
          onConfirmChange={pair.onConfirmChange}
          onConfirmBlur={pair.onConfirmBlur}
          confirmError={pair.confirmError}
          serverFailures={pair.serverFailures}
          disabled={loading}
          passwordRef={pair.passwordRef}
          confirmRef={pair.confirmRef}
        />
        {mfaRequired ? (
          <label htmlFor="reset-password-totp">
            <span>Authenticator code</span>
            <input
              id="reset-password-totp"
              value={totp}
              onChange={(event) => setTotp(event.target.value.replace(/\D/g, '').slice(0, 6))}
              className="mono"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              minLength={6}
              maxLength={6}
              required
              autoFocus
              aria-describedby="reset-password-totp-help"
            />
            <span className="auth-field-help" id="reset-password-totp-help">
              Enter the current 6-digit code from your authenticator app.
            </span>
          </label>
        ) : null}
        {error ? <div className="form-error public-form-error" role="alert" tabIndex={-1} ref={errorRef}><p>{error}</p></div> : null}
        <div className="auth-form-actions">
          <Button type="submit" loading={loading} loadingText="Changing password…">
            {mfaRequired ? 'Verify and change password' : 'Change password'}
          </Button>
        </div>
        {!editToken ? (
          <button type="button" className="public-text-button" onClick={() => setEditToken(true)}>
            Use a different recovery code
          </button>
        ) : null}
      </form>
    );
  }

  return (
    <PublicShell activeNav="login" showEyebrow={false} loginHref={config.loginUrl} signupEnabled={config.siteConfig.signup_enabled !== false}>
      <AuthTaskLayout
        title={done ? 'Password changed' : 'Choose a new password'}
        lead={done ? undefined : 'Changing your password signs out existing password sessions and closes open recovery links.'}
        links={(
          <>
            <a href={config.loginUrl}>Back to log in</a>
            <a href="/login?flow=request-password-reset">Request a new recovery link</a>
          </>
        )}
      >
        <Card className="auth-card public-auth-card">
          <CardContent>{body}</CardContent>
        </Card>
      </AuthTaskLayout>
    </PublicShell>
  );
}

/**
 * Consume a one-time password invitation.
 *
 * `POST /v1/auth/set-password` deliberately does NOT return a session, so this
 * page hands the user to /login afterwards rather than signing them in.
 */
export function SetPasswordPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Set your password · AstraNull', robots: 'noindex, nofollow' });

  const { token, setToken, fromLink } = useTransientUrlToken();
  const [editToken, setEditToken] = useState(!fromLink);
  const pair = usePasswordPair();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState<Record<string, unknown> | null>(null);
  const [terminal, setTerminal] = useState<TerminalTokenState>(null);
  const errorRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (loading) return;
    setError('');
    pair.setServerFailures([]);
    if (!token.trim()) {
      setError('Enter the invitation code, or open the link from your invitation.');
      return;
    }
    const problem = pair.validate();
    if (problem) {
      setError(problem);
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('/v1/auth/set-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ token: token.trim(), password: pair.password })
      });
      const json = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      if (!response.ok) {
        const code = publicApiErrorCode(response.status, json);
        if (code === 'weak_password') {
          pair.setServerFailures(passwordPolicyMessages(json.failures));
          throw new Error('That password does not meet the password policy.');
        }
        if (code === 'invalid_invite' || code === 'invite_expired') {
          setToken('');
          pair.clear();
          setTerminal(code === 'invite_expired'
            ? { title: 'This invitation has expired.', body: 'No account was activated. Ask your AstraNull administrator to send a new invitation.' }
            : { title: 'This invitation cannot be used.', body: 'It may have been used already or replaced. No account was activated by this attempt. If you already set a password, log in.' });
          return;
        }
        if (code === 'rate_limited') {
          throw new Error(`Too many attempts. Try again ${retryAfterLabel(json, response)}.`);
        }
        if (code === 'password_login_disabled' || code === 'password_login_unavailable') {
          throw new Error('Password setup is not available on this deployment. Your organization signs in through its identity provider.');
        }
        throw new Error(publicApiErrorMessage(
          response.status,
          json,
          'Could not set the password. Check the invitation details and try again.'
        ));
      }
      pair.clear();
      setToken('');
      setDone(json);
    } catch (err) {
      setError(isNetworkFailure(err)
        ? 'We could not confirm whether your password was set. Try logging in first; if that fails, retry with the same invitation.'
        : err instanceof Error ? err.message : 'Could not set the password.');
    } finally {
      setLoading(false);
    }
  }

  const activatedEmail = done ? String(done.email ?? '').trim() : '';

  let body: React.ReactNode;
  if (done) {
    body = (
      <div className="success-panel" role="status" aria-live="polite">
        <PublicNotice tone="success" title="Your account is active.">
          <p>
            {activatedEmail
              ? <>Log in as <strong>{activatedEmail}</strong> with the password you just chose.</>
              : 'Log in with your work email and the password you just chose.'}
            {' '}The invitation is now closed.
          </p>
        </PublicNotice>
        <div className="auth-form-actions">
          <AnchorButton href={config.loginUrl}>Log in</AnchorButton>
        </div>
      </div>
    );
  } else if (terminal) {
    body = (
      <PublicNotice
        tone="warn"
        role="alert"
        title={terminal.title}
        actions={<AnchorButton href={config.loginUrl} variant="secondary">Go to log in</AnchorButton>}
      >
        <p>{terminal.body}</p>
      </PublicNotice>
    );
  } else {
    body = (
      <form className="auth-form" onSubmit={submit} aria-busy={loading} noValidate>
        {editToken ? (
          <label htmlFor="set-password-token">
            <span>Invitation code</span>
            <input
              id="set-password-token"
              type="password"
              value={token}
              onChange={(event) => setToken(event.target.value)}
              className="mono"
              autoComplete="off"
              spellCheck={false}
              required
              disabled={loading}
              data-1p-ignore="true"
              data-lpignore="true"
              aria-describedby="set-password-token-help"
            />
            <span className="auth-field-help" id="set-password-token-help">
              Opening the link in your invitation fills this for you. Only paste a code if the link does not open.
            </span>
          </label>
        ) : (
          <PublicNotice tone="info" role="note" title="Invitation link detected.">
            <p>Choose a password below. The code from your link is kept only on this page.</p>
          </PublicNotice>
        )}
        <PasswordFields
          idPrefix="set-password"
          password={pair.password}
          onPasswordChange={pair.onPasswordChange}
          confirm={pair.confirm}
          onConfirmChange={pair.onConfirmChange}
          onConfirmBlur={pair.onConfirmBlur}
          confirmError={pair.confirmError}
          serverFailures={pair.serverFailures}
          disabled={loading}
          passwordRef={pair.passwordRef}
          confirmRef={pair.confirmRef}
        />
        {error ? <div className="form-error public-form-error" role="alert" tabIndex={-1} ref={errorRef}><p>{error}</p></div> : null}
        <div className="auth-form-actions">
          <Button type="submit" loading={loading} loadingText="Setting password…">Set password</Button>
        </div>
        {!editToken ? (
          <button type="button" className="public-text-button" onClick={() => setEditToken(true)}>
            Use a different invitation code
          </button>
        ) : null}
      </form>
    );
  }

  return (
    <PublicShell activeNav="login" showEyebrow={false} loginHref={config.loginUrl} signupEnabled={config.siteConfig.signup_enabled !== false}>
      <AuthTaskLayout
        title={done ? 'Password set' : 'Set your password'}
        lead={done ? undefined : 'Your invitation lets you set a password once. Your role and workspace come from the invitation, not this form.'}
        links={<a href={config.loginUrl}>Back to log in</a>}
      >
        <Card className="auth-card public-auth-card">
          <CardContent>{body}</CardContent>
        </Card>
      </AuthTaskLayout>
    </PublicShell>
  );
}

/* ── Request access ─────────────────────────────────────────────────── */

const SIGNUP_PLAN_LABELS: Record<string, string> = {
  starter: 'Starter',
  professional: 'Professional',
  enterprise: 'Enterprise'
};

const SIGNUP_REGION_LABELS: Record<string, string> = {
  us: 'United States',
  eu: 'European Union',
  uk: 'United Kingdom',
  apac: 'Asia-Pacific'
};

function signupPlanLabel(slug: unknown) {
  const key = String(slug ?? '').trim();
  return SIGNUP_PLAN_LABELS[key] ?? (key || 'Not recorded');
}

function signupRegionLabel(slug: unknown) {
  const key = String(slug ?? '').trim();
  return SIGNUP_REGION_LABELS[key] ?? (key || 'Not recorded');
}

type SignupPlanOption = { value: string; label: string };

// Consume plans[] from the public site-config so the requested-plan options reflect
// the server's subscription catalog. Falls back to the static labels if omitted.
function signupPlanOptions(config: PublicPageProps['config']): SignupPlanOption[] {
  const rawPlans = (config.siteConfig as { plans?: unknown }).plans;
  if (Array.isArray(rawPlans)) {
    const options = rawPlans
      .map((plan): SignupPlanOption | null => {
        if (!plan || typeof plan !== 'object') return null;
        const record = plan as Record<string, unknown>;
        const value = String(record.id ?? '').trim();
        if (!value) return null;
        const label = String(record.name ?? '').trim() || signupPlanLabel(value);
        return { value, label };
      })
      .filter((option): option is SignupPlanOption => option !== null);
    if (options.length > 0) return options;
  }
  return Object.entries(SIGNUP_PLAN_LABELS).map(([value, label]) => ({ value, label }));
}

function formatRecordedTime(value: unknown) {
  const raw = String(value ?? '').trim();
  if (!raw) return null;
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function SignupRequestFacts({ record }: { record: Record<string, unknown> }) {
  const created = formatRecordedTime(record.created_at);
  const updated = formatRecordedTime(record.updated_at);
  return (
    <dl className="public-facts">
      <div>
        <dt>Organization</dt>
        <dd>{String(record.organization_name ?? '').trim() || 'Not recorded'}</dd>
      </div>
      <div>
        <dt>Requested plan</dt>
        <dd>{signupPlanLabel(record.requested_plan)} <span className="public-facts-note">(requested, not granted)</span></dd>
      </div>
      <div>
        <dt>Region</dt>
        <dd>{signupRegionLabel(record.region)}</dd>
      </div>
      {created ? (
        <div>
          <dt>Submitted</dt>
          <dd>{created}</dd>
        </div>
      ) : null}
      {updated && updated !== created ? (
        <div>
          <dt>Last updated</dt>
          <dd>{updated}</dd>
        </div>
      ) : null}
    </dl>
  );
}

type SignupField = 'organization_name' | 'contact_name' | 'contact_email' | 'intended_use' | 'requested_plan' | 'region';

const SIGNUP_FIELD_MESSAGES: Record<SignupField, string> = {
  organization_name: 'Enter your organization name (at least 2 characters).',
  contact_name: 'Enter the contact person’s name (at least 2 characters).',
  contact_email: 'Enter a valid work email, like name@company.com.',
  intended_use: 'Describe what you want to validate (at least 8 characters).',
  requested_plan: 'Choose a plan.',
  region: 'Choose a region.'
};

const SIGNUP_FIELD_ORDER: SignupField[] = ['organization_name', 'contact_name', 'contact_email', 'requested_plan', 'region', 'intended_use'];

export function validateSignupDraft(values: Record<SignupField, string>): Partial<Record<SignupField, string>> {
  const errors: Partial<Record<SignupField, string>> = {};
  if (values.organization_name.trim().length < 2) errors.organization_name = SIGNUP_FIELD_MESSAGES.organization_name;
  if (values.contact_name.trim().length < 2) errors.contact_name = SIGNUP_FIELD_MESSAGES.contact_name;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.contact_email.trim())) errors.contact_email = SIGNUP_FIELD_MESSAGES.contact_email;
  if (values.intended_use.trim().length < 8) errors.intended_use = SIGNUP_FIELD_MESSAGES.intended_use;
  if (!values.requested_plan) errors.requested_plan = SIGNUP_FIELD_MESSAGES.requested_plan;
  if (!values.region) errors.region = SIGNUP_FIELD_MESSAGES.region;
  return errors;
}

function serverFieldErrors(json: Record<string, unknown>): Partial<Record<SignupField, string>> {
  const fields = Array.isArray(json.fields) ? json.fields.map(String) : [];
  const errors: Partial<Record<SignupField, string>> = {};
  for (const field of fields) {
    const key = (field === 'contact_email_domain' ? 'contact_email' : field) as SignupField;
    if (SIGNUP_FIELD_MESSAGES[key]) errors[key] = SIGNUP_FIELD_MESSAGES[key];
  }
  return errors;
}

function signupSubmitErrorMessage(status: number, json: Record<string, unknown>) {
  const code = publicApiErrorCode(status, json);
  if (status === 429 || code === 'rate_limited') {
    return 'Too many requests from this network. Wait a few minutes, then submit again. Your answers are still here.';
  }
  if (code === 'duplicate_request') {
    return 'A request for this organization or email domain is already open. Use the request ID from your first confirmation to check its status.';
  }
  if (status === 403 || code === 'signup_disabled') {
    return 'Access requests are closed on this deployment right now. Nothing was submitted.';
  }
  if (code === 'validation_failed') {
    return 'Some answers need attention. Check the highlighted fields.';
  }
  return publicApiErrorMessage(status, json, 'Could not submit the request. Your answers are still here; try again.');
}

const SIGNUP_PREVIEW_STAGES: LifecycleStage[] = [
  ...SIGNUP_STAGES.map((stage) => ({ ...stage, status: 'upcoming' as const })),
  { ...SIGNUP_FINAL_STAGE, detail: 'You open the invitation, set a password and log in.', status: 'upcoming' as const }
];

const EMPTY_SIGNUP_DRAFT: Record<SignupField, string> = {
  organization_name: '',
  contact_name: '',
  contact_email: '',
  intended_use: '',
  requested_plan: 'professional',
  region: 'us'
};

export function SignupPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Request access · AstraNull' });

  const signupEnabled = config.siteConfig.signup_enabled !== false;
  const [submitted, setSubmitted] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [hydrating, setHydrating] = useState(false);
  const [hydrateFailedId, setHydrateFailedId] = useState('');
  const [values, setValues] = useState<Record<SignupField, string>>(EMPTY_SIGNUP_DRAFT);
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<SignupField, string>>>({});
  const planOptions = useMemo(() => signupPlanOptions(config), [config]);
  const fieldRefs = useRef<Partial<Record<SignupField, HTMLElement | null>>>({});
  const errorRef = useRef<HTMLDivElement>(null);
  const confirmationRef = useRef<HTMLDivElement>(null);
  const contact = publicSupportContact(config.siteConfig);

  useEffect(() => {
    if (planOptions.length > 0 && !planOptions.some((option) => option.value === values.requested_plan)) {
      setValues((current) => ({ ...current, requested_plan: planOptions[0].value }));
    }
  }, [planOptions, values.requested_plan]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const id = new URLSearchParams(window.location.search).get('id')?.trim();
    if (!id) return;

    let cancelled = false;
    setHydrating(true);
    void (async () => {
      try {
        const response = await fetch(`/v1/signup-requests/${encodeURIComponent(id)}`, {
          headers: { accept: 'application/json' }
        });
        const json = await response.json().catch(() => ({}));
        if (cancelled) return;
        if (!response.ok) {
          setHydrateFailedId(id);
          return;
        }
        setSubmitted((json.request ?? json) as Record<string, unknown>);
      } catch {
        if (!cancelled) setHydrateFailedId(id);
      } finally {
        if (!cancelled) setHydrating(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (submitted) confirmationRef.current?.focus();
  }, [submitted]);

  function update(field: SignupField, value: string) {
    setValues((current) => ({ ...current, [field]: value }));
    if (fieldErrors[field]) setFieldErrors((current) => ({ ...current, [field]: undefined }));
  }

  function focusFirstInvalid(errors: Partial<Record<SignupField, string>>) {
    const first = SIGNUP_FIELD_ORDER.find((field) => errors[field]);
    if (!first) return false;
    const node = fieldRefs.current[first];
    (node?.querySelector?.('button, input, textarea') as HTMLElement | null ?? node)?.focus();
    return true;
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!signupEnabled || loading) return;
    setError('');
    const clientErrors = validateSignupDraft(values);
    setFieldErrors(clientErrors);
    if (focusFirstInvalid(clientErrors)) return;

    setLoading(true);
    const body = {
      organization_name: values.organization_name.trim(),
      contact_email: values.contact_email.trim(),
      contact_name: values.contact_name.trim(),
      requested_plan: values.requested_plan,
      intended_use: values.intended_use.trim(),
      region: values.region
    };
    try {
      const response = await fetch('/v1/signup-requests', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', accept: 'application/json' },
        body: JSON.stringify(body)
      });
      const json = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      if (!response.ok) {
        const serverErrors = serverFieldErrors(json);
        if (Object.keys(serverErrors).length) {
          setFieldErrors(serverErrors);
          focusFirstInvalid(serverErrors);
        }
        throw new Error(signupSubmitErrorMessage(response.status, json));
      }
      const record = (json.request ?? json) as Record<string, unknown>;
      setValues(EMPTY_SIGNUP_DRAFT);
      setSubmitted(record);
      const submittedId = String(record.id ?? '').trim();
      if (submittedId && typeof window !== 'undefined') {
        const url = new URL(window.location.href);
        url.searchParams.set('id', submittedId);
        window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
      }
    } catch (err) {
      setError(isNetworkFailure(err)
        ? 'Could not reach AstraNull, so the request may not have been recorded. Your answers are still here; try again.'
        : err instanceof Error ? err.message : 'Could not submit the request.');
      window.setTimeout(() => errorRef.current?.focus(), 0);
    } finally {
      setLoading(false);
    }
  }

  const submittedId = String(submitted?.id ?? '').trim();

  function fieldProps(field: SignupField, describedId?: string) {
    const errorId = `signup-${field}-error`;
    return {
      'aria-invalid': fieldErrors[field] ? true : undefined,
      'aria-describedby': describedBy(describedId, fieldErrors[field] && errorId),
      disabled: loading
    } as const;
  }

  let content: React.ReactNode;
  if (!signupEnabled && !submitted) {
    content = (
      <PublicNotice
        tone="warn"
        title="Access requests are closed on this deployment."
        actions={(
          <>
            <AnchorButton href="/signup-status">Check request status</AnchorButton>
            <AnchorButton href={config.loginUrl} variant="secondary">Log in</AnchorButton>
          </>
        )}
      >
        <p>Existing customers can log in. If you already submitted a request, you can still check its status.</p>
      </PublicNotice>
    );
  } else if (hydrating) {
    content = (
      <div className="public-loading" role="status" aria-live="polite" aria-busy="true">
        <p className="success-panel-lead">Loading your request confirmation…</p>
        <span className="skeleton skeleton-row" aria-hidden="true" />
        <span className="skeleton skeleton-row" aria-hidden="true" />
        <span className="skeleton skeleton-row" aria-hidden="true" />
      </div>
    );
  } else if (submitted) {
    const stages = signupLifecycleStages(submitted.state ?? 'submitted');
    content = (
      <div className="public-confirmation" ref={confirmationRef} tabIndex={-1} aria-labelledby="signup-confirmation-title">
        <PublicNotice tone="success" role="status" title="Request received.">
          <p>No account exists yet. AstraNull reviews every request before creating a workspace.</p>
        </PublicNotice>
        {submittedId ? <RequestReference id={submittedId} /> : null}
        <p className="public-help-line" id="signup-confirmation-title">
          Keep this ID to check status. This page's address also contains it, so you can bookmark it.
        </p>
        <SignupRequestFacts record={submitted} />
        {stages.length ? <SignupLifecycle stages={stages} label="Request progress" /> : null}
        <div className="auth-form-actions row-actions">
          <AnchorButton href={`/signup-status?id=${encodeURIComponent(submittedId)}`}>Check status</AnchorButton>
          <AnchorButton href="/" variant="secondary">Back to home</AnchorButton>
        </div>
      </div>
    );
  } else {
    content = (
      <>
        {hydrateFailedId ? (
          <PublicNotice
            tone="warn"
            role="status"
            title="We could not load that request confirmation."
            actions={<AnchorButton href={`/signup-status?id=${encodeURIComponent(hydrateFailedId)}`} variant="secondary">Check its status instead</AnchorButton>}
          >
            <p>The ID in this address was not found or the lookup failed. Submitting this form creates a new request.</p>
          </PublicNotice>
        ) : null}
        <form className="auth-form auth-form--grid" onSubmit={submit} aria-busy={loading} noValidate>
          <label htmlFor="signup-organization" ref={(node) => { fieldRefs.current.organization_name = node; }}>
            <span>Organization</span>
            <input
              id="signup-organization"
              name="organization_name"
              value={values.organization_name}
              onChange={(event) => update('organization_name', event.target.value)}
              required
              autoComplete="organization"
              {...fieldProps('organization_name')}
            />
            <FieldError id="signup-organization_name-error" message={fieldErrors.organization_name} />
          </label>
          <label htmlFor="signup-contact" ref={(node) => { fieldRefs.current.contact_name = node; }}>
            <span>Contact name</span>
            <input
              id="signup-contact"
              name="contact_name"
              value={values.contact_name}
              onChange={(event) => update('contact_name', event.target.value)}
              required
              autoComplete="name"
              {...fieldProps('contact_name')}
            />
            <FieldError id="signup-contact_name-error" message={fieldErrors.contact_name} />
          </label>
          <label className="auth-field-full" htmlFor="signup-email" ref={(node) => { fieldRefs.current.contact_email = node; }}>
            <span>Work email</span>
            <input
              id="signup-email"
              name="contact_email"
              type="email"
              value={values.contact_email}
              onChange={(event) => update('contact_email', event.target.value)}
              required
              autoComplete="email"
              autoCapitalize="none"
              spellCheck={false}
              {...fieldProps('contact_email', 'signup-email-help')}
            />
            <span className="auth-field-help" id="signup-email-help">Used only to follow up on this request.</span>
            <FieldError id="signup-contact_email-error" message={fieldErrors.contact_email} />
          </label>
          <div ref={(node) => { fieldRefs.current.requested_plan = node; }}>
            <Select
              label="Requested plan"
              name="requested_plan"
              value={values.requested_plan}
              options={planOptions}
              onChange={(value) => update('requested_plan', value)}
              disabled={loading}
              hint="A request, not an entitlement. The plan is confirmed during review."
              error={fieldErrors.requested_plan}
            />
          </div>
          <div ref={(node) => { fieldRefs.current.region = node; }}>
            <Select
              label="Data region"
              name="region"
              value={values.region}
              options={Object.entries(SIGNUP_REGION_LABELS).map(([value, label]) => ({ value, label }))}
              onChange={(value) => update('region', value)}
              disabled={loading}
              hint="Where you would like workspace data to be kept."
              error={fieldErrors.region}
            />
          </div>
          <label className="auth-field-full" htmlFor="signup-intended-use" ref={(node) => { fieldRefs.current.intended_use = node; }}>
            <span>What do you want to validate?</span>
            <textarea
              id="signup-intended-use"
              name="intended_use"
              value={values.intended_use}
              onChange={(event) => update('intended_use', event.target.value)}
              required
              rows={4}
              {...fieldProps('intended_use', 'signup-intended-use-help')}
            />
            <span className="auth-field-help" id="signup-intended-use-help">
              For example: public websites and APIs we own, and how they respond to bursts of traffic. Do not include credentials.
            </span>
            <FieldError id="signup-intended_use-error" message={fieldErrors.intended_use} />
          </label>
          {error ? (
            <div className="form-error public-form-error auth-field-full" role="alert" tabIndex={-1} ref={errorRef}>
              <p>{error}</p>
            </div>
          ) : null}
          <div className="auth-form-actions auth-field-full">
            <Button type="submit" loading={loading} loadingText="Submitting request…">Submit request</Button>
          </div>
        </form>
      </>
    );
  }

  return (
    <PublicShell activeNav="signup" showEyebrow={false} loginHref={config.loginUrl} signupEnabled={signupEnabled}>
      <AuthPageLayout
        wide
        aside={(
          <>
            <h1 className="auth-title">Request access to AstraNull.</h1>
            <p className="auth-lead">Tell us who you are and what you want to validate. Every request is reviewed before a workspace is created.</p>
            <ul className="auth-points">
              <li><ShieldCheck size={16} aria-hidden="true" />No cloud credentials, agents or IP discovery are needed.</li>
              <li><LockKeyhole size={16} aria-hidden="true" />Submitting does not create an account or grant a plan.</li>
            </ul>
          </>
        )}
        footer={(
          <p>
            Already have access? <a href={config.loginUrl}>Log in</a>
            {' · '}
            <a href="/signup-status">Check request status</a>
          </p>
        )}
      >
        <Card className="auth-card auth-card--wide public-auth-card">
          <CardHeader className="auth-card-header">
            <div className="auth-card-heading">
              <CardTitle>{submitted ? 'Request submitted' : 'Request an AstraNull account'}</CardTitle>
              {!submitted && signupEnabled ? <CardDescription>All fields are required.</CardDescription> : null}
            </div>
          </CardHeader>
          <CardContent>{content}</CardContent>
        </Card>
        {!submitted && signupEnabled && !hydrating ? (
          <section className="public-next-steps" aria-labelledby="signup-next-heading">
            <h2 id="signup-next-heading">What happens after you submit</h2>
            <p className="public-help-line">Each step is recorded. Check progress any time with your request ID.</p>
            <SignupLifecycle stages={SIGNUP_PREVIEW_STAGES} label="Request steps" />
          </section>
        ) : null}
        {submitted ? <LostReferenceHelp contact={contact} /> : null}
      </AuthPageLayout>
    </PublicShell>
  );
}

/* ── Request status ─────────────────────────────────────────────────── */

type StatusLookupError = { kind: 'not_found' | 'rate_limited' | 'unavailable' | 'empty'; message: string };

export function SignupStatusPage({ config }: Partial<PublicPageProps> = {}) {
  usePageMeta({ title: 'Request status · AstraNull' });

  const [requestId, setRequestId] = useState(() => {
    if (typeof window === 'undefined') return '';
    return new URLSearchParams(window.location.search).get('id')?.trim() ?? '';
  });
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [lookupError, setLookupError] = useState<StatusLookupError | null>(null);
  const [loading, setLoading] = useState(false);
  const [siteConfig, setSiteConfig] = useState<Record<string, unknown> | null>(config?.siteConfig ?? null);
  const inputRef = useRef<HTMLInputElement>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const loginUrl = config?.loginUrl ?? String(siteConfig?.login_url ?? '/login');

  useEffect(() => {
    if (config?.siteConfig) return;
    let cancelled = false;
    void fetch('/v1/public/site-config', { headers: { accept: 'application/json' } })
      .then((response) => (response.ok ? response.json() : {}))
      .then((json) => {
        if (!cancelled) setSiteConfig(json && typeof json === 'object' ? json as Record<string, unknown> : {});
      })
      .catch(() => {
        if (!cancelled) setSiteConfig({});
      });
    return () => {
      cancelled = true;
    };
  }, [config?.siteConfig]);

  const contact = siteConfig === null ? undefined : publicSupportContact(siteConfig);

  async function lookupSignupRequest(id: string) {
    const trimmed = id.trim();
    if (!trimmed) {
      setLookupError({ kind: 'empty', message: 'Enter a request ID to check status.' });
      inputRef.current?.focus();
      return;
    }
    setRequestId(trimmed);
    setLookupError(null);
    setResult(null);
    setLoading(true);
    try {
      const response = await fetch(`/v1/signup-requests/${encodeURIComponent(trimmed)}`, {
        headers: { accept: 'application/json' }
      });
      const json = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      if (!response.ok) {
        const code = publicApiErrorCode(response.status, json);
        if (response.status === 429 || code === 'rate_limited') {
          setLookupError({ kind: 'rate_limited', message: `Too many status lookups. Try again ${retryAfterLabel(json, response)}.` });
        } else if (response.status === 404) {
          setLookupError({ kind: 'not_found', message: 'No request matches this ID. Check each character; IDs are case-sensitive.' });
        } else {
          setLookupError({
            kind: 'unavailable',
            message: publicApiErrorMessage(response.status, json, 'Status could not be loaded right now. Your ID is kept; try again.')
          });
        }
        return;
      }
      setResult((json.request ?? json) as Record<string, unknown>);
      if (typeof window !== 'undefined') {
        const url = new URL(window.location.href);
        url.searchParams.set('id', trimmed);
        window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
      }
      window.setTimeout(() => resultRef.current?.focus(), 0);
    } catch {
      setLookupError({ kind: 'unavailable', message: 'Could not reach AstraNull. Your ID is kept; try again.' });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const urlId = new URLSearchParams(window.location.search).get('id')?.trim();
    if (!urlId) return;
    void lookupSignupRequest(urlId);
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (loading) return;
    await lookupSignupRequest(requestId);
  }

  const state = result ? (result.state ?? result.status) : null;
  const stages = result ? signupLifecycleStages(state) : [];
  const next = result ? signupNextStep(state) : null;
  const notice = result ? String(result.customer_notice ?? '').trim() : '';
  const fieldError = lookupError && (lookupError.kind === 'empty' || lookupError.kind === 'not_found') ? lookupError.message : '';

  return (
    <PublicShell showEyebrow={false} loginHref={loginUrl} signupEnabled={false}>
      <AuthTaskLayout
        title="Check an access request"
        lead="Enter the request ID from your confirmation. You do not need an account to check status."
        links={(
          <>
            <a href={loginUrl}>Log in</a>
            {siteConfig?.signup_enabled !== false ? <a href="/signup">Request access</a> : null}
          </>
        )}
      >
        <Card className="auth-card public-auth-card">
          <CardContent>
            <form className="auth-form" onSubmit={submit} aria-busy={loading} noValidate>
              <label htmlFor="signup-status-request-id">
                <span>Request ID</span>
                <input
                  id="signup-status-request-id"
                  ref={inputRef}
                  value={requestId}
                  onChange={(event) => {
                    setRequestId(event.target.value);
                    if (lookupError?.kind === 'empty' || lookupError?.kind === 'not_found') setLookupError(null);
                  }}
                  placeholder="sgn_…"
                  className="mono"
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  required
                  disabled={loading}
                  aria-invalid={fieldError ? true : undefined}
                  aria-describedby={describedBy('signup-status-request-id-help', fieldError && 'signup-status-request-id-error')}
                />
                <span className="auth-field-help" id="signup-status-request-id-help">Starts with sgn_. Letters are case-sensitive; spaces are ignored.</span>
                <FieldError id="signup-status-request-id-error" message={fieldError} />
              </label>
              {lookupError && !fieldError ? (
                <div className="form-error public-form-error" role="alert">
                  <p>{lookupError.message}</p>
                </div>
              ) : null}
              <div className="auth-form-actions">
                <Button type="submit" loading={loading} loadingText="Checking…">
                  {lookupError?.kind === 'unavailable' || lookupError?.kind === 'rate_limited' ? 'Try again' : 'Check status'}
                </Button>
              </div>
            </form>
            {loading ? (
              <div className="public-loading" role="status" aria-live="polite" aria-busy="true">
                <span className="sr-only">Loading request status</span>
                <span className="skeleton skeleton-row" aria-hidden="true" />
                <span className="skeleton skeleton-row" aria-hidden="true" />
                <span className="skeleton skeleton-row" aria-hidden="true" />
              </div>
            ) : null}
            {result && next ? (
              <div className="public-status-result" ref={resultRef} tabIndex={-1} aria-labelledby="signup-status-result-title">
                <div className="public-status-head">
                  <h2 id="signup-status-result-title">{signupStateLabel(state)}</h2>
                  <Badge tone={signupStateTone(state)}>{next.canSignIn ? 'Ready to activate' : normalizeSignupState(state) === 'rejected' ? 'Closed' : 'No sign-in yet'}</Badge>
                </div>
                <PublicNotice
                  tone={normalizeSignupState(state) === 'rejected' ? 'warn' : next.canSignIn ? 'success' : 'info'}
                  role="status"
                  title={next.headline}
                  actions={next.canSignIn ? <AnchorButton href={loginUrl}>Log in</AnchorButton> : undefined}
                >
                  <p>{next.body}</p>
                </PublicNotice>
                {notice ? (
                  <blockquote className="public-reviewer-note">
                    <p className="public-reviewer-note-label">Message from AstraNull</p>
                    <p>{notice}</p>
                  </blockquote>
                ) : null}
                {stages.length ? <SignupLifecycle stages={stages} label="Request progress" /> : null}
                <SignupRequestFacts record={result} />
                <p className="public-help-line">Dates come from the request record. AstraNull does not estimate when the next step happens.</p>
              </div>
            ) : null}
          </CardContent>
        </Card>
        <LostReferenceHelp contact={contact} />
      </AuthTaskLayout>
    </PublicShell>
  );
}

/* ── Unavailable routes: not found, access denied and missing records stay distinct ── */

export type PortalUnavailableKind = 'not-found' | 'access-denied' | 'record-missing';

/** Keep only the route part of a hash for display; query strings can carry identifiers. */
export function displayRequestedRoute(hash: string | null | undefined): string {
  const raw = String(hash ?? '').replace(/^#/, '').split('?')[0] ?? '';
  const cleaned = raw.replace(/[^A-Za-z0-9_./-]/g, '').slice(0, 80);
  return cleaned ? `#${cleaned}` : '';
}

export function PortalUnavailablePage({
  kind,
  requestedHash,
  requestedLabel,
  role,
  homeHref = '#dashboard',
  homeLabel = 'Go to dashboard',
  parentHref,
  parentLabel
}: {
  kind: PortalUnavailableKind;
  requestedHash?: string;
  requestedLabel?: string;
  role?: string;
  homeHref?: string;
  homeLabel?: string;
  parentHref?: string;
  parentLabel?: string;
}) {
  const requested = displayRequestedRoute(requestedHash ?? (typeof window === 'undefined' ? '' : window.location.hash));
  const roleLabel = String(role ?? '').trim();
  const [canGoBack] = useState(() => typeof window !== 'undefined' && window.history.length > 1);

  const copy = kind === 'access-denied'
    ? {
      title: 'You do not have access to this page.',
      body: `${requestedLabel ?? 'This page'} is not available to ${roleLabel ? `the ${roleLabel} role` : 'your role'}. Nothing from it was loaded.`,
      help: 'If you need it, ask a workspace owner or admin to review your role.',
      Icon: LockKeyhole
    }
    : kind === 'record-missing'
      ? {
        title: 'This record is not available.',
        body: `${requestedLabel ? `The ${requestedLabel.toLowerCase()} you asked for` : 'The record you asked for'} could not be found. It may have been removed, or the link may be incomplete. No placeholder values are shown in its place.`,
        help: '',
        Icon: FileQuestion
      }
      : {
        title: 'This page is unavailable.',
        body: 'The address does not match a page in the AstraNull portal. Removed pages are not redirected, so nothing else opened in its place.',
        help: '',
        Icon: FileQuestion
      };

  return (
    <div className="content">
      <section className="public-unavailable" aria-labelledby="public-unavailable-title" data-unavailable-kind={kind}>
        <span className="public-unavailable-icon" aria-hidden="true"><copy.Icon size={22} /></span>
        <h1 id="public-unavailable-title">{copy.title}</h1>
        <p className="public-unavailable-body">{copy.body}</p>
        {copy.help ? <p className="public-unavailable-help">{copy.help}</p> : null}
        {requested ? (
          <p className="public-unavailable-requested">
            <span>Requested address</span>
            <code>{requested}</code>
          </p>
        ) : null}
        <div className="public-unavailable-actions">
          {parentHref && parentLabel ? <AnchorButton href={parentHref}>{parentLabel}</AnchorButton> : null}
          <AnchorButton href={homeHref} variant={parentHref ? 'secondary' : 'default'}>{homeLabel}</AnchorButton>
          {canGoBack ? (
            <Button type="button" variant="ghost" onClick={() => window.history.back()}>
              <ArrowLeft size={15} aria-hidden="true" />
              Go back
            </Button>
          ) : null}
        </div>
      </section>
    </div>
  );
}

/* ── Staff sign-in (deferred surface; unchanged in this release) ────── */

const STAFF_ROLE_LABELS: Record<string, string> = {
  internal_admin: 'Internal admin',
  billing_ops: 'Billing operations',
  support_engineer: 'Support engineer',
  security_admin: 'Security admin',
  soc_analyst: 'SOC analyst',
  soc_lead: 'SOC lead'
};

function staffRoleLabel(slug: string) {
  return STAFF_ROLE_LABELS[slug] ?? slug.replace(/_/g, ' ');
}

const STAFF_STAGING_ROLES = [
  'internal_admin',
  'billing_ops',
  'support_engineer',
  'security_admin',
  'soc_analyst',
  'soc_lead'
] as const;

function AuthCardHeader({
  badge,
  title,
  description
}: {
  badge: React.ReactNode;
  title: string;
  description: string;
}) {
  return (
    <CardHeader className="auth-card-header">
      {badge}
      <div className="auth-card-heading">
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </div>
    </CardHeader>
  );
}

export function StaffLoginPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Staff sign-in · AstraNull Internal', robots: 'noindex, nofollow' });

  const [staffId, setStaffId] = useState('');
  const [staffRole, setStaffRole] = useState('internal_admin');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const isDevHeaders = config.authMode === 'dev-headers';
  const isOidc = isOidcJwtMode(config);
  const showStagingStaffRolePicker = isDevHeaders || config.bundledLoginEnabled;
  const idpRedirect = useMemo(() => resolveOidcLoginRedirect(config, 'staff'), [config]);
  const loginDisabled = isOidc && !config.bundledLoginEnabled && !idpRedirect;
  const staffLoginPath = typeof window !== 'undefined' ? window.location.pathname : config.staffLoginPath;

  useEffect(() => {
    const existing = loadSession();
    if (existing?.access_token && existing.principal === 'staff') {
      navigateSpa(staffHomePath(existing));
    }
  }, []);

  useEffect(() => {
    if (idpRedirect) window.location.replace(idpRedirect);
  }, [idpRedirect]);

  useEffect(() => {
    if (loginDisabled) setError('Staff SSO is required for this deployment.');
  }, [loginDisabled]);

  const cardDescription = isDevHeaders
    ? 'Developer validation mode: continue with staff dev headers (no password required).'
    : config.bundledLoginEnabled
      ? 'Bundled staging login mints a short-lived staff bearer session for this environment.'
      : idpRedirect
        ? 'Redirecting to your organization staff sign-in provider.'
        : 'Staff sign-in is managed by your organization identity provider.';

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (loginDisabled) return;
    setError('');
    setLoading(true);

    if (isDevHeaders) {
      const devSession = {
        mode: 'dev-headers',
        principal: 'staff',
        staff_id: staffId.trim(),
        staff_role: staffRole,
        staff_login_path: staffLoginPath
      };
      saveSession(devSession);
      navigateSpa(staffHomePath(devSession));
      return;
    }

    try {
      const response = await fetch('/v1/auth/bundled-staging-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({
          principal: 'staff',
          staff_id: staffId.trim(),
          staff_role: staffRole
        })
      });
      const json = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(publicApiErrorMessage(
          response.status,
          json,
          'Staff login failed. Check the selected staging identity and try again.'
        ));
      }
      const staffSession = {
        ...sessionFromLoginResponse(json as Record<string, unknown>),
        staff_login_path: staffLoginPath
      };
      saveSession(staffSession);
      navigateSpa(staffHomePath(staffSession));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Staff login failed.');
      setLoading(false);
    }
  }

  return (
    <PublicShell eyebrow="Internal staff access" showAccountNav={false}>
      <AuthPageLayout
        aside={(
          <>
            <h1 className="auth-title">Staff sign-in.</h1>
            <p className="auth-lead">
              {isDevHeaders
                ? 'Local developer validation uses staff headers to preview internal RBAC without a password.'
                : 'Review signup intake, tenant lifecycle, entitlement grants, approval queues, and internal audit from the staff-only control plane.'}
            </p>
            <p className="auth-field-help" role="note">
              Customer accounts do not grant access to this surface. Provisioning and approval actions are written to the internal audit log.
            </p>
          </>
        )}
        footer={<p><a href="/">Back to public site</a></p>}
      >
        <Card className="auth-card">
          <AuthCardHeader
            badge={<Badge tone="warn">Staff plane</Badge>}
            title="Staff sign-in"
            description={cardDescription}
          />
          <CardContent>
            {idpRedirect ? (
              <AuthRedirectPanel
                lead="Redirecting to your staff identity provider…"
                help="You will be sent to your organization&apos;s staff sign-in page. If nothing happens, contact your administrator."
              />
            ) : (
              <form className="auth-form" onSubmit={submit} aria-busy={loading}>
                <label htmlFor="staff-login-id">
                  <span>Staff ID</span>
                  <input
                    id="staff-login-id"
                    value={staffId}
                    onChange={(event) => setStaffId(event.target.value)}
                    autoComplete="username"
                    required={!loginDisabled}
                    disabled={loginDisabled}
                  />
                </label>
                {showStagingStaffRolePicker ? (
                  <div className="auth-field-group">
                    <Select
                      label={isDevHeaders ? 'Staff role' : 'Staging staff role'}
                      value={staffRole}
                      options={STAFF_STAGING_ROLES.map((item) => ({
                        value: item,
                        label: staffRoleLabel(item)
                      }))}
                      onChange={setStaffRole}
                      disabled={loginDisabled}
                    />
                    {!isDevHeaders && config.bundledLoginEnabled ? (
                      <span className="auth-field-help">Staging only. Production staff sign-in derives role from your identity provider.</span>
                    ) : null}
                  </div>
                ) : null}
                {error ? <p className="form-error" role="alert">{error}</p> : null}
                <div className="auth-form-actions">
                  <Button type="submit" loading={loading} disabled={loginDisabled}>
                    Continue to internal admin
                  </Button>
                </div>
              </form>
            )}
          </CardContent>
        </Card>
      </AuthPageLayout>
    </PublicShell>
  );
}
