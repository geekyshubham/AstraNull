import { FormEvent, useEffect, useMemo, useState } from 'react';
import {
  ArrowRight,
  Check,
  CheckCircle2,
  Eye,
  EyeOff,
  FileCheck2,
  LockKeyhole,
  ShieldCheck,
  Siren,
  TriangleAlert,
  UserRound,
  type LucideIcon
} from 'lucide-react';
import {
  isOidcJwtMode,
  loadSession,
  resolveOidcLoginRedirect,
  saveSession,
  sessionFromLoginResponse
} from '../lib/api';
import { publicApiErrorCode, publicApiErrorMessage } from '../lib/error-messages';
import { PLATFORM_PROMISE, STAFF_LINKS } from '../lib/navigation';
import type { PortalConfig } from '../lib/types';
import { AnchorButton, Button } from '../components/ui/button';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Select } from '../components/ui/select';
import { BrandMark } from '../components/layout/brand';

type BadgeTone = NonNullable<BadgeProps['tone']>;

function signupRequestStateTone(state: string): BadgeTone {
  const normalized = state.trim().toLowerCase();
  if (['approved', 'provisioned', 'active'].includes(normalized)) return 'success';
  if (['rejected', 'denied', 'cancelled', 'canceled'].includes(normalized)) return 'danger';
  if (['under_review', 'reviewing', 'in_review'].includes(normalized)) return 'warn';
  if (['submitted', 'pending', 'recorded'].includes(normalized)) return 'info';
  return 'muted';
}

function signupRequestStateLabel(state: string) {
  const normalized = state.trim().toLowerCase();
  const labels: Record<string, string> = {
    under_review: 'Under review',
    in_review: 'In review',
    submitted: 'Submitted',
    provisioned: 'Provisioned'
  };
  return labels[normalized] ?? (state.trim() || 'Recorded');
}

function SignupStateBadge({ state }: { state: unknown }) {
  const raw = String(state ?? 'recorded').trim() || 'recorded';
  return <Badge tone={signupRequestStateTone(raw)}>{signupRequestStateLabel(raw)}</Badge>;
}

function SignupRequestSummary({
  record,
  requestIdFallback,
  organizationFallback = 'Not recorded',
  planFallback = 'professional',
  regionFallback = 'us',
  showPlanBadgeWhenMissing = false,
  statusFallback = 'recorded'
}: {
  record: Record<string, unknown>;
  requestIdFallback?: string;
  organizationFallback?: string;
  planFallback?: string;
  regionFallback?: string;
  showPlanBadgeWhenMissing?: boolean;
  statusFallback?: string;
}) {
  const plan = record.requested_plan ?? (showPlanBadgeWhenMissing ? planFallback : null);
  const region = record.region ?? (showPlanBadgeWhenMissing ? regionFallback : null);
  return (
    <dl>
      <div>
        <dt>Request ID</dt>
        <dd><Badge mono tone="muted">{String(record.id ?? requestIdFallback ?? 'submitted')}</Badge></dd>
      </div>
      <div>
        <dt>Status</dt>
        <dd><SignupStateBadge state={record.state ?? record.status ?? statusFallback} /></dd>
      </div>
      <div>
        <dt>Organization</dt>
        <dd>{String(record.organization_name ?? record.organization ?? organizationFallback)}</dd>
      </div>
      <div>
        <dt>Requested plan</dt>
        <dd>
          {plan != null
            ? <Badge tone="info">{signupPlanLabel(plan)}</Badge>
            : 'Not recorded'}
        </dd>
      </div>
      <div>
        <dt>Region</dt>
        <dd>{region != null ? signupRegionLabel(region) : 'Not recorded'}</dd>
      </div>
    </dl>
  );
}

function AuthAsidePoints({ items }: { items: { icon: LucideIcon; text: string }[] }) {
  return (
    <ul className="auth-points">
      {items.map(({ icon: Icon, text }) => (
        <li key={text}>
          <Icon size={16} aria-hidden="true" />
          {text}
        </li>
      ))}
    </ul>
  );
}

function PublicAccessActions({
  signupEnabled,
  loginUrl,
  showArrowOnPrimary = false
}: {
  signupEnabled: boolean;
  loginUrl: string;
  showArrowOnPrimary?: boolean;
}) {
  return (
    <div className="public-actions">
      {signupEnabled ? (
        <>
          <AnchorButton href="/signup">
            Request access
            {showArrowOnPrimary ? <ArrowRight size={15} aria-hidden="true" /> : null}
          </AnchorButton>
          <AnchorButton href={loginUrl} variant="secondary">Log in</AnchorButton>
        </>
      ) : <AnchorButton href={loginUrl}>Log in</AnchorButton>}
    </div>
  );
}

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

function AuthRedirectPanel({ lead, help }: { lead: string; help?: string }) {
  return (
    <div className="success-panel" role="status" aria-live="polite" aria-busy="true">
      <span className="spinner" aria-hidden="true" />
      <p className="success-panel-lead">{lead}</p>
      {help ? <p className="auth-field-help">{help}</p> : null}
    </div>
  );
}

function SignupFormSkeleton() {
  return (
    <div className="auth-form auth-form--grid" aria-hidden="true">
      <label><span className="skeleton skeleton-text" /><span className="skeleton skeleton-row" /></label>
      <label><span className="skeleton skeleton-text" /><span className="skeleton skeleton-row" /></label>
      <label><span className="skeleton skeleton-text" /><span className="skeleton skeleton-row" /></label>
      <label><span className="skeleton skeleton-text" /><span className="skeleton skeleton-row" /></label>
      <label className="auth-field-full"><span className="skeleton skeleton-text" /><span className="skeleton skeleton-row" /></label>
      <label><span className="skeleton skeleton-text" /><span className="skeleton skeleton-row" /></label>
    </div>
  );
}

type PublicPageProps = {
  config: PortalConfig;
};

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

function enterDemoPortal(portalPath: string) {
  saveSession({
    mode: 'dev-headers',
    principal: 'customer',
    tenant_id: 'ten_demo',
    user_id: 'usr_admin',
    role: 'admin'
  });
  window.location.href = portalPath;
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
    <main id="public-main" className={`auth-page${wide ? ' auth-page--wide' : ''}`}>
      <aside className="auth-aside">{aside}</aside>
      <section className="auth-panel">
        {children}
        {footer ? <footer className="auth-footer">{footer}</footer> : null}
      </section>
    </main>
  );
}

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

type LandingEvidenceItem = {
  label: string;
  title: string;
  body: string;
  icon: LucideIcon;
};

const LANDING_BOUNDARIES: readonly LandingEvidenceItem[] = [
  {
    label: 'Scope',
    title: 'Customer-declared targets.',
    body: 'You choose the exact FQDNs, DNS zones, and TCP surfaces in scope. The core product does not perform automatic IP inventory discovery.',
    icon: FileCheck2
  },
  {
    label: 'Access',
    title: 'No infrastructure keys by default.',
    body: 'The no-access-first path requires no customer cloud credentials. Optional agents connect outbound and add corroborating origin evidence.',
    icon: LockKeyhole
  },
  {
    label: 'Execution',
    title: 'Bounded checks with an ownership gate.',
    body: 'Safe validation is constrained to proven targets and bounded probe jobs. Missing evidence remains visible instead of being inferred.',
    icon: ShieldCheck
  },
  {
    label: 'Escalation',
    title: 'High-scale remains governed.',
    body: 'Customers request high-scale work. The SOC validates authorization, schedules execution, and retains the stop controls and audit trail.',
    icon: Siren
  }
];

const LANDING_PROOF: readonly LandingEvidenceItem[] = [
  {
    label: '01 · Declaration',
    title: 'Record the expected path.',
    body: 'The target, environment, ownership state, and expected protected behavior establish what the validation is allowed to test.',
    icon: FileCheck2
  },
  {
    label: '02 · Bounded probe',
    title: 'Observe from outside.',
    body: 'A signed, rate-bounded job records reachability and path metadata against the approved target instead of inventing a posture from configuration.',
    icon: ShieldCheck
  },
  {
    label: '03 · Corroboration',
    title: 'Add origin evidence when available.',
    body: 'An optional outbound-only agent can report what the protected environment observed. If no agent is present, that absence stays explicit.',
    icon: UserRound
  },
  {
    label: '04 · Verdict and custody',
    title: 'Explain the conclusion.',
    body: 'The verdict points back to its evidence references and reason codes. Exports preserve custody metadata for review and audit.',
    icon: CheckCircle2
  }
];

const LANDING_COMPARE = [
  ['Scope source', 'Customer-declared targets', 'Operator-defined test target', 'Provider resource inventory'],
  ['Cloud credentials', 'Not required by default', 'Depends on the test setup', 'Required for the provider account'],
  ['Internal corroboration', 'Optional outbound-only agent', 'Not inherent', 'Provider telemetry'],
  ['High-scale control', 'SOC approval and governed execution', 'Operator-owned', 'Provider-specific'],
  ['Evidence model', 'Correlated evidence and custody references', 'Tool-specific run output', 'Provider metrics and logs']
];

const LANDING_TRUST_ITEMS = [
  { icon: Check, text: 'Customer-declared scope' },
  { icon: Check, text: 'No cloud credentials by default' },
  { icon: Check, text: 'Ownership-gated safe checks' },
  { icon: Check, text: 'SOC-gated high-scale' }
] as const;

function PublicEvidenceList({ items }: { items: readonly LandingEvidenceItem[] }) {
  return (
    <ol className="auth-points">
      {items.map(({ label, title, body, icon: Icon }) => (
        <li key={label}>
          <Icon size={16} aria-hidden="true" />
          <span>
            <span className="check-fact-label">{label}</span>
            <strong>{title}</strong> {body}
          </span>
        </li>
      ))}
    </ol>
  );
}

function ValidationContractPreview() {
  return (
    <aside id="boundaries" aria-labelledby="validation-contract-title">
      <Card className="auth-card">
        <CardHeader className="auth-card-header">
          <Badge tone="muted">No-access-first</Badge>
          <div className="auth-card-heading">
            <CardTitle id="validation-contract-title">Validation contract</CardTitle>
            <CardDescription>What AstraNull requires, observes, and refuses to assume.</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="stack">
          <PublicEvidenceList items={LANDING_BOUNDARIES} />
          <div className="callout info">
            <ShieldCheck size={18} aria-hidden="true" />
            <p>Default validation is bounded and defensive. It does not expose self-service attack tooling or unmanaged traffic generation.</p>
          </div>
        </CardContent>
      </Card>
    </aside>
  );
}

function ProofChainSection() {
  return (
    <section className="public-section public-section--spaced" id="proof" aria-labelledby="proof-heading">
      <p className="eyebrow">Evidence before verdict</p>
      <h2 id="proof-heading">A conclusion should show its chain of proof.</h2>
      <p className="public-section-lead">AstraNull starts with declared scope, records bounded observations, and keeps uncertainty explicit. A verdict is the end of that chain, not a substitute for it.</p>
      <Card className="auth-card">
        <CardContent className="stack">
          <PublicEvidenceList items={LANDING_PROOF} />
          <div className="callout info">
            <FileCheck2 size={18} aria-hidden="true" />
            <p>Evidence references, reason codes, and custody metadata travel with the result so reviewers can inspect what supports it.</p>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}

export function PublicLandingPage({ config }: PublicPageProps) {
  const productName = String(config.siteConfig.product_name ?? 'AstraNull');
  const promise = String(config.siteConfig.promise ?? PLATFORM_PROMISE);
  const signupEnabled = config.siteConfig.signup_enabled !== false;
  const loginUrl = config.loginUrl;

  usePageMeta({
    title: `${productName} · Prove DDoS readiness without handing over your cloud keys`
  });

  return (
    <PublicShell loginHref={loginUrl} signupEnabled={signupEnabled}>
      <main id="public-main" className="public-wrap">
        <section className="public-section">
          <div className="public-hero-grid">
            <div>
              <p className="eyebrow">No-access-first DDoS readiness validation</p>
              <h1 className="auth-title">Prove DDoS readiness without handing over your cloud keys.</h1>
              <p className="public-hero-lead">{promise}</p>
              <div className="public-actions">
                {signupEnabled ? (
                  <AnchorButton href="/signup">
                    Request access
                    <ArrowRight size={15} aria-hidden="true" />
                  </AnchorButton>
                ) : (
                  <AnchorButton href={loginUrl}>Log in</AnchorButton>
                )}
                <AnchorButton href="#proof" variant="ghost">See the proof chain</AnchorButton>
              </div>
              <div className="public-hero-meta" id="trust" aria-label="Platform trust commitments">
                {LANDING_TRUST_ITEMS.map(({ icon: Icon, text }) => (
                  <span key={text}>
                    <Icon size={16} aria-hidden="true" />
                    {text}
                  </span>
                ))}
              </div>
            </div>
            <ValidationContractPreview />
          </div>
        </section>

        <ProofChainSection />

        <section className="public-section public-section--compare" id="compare">
          <h2>Compare the operating model, not a marketing score.</h2>
          <p className="public-section-lead">The distinction is where scope comes from, what access is required, who controls high-scale work, and what evidence remains after the run.</p>
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
        </section>

        <section className="public-cta-final">
          <h2>Start with the scope you need to prove.</h2>
          <p>Request reviewed access, or return to an existing customer workspace.</p>
          <PublicAccessActions signupEnabled={signupEnabled} loginUrl={loginUrl} />
        </section>

        <footer className="public-footer">
          <span>© {productName} · Defensive DDoS readiness validation.</span>
          <nav aria-label="Public footer">
            <a href={loginUrl}>Log in</a>
            {signupEnabled ? <a href="/signup">Request access</a> : null}
            <a href="/signup-status">Request status</a>
            <a href="#boundaries">Boundaries</a>
            <a href="#proof">Proof chain</a>
            <a href="#compare">Compare</a>
          </nav>
        </footer>
      </main>
    </PublicShell>
  );
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
      return 'This email is registered in more than one workspace. Enter the tenant ID to continue.';
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
      return 'Password sign-in is not available on this deployment. Contact your administrator for a login link.';
    default:
      return publicApiErrorMessage(response.status, json, 'Login failed. Check your details and try again.');
  }
}

const PASSWORD_POLICY_LABELS: Record<string, string> = {
  too_short: 'Use at least 12 characters.',
  too_long: 'Use at most 200 characters.',
  invalid_type: 'Enter a password.',
  insufficient_character_classes:
    'Mix at least three of: lowercase, uppercase, digits, symbols.',
  contains_email_local_part: 'Do not reuse the name part of your email address.',
  common_password: 'This password is too common. Choose something less guessable.'
};

function passwordPolicyMessages(failures: unknown): string[] {
  if (!Array.isArray(failures)) return [];
  return failures.map((code) => PASSWORD_POLICY_LABELS[String(code)] ?? String(code));
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

function CredentialLoginPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Log in · AstraNull Customer Portal' });

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
  const [loading, setLoading] = useState(false);
  const [stagingBypass, setStagingBypass] = useState(false);

  const isDevHeaders = config.authMode === 'dev-headers';
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

  useEffect(() => {
    const existing = loadSession();
    if (existing?.access_token && existing.principal !== 'staff') {
      window.location.replace(config.portalPath);
    }
  }, [config.portalPath]);

  useEffect(() => {
    if (idpRedirect) window.location.replace(idpRedirect);
  }, [idpRedirect]);

  useEffect(() => {
    if (loginDisabled) {
      setError('Enterprise SSO is required for this deployment. Contact your administrator for a login link.');
    }
  }, [loginDisabled]);

  const cardDescription = isDevHeaders
    ? 'Developer validation mode: continue with local tenant headers (no password required).'
    : passwordLane
      ? 'Sign in with your work email and account password.'
      : config.bundledLoginEnabled
        ? 'Bundled staging login mints a short-lived bearer session for this environment.'
        : idpRedirect
          ? 'Redirecting to your organization sign-in provider.'
          : 'Sign-in is managed by your organization identity provider.';

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
      window.location.href = config.portalPath;
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
        'Login failed. Check the selected staging identity and try again.'
      ));
    }
    saveSession(sessionFromLoginResponse(json as Record<string, unknown>));
    window.location.href = config.portalPath;
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
      throw new Error(passwordLoginErrorMessage(response, code, json));
    }
    // Never keep plaintext credentials or a one-time code in component state past success.
    setPassword('');
    setTotp('');
    setMfaRequired(false);
    saveSession(sessionFromLoginResponse(json));
    window.location.href = config.portalPath;
  }

  function clearMfaChallenge() {
    if (!mfaRequired) return;
    setMfaRequired(false);
    setTotp('');
    setError('');
    setErrorCode('');
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (loginDisabled) return;
    setError('');
    setErrorCode('');
    setLoading(true);

    try {
      if (passwordLane && !stagingBypass) {
        await submitPasswordLogin();
      } else {
        await submitStagingBypass();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed.');
      setLoading(false);
    }
  }

  return (
    <PublicShell activeNav="login" showEyebrow={false} signupEnabled={signupEnabled}>
      <AuthPageLayout
        aside={(
          <>
            <h1 className="auth-title">Sign in to your readiness workspace.</h1>
            <p className="auth-lead">
              {isDevHeaders
                ? 'Local developer validation uses tenant headers to preview RBAC without a password.'
                : 'Return to declared targets, agent observations, validation evidence, and governed high-scale requests in one tenant-scoped workspace.'}
            </p>
            <AuthAsidePoints
              items={[
                { icon: ShieldCheck, text: 'Evidence-backed verdicts tied to observed probe data' },
                { icon: LockKeyhole, text: 'No cloud credentials required in the default path' },
                { icon: FileCheck2, text: 'Audit-ready exports and custody references' }
              ]}
            />
          </>
        )}
        footer={(
          <p>
            {signupEnabled ? <>Need an account? <a href="/signup">Request access</a>{' · '}</> : null}
            <a href="/signup-status">Check request status</a>
            {passwordLane ? <>{' · '}<a href="/login?flow=request-password-reset">Forgot password?</a></> : null}
          </p>
        )}
      >
        <Card className="auth-card">
          <AuthCardHeader
            badge={<Badge tone="info">Customer portal</Badge>}
            title="Customer sign-in"
            description={cardDescription}
          />
          <CardContent>
            {idpRedirect ? (
              <AuthRedirectPanel
                lead="Redirecting to your identity provider…"
                help="You will be sent to your organization&apos;s sign-in page. If nothing happens, contact your administrator."
              />
            ) : (
              <form className="auth-form" onSubmit={submit} aria-busy={loading}>
                <label htmlFor="login-user-id">
                  <span>{passwordLane || isDevHeaders || config.bundledLoginEnabled ? 'Work email' : 'User ID'}</span>
                  <input
                    id="login-user-id"
                    type={passwordLane && !stagingBypass ? 'email' : 'text'}
                    value={userId}
                    onChange={(event) => {
                      setUserId(event.target.value);
                      clearMfaChallenge();
                    }}
                    autoComplete="username"
                    autoCapitalize="none"
                    spellCheck={false}
                    required={!loginDisabled}
                    disabled={loginDisabled}
                  />
                </label>
                {passwordLane && !stagingBypass ? (
                  <>
                    <label htmlFor="login-password">
                      <span>Password</span>
                      <span className="auth-password-field">
                        <input
                          id="login-password"
                          type={showPassword ? 'text' : 'password'}
                          value={password}
                          onChange={(event) => {
                            setPassword(event.target.value);
                            clearMfaChallenge();
                          }}
                          autoComplete="current-password"
                          required
                          maxLength={200}
                          disabled={loginDisabled}
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
                    </label>
                    {tenantRequired ? (
                      <label htmlFor="login-tenant-scope">
                        <span>Tenant ID</span>
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
                          This email is registered in more than one workspace. Enter the tenant ID you want to sign in to.
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
                    <span>Tenant</span>
                    <input id="login-tenant-id" value="ten_demo" readOnly aria-readonly="true" disabled={loginDisabled} />
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
                      disabled={loginDisabled}
                    />
                    {!isDevHeaders && config.bundledLoginEnabled ? (
                      <span className="auth-field-help">Staging only. Production sign-in derives role from your identity provider.</span>
                    ) : null}
                  </div>
                ) : null}
                {error ? (
                  <div className="form-error" role="alert">
                    <p>{error}</p>
                    {errorCode === 'password_setup_required' || errorCode === 'password_change_required' ? (
                      <p><a href="/set-password">Set a password with an invitation</a></p>
                    ) : null}
                  </div>
                ) : null}
                <div className="auth-form-actions row-actions">
                  <Button type="submit" loading={loading} disabled={loginDisabled}>
                    {mfaRequired ? 'Verify and continue' : 'Continue to portal'}
                  </Button>
                  {config.authMode === 'dev-headers' ? (
                    <Button type="button" variant="secondary" disabled={loginDisabled} onClick={() => enterDemoPortal(config.portalPath)}>
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
            )}
          </CardContent>
        </Card>
      </AuthPageLayout>
    </PublicShell>
  );
}

/** Initiate password recovery without revealing account or delivery state. */
function RequestPasswordResetPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Request password recovery · AstraNull', robots: 'noindex, nofollow' });

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
      setError(err instanceof Error ? err.message : 'The recovery request could not be submitted. Try again.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <PublicShell activeNav="login" showEyebrow={false} loginHref={config.loginUrl} signupEnabled={config.siteConfig.signup_enabled !== false}>
      <AuthPageLayout
        aside={(
          <>
            <h1 className="auth-title">Request password recovery.</h1>
            <p className="auth-lead">Enter your work email. The response remains the same whether an eligible account exists or recovery delivery is available.</p>
            <AuthAsidePoints
              items={[
                { icon: LockKeyhole, text: 'Account existence is never disclosed' },
                { icon: ShieldCheck, text: 'Issued recovery tokens are one-time and time-limited' },
                { icon: FileCheck2, text: 'A successful reset revokes prior password sessions' }
              ]}
            />
          </>
        )}
        footer={(
          <p>
            <a href={config.loginUrl}>Back to log in</a>
            {' · '}
            <a href="/login?flow=password-reset">Already have a recovery token?</a>
          </p>
        )}
      >
        <Card className="auth-card">
          <AuthCardHeader
            badge={<Badge tone="info">Password recovery</Badge>}
            title="Request recovery instructions"
            description="Submit a work email without revealing account or delivery state."
          />
          <CardContent>
            {submitted ? (
              <div className="success-panel" role="status" aria-live="polite">
                <div className="callout info">
                  <CheckCircle2 size={18} aria-hidden="true" />
                  <p className="success-panel-lead">If an account is eligible and recovery delivery is configured and succeeds, instructions may arrive. This response confirms neither condition.</p>
                </div>
                <div className="auth-form-actions row-actions">
                  <Button type="button" variant="secondary" onClick={() => setSubmitted(false)}>Submit another email</Button>
                  <AnchorButton href={config.loginUrl}>Back to log in</AnchorButton>
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
                {error ? <div className="form-error" role="alert"><p>{error}</p></div> : null}
                <div className="auth-form-actions row-actions">
                  <Button type="submit" loading={loading}>Request recovery instructions</Button>
                  <AnchorButton href={config.loginUrl} variant="secondary">Back to log in</AnchorButton>
                </div>
              </form>
            )}
          </CardContent>
        </Card>
      </AuthPageLayout>
    </PublicShell>
  );
}

/**
 * Consume a one-time password recovery token.
 *
 * Recovery is deliberately a distinct `flow=password-reset` mode on the public
 * login route. Invitation activation below continues to call /v1/auth/set-password.
 */
function ResetPasswordPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Reset your password · AstraNull', robots: 'noindex, nofollow' });

  const [token, setToken] = useState(() => {
    if (typeof window === 'undefined') return '';
    return new URLSearchParams(window.location.search).get('token')?.trim() ?? '';
  });
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [totp, setTotp] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [policyFailures, setPolicyFailures] = useState<string[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);

  // The reset token is a live secret. Keep only the flow discriminator in the URL
  // after React has copied the token into component memory.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const url = new URL(window.location.href);
    if (!url.searchParams.has('token')) return;
    url.searchParams.delete('token');
    window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError('');
    setPolicyFailures([]);

    if (password !== confirm) {
      setError('The two passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      const body: Record<string, unknown> = { token: token.trim(), password };
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
          setPolicyFailures(passwordPolicyMessages(json.failures));
          throw new Error('That password does not meet the password policy.');
        }
        if (code === 'mfa_required' || code === 'mfa_invalid') {
          setMfaRequired(true);
          setTotp('');
          throw new Error(code === 'mfa_required'
            ? 'Enter the 6-digit code from your authenticator app to complete recovery.'
            : 'That authenticator code could not be verified. Enter the current 6-digit code.');
        }
        if (code === 'invalid_reset_token') {
          throw new Error('This password recovery token is invalid or has already been used. Request password recovery again.');
        }
        if (code === 'reset_token_expired') {
          throw new Error('This password recovery token has expired. Request password recovery again.');
        }
        if (code === 'rate_limited') {
          throw new Error(`Too many attempts. Try again ${retryAfterLabel(json, response)}.`);
        }
        throw new Error(publicApiErrorMessage(
          response.status,
          json,
          'Could not reset the password. Check the recovery details and try again.'
        ));
      }
      setPassword('');
      setConfirm('');
      setTotp('');
      setToken('');
      setMfaRequired(false);
      setDone(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not reset the password.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <PublicShell activeNav="login" showEyebrow={false} loginHref={config.loginUrl} signupEnabled={config.siteConfig.signup_enabled !== false}>
      <AuthPageLayout
        aside={(
          <>
            <h1 className="auth-title">Choose a new account password.</h1>
            <p className="auth-lead">
              Use a valid one-time recovery token. A completed reset revokes outstanding recovery
              tokens, invitations, and existing password sessions.
            </p>
            <AuthAsidePoints
              items={[
                { icon: LockKeyhole, text: 'Recovery tokens are stored only as one-way digests' },
                { icon: ShieldCheck, text: 'Enrolled accounts still require their authenticator code' },
                { icon: FileCheck2, text: 'Credential changes are recorded in the tenant audit log' }
              ]}
            />
          </>
        )}
        footer={(
          <p>
            <a href={config.loginUrl}>Back to log in</a>
            {' · '}
            <a href="/login?flow=request-password-reset">Request password recovery</a>
          </p>
        )}
      >
        <Card className="auth-card">
          <AuthCardHeader
            badge={<Badge tone="info">Password recovery</Badge>}
            title={done ? 'Password reset' : 'Choose a new password'}
            description={done
              ? 'Your password has been changed and prior password sessions have been revoked.'
              : 'Enter the recovery token issued for this request and choose a password of at least 12 characters.'}
          />
          <CardContent>
            {done ? (
              <div className="success-panel" role="status" aria-live="polite">
                <div className="callout info">
                  <CheckCircle2 size={18} aria-hidden="true" />
                  <p className="success-panel-lead">Your password was reset. Sign in with the new password.</p>
                </div>
                <div className="auth-form-actions">
                  <AnchorButton href={config.loginUrl}>Continue to log in</AnchorButton>
                </div>
              </div>
            ) : (
              <form className="auth-form" onSubmit={submit} aria-busy={loading}>
                <label htmlFor="reset-password-token">
                  <span>Recovery token</span>
                  <input
                    id="reset-password-token"
                    value={token}
                    onChange={(event) => {
                      setToken(event.target.value);
                      setMfaRequired(false);
                      setTotp('');
                    }}
                    className="mono"
                    placeholder="pwr_…"
                    autoComplete="off"
                    spellCheck={false}
                    required
                    disabled={loading}
                  />
                </label>
                <label htmlFor="reset-password-new">
                  <span>New password</span>
                  <span className="auth-password-field">
                    <input
                      id="reset-password-new"
                      type={showPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      autoComplete="new-password"
                      minLength={12}
                      maxLength={200}
                      required
                      disabled={loading}
                      aria-describedby="reset-password-policy"
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
                  <span className="auth-field-help" id="reset-password-policy">
                    At least 12 characters, mixing at least three of: lowercase, uppercase, digits, symbols.
                  </span>
                </label>
                <label htmlFor="reset-password-confirm">
                  <span>Confirm password</span>
                  <input
                    id="reset-password-confirm"
                    type={showPassword ? 'text' : 'password'}
                    value={confirm}
                    onChange={(event) => setConfirm(event.target.value)}
                    autoComplete="new-password"
                    required
                    disabled={loading}
                  />
                </label>
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
                {error ? (
                  <div className="form-error" role="alert">
                    <p>{error}</p>
                    {policyFailures.length > 0 ? (
                      <ul>
                        {policyFailures.map((message) => <li key={message}>{message}</li>)}
                      </ul>
                    ) : null}
                  </div>
                ) : null}
                <div className="auth-form-actions">
                  <Button type="submit" loading={loading}>
                    {mfaRequired ? 'Verify and reset password' : 'Reset password'}
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

/**
 * Consume a one-time password invitation.
 *
 * `POST /v1/auth/set-password` deliberately does NOT return a session, so this
 * page hands the user to /login afterwards rather than signing them in.
 */
export function SetPasswordPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Set your password · AstraNull', robots: 'noindex, nofollow' });

  const [token, setToken] = useState(() => {
    if (typeof window === 'undefined') return '';
    return new URLSearchParams(window.location.search).get('token')?.trim() ?? '';
  });
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [policyFailures, setPolicyFailures] = useState<string[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState<Record<string, unknown> | null>(null);

  // A token in the query string is a live secret; drop it from the address bar so
  // it does not persist in history or leak through a Referer on the next click.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const url = new URL(window.location.href);
    if (!url.searchParams.has('token')) return;
    url.searchParams.delete('token');
    window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError('');
    setPolicyFailures([]);

    if (password !== confirm) {
      setError('The two passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('/v1/auth/set-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ token: token.trim(), password })
      });
      const json = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      if (!response.ok) {
        const code = publicApiErrorCode(response.status, json);
        if (code === 'weak_password') {
          setPolicyFailures(passwordPolicyMessages(json.failures));
          throw new Error('That password does not meet the password policy.');
        }
        if (code === 'invalid_invite') {
          throw new Error('This invitation is invalid or has already been used. Ask your administrator for a new one.');
        }
        if (code === 'invite_expired') {
          throw new Error('This invitation has expired. Ask your administrator for a new one.');
        }
        if (code === 'rate_limited') {
          throw new Error(`Too many attempts. Try again ${retryAfterLabel(json, response)}.`);
        }
        throw new Error(publicApiErrorMessage(
          response.status,
          json,
          'Could not set the password. Check the invitation details and try again.'
        ));
      }
      setPassword('');
      setConfirm('');
      setToken('');
      setDone(json);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not set the password.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <PublicShell activeNav="login" showEyebrow={false} loginHref={config.loginUrl} signupEnabled={config.siteConfig.signup_enabled !== false}>
      <AuthPageLayout
        aside={(
          <>
            <h1 className="auth-title">Set your account password.</h1>
            <p className="auth-lead">
              A one-time invitation authorizes password setup for this account. Setting a password
              activates the account and closes the invitation; it cannot be reused.
            </p>
            <AuthAsidePoints
              items={[
                { icon: LockKeyhole, text: 'Stored as a salted scrypt verifier, never in plaintext' },
                { icon: ShieldCheck, text: 'Your role and workspace come from your account, not this form' },
                { icon: FileCheck2, text: 'Activation is written to the tenant audit log' }
              ]}
            />
          </>
        )}
        footer={<p><a href={config.loginUrl}>Back to log in</a></p>}
      >
        <Card className="auth-card">
          <AuthCardHeader
            badge={<Badge tone="info">One-time invitation</Badge>}
            title={done ? 'Password set' : 'Set your password'}
            description={done
              ? 'The account is active. Sign in with your work email and the password you just chose.'
              : 'Enter the invitation token provided to you, then choose a password of at least 12 characters.'}
          />
          <CardContent>
            {done ? (
              <div className="success-panel" role="status" aria-live="polite">
                <div className="callout info">
                  <CheckCircle2 size={18} aria-hidden="true" />
                  <p className="success-panel-lead">
                    Password set for {String(done.email ?? 'your account')}. The invitation is now closed.
                  </p>
                </div>
                <div className="auth-form-actions">
                  <AnchorButton href={config.loginUrl}>Continue to log in</AnchorButton>
                </div>
              </div>
            ) : (
              <form className="auth-form" onSubmit={submit} aria-busy={loading}>
                <label htmlFor="set-password-token">
                  <span>Invitation token</span>
                  <input
                    id="set-password-token"
                    value={token}
                    onChange={(event) => setToken(event.target.value)}
                    className="mono"
                    placeholder="pwi_…"
                    autoComplete="off"
                    spellCheck={false}
                    required
                    disabled={loading}
                  />
                </label>
                <label htmlFor="set-password-new">
                  <span>New password</span>
                  <span className="auth-password-field">
                    <input
                      id="set-password-new"
                      type={showPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      autoComplete="new-password"
                      minLength={12}
                      maxLength={200}
                      required
                      disabled={loading}
                      aria-describedby="set-password-policy"
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
                  <span className="auth-field-help" id="set-password-policy">
                    At least 12 characters, mixing at least three of: lowercase, uppercase, digits, symbols.
                    Do not reuse the name part of your email address.
                  </span>
                </label>
                <label htmlFor="set-password-confirm">
                  <span>Confirm password</span>
                  <input
                    id="set-password-confirm"
                    type={showPassword ? 'text' : 'password'}
                    value={confirm}
                    onChange={(event) => setConfirm(event.target.value)}
                    autoComplete="new-password"
                    required
                    disabled={loading}
                  />
                </label>
                {error ? (
                  <div className="form-error" role="alert">
                    <p>{error}</p>
                    {policyFailures.length > 0 ? (
                      <ul>
                        {policyFailures.map((message) => <li key={message}>{message}</li>)}
                      </ul>
                    ) : null}
                  </div>
                ) : null}
                <div className="auth-form-actions">
                  <Button type="submit" loading={loading}>Set password</Button>
                </div>
              </form>
            )}
          </CardContent>
        </Card>
      </AuthPageLayout>
    </PublicShell>
  );
}

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
  return SIGNUP_PLAN_LABELS[key] ?? (key || 'Professional');
}

function signupRegionLabel(slug: unknown) {
  const key = String(slug ?? '').trim();
  return SIGNUP_REGION_LABELS[key] ?? (key || 'United States');
}

type SignupPlanOption = { value: string; label: string };

// Consume plans[] from the public site-config (config.siteConfig.plans) so the
// requested-plan options reflect the server's subscription catalog rather than a
// hardcoded list. Falls back to the static labels if the config omits plans.
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

const STAFF_STAGING_ROLES = [
  'internal_admin',
  'billing_ops',
  'support_engineer',
  'security_admin',
  'soc_analyst',
  'soc_lead'
] as const;

function signupSubmitErrorMessage(status: number, json: Record<string, unknown>) {
  const code = publicApiErrorCode(status, json);
  if (status === 429 || code === 'rate_limited') {
    return 'Too many sign-up attempts. Please try again later.';
  }
  if (code === 'duplicate_request') {
    return 'A pending request already exists for this organization or email domain.';
  }
  if (status === 403 || code === 'signup_disabled') {
    return 'Account requests are not being accepted right now. Contact your AstraNull representative.';
  }
  if (code === 'validation_failed') {
    return 'Could not submit request. Check required fields and try again.';
  }
  return publicApiErrorMessage(status, json, 'Could not submit request. Try again.');
}

export function SignupPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Request access · AstraNull' });

  const signupEnabled = config.siteConfig.signup_enabled !== false;
  const [submitted, setSubmitted] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [hydrating, setHydrating] = useState(false);
  const [requestedPlan, setRequestedPlan] = useState('professional');
  const [region, setRegion] = useState('us');
  const planOptions = useMemo(() => signupPlanOptions(config), [config]);

  useEffect(() => {
    if (planOptions.length > 0 && !planOptions.some((option) => option.value === requestedPlan)) {
      setRequestedPlan(planOptions[0].value);
    }
  }, [planOptions, requestedPlan]);

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
        if (!response.ok) return;
        setSubmitted((json.request ?? json) as Record<string, unknown>);
      } finally {
        if (!cancelled) setHydrating(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!signupEnabled) return;
    setError('');
    setLoading(true);
    const data = new FormData(event.currentTarget);
    const body = {
      organization_name: data.get('organization_name'),
      contact_email: data.get('contact_email'),
      contact_name: data.get('contact_name'),
      requested_plan: data.get('requested_plan'),
      intended_use: data.get('intended_use'),
      region: data.get('region'),
      high_scale_interest: data.get('high_scale_interest') === 'on'
    };
    try {
      const response = await fetch('/v1/signup-requests', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const json = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(signupSubmitErrorMessage(response.status, json as Record<string, unknown>));
      const record = (json.request ?? json) as Record<string, unknown>;
      setSubmitted(record);
      const submittedId = String(record.id ?? '').trim();
      if (submittedId && typeof window !== 'undefined') {
        const url = new URL(window.location.href);
        url.searchParams.set('id', submittedId);
        window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not submit request.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <PublicShell activeNav="signup" showEyebrow={false} signupEnabled={signupEnabled}>
      <AuthPageLayout
        wide
        aside={(
          <>
            <h1 className="auth-title">Request governed validation access.</h1>
            <p className="auth-lead">Provisioning is review-gated. Operations validates organization details, intended use, and plan fit before creating a tenant workspace.</p>
            <AuthAsidePoints
              items={[
                { icon: ShieldCheck, text: 'Approved requests move to provisioning before access begins' },
                { icon: Siren, text: 'High-scale programs stay SOC-scheduled and pack-gated' },
                { icon: UserRound, text: 'Track request status any time with your request ID' }
              ]}
            />
          </>
        )}
        footer={(
          <p>
            Already have access? <a href="/login">Log in</a>
            {' · '}
            <a href="/signup-status">Check request status</a>
          </p>
        )}
      >
        <Card className="auth-card auth-card--wide">
          <AuthCardHeader
            badge={<Badge tone="info">Reviewed access</Badge>}
            title={submitted ? 'Request submitted' : 'Request an AstraNull account'}
            description="Account creation is reviewed before tenant provisioning. Save the request ID shown after submission."
          />
          <CardContent>
            {!signupEnabled ? (
              <div className="success-panel">
                <div className="callout warn">
                  <TriangleAlert size={18} aria-hidden="true" />
                  <p className="success-panel-lead">Account intake is temporarily closed for this deployment. Existing customers can sign in; approved request IDs can still be checked on the status page.</p>
                </div>
                <div className="auth-form-actions row-actions">
                  <AnchorButton href="/login" variant="secondary">Log in</AnchorButton>
                  <AnchorButton href="/signup-status">Check request status</AnchorButton>
                </div>
              </div>
            ) : hydrating ? (
              <div role="status" aria-live="polite" aria-busy="true">
                <p className="success-panel-lead">Loading your request confirmation…</p>
                <SignupFormSkeleton />
              </div>
            ) : submitted ? (
              <div className="success-panel" role="status" aria-live="polite">
                <div className="callout info">
                  <CheckCircle2 size={18} aria-hidden="true" />
                  <p className="success-panel-lead">We provision reviewed accounts only. Save your request ID to check status any time.</p>
                </div>
                <SignupRequestSummary record={submitted} organizationFallback="Recorded" showPlanBadgeWhenMissing statusFallback="submitted" />
                <div className="auth-form-actions row-actions">
                  <AnchorButton href={`/signup-status?id=${encodeURIComponent(String(submitted.id ?? ''))}`}>
                    Check status
                  </AnchorButton>
                  <AnchorButton href="/" variant="secondary">Back to landing</AnchorButton>
                </div>
              </div>
            ) : (
              <form className="auth-form auth-form--grid" onSubmit={submit} aria-busy={loading}>
                <label htmlFor="signup-organization"><span>Organization</span><input id="signup-organization" name="organization_name" required placeholder="Organization name" autoComplete="organization" disabled={loading} /></label>
                <label htmlFor="signup-contact"><span>Contact name</span><input id="signup-contact" name="contact_name" required placeholder="Full name" autoComplete="name" disabled={loading} /></label>
                <label className="auth-field-full" htmlFor="signup-email"><span>Contact email</span><input id="signup-email" name="contact_email" type="email" required placeholder="name@company.com" autoComplete="email" disabled={loading} /></label>
                <Select
                  label="Requested plan"
                  name="requested_plan"
                  value={requestedPlan}
                  options={planOptions}
                  onChange={setRequestedPlan}
                  disabled={loading}
                />
                <Select
                  label="Region"
                  name="region"
                  value={region}
                  options={Object.entries(SIGNUP_REGION_LABELS).map(([value, label]) => ({ value, label }))}
                  onChange={setRegion}
                  disabled={loading}
                />
                <label className="auth-field-full" htmlFor="signup-intended-use"><span>Intended use</span><textarea id="signup-intended-use" name="intended_use" required rows={4} placeholder="Defensive readiness for declared production origins." disabled={loading} /></label>
                <label className="auth-field-full auth-check-row" htmlFor="signup-high-scale"><input id="signup-high-scale" name="high_scale_interest" type="checkbox" disabled={loading} /><span>Request a conversation about governed high-scale rehearsal programs. Approval and execution remain separate.</span></label>
                {error ? <p className="form-error auth-field-full" role="alert">{error}</p> : null}
                <div className="auth-form-actions auth-field-full row-actions">
                  <Button type="submit" loading={loading}>Submit request</Button>
                  {config.authMode === 'dev-headers' ? (
                    <Button type="button" variant="secondary" onClick={() => enterDemoPortal(config.portalPath)}>Try demo</Button>
                  ) : null}
                </div>
              </form>
            )}
          </CardContent>
        </Card>
      </AuthPageLayout>
    </PublicShell>
  );
}

export function SignupStatusPage() {
  usePageMeta({ title: 'Request status · AstraNull' });

  const [requestId, setRequestId] = useState(() => {
    if (typeof window === 'undefined') return '';
    return new URLSearchParams(window.location.search).get('id')?.trim() ?? '';
  });
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function lookupSignupRequest(id: string) {
    const trimmed = id.trim();
    if (!trimmed) {
      setError('Enter a request ID to check status.');
      return;
    }
    setError('');
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
          throw new Error(`Too many status lookups. Try again ${retryAfterLabel(json, response)}.`);
        }
        throw new Error(publicApiErrorMessage(
          response.status,
          json,
          'Request status was not found. Check the request ID and try again.'
        ));
      }
      setResult((json.request ?? json) as Record<string, unknown>);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Request status was not found.');
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
    await lookupSignupRequest(requestId);
  }

  return (
    <PublicShell showEyebrow={false} signupEnabled={false}>
      <AuthPageLayout
        aside={(
          <>
            <h1 className="auth-title">Track an access request.</h1>
            <p className="auth-lead">Use the request ID shown in the confirmation panel after intake submission. Status lookup does not require an account session.</p>
          </>
        )}
        footer={(
          <p>
            If you no longer have the request ID, contact your deployment administrator or the support channel provided during onboarding.
            {' · '}
            <a href="/login">Log in</a>
          </p>
        )}
      >
        <Card className="auth-card">
          <AuthCardHeader
            badge={<Badge tone="info">Status lookup</Badge>}
            title="Check request status"
            description="Enter the case-sensitive request ID shown after intake submission."
          />
          <CardContent>
            <form className="auth-form" onSubmit={submit} aria-busy={loading}>
              <label htmlFor="signup-status-request-id">
                <span>Request ID</span>
                <input
                  id="signup-status-request-id"
                  value={requestId}
                  onChange={(event) => setRequestId(event.target.value)}
                  placeholder="sgn_… (from your confirmation)"
                  className="mono"
                  autoComplete="off"
                  required
                  disabled={loading}
                  aria-describedby="signup-status-request-id-help"
                />
                <span className="auth-field-help" id="signup-status-request-id-help">Use the ID returned after intake submission. Case-sensitive.</span>
              </label>
              {error ? <p className="form-error" role="alert">{error}</p> : null}
              <div className="auth-form-actions">
                <Button type="submit" loading={loading}>Look up status</Button>
              </div>
            </form>
            {loading && !result ? (
              <div className="stack-tight" role="status" aria-live="polite" aria-busy="true" aria-label="Loading request status">
                <span className="skeleton skeleton-row" />
                <span className="skeleton skeleton-row" />
                <span className="skeleton skeleton-row" />
              </div>
            ) : null}
            {result ? (
              <div className="success-panel" role="status" aria-live="polite">
                <div className="callout info">
                  <CheckCircle2 size={18} aria-hidden="true" />
                  <p className="success-panel-lead">Request found. Provisioning remains review-gated.</p>
                </div>
                <SignupRequestSummary record={result} requestIdFallback={requestId} />
                {result.customer_notice ? (
                  <p className="auth-field-help">{String(result.customer_notice)}</p>
                ) : null}
              </div>
            ) : null}
          </CardContent>
        </Card>
      </AuthPageLayout>
    </PublicShell>
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
      window.location.replace('/internal/admin');
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
      saveSession({
        mode: 'dev-headers',
        principal: 'staff',
        staff_id: staffId.trim(),
        staff_role: staffRole,
        staff_login_path: staffLoginPath
      });
      window.location.href = '/internal/admin';
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
      saveSession({
        ...sessionFromLoginResponse(json as Record<string, unknown>),
        staff_login_path: staffLoginPath
      });
      window.location.href = '/internal/admin';
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
