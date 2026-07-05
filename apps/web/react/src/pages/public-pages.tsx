import { FormEvent, useEffect, useMemo, useState } from 'react';
import {
  ArrowRight,
  Check,
  CheckCircle2,
  FileCheck2,
  LockKeyhole,
  ShieldCheck,
  Siren,
  TriangleAlert,
  UserRound
} from 'lucide-react';
import {
  isOidcJwtMode,
  loadSession,
  resolveOidcLoginRedirect,
  saveSession,
  sessionFromLoginResponse
} from '../lib/api';
import { PLATFORM_PROMISE, STAFF_LINKS } from '../lib/navigation';
import type { PortalConfig } from '../lib/types';
import { AnchorButton, Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { BrandMark } from '../components/layout/brand';

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

function PublicShell({
  children,
  eyebrow = 'No-access-first · Evidence-backed · SOC-gated',
  activeNav,
  loginHref = '/login',
  signupEnabled = true
}: {
  children: React.ReactNode;
  eyebrow?: string;
  activeNav?: 'login' | 'signup';
  loginHref?: string;
  signupEnabled?: boolean;
}) {
  return (
    <div className="public-app">
      <header className="public-topnav">
        <div className="public-topnav-inner">
          <a href="/" className="brand">
            <BrandMark />
            <span>AstraNull</span>
          </a>
          <span className="public-topnav-eyebrow eyebrow">{eyebrow}</span>
          <nav className="public-topnav-actions" aria-label="Account access">
            {signupEnabled ? (
              <AnchorButton href="/signup" variant={activeNav === 'signup' ? 'default' : 'secondary'} size="sm">Sign up</AnchorButton>
            ) : null}
            <AnchorButton href={loginHref} variant={activeNav === 'login' ? 'default' : 'secondary'} size="sm">Log in</AnchorButton>
          </nav>
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
    <main className={`auth-page${wide ? ' auth-page--wide' : ''}`}>
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

const LANDING_PRINCIPLES = [
  {
    num: '01',
    title: 'No-access-first',
    body: 'You declare the target groups you want validated. AstraNull never defaults to cloud access and never auto-discovers your IP inventory. Validation uses outside probes and inside agents you place — nothing more.'
  },
  {
    num: '02',
    title: 'Evidence over assumptions',
    body: 'Every verdict is backed by correlated probe results and agent observations, written to an evidence vault you control. Readiness is a number you can defend in an incident review — not a green checkmark.'
  },
  {
    num: '03',
    title: 'SOC-gated high-scale',
    body: 'Default validation is low-volume, bounded, and non-disruptive. High-scale assessments are reviewed and executed by the AstraNull SOC after approval — customers submit requests, never run floods themselves.'
  }
];

const LANDING_FLOW = [
  {
    tag: '01 · Declare',
    title: 'Scope your target groups',
    body: 'Register environments and target groups — the FQDNs, DNS zones, and TCP surfaces you want validated. Declare expected behavior so verdicts map to your real edge topology.'
  },
  {
    tag: '02 · Validate',
    title: 'Place agents, run safe checks',
    body: 'Install outbound-only agents and run the safe-by-default check catalog: origin-bypass, L3/L4, DNS, L7/API. Each check is bounded and metadata-only unless you escalate.'
  },
  {
    tag: '03 · Evidence',
    title: 'Correlate probe + agent',
    body: 'Verdicts combine external probe reachability with internal agent path observation. Every result lands in the evidence vault, exportable for audits and incident reviews.'
  },
  {
    tag: '04 · Govern',
    title: 'Escalate through the SOC',
    body: 'When you need high-scale validation, submit a request. The SOC reviews, schedules, and executes under a kill switch — with full custody and audit trail.'
  }
];

const LANDING_COMPARE = [
  ['Requires cloud credentials', 'No — declared scope only', 'Often', 'Yes, read/write'],
  ['Default probe posture', 'Bounded & non-disruptive', 'High-volume by default', 'Passive metrics only'],
  ['Inside + outside correlation', 'Probes + placed agents', 'Outside only', 'Inside only'],
  ['High-scale execution', 'SOC-gated after approval', 'Self-service', 'Not available'],
  ['Exportable evidence trail', 'Evidence vault + custody', 'Run logs', 'Metric exports']
];

const LANDING_USE_CASES = [
  {
    quote: 'Regulated fintech that needs a defensible readiness number for audit — without granting a tool cloud credentials or letting it inventory production IPs.',
    attr: 'Platform & security leads — declared-scope validation and evidence they can hand to an auditor.'
  },
  {
    quote: 'High-traffic media & CDN teams that want real high-scale assurance, but only under governance — no self-service floods pointed at production.',
    attr: 'SRE & edge owners — SOC-governed high-scale, bounded probes the rest of the time.'
  }
];

export function PublicLandingPage({ config }: PublicPageProps) {
  const productName = String(config.siteConfig.product_name ?? 'AstraNull');
  const promise = String(config.siteConfig.promise ?? PLATFORM_PROMISE);
  const signupEnabled = config.siteConfig.signup_enabled !== false;
  const loginUrl = config.loginUrl;

  usePageMeta({
    title: `${productName} — Prove DDoS readiness without handing over your cloud keys`
  });

  return (
    <PublicShell
      eyebrow="No-access-first · Evidence-backed · SOC-gated high-scale"
      loginHref={loginUrl}
      signupEnabled={signupEnabled}
    >
      <main className="public-wrap">
        <section className="public-hero">
          <p className="eyebrow">Defensive DDoS readiness validation</p>
          <h1>Prove DDoS readiness without handing over your cloud keys</h1>
          <p className="public-hero-lead">{promise}</p>
          <div className="public-actions">
            {signupEnabled ? (
              <AnchorButton href="/signup">
                Request access
                <ArrowRight size={15} />
              </AnchorButton>
            ) : null}
            <AnchorButton href={loginUrl} variant="secondary">Log in</AnchorButton>
          </div>
          <div className="public-hero-meta">
            <span><Check size={16} />No cloud credentials required</span>
            <span><Check size={16} />Low-volume, bounded probes</span>
            <span><Check size={16} />SOC-governed high-scale</span>
          </div>
        </section>

        <section className="public-section" id="principles">
          <p className="eyebrow">Principles</p>
          <h2>A defensive readiness platform, not self-service attack tooling</h2>
          <p className="public-section-lead">Three commitments shape every screen, every probe, every verdict in AstraNull.</p>
          <div className="public-pillars">
            {LANDING_PRINCIPLES.map((pillar) => (
              <article className="public-pillar" key={pillar.title}>
                <p className="public-pillar-num">{pillar.num}</p>
                <h3>{pillar.title}</h3>
                <p>{pillar.body}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="public-section" id="how">
          <p className="eyebrow">How it works</p>
          <h2>Declare · Validate · Evidence · Govern</h2>
          <p className="public-section-lead">A four-stage loop that turns a declared scope into a defensible readiness posture.</p>
          <div className="public-flow">
            {LANDING_FLOW.map((step) => (
              <article className="public-flow-step" key={step.tag}>
                <p className="public-flow-tag">{step.tag}</p>
                <h3>{step.title}</h3>
                <p>{step.body}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="public-section public-section--narrow" id="compare">
          <p className="eyebrow">Why AstraNull</p>
          <h2>Built for teams that can&apos;t hand over the keys</h2>
          <div className="public-compare">
            <table>
              <thead>
                <tr>
                  <th scope="col" />
                  <th scope="col">AstraNull</th>
                  <th scope="col">Legacy load-testing</th>
                  <th scope="col">Cloud DDoS dashboards</th>
                </tr>
              </thead>
              <tbody>
                {LANDING_COMPARE.map(([label, anull, legacy, cloud]) => (
                  <tr key={label}>
                    <th scope="row">{label}</th>
                    <td className="public-compare-yes">{anull}</td>
                    <td>{legacy}</td>
                    <td>{cloud}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="public-section">
          <p className="eyebrow">Who it&apos;s built for</p>
          <h2>Where the no-access model matters most</h2>
          <p className="public-section-lead">Two profiles that keep hitting the wall between &ldquo;prove the edge holds&rdquo; and &ldquo;don&apos;t hand a validation tool our cloud keys.&rdquo;</p>
          <div className="public-quotes">
            {LANDING_USE_CASES.map((item) => (
              <article className="public-quote" key={item.attr}>
                <blockquote>{item.quote}</blockquote>
                <p>{item.attr}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="public-cta-final">
          <h2>Prove your edge holds — before an attacker proves it doesn&apos;t.</h2>
          <p>Request access. We&apos;ll review your account and stand up a tenant with the full customer portal.</p>
          <div className="public-actions">
            {signupEnabled ? <AnchorButton href="/signup">Request access</AnchorButton> : null}
            <AnchorButton href={loginUrl} variant="secondary">Log in</AnchorButton>
          </div>
        </section>

        <footer className="public-footer">
          <span>© {productName} — DDoS readiness validation. Defensive platform only.</span>
          <nav aria-label="Public footer">
            <a href={loginUrl}>Log in</a>
            <a href="#principles">Principles</a>
          </nav>
        </footer>
      </main>
    </PublicShell>
  );
}

export function LoginPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Log in — AstraNull Customer Portal' });

  const [userId, setUserId] = useState('usr_admin');
  const [role, setRole] = useState('admin');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const isDevHeaders = config.authMode === 'dev-headers';
  const isOidc = isOidcJwtMode(config);
  const idpRedirect = useMemo(() => resolveOidcLoginRedirect(config, 'customer'), [config]);
  const loginDisabled = isOidc && !config.bundledLoginEnabled && !idpRedirect;

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
    ? 'Developer validation mode — continue with local tenant headers (no password required).'
    : config.bundledLoginEnabled
      ? 'Bundled staging login mints a short-lived bearer session for this environment.'
      : idpRedirect
        ? 'Redirecting to your organization sign-in provider.'
        : 'Sign-in is managed by your organization identity provider.';

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (loginDisabled) return;
    setError('');
    setLoading(true);

    if (isDevHeaders) {
      saveSession({
        mode: 'dev-headers',
        principal: 'customer',
        tenant_id: 'ten_demo',
        user_id: userId.trim() || 'usr_admin',
        role
      });
      window.location.href = config.portalPath;
      return;
    }

    try {
      const response = await fetch('/v1/auth/bundled-staging-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({
          principal: 'customer',
          tenant_id: 'ten_demo',
          user_id: userId.trim() || 'usr_admin',
          role
        })
      });
      const json = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(String(json.message ?? json.error ?? 'Login failed.'));
      saveSession(sessionFromLoginResponse(json as Record<string, unknown>));
      window.location.href = config.portalPath;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed.');
      setLoading(false);
    }
  }

  return (
    <PublicShell eyebrow="Customer portal" activeNav="login">
      <AuthPageLayout
        aside={(
          <>
            <p className="auth-kicker">Customer workspace</p>
            <h1 className="auth-title">Log in to your readiness console.</h1>
            <p className="auth-lead">
              {isDevHeaders
                ? 'Local developer validation uses tenant headers to preview RBAC without a password.'
                : 'Review declared targets, agent heartbeats, safe validation runs, and SOC-governed high-scale intake from one tenant-scoped surface.'}
            </p>
            <ul className="auth-points">
              <li><ShieldCheck size={16} /> Evidence-backed verdicts tied to observed probe data</li>
              <li><LockKeyhole size={16} /> No default cloud credentials required</li>
              <li><FileCheck2 size={16} /> Audit-ready exports and custody references</li>
            </ul>
          </>
        )}
        footer={(
          <p>
            Need an account? <a href="/signup">Request access</a>
            {' · '}
            <a href="/signup-status">Check request status</a>
          </p>
        )}
      >
        <Card className="auth-card">
          <AuthCardHeader
            badge={<Badge tone="info">Customer portal</Badge>}
            title="Log in to AstraNull"
            description={cardDescription}
          />
          <CardContent>
            <form className="auth-form" onSubmit={submit}>
              <label>
                <span>{isDevHeaders || config.bundledLoginEnabled ? 'Work email / user ID' : 'User ID'}</span>
                <input
                  value={userId}
                  onChange={(event) => setUserId(event.target.value)}
                  autoComplete="username"
                  required={!loginDisabled}
                  disabled={loginDisabled || Boolean(idpRedirect)}
                />
              </label>
              <label>
                <span>Tenant</span>
                <input value="ten_demo" readOnly aria-readonly="true" disabled={loginDisabled || Boolean(idpRedirect)} />
              </label>
              <label>
                <span>Role</span>
                <select
                  value={role}
                  onChange={(event) => setRole(event.target.value)}
                  disabled={loginDisabled || Boolean(idpRedirect)}
                >
                  {['admin', 'engineer', 'soc', 'viewer', 'auditor', 'owner'].map((item) => (
                    <option value={item} key={item}>{item}</option>
                  ))}
                </select>
              </label>
              {error ? <p className="form-error" role="alert">{error}</p> : null}
              <div className="auth-form-actions">
                <Button type="submit" disabled={loading || loginDisabled || Boolean(idpRedirect)}>
                  {loading ? 'Signing in...' : 'Continue to portal'}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </AuthPageLayout>
    </PublicShell>
  );
}

function signupSubmitErrorMessage(status: number, json: Record<string, unknown>) {
  const code = String(json.error ?? '');
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
  return String(json.message ?? json.error ?? 'Could not submit request.');
}

export function SignupPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Request access — AstraNull' });

  const signupEnabled = config.siteConfig.signup_enabled !== false;
  const [submitted, setSubmitted] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState('');

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!signupEnabled) return;
    setError('');
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
      setSubmitted(json.request ?? json);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not submit request.');
    }
  }

  return (
    <PublicShell eyebrow="Approval-gated account intake" activeNav="signup">
      <AuthPageLayout
        wide
        aside={(
          <>
            <p className="auth-kicker">Account intake</p>
            <h1 className="auth-title">Request governed validation access.</h1>
            <p className="auth-lead">Provisioning is review-gated. Operations validates organization details, intended use, and plan fit before creating a tenant workspace.</p>
            <ul className="auth-points">
              <li><ShieldCheck size={16} /> Safe-by-default validation is available immediately after approval</li>
              <li><Siren size={16} /> High-scale programs stay SOC-scheduled and authorization-pack gated</li>
              <li><UserRound size={16} /> Track request status any time with your request ID</li>
            </ul>
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
            description="Account creation is reviewed before provisioning a tenant."
          />
          <CardContent>
            {!signupEnabled ? (
              <div className="success-panel">
                <TriangleAlert size={30} />
                <p className="success-panel-lead">Account intake is temporarily closed for this deployment. Existing customers can sign in; approved request IDs can still be checked on the status page.</p>
                <div className="auth-form-actions row-actions">
                  <AnchorButton href="/login" variant="secondary">Log in</AnchorButton>
                  <AnchorButton href="/signup-status">Check request status</AnchorButton>
                </div>
              </div>
            ) : submitted ? (
              <div className="success-panel">
                <CheckCircle2 size={30} />
                <p className="success-panel-lead">We provision reviewed accounts only. Save your request ID to check status any time.</p>
                <dl>
                  <div><dt>Request ID</dt><dd>{String(submitted.id ?? 'submitted')}</dd></div>
                  <div><dt>Status</dt><dd>{String(submitted.state ?? 'submitted')}</dd></div>
                  <div><dt>Organization</dt><dd>{String(submitted.organization_name ?? 'Recorded')}</dd></div>
                  <div><dt>Requested plan</dt><dd>{String(submitted.requested_plan ?? 'professional')}</dd></div>
                  <div><dt>Region</dt><dd>{String(submitted.region ?? 'us')}</dd></div>
                </dl>
                <div className="auth-form-actions row-actions">
                  <AnchorButton href="/signup-status" variant="secondary">Check status</AnchorButton>
                  <AnchorButton href="/">Back to landing</AnchorButton>
                </div>
              </div>
            ) : (
              <form className="auth-form auth-form--grid" onSubmit={submit}>
                <label><span>Organization</span><input name="organization_name" required placeholder="Acme Corp" autoComplete="organization" /></label>
                <label><span>Work email</span><input name="contact_email" type="email" required placeholder="you@company.com" autoComplete="email" /></label>
                <label><span>Primary contact</span><input name="contact_name" required placeholder="Jordan Lee" autoComplete="name" /></label>
                <label><span>Requested plan</span><select name="requested_plan" defaultValue="professional"><option value="starter">starter</option><option value="professional">professional</option><option value="enterprise">enterprise</option></select></label>
                <label className="auth-field-full"><span>Intended use</span><textarea name="intended_use" required rows={4} placeholder="Defensive DDoS readiness validation for declared production origins." /></label>
                <label><span>Region</span><select name="region" defaultValue="us"><option value="us">United States</option><option value="eu">European Union</option><option value="uk">United Kingdom</option><option value="apac">Asia-Pacific</option></select></label>
                <label className="auth-field-full auth-check-row"><input name="high_scale_interest" type="checkbox" /><span>We may need SOC-governed high-scale validation.</span></label>
                {error ? <p className="form-error auth-field-full" role="alert">{error}</p> : null}
                <div className="auth-form-actions auth-field-full">
                  <Button type="submit">Submit request</Button>
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
  usePageMeta({ title: 'Request status — AstraNull' });

  const [requestId, setRequestId] = useState('');
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError('');
    setResult(null);
    const id = requestId.trim();
    if (!id) {
      setError('Enter a request ID to check status.');
      return;
    }
    setLoading(true);
    try {
      const response = await fetch(`/v1/signup-requests/${encodeURIComponent(id)}`, {
        headers: { accept: 'application/json' }
      });
      const json = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(String(json.message ?? json.error ?? 'Request status was not found.'));
      setResult((json.request ?? json) as Record<string, unknown>);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Request status was not found.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <PublicShell eyebrow="Self-service status lookup">
      <AuthPageLayout
        aside={(
          <>
            <p className="auth-kicker">Self-service</p>
            <h1 className="auth-title">Sign-up status</h1>
            <p className="auth-lead">Track your account request. You&apos;ll find the request ID in the confirmation panel shown after you submit the intake form, or in the email we sent to the work address you registered.</p>
          </>
        )}
        footer={(
          <p>
            Lost your request ID? <a href="/signup">Re-submit the intake</a>
            {' · '}
            <a href="/login">Log in</a>
          </p>
        )}
      >
        <Card className="auth-card">
          <AuthCardHeader
            badge={<Badge tone="info">Status lookup</Badge>}
            title="Check request status"
            description="Account provisioning remains review-gated and every status change is reviewed by operations."
          />
          <CardContent>
            <form className="auth-form" onSubmit={submit}>
              <label>
                <span>Request ID</span>
                <input
                  value={requestId}
                  onChange={(event) => setRequestId(event.target.value)}
                  placeholder="sgn_… (from your confirmation)"
                  className="mono"
                  autoComplete="off"
                  required
                />
                <span className="auth-field-help">Use the ID returned after intake submission. Case-sensitive.</span>
              </label>
              {error ? <p className="form-error" role="alert">{error}</p> : null}
              <div className="auth-form-actions">
                <Button type="submit" disabled={loading}>{loading ? 'Checking...' : 'Look up status'}</Button>
              </div>
              {result ? (
                <div className="success-panel">
                  <dl>
                    <div><dt>Request ID</dt><dd>{String(result.id ?? requestId)}</dd></div>
                    <div><dt>Status</dt><dd>{String(result.state ?? result.status ?? 'recorded')}</dd></div>
                    <div><dt>Organization</dt><dd>{String(result.organization_name ?? result.organization ?? 'Not recorded')}</dd></div>
                    <div><dt>Requested plan</dt><dd>{String(result.requested_plan ?? 'Not recorded')}</dd></div>
                    <div><dt>Region</dt><dd>{String(result.region ?? 'Not recorded')}</dd></div>
                  </dl>
                  {result.customer_notice ? (
                    <p className="auth-field-help">{String(result.customer_notice)}</p>
                  ) : null}
                </div>
              ) : null}
            </form>
          </CardContent>
        </Card>
      </AuthPageLayout>
    </PublicShell>
  );
}

export function StaffLoginPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Staff sign-in — AstraNull Internal', robots: 'noindex, nofollow' });

  const [staffId, setStaffId] = useState('staff_admin');
  const [staffRole, setStaffRole] = useState('internal_admin');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const isDevHeaders = config.authMode === 'dev-headers';
  const isOidc = isOidcJwtMode(config);
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
    ? 'Developer validation mode — continue with staff dev headers (no password required).'
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
        staff_id: staffId.trim() || 'staff_admin',
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
          staff_id: staffId.trim() || 'staff_admin',
          staff_role: staffRole
        })
      });
      const json = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(String(json.message ?? json.error ?? 'Staff login failed.'));
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
    <PublicShell eyebrow="Internal staff access">
      <AuthPageLayout
        aside={(
          <>
            <p className="auth-kicker">Staff plane</p>
            <h1 className="auth-title">Sign in to internal management.</h1>
            <p className="auth-lead">
              {isDevHeaders
                ? 'Local developer validation uses staff headers to preview internal RBAC without a password.'
                : 'Review signup intake, tenant lifecycle, entitlement grants, approval queues, and internal audit from a separate staff surface.'}
            </p>
            <div className="staff-callout" role="note">
              <TriangleAlert size={18} />
              <span>This surface performs provisioning and approval decisions. All actions are written to the internal audit log.</span>
            </div>
          </>
        )}
        footer={<p><a href="/">Back to site</a> · <a href="/login">Customer login</a></p>}
      >
        <Card className="auth-card">
          <AuthCardHeader
            badge={<Badge tone="warn">Staff only</Badge>}
            title="Staff sign-in"
            description={cardDescription}
          />
          <CardContent>
            <form className="auth-form" onSubmit={submit}>
              <label>
                <span>Staff ID</span>
                <input
                  value={staffId}
                  onChange={(event) => setStaffId(event.target.value)}
                  autoComplete="username"
                  required={!loginDisabled}
                  disabled={loginDisabled || Boolean(idpRedirect)}
                />
              </label>
              <label>
                <span>Staff role</span>
                <select
                  value={staffRole}
                  onChange={(event) => setStaffRole(event.target.value)}
                  disabled={loginDisabled || Boolean(idpRedirect)}
                >
                  {['internal_admin', 'billing_ops', 'support_engineer', 'security_admin', 'soc_analyst', 'soc_lead'].map((item) => (
                    <option value={item} key={item}>{item}</option>
                  ))}
                </select>
              </label>
              {error ? <p className="form-error" role="alert">{error}</p> : null}
              <div className="auth-form-actions">
                <Button type="submit" disabled={loading || loginDisabled || Boolean(idpRedirect)}>
                  {loading ? 'Signing in...' : 'Continue to internal admin'}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </AuthPageLayout>
    </PublicShell>
  );
}

export function InternalAdminPage({ config }: PublicPageProps) {
  void config;
  return (
    <PublicShell eyebrow="Internal management">
      <main className="public-wrap">
        <section className="page-head staff-head">
          <div>
            <p className="eyebrow">Staff management plane</p>
            <h2>Internal Admin</h2>
            <p>Separate staff surface for tenant lifecycle, sign-up review, subscriptions, support actions, approvals, and audit.</p>
          </div>
          <AnchorButton href="/app" variant="secondary">Customer portal</AnchorButton>
        </section>
        <section className="public-grid">
          {STAFF_LINKS.map((link) => {
            const Icon = link.icon;
            return (
              <a className="public-card" href={link.href} key={link.label}>
                <span><Icon size={18} /></span>
                <h3>{link.label}</h3>
                <p>{link.description}</p>
                <small>Open <ArrowRight size={13} /></small>
              </a>
            );
          })}
          <div className="public-card">
            <span><UserRound size={18} /></span>
            <h3>Tenant detail</h3>
            <p>Lifecycle state, entitlements, owner users, support notes, and audit activity.</p>
            <small>Staff only</small>
          </div>
        </section>
      </main>
    </PublicShell>
  );
}
