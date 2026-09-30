import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const SOURCE = readFileSync(
  new URL('../../apps/web/react/src/pages/page-components.tsx', import.meta.url),
  'utf8',
);

const APP_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/App.tsx', import.meta.url),
  'utf8',
);
const ROUTER_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/pages/router.tsx', import.meta.url),
  'utf8',
);
const API_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/lib/api.ts', import.meta.url),
  'utf8',
);
const PAYLOAD_GATE_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/lib/payload-commit-generation.mjs', import.meta.url),
  'utf8',
);
const LOADING_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/lib/empty-from-api.tsx', import.meta.url),
  'utf8',
);

function section(start, end) {
  const startIndex = SOURCE.indexOf(start);
  const endIndex = SOURCE.indexOf(end, startIndex);
  assert.ok(startIndex >= 0, `missing section start: ${start}`);
  assert.ok(endIndex > startIndex, `missing section end: ${end}`);
  return SOURCE.slice(startIndex, endIndex);
}

describe('Route-level hydration truthfulness', () => {
  it('gates both React state and the shared portal cache with one route-generation ticket', () => {
    assert.match(APP_SOURCE, /const \[hydratingRoute, setHydratingRoute\] = useState<RouteId \| null>\(null\)/);
    assert.match(APP_SOURCE, /const payloadCommitGate = useRef\(createPayloadCommitGate\(route\)\)/);
    assert.match(APP_SOURCE, /load: \(isCurrent\) => options\.datasets/);
    assert.match(APP_SOURCE, /const scopedSession = sessionForRoute\(nextSession, nextRoute\)/);
    assert.match(APP_SOURCE, /fetchPortalDatasets\(nextConfig, scopedSession, options\.datasets, isCurrent\)/);
    assert.match(APP_SOURCE, /shouldCommitCache: isCurrent/);
    assert.match(APP_SOURCE, /setHydratingRoute\(route\)/);
    assert.match(APP_SOURCE, /hydrating=\{hydratingRoute === route\}/);

    assert.match(PAYLOAD_GATE_SOURCE, /const isCurrent = \(\) => gate\.isCurrent\(ticket\)/);
    assert.match(PAYLOAD_GATE_SOURCE, /const payload = await load\(isCurrent\)/);
    assert.match(API_SOURCE, /shouldCommitCache\?: \(\) => boolean/);
    assert.match(API_SOURCE, /if \(options\.shouldCommitCache\?\.\(\) \?\? true\) \{\s*portalDataCache\.set/);

    assert.match(ROUTER_SOURCE, /function routeHydrationLabel\(route: RouteId\)[\s\S]*return `Loading \${route\.replaceAll\('-', ' '\)}`/);
    assert.match(ROUTER_SOURCE, /if \(hydrating\) \{[\s\S]*<PortalLoadingSkeleton rows=\{4\} label=\{routeHydrationLabel\(route\)\} \/>/);
    assert.doesNotMatch(ROUTER_SOURCE, /ROUTE_HYDRATION_LABELS|hydrating && hydrationLabel/);
    assert.equal(`Loading ${'reports'.replaceAll('-', ' ')}`, 'Loading reports');
    assert.match(LOADING_SOURCE, /role="status" aria-label=\{label\} aria-busy="true"/);
  });
});

const INTEGRATIONS_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/pages/integrations-page.tsx', import.meta.url),
  'utf8',
);
const INTEGRATIONS_STYLES_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/pages/integrations-page-styles.ts', import.meta.url),
  'utf8',
);
const PROVIDER_LOGOS_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/components/integrations/provider-logos.tsx', import.meta.url),
  'utf8',
);

describe('Integrations portal annotations', () => {
  const integrations = INTEGRATIONS_SOURCE;

  it('offers implemented connect, credential-free manual, and single-domain paths', () => {
    for (const label of ['Connect read-only', 'Manual metadata', 'Single domain']) {
      assert.match(integrations, new RegExp(`>${label}<`));
    }
    assert.match(integrations, /supportsCredentialPolling/);
    assert.match(integrations, /AstraNull does not contact the provider/);
    assert.match(integrations, /Opening a provider never grants AstraNull cloud access/);
    assert.doesNotMatch(integrations, /api\.cloudflare\.com|route53\.amazonaws\.com|management\.azure\.com/);
  });

  it('renders accurate provider brand logos, not emoji or guessed marks', () => {
    // Provider directory uses the dedicated ProviderLogo component.
    assert.match(integrations, /import \{ ProviderLogo, type ProviderLogoId \} from '\.\.\/components\/integrations\/provider-logos'/);
    assert.match(integrations, /<ProviderLogo provider=\{provider\.logo\}/);
    // Simple Icons (CC0) attribution must be present in the logo source.
    assert.match(PROVIDER_LOGOS_SOURCE, /Simple Icons/);
    assert.match(PROVIDER_LOGOS_SOURCE, /CC0/);
    // Marks render in currentColor so token CSS controls color; no emoji.
    assert.match(PROVIDER_LOGOS_SOURCE, /fill="currentColor"/);
    assert.doesNotMatch(PROVIDER_LOGOS_SOURCE, /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}]/u);
  });

  it('declares single domains via POST /v1/targets without environments (ADR-0008)', () => {
    assert.match(integrations, /validateDeclaredHostname/);
    assert.match(integrations, /requestJson\(config, session, '\/v1\/targets', \{/);
    assert.match(integrations, /kind: 'fqdn'/);
    assert.match(integrations, /target_group_id: groupId/);
    assert.match(integrations, /Ownership remains unverified/);
    // Environments are gone: no environment fetch, picker, or /v1/environments call.
    assert.doesNotMatch(integrations, /\/v1\/environments/);
    assert.doesNotMatch(integrations, /environment_id/);
    // The single-domain path no longer creates a target group as a prerequisite.
    assert.doesNotMatch(integrations, /'\/v1\/target-groups',/);
  });

  it('keeps the single-domain path usable when connectors are disabled', () => {
    assert.match(integrations, /const connectorsEnabled = featureFlags\?\.connectors === true/);
    assert.match(integrations, /connector add-on is not enabled/i);
    // Add domain action is gated on target write, not on connectors being enabled.
    assert.match(integrations, /canWriteIntegrationTargets \? \(/);
  });

  it('renders list failures before connector empty states', () => {
    assert.match(integrations, /const connectorsLoadError = data\.loadErrors\.connectors/);
    assert.match(integrations, /const targetGroupsLoadError = data\.loadErrors\.targetGroups/);
    assert.match(integrations, /loadError=\{connectorsLoadError\}/);
    assert.match(integrations, /onRetry=\{\(\) => void onRefresh\(\)\}/);
  });

  it('uses scoped design tokens rather than raw color literals', () => {
    assert.doesNotMatch(INTEGRATIONS_STYLES_SOURCE, /#[0-9a-f]{3,8}\b/i);
    assert.match(INTEGRATIONS_STYLES_SOURCE, /var\(--accent\)/);
    assert.match(INTEGRATIONS_STYLES_SOURCE, /var\(--border-soft\)/);
  });
});

describe('Subscription portal annotations', () => {
  const subscription = section('const SUBSCRIPTION_PAGE_STYLES', 'export function StaffSurfacePage');

  it('prioritizes load error and retry before loading and empty subscription states', () => {
    const loadErrorBranch = subscription.indexOf('if (subscriptionLoadError)');
    const loadingBranch = subscription.indexOf('if (!data.loaded)');
    const emptyBranch = subscription.indexOf('if (!hasSubscription)');
    assert.ok(loadErrorBranch >= 0 && loadErrorBranch < loadingBranch);
    assert.ok(loadingBranch < emptyBranch);
    assert.match(subscription, /Subscription data could not be loaded/);
    assert.match(subscription, /window\.location\.reload\(\)/);
    assert.match(subscription, /Loading subscription…/);
    assert.match(subscription, /No subscription record is available/);
  });

  it('uses a three, two, one responsive usage-card grid', () => {
    assert.match(subscription, /\.subscription-usage-grid \{[\s\S]*?grid-template-columns: repeat\(3, minmax\(0, 1fr\)\)/);
    assert.match(subscription, /@media \(max-width: 960px\)[\s\S]*?\.subscription-usage-grid \{[\s\S]*?repeat\(2, minmax\(0, 1fr\)\)/);
    assert.match(subscription, /@media \(max-width: 620px\)[\s\S]*?\.subscription-usage-grid \{[\s\S]*?grid-template-columns: 1fr/);
    assert.match(subscription, /role="list" aria-label="Subscription usage"/);
  });

  it('shows freshness and one authoritative entitlement table with labeled indicators', () => {
    assert.match(subscription, /subscriptionRecordedTimestamp/);
    assert.match(subscription, /Source snapshot/);
    assert.match(subscription, /source timestamp not provided/);
    assert.match(subscription, /> Refresh\s*<\/Button>/);
    assert.match(subscription, /Effective access \(authoritative\)/);
    assert.match(subscription, /enabledLabel="Included" disabledLabel="Not included"/);
    assert.match(subscription, /enabledLabel="Enabled" disabledLabel="Disabled"/);
    assert.match(subscription, /CheckCircle2 : value === false \? CircleMinus : CircleHelp/);
    assert.doesNotMatch(subscription, /subscription-entitlement-pill|Entitlement breakdown/);
  });

  it('keeps subscription styling token-scoped', () => {
    assert.doesNotMatch(subscription, /#[0-9a-f]{3,8}\b/i);
    assert.match(subscription, /var\(--proof-surface\)/);
    assert.match(subscription, /var\(--success\)/);
  });
});
