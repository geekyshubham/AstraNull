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
  it('blocks reports and every other route behind hydration instead of a route allowlist', () => {
    assert.match(APP_SOURCE, /const \[hydratingRoute, setHydratingRoute\] = useState<RouteId \| null>\(null\)/);
    assert.match(APP_SOURCE, /const requestId = \+\+routeHydrationRequestId\.current/);
    assert.match(APP_SOURCE, /setHydratingRoute\(route\)/);
    assert.match(APP_SOURCE, /routeHydrationRequestId\.current !== requestId/);
    assert.match(APP_SOURCE, /hydrating=\{hydratingRoute === route\}/);

    assert.match(ROUTER_SOURCE, /function routeHydrationLabel\(route: RouteId\)[\s\S]*return `Loading \${route\.replaceAll\('-', ' '\)}`/);
    assert.match(ROUTER_SOURCE, /if \(hydrating\) \{[\s\S]*<PortalLoadingSkeleton rows=\{4\} label=\{routeHydrationLabel\(route\)\} \/>/);
    assert.doesNotMatch(ROUTER_SOURCE, /ROUTE_HYDRATION_LABELS|hydrating && hydrationLabel/);
    assert.equal(`Loading ${'reports'.replaceAll('-', ' ')}`, 'Loading reports');
    assert.match(LOADING_SOURCE, /role="status" aria-label=\{label\} aria-busy="true"/);
  });
});

describe('Integrations portal annotations', () => {
  const integrations = section('type DnsProviderDirectoryEntry', 'export function SupportPage');

  it('offers implemented connect, credential-free manual, and single-domain paths', () => {
    for (const label of ['Connect read-only', 'Manual metadata', 'Single domain']) {
      assert.match(integrations, new RegExp(`>${label}<`));
    }
    assert.match(integrations, /title="Add provider"/);
    assert.match(integrations, /supportsCredentialPolling/);
    assert.match(integrations, /No provider API call is made/);
    assert.match(integrations, /Opening a provider never grants AstraNull cloud access/);
    assert.doesNotMatch(integrations, /api\.cloudflare\.com|route53\.amazonaws\.com|management\.azure\.com/);
  });

  it('creates real declared scope and persists truthful single-domain provenance', () => {
    assert.match(integrations, /validateDeclaredHostname/);
    assert.match(integrations, /requestJson\(config, session, '\/v1\/target-groups', \{/);
    assert.match(integrations, /\/v1\/target-groups\/\$\{encodeURIComponent\(groupId\)\}\/targets/);
    assert.match(integrations, /kind: 'fqdn'/);
    assert.match(integrations, /source: 'manual'/);
    assert.match(integrations, /source_app: 'AstraNull portal'/);
    assert.match(integrations, /declaration_path: 'integrations_single_domain'/);
    assert.match(integrations, /provider_access: 'none'/);
    assert.match(integrations, /Ownership remains unverified/);
    assert.match(integrations, /Domain declaration progress/);
  });

  it('renders list failures before connector or target-group empty states', () => {
    assert.match(integrations, /const connectorsLoadError = data\.loadErrors\.connectors/);
    assert.match(integrations, /const targetGroupsLoadError = data\.loadErrors\.targetGroups/);
    assert.match(integrations, /loadError=\{connectorsLoadError\}/);
    assert.match(integrations, /onRetry=\{\(\) => void onRefresh\(\)\}/);
    assert.match(integrations, /Could not refresh target groups/);
  });

  it('uses scoped design tokens rather than raw color literals', () => {
    assert.doesNotMatch(integrations, /#[0-9a-f]{3,8}\b/i);
    assert.match(integrations, /var\(--accent\)/);
    assert.match(integrations, /var\(--border-soft\)/);
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
    assert.match(subscription, /returned no subscription record/);
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
