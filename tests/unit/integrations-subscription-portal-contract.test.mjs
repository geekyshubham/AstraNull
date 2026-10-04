import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
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
    // Full-color DNS Migrator marks ship as bundled PNG imports with a notice.
    assert.match(PROVIDER_LOGOS_SOURCE, /import cloudflareLogo from '\.\/logos\/cloudflare\.png'/);
    assert.match(PROVIDER_LOGOS_SOURCE, /THIRD_PARTY_NOTICES\/provider-logos-NOTICE\.txt/);
    // Decorative when adjacent text names the provider; dark variants follow the theme.
    assert.match(PROVIDER_LOGOS_SOURCE, /alt=\{decorative \? '' : title\}/);
    assert.match(PROVIDER_LOGOS_SOURCE, /route53DarkLogo/);
    assert.match(PROVIDER_LOGOS_SOURCE, /getAttribute\('data-theme'\) !== 'light'/);
    // Generic fallback stays an outline glyph; no emoji anywhere.
    assert.match(PROVIDER_LOGOS_SOURCE, /stroke="currentColor"/);
    assert.doesNotMatch(PROVIDER_LOGOS_SOURCE, /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}]/u);
    // The logo well is neutral: no per-provider color tints.
    assert.doesNotMatch(INTEGRATIONS_STYLES_SOURCE, /provider-logo-frame\[data-provider/);
    for (const file of ['cloudflare', 'akamai', 'route53', 'route53-dark', 'godaddy', 'namecheap', 'hetzner', 'hetzner-dark', 'gcp', 'azure', 'ns1', 'ns1-dark']) {
      assert.ok(existsSync(new URL(`../../apps/web/react/src/components/integrations/logos/${file}.png`, import.meta.url)), `${file}.png is bundled`);
    }
  });

  it('links a verified least-privilege setup guide for every directory provider', () => {
    const guides = readFileSync(
      new URL('../../apps/web/react/src/components/integrations/provider-setup-guides.ts', import.meta.url),
      'utf8',
    );
    const ids = [...integrations.matchAll(/^    id: '([a-z0-9_]+)',$/gm)].map((match) => match[1]);
    assert.ok(ids.length >= 9, 'directory ids parsed');
    for (const id of ids) assert.match(guides, new RegExp(`\\n  ${id}: \\{`), `${id} has a setup guide`);
    assert.match(guides, /Zone > Zone > Read/);
    assert.match(guides, /DNS—Zone Record Management/);
    assert.match(guides, /View zones/);
    assert.match(guides, /wafv2:ListWebACLs and wafv2:GetWebACL/);
    assert.match(integrations, /<BookOpen size=\{14\} aria-hidden="true" \/> Setup guide/);
    assert.match(integrations, /rel="noopener noreferrer"/);
    assert.match(integrations, /scope: awsScope/);
    assert.ok(existsSync(new URL('../../docs/integrations/03-dns-edge-provider-setup.md', import.meta.url)));
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

  it('mounts notification channels and offers direct CTAs from the connector empty state', () => {
    assert.match(integrations, /import \{ NotificationChannelsPanel \} from '\.\.\/components\/integrations\/notification-channels'/);
    assert.match(integrations, /<NotificationChannelsPanel\s+config=\{config\}\s+session=\{session\}\s+onChanged=\{onRefresh\}/);
    assert.match(integrations, /title="No connectors configured yet"/);
    assert.match(integrations, /actionLabel=\{canAddIntegration \? 'Add provider' : undefined\}/);
    assert.match(integrations, /onAction=\{canAddIntegration \? \(\) => openProviderFlow\(\) : undefined\}/);
    assert.match(integrations, /Set up notifications/);
    assert.match(integrations, /prefersReducedMotion\(\) \? 'auto' : 'smooth'/);
    const panel = readFileSync(
      new URL('../../apps/web/react/src/components/integrations/notification-channels.tsx', import.meta.url),
      'utf8',
    );
    assert.match(panel, />Notification channels</);
    assert.match(panel, /headingId\?: string/);
  });

  it('renders provider and notification channel cards with one shared tile language', () => {
    const tiles = readFileSync(
      new URL('../../apps/web/react/src/components/integrations/integration-tile-styles.ts', import.meta.url),
      'utf8',
    );
    const panel = readFileSync(
      new URL('../../apps/web/react/src/components/integrations/notification-channels.tsx', import.meta.url),
      'utf8',
    );
    const channelLogos = readFileSync(
      new URL('../../apps/web/react/src/components/integrations/channel-logos.tsx', import.meta.url),
      'utf8',
    );
    assert.doesNotMatch(tiles, /#[0-9a-f]{3,8}\b/i);
    assert.match(tiles, /prefers-reduced-motion: reduce/);
    assert.match(tiles, /min-height: 44px/);
    for (const source of [integrations, panel]) {
      assert.match(source, /INTEGRATION_TILE_STYLES/);
      for (const cls of ['integration-tile-grid', 'integration-tile', 'integration-identity', 'integration-tile-footer', 'integration-chip', 'integration-tile-actions']) {
        assert.match(source, new RegExp(`className="${cls}"`), `${cls} is shared`);
      }
    }
    assert.match(integrations, /className="integration-logo-well"/);
    assert.match(channelLogos, /'integration-logo-well'/);
    // The old per-family card classes are gone, so the two grids cannot drift apart.
    assert.doesNotMatch(integrations, /className="provider-card"|provider-mode-chip/);
    assert.doesNotMatch(panel, /nc-card|nc-grid/);
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
    assert.match(subscription, /title="Feature access"/);
    assert.match(subscription, /label: 'Access',/);
    assert.match(subscription, /value=\{item\.effective_enabled\} enabledLabel="Available" disabledLabel="Unavailable"/);
    assert.match(subscription, /item\.plan_enabled === true \? 'Included in plan' : item\.plan_enabled === false \? 'Not in plan' : 'Plan inclusion not recorded'/);
    assert.match(subscription, /Source: \{source\}/);
    assert.match(subscription, /CheckCircle2 : value === false \? CircleMinus : CircleHelp/);
    assert.match(SOURCE, /const label = value === true \? enabledLabel : value === false \? disabledLabel : 'Not recorded';/);
    assert.doesNotMatch(subscription, /subscription-entitlement-pill|Entitlement breakdown/);
  });

  it('keeps feature access separate from configured or working integrations', () => {
    assert.match(subscription, /label: 'What access does not mean'/);
    assert.match(subscription, /Available does not mean it is configured or working/);
    assert.match(SOURCE, /connectors: 'Not that a provider is connected; set one up in Integrations\.'/);
    assert.match(SOURCE, /high_scale_program: 'Not self-service\. Only SOC can approve and run high-scale validation\.'/);
  });

  it('never presents unknown usage or limits as zero or unlimited and states units and windows', () => {
    assert.match(subscription, /Unit: checks · window: last 60 minutes/);
    assert.match(subscription, /usage not measured \(not zero\)/);
    assert.match(subscription, /limit not recorded \(not unlimited\)/);
    assert.match(subscription, /Progress is unavailable until both usage and a plan limit are recorded/);
    assert.doesNotMatch(subscription, /high_scale_requests_per_month|High-scale requests/);
  });

  it('keeps subscription styling token-scoped', () => {
    assert.doesNotMatch(subscription, /#[0-9a-f]{3,8}\b/i);
    assert.match(subscription, /var\(--proof-surface\)/);
    assert.match(subscription, /var\(--success\)/);
  });
});
