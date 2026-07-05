#!/usr/bin/env node
/**
 * Browser validation for React customer portal routes (desktop + mobile).
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

const ROUTES = [
  'dashboard',
  'onboarding',
  'environments',
  'target-groups',
  'agents',
  'checks',
  'runs',
  'findings',
  'evidence',
  'test-policies',
  'waf-posture',
  'cve-pipeline',
  'supply-chain',
  'remediation',
  'discovery',
  'integrations',
  'high-scale',
  'reports',
  'report-detail',
  'notifications',
  'audit',
  'release-evidence',
  'settings',
  'support',
  'subscription',
  'soc',
  'run-detail',
  'target-group-detail',
  'agent-detail',
  'waf-asset-detail',
  'cve-detail',
  'supply-chain-detail',
  'discovery-entity'
];

const STAFF_ROUTES = ['admin', 'tenant-detail'];

const STAFF_SOC_ROUTES = ['internal-soc'];

const PUBLIC_AUTH_ROUTES = ['login', 'signup'];

const EXPECTED_SNIPPETS = {
  dashboard: ['Recent test runs', 'Open findings'],
  onboarding: ['Start placement test', 'Agent heartbeat verification'],
  'target-groups': ['Save target', 'Delete target'],
  agents: ['Create bootstrap token', 'Agent fleet'],
  'run-detail': ['Why this verdict', 'Verdict truth table', 'Summary'],
  'target-group-detail': ['Declared targets', 'Group summary', 'Expected Behavior'],
  'agent-detail': ['Agent identity', 'Actions'],
  'waf-asset-detail': ['Evidence-backed factors', 'WAF effectiveness'],
  'discovery-entity': ['Evidence-backed factors', 'Discovery decision trail'],
  runs: ['Start safe run', 'Test runs', 'Why this verdict'],
  findings: ['Open findings', 'Accepted risk', 'Closed (30d)', 'By Target Group', 'By Vector', 'SLA'],
  environments: ['Environment readiness', 'open findings'],
  checks: ['Check library'],
  'test-policies': ['Create safe validation policy', 'Safe validation policies', 'Active policies'],
  'waf-posture': ['Create WAF asset'],
  'cve-pipeline': ['Create CVE item'],
  'cve-detail': ['CVE detail', 'Run triage'],
  reports: ['Generate report', 'Generated reports', 'PDF export is not available'],
  'report-detail': ['Report detail', 'Export formats', 'Custody preview', 'PDF export is not available'],
  'supply-chain': ['Create risk'],
  'supply-chain-detail': ['Supply chain risk detail', 'Remediation steps'],
  remediation: ['Create action item', 'Dry-run deliver'],
  discovery: ['Declare entity', 'Import to target group'],
  integrations: ['Create read-only connector', 'Configured connectors', 'Secret refs'],
  notifications: ['DLQ', 'redrive'],
  soc: ['SOC role required', 'Kill switch'],
  settings: ['Organization profile', 'Secret vault', 'API keys', 'Data retention'],
  support: ['Support readiness', 'Support workflows', 'Kill switch'],
  subscription: ['Entitlement breakdown', 'Usage against limits', 'Professional'],
  'subscription-empty': ['No subscription configured', 'Contact your AstraNull support team', 'Not configured'],
  'high-scale': ['Lifecycle timeline', 'Authorization pack status'],
  admin: ['Entitlement grants', 'Tenant directory'],
  'tenant-detail': ['Tenant administration', 'Subscription', 'Support owner'],
  'internal-soc': ['SOC execution plane', 'Kill switch'],
  login: ['Log in to AstraNull', 'Continue to portal'],
  signup: ['Request an AstraNull account', 'Submit request']
};

const VIEWPORTS = [
  { name: 'desktop', width: 1440, height: 1000 },
  { name: 'tablet', width: 820, height: 1180 },
  { name: 'mobile', width: 390, height: 844 }
];

function parseArgs(argv = []) {
  const opts = { baseUrl: process.env.ASTRANULL_BASE_URL ?? 'http://127.0.0.1:4320', help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--base-url') opts.baseUrl = argv[++i];
  }
  return opts;
}

const DEMO_HEADERS = {
  'x-tenant-id': 'ten_demo',
  'x-user-id': 'usr_admin',
  'x-role': 'admin',
  'Content-Type': 'application/json'
};

const STAFF_HEADERS = {
  'x-principal-type': 'staff',
  'x-staff-id': 'staff_admin',
  'x-staff-role': 'internal_admin',
  'Content-Type': 'application/json'
};

function customerHeaders(tenantId, userId = 'usr_admin', role = 'admin') {
  return {
    'x-tenant-id': tenantId,
    'x-user-id': userId,
    'x-role': role,
    'Content-Type': 'application/json'
  };
}

async function apiJson(baseUrl, method, path, body, headers = DEMO_HEADERS) {
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return { status: res.status, json };
}

async function verifySeededSubscription(baseUrl) {
  const current = await apiJson(baseUrl, 'GET', '/v1/subscription/current');
  if (current.status !== 200) {
    throw new Error(`seeded subscription lookup failed (${current.status})`);
  }
  if (!current.json?.subscription) {
    throw new Error('ten_demo is expected to have a seeded subscription record');
  }
  if (current.json.plan?.name !== 'Professional') {
    throw new Error(`ten_demo plan expected Professional (got ${current.json.plan?.name ?? 'none'})`);
  }
  return current.json;
}

async function bootstrapTenantWithoutSubscription(baseUrl) {
  const suffix = Date.now();
  const tenantId = `ten_e2e_nosub_${suffix}`;
  const userId = `usr_e2e_nosub_${suffix}`;
  const headers = customerHeaders(tenantId, userId);

  const current = await apiJson(baseUrl, 'GET', '/v1/subscription/current', undefined, headers);
  if (current.status !== 200) {
    throw new Error(`subscription lookup failed for fresh tenant (${current.status})`);
  }
  if (current.json?.subscription) {
    throw new Error('fresh tenant bootstrap expected null subscription record');
  }

  return { tenantId, userId, headers };
}

async function injectCustomerSession(page, tenantId, userId) {
  await page.evaluate(({ tenantId: nextTenantId, userId: nextUserId }) => {
    sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify({
      mode: 'dev-headers',
      principal: 'customer',
      tenant_id: nextTenantId,
      user_id: nextUserId,
      role: 'admin'
    }));
  }, { tenantId, userId });
}

async function resolveWorkspaceIds(baseUrl) {
  const ids = {
    runId: '',
    agentId: '',
    targetGroupId: '',
    targetId: '',
    wafAssetId: '',
    cveItemId: '',
    supplyChainRiskId: '',
    discoveryEntityId: '',
    reportId: '',
    tenantId: 'ten_demo'
  };

  const targetGroups = await apiJson(baseUrl, 'GET', '/v1/target-groups');
  const targetGroup = targetGroups.json?.items?.[0];
  if (!targetGroup?.id) {
    throw new Error('browser e2e requires at least one target group for ten_demo');
  }
  ids.targetGroupId = targetGroup.id;

  const targetGroupDetail = await apiJson(baseUrl, 'GET', `/v1/target-groups/${encodeURIComponent(ids.targetGroupId)}`);
  const target = targetGroupDetail.json?.targets?.[0];
  if (!target?.id) {
    throw new Error(`browser e2e requires at least one target in ${ids.targetGroupId}`);
  }
  ids.targetId = target.id;

  return ids;
}

async function ensureAgentFixture(baseUrl, ids) {
  const agents = await apiJson(baseUrl, 'GET', '/v1/agents');
  if (agents.status === 200 && Array.isArray(agents.json?.items) && agents.json.items[0]?.id) {
    ids.agentId = agents.json.items[0].id;
    return ids;
  }

  const token = await apiJson(baseUrl, 'POST', '/v1/bootstrap-tokens', {
    target_group_id: ids.targetGroupId,
    max_registrations: 1
  });
  if (token.status !== 201 || !token.json?.secret) {
    throw new Error(`bootstrap token create failed (${token.status})`);
  }

  const reg = await apiJson(baseUrl, 'POST', '/v1/agents/register', {
    bootstrap_token: token.json.secret,
    hostname: 'browser-e2e-host',
    name: 'browser-e2e-agent',
    capabilities: ['heartbeat', 'canary']
  });
  if (reg.status !== 201 || !reg.json?.agent?.id) {
    throw new Error(`agent register failed (${reg.status})`);
  }

  ids.agentId = reg.json.agent.id;
  const credential = reg.json.agent_credential;
  await fetch(`${baseUrl}/v1/agents/${ids.agentId}/heartbeat`, {
    method: 'POST',
    headers: {
      ...DEMO_HEADERS,
      Authorization: `Bearer ${credential}`
    },
    body: JSON.stringify({ version: '0.1.0-browser-e2e' })
  });
  return ids;
}

async function ensureRunFixture(baseUrl, ids) {
  const runs = await apiJson(baseUrl, 'GET', '/v1/test-runs');
  if (runs.status === 200 && Array.isArray(runs.json?.items) && runs.json.items[0]?.id) {
    ids.runId = runs.json.items[0].id;
    return ids;
  }

  const run = await apiJson(baseUrl, 'POST', '/v1/test-runs', {
    check_id: 'origin.direct_bypass.safe',
    target_group_id: ids.targetGroupId,
    target_id: ids.targetId
  });
  if (run.status !== 201 || !run.json?.run?.id) {
    throw new Error(`test run create failed (${run.status})`);
  }
  ids.runId = run.json.run.id;
  return ids;
}

async function ensureWafAssetFixture(baseUrl, ids) {
  const assets = await apiJson(baseUrl, 'GET', '/v1/waf/assets');
  if (assets.status === 200 && Array.isArray(assets.json?.items) && assets.json.items[0]?.id) {
    ids.wafAssetId = assets.json.items[0].id;
    return ids;
  }

  const asset = await apiJson(baseUrl, 'POST', '/v1/waf/assets', {
    target_group_id: ids.targetGroupId,
    target_id: ids.targetId,
    canonical_url: 'https://browser-e2e.example.com',
    owner_hint: 'edge-team'
  });
  if (asset.status !== 201 || !asset.json?.asset?.id) {
    throw new Error(`waf asset create failed (${asset.status})`);
  }
  ids.wafAssetId = asset.json.asset.id;
  return ids;
}

async function ensureCveFixture(baseUrl, ids) {
  const items = await apiJson(baseUrl, 'GET', '/v1/waf/cve-pipeline');
  if (items.status === 200 && Array.isArray(items.json?.items) && items.json.items[0]?.id) {
    ids.cveItemId = items.json.items[0].id;
    await apiJson(
      baseUrl,
      'POST',
      `/v1/waf/cve-pipeline/${encodeURIComponent(ids.cveItemId)}/triage`,
      {}
    );
    return ids;
  }

  const created = await apiJson(baseUrl, 'POST', '/v1/waf/cve-pipeline', {
    cve_id: 'CVE-2026-9901',
    severity: 'high',
    affected_products: ['browser-e2e-product'],
    known_exploited: false
  });
  if (created.status !== 201 || !created.json?.item?.id) {
    throw new Error(`cve pipeline create failed (${created.status})`);
  }
  ids.cveItemId = created.json.item.id;
  const triage = await apiJson(
    baseUrl,
    'POST',
    `/v1/waf/cve-pipeline/${encodeURIComponent(ids.cveItemId)}/triage`,
    {}
  );
  if (triage.status !== 200) {
    throw new Error(`cve pipeline triage failed (${triage.status})`);
  }
  return ids;
}

async function ensureSupplyChainFixture(baseUrl, ids) {
  const risks = await apiJson(baseUrl, 'GET', '/v1/waf/supply-chain/risks');
  if (risks.status === 200 && Array.isArray(risks.json?.items) && risks.json.items[0]?.id) {
    ids.supplyChainRiskId = risks.json.items[0].id;
    return ids;
  }

  const created = await apiJson(baseUrl, 'POST', '/v1/waf/supply-chain/risks', {
    exposure_type: 'dangling_cname',
    hostname: 'browser-e2e-supply.example.com',
    severity: 'high',
    confidence: 0.82,
    state: 'suspected',
    evidence_summary: { data_source: 'browser_e2e' },
    remediation_steps: ['Review DNS chain and remove dangling reference.']
  });
  if (created.status !== 201 || !created.json?.risk?.id) {
    throw new Error(`supply-chain risk create failed (${created.status})`);
  }
  ids.supplyChainRiskId = created.json.risk.id;
  return ids;
}

async function testDryRunDeliver(baseUrl, actionItemId) {
  const delivered = await apiJson(baseUrl, 'POST', `/v1/waf/action-items/${encodeURIComponent(actionItemId)}/deliver`, {
    channel: 'webhook',
    dry_run: true
  });
  if (delivered.status !== 200) {
    throw new Error(`dry-run deliver failed (${delivered.status})`);
  }
  if (delivered.json?.delivery?.dry_run !== true) {
    throw new Error('dry-run deliver did not return dry_run=true');
  }
}

async function ensureWafFindingForRemediation(baseUrl, ids) {
  await ensureWafAssetFixture(baseUrl, ids);

  const validation = await apiJson(baseUrl, 'POST', '/v1/waf/validations', {
    waf_asset_id: ids.wafAssetId,
    modes: ['marker']
  });
  if (validation.status !== 201 || !validation.json?.validation_run?.id) {
    throw new Error(`waf validation create failed (${validation.status})`);
  }
  const validationRunId = validation.json.validation_run.id;

  const finalize = await apiJson(baseUrl, 'POST', `/v1/waf/validations/${encodeURIComponent(validationRunId)}/finalize`, {
    waf_detected: true,
    validation_failed: true,
    scenario_results: [{
      scenario_family: 'marker',
      expected_action: 'block',
      observed_action: 'allow',
      passed: false,
      evidence_summary_json: { blocked: false }
    }]
  });
  if (finalize.status !== 200) {
    throw new Error(`waf validation finalize failed (${finalize.status})`);
  }

  const findings = await apiJson(baseUrl, 'GET', '/v1/findings');
  const items = Array.isArray(findings.json?.items) ? findings.json.items : [];
  const wafFinding = items.find((finding) => finding.check_id === `waf.posture.${ids.wafAssetId}`) ?? items[0];
  if (!wafFinding?.id) {
    throw new Error('waf finding not created after validation finalize');
  }
  return wafFinding.id;
}

async function ensureRemediationFixture(baseUrl, ids) {
  const actionItems = await apiJson(baseUrl, 'GET', '/v1/waf/action-items');
  if (actionItems.status === 200 && Array.isArray(actionItems.json?.items) && actionItems.json.items.length > 0) {
    const actionItemId = actionItems.json.items[0].action_item_id ?? actionItems.json.items[0].id;
    if (!actionItemId) {
      throw new Error('existing action item is missing action_item_id');
    }
    await testDryRunDeliver(baseUrl, actionItemId);
    return ids;
  }

  const findings = await apiJson(baseUrl, 'GET', '/v1/findings');
  let findingId = '';
  if (findings.status === 200 && Array.isArray(findings.json?.items) && findings.json.items[0]?.id) {
    findingId = findings.json.items[0].id;
  } else {
    findingId = await ensureWafFindingForRemediation(baseUrl, ids);
  }

  const created = await apiJson(baseUrl, 'POST', '/v1/waf/action-items', { finding_id: findingId });
  if (created.status !== 201 || !created.json?.action_item?.action_item_id) {
    throw new Error(`action item create failed (${created.status})`);
  }

  await testDryRunDeliver(baseUrl, created.json.action_item.action_item_id);
  return ids;
}

async function ensureImportableDiscoveryCandidate(baseUrl, ids) {
  const candidates = await apiJson(baseUrl, 'GET', '/v1/discovery/candidates');
  const items = Array.isArray(candidates.json?.items) ? candidates.json.items : [];
  const importable = items.find((item) => item.state === 'approved_target' && !item.approved_target_id);
  if (importable?.id) {
    ids.discoveryEntityId = importable.id;
    return ids;
  }

  const pending = items.find((item) => item.state === 'candidate' || item.state === 'pending_review');
  let candidateId = pending?.id ?? '';
  if (!candidateId) {
    const candidate = await apiJson(baseUrl, 'POST', '/v1/discovery/candidates', {
      candidate_id: `cand_browser_e2e_${Date.now()}`,
      hostname: 'browser-e2e-import.example.com',
      source_type: 'dns',
      source_ref: 'browser_e2e_ref',
      confidence: 0.82,
      ownership_status: 'unknown',
      approval_status: 'not_requested',
      first_seen_at: '2026-07-02T00:00:00.000Z',
      last_seen_at: '2026-07-02T12:00:00.000Z',
      evidence_summary: {
        source_kind: 'dns',
        dns_record_type: 'CNAME',
        root_domain_match: true
      },
      state: 'candidate'
    });
    if (candidate.status !== 201 || !candidate.json?.candidate?.id) {
      throw new Error(`discovery candidate create failed (${candidate.status})`);
    }
    candidateId = candidate.json.candidate.id;
  }

  const approved = await apiJson(
    baseUrl,
    'POST',
    `/v1/discovery/candidates/${candidateId}/approve`,
    { target_group_id: ids.targetGroupId }
  );
  if (approved.status !== 200) {
    throw new Error(`discovery candidate approve failed (${approved.status})`);
  }
  ids.discoveryEntityId = candidateId;
  return ids;
}

async function ensureDiscoveryFixture(baseUrl, ids) {
  return ensureImportableDiscoveryCandidate(baseUrl, ids);
}

async function ensureReportFixture(baseUrl, ids) {
  const reports = await apiJson(baseUrl, 'GET', '/v1/reports');
  if (reports.status === 200 && Array.isArray(reports.json?.items) && reports.json.items[0]?.id) {
    ids.reportId = reports.json.items[0].id;
    return ids;
  }

  const created = await apiJson(baseUrl, 'POST', '/v1/reports', { kind: 'technical' });
  if (created.status !== 201 || !created.json?.id) {
    throw new Error(`report create failed (${created.status})`);
  }
  ids.reportId = created.json.id;
  return ids;
}

async function createSignupRequest(baseUrl, suffix = Date.now()) {
  const signup = await apiJson(baseUrl, 'POST', '/v1/signup-requests', {
    organization_name: `E2E Staff Provision Org ${suffix}`,
    contact_email: `staff-provision-${suffix}@e2e-${suffix}.astranull.local`,
    contact_name: 'E2E Staff Provision Contact',
    requested_plan: 'starter',
    intended_use: 'Staff provisioning browser validation.',
    region: 'us',
    high_scale_interest: false
  });
  if (signup.status !== 201 || !signup.json?.request?.id) {
    throw new Error(`staff provisioning signup failed (${signup.status})`);
  }
  return {
    suffix,
    signupRequestId: signup.json.request.id,
    organizationName: `E2E Staff Provision Org ${suffix}`
  };
}

async function approveSignupViaApi(baseUrl, signupRequestId) {
  const approved = await apiJson(
    baseUrl,
    'POST',
    `/internal/admin/signup-requests/${encodeURIComponent(signupRequestId)}/approve`,
    { reason: 'Approved for staff provisioning E2E validation.' },
    STAFF_HEADERS
  );
  if (approved.status !== 200 || !approved.json?.provisioning?.tenant_id) {
    throw new Error(`staff provisioning approve failed (${approved.status})`);
  }
  return {
    tenantId: approved.json.provisioning.tenant_id,
    environmentId: approved.json.provisioning.environment_id
  };
}

async function grantEntitlementViaApi(baseUrl, tenantId, feature = 'waf_posture') {
  const grant = await apiJson(
    baseUrl,
    'POST',
    `/internal/admin/tenants/${encodeURIComponent(tenantId)}/entitlements`,
    { feature, enabled: true, reason: 'Staff provisioning E2E entitlement validation.' },
    STAFF_HEADERS
  );
  if (grant.status !== 200) {
    throw new Error(`staff entitlement grant failed (${grant.status})`);
  }
  return grant.json;
}

async function validateProvisionedTenant(baseUrl, tenantId, feature = 'waf_posture') {
  const headers = customerHeaders(tenantId, `usr_e2e_staff_${tenantId}`);
  const subscription = await apiJson(baseUrl, 'GET', '/v1/subscription/current', undefined, headers);
  if (subscription.status !== 200) {
    throw new Error(`provisioned tenant subscription lookup failed (${subscription.status})`);
  }
  if (!subscription.json?.subscription) {
    throw new Error('provisioned tenant expected subscription record after staff approval');
  }
  const enabled = subscription.json?.effective_entitlements?.[feature]
    ?? subscription.json?.subscription?.effective_entitlements?.[feature];
  if (enabled !== true) {
    throw new Error(`provisioned tenant expected ${feature} entitlement enabled after staff grant`);
  }
  return subscription.json;
}

function routeHash(route, detailIds) {
  if (route === 'run-detail') return `run-detail?id=${encodeURIComponent(detailIds.runId)}`;
  if (route === 'agent-detail') return `agent-detail?id=${encodeURIComponent(detailIds.agentId)}`;
  if (route === 'target-group-detail') {
    return `target-group-detail?id=${encodeURIComponent(detailIds.targetGroupId)}`;
  }
  if (route === 'waf-asset-detail') {
    return `waf-asset-detail?id=${encodeURIComponent(detailIds.wafAssetId)}`;
  }
  if (route === 'cve-detail') {
    return `cve-detail?id=${encodeURIComponent(detailIds.cveItemId)}`;
  }
  if (route === 'supply-chain-detail') {
    return `supply-chain-detail?id=${encodeURIComponent(detailIds.supplyChainRiskId)}`;
  }
  if (route === 'discovery-entity') {
    return `discovery-entity?id=${encodeURIComponent(detailIds.discoveryEntityId)}`;
  }
  if (route === 'tenant-detail') {
    return `tenant-detail?id=${encodeURIComponent(detailIds.tenantId)}`;
  }
  if (route === 'report-detail') {
    return `report-detail?id=${encodeURIComponent(detailIds.reportId)}`;
  }
  return route;
}

async function injectStaffSession(page) {
  await page.evaluate(() => {
    sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify({
      mode: 'dev-headers',
      principal: 'staff',
      staff_id: 'staff_admin',
      staff_role: 'internal_admin',
      role: 'internal_admin'
    }));
  });
}

async function injectStaffSocSession(page) {
  await page.evaluate(() => {
    sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify({
      mode: 'dev-headers',
      principal: 'staff',
      staff_id: 'staff_soc',
      staff_role: 'soc_analyst',
      role: 'soc_analyst'
    }));
  });
}

async function resolveProvisionedTenantId(baseUrl, organizationName, signupRequestId = '') {
  if (signupRequestId) {
    const signupStatus = await apiJson(
      baseUrl,
      'GET',
      `/internal/admin/signup-requests`,
      undefined,
      STAFF_HEADERS
    );
    if (signupStatus.status === 200 && Array.isArray(signupStatus.json?.items)) {
      const request = signupStatus.json.items.find((item) => item.id === signupRequestId);
      const tenantFromRequest = request?.provisioned_tenant_id ?? '';
      if (tenantFromRequest) return tenantFromRequest;
    }
  }

  const tenants = await apiJson(
    baseUrl,
    'GET',
    `/internal/admin/tenants?q=${encodeURIComponent(organizationName)}`,
    undefined,
    STAFF_HEADERS
  );
  if (tenants.status !== 200 || !Array.isArray(tenants.json?.items)) {
    throw new Error(`tenant directory lookup failed (${tenants.status})`);
  }
  const match = tenants.json.items.find((item) => {
    const name = String(item.name ?? item.legal_name ?? '').toLowerCase();
    return name.includes(organizationName.toLowerCase());
  });
  const tenantId = match?.tenant_id ?? match?.id ?? '';
  if (!tenantId) {
    throw new Error(`provisioned tenant not found for ${organizationName}`);
  }
  return tenantId;
}

async function validateStaffProvisioningInBrowser(page, baseUrl, viewportName, tenantId, failures) {
  const stepPrefix = `${viewportName}:staff-provisioning`;
  if (!tenantId) {
    failures.push({ step: stepPrefix, detail: 'missing shared provisioned tenant id' });
    return;
  }
  try {
    await injectStaffSession(page);
    await page.goto(`${baseUrl}/internal/admin#tenant-detail?id=${encodeURIComponent(tenantId)}`, { waitUntil: 'networkidle', timeout: 45000 });
    await page.waitForTimeout(800);
    const tenantBody = await page.locator('body').innerText();
    for (const snippet of EXPECTED_SNIPPETS['tenant-detail'] ?? []) {
      if (!bodyIncludesSnippet(tenantBody, snippet)) {
        failures.push({ step: `${stepPrefix}:tenant-detail`, detail: `missing expected text: ${snippet}` });
      }
    }
    await validateProvisionedTenant(baseUrl, tenantId, 'waf_posture');
  } catch (err) {
    failures.push({ step: stepPrefix, detail: String(err) });
  }
}

async function runStaffProvisioningBrowserFlow(page, baseUrl, viewportName, failures) {
  const stepPrefix = `${viewportName}:staff-provisioning`;
  let provisionedTenantId = '';
  try {
    const signup = await createSignupRequest(baseUrl);

    await page.goto(`${baseUrl}/internal/admin`, { waitUntil: 'domcontentloaded', timeout: 45000 });
    await injectStaffSession(page);
    await page.reload({ waitUntil: 'networkidle', timeout: 45000 });
    await page.goto(`${baseUrl}/internal/admin#admin`, { waitUntil: 'networkidle', timeout: 45000 });
    await page.waitForTimeout(800);
    await page.getByRole('button', { name: 'Refresh' }).click({ timeout: 10000 });
    await page.waitForTimeout(1200);
    await page.waitForSelector(`tr >> text=${signup.organizationName}`, { timeout: 20000 });

    const approveButton = page.locator('tr', { hasText: signup.organizationName }).getByRole('button', { name: 'Approve' });
    await approveButton.click({ timeout: 20000 });
    await page.waitForTimeout(1200);

    const bodyAfterApprove = await page.locator('body').innerText();
    if (!bodyAfterApprove.includes('Signup request approved and tenant provisioned.')) {
      failures.push({ step: `${stepPrefix}:approve`, detail: 'missing approval success message' });
    }

    provisionedTenantId = await resolveProvisionedTenantId(baseUrl, signup.organizationName, signup.signupRequestId);

    await page.goto(`${baseUrl}/internal/admin#tenant-detail?id=${encodeURIComponent(provisionedTenantId)}`, { waitUntil: 'networkidle', timeout: 45000 });
    await page.waitForTimeout(800);
    const tenantBody = await page.locator('body').innerText();
    for (const snippet of EXPECTED_SNIPPETS['tenant-detail'] ?? []) {
      if (!bodyIncludesSnippet(tenantBody, snippet)) {
        failures.push({ step: `${stepPrefix}:tenant-detail`, detail: `missing expected text: ${snippet}` });
      }
    }

    await page.goto(`${baseUrl}/internal/admin#admin`, { waitUntil: 'networkidle', timeout: 45000 });
    await page.waitForTimeout(800);
    await page.waitForSelector(`select option[value="${provisionedTenantId}"]`, { state: 'attached', timeout: 20000 });

    const entitlementCard = page.locator('div').filter({
      has: page.getByText('Entitlement grants', { exact: true })
    }).filter({
      has: page.getByRole('button', { name: 'Apply entitlement' })
    }).first();
    await entitlementCard.locator(`select:has(option[value="${provisionedTenantId}"])`).first().selectOption(provisionedTenantId);
    const entitlementForm = entitlementCard.locator('form').filter({
      has: page.getByRole('button', { name: 'Apply entitlement' })
    });
    await entitlementForm.locator('input[name="reason"]').fill('Staff provisioning E2E entitlement validation.');
    await entitlementForm.getByRole('button', { name: 'Apply entitlement' }).click({ timeout: 15000 });
    await page.waitForTimeout(1200);

    const bodyAfterGrant = await page.locator('body').innerText();
    if (!bodyAfterGrant.toLowerCase().includes('waf_posture entitlement granted')) {
      failures.push({ step: `${stepPrefix}:entitlement`, detail: 'missing entitlement grant success message' });
    }

    await validateProvisionedTenant(baseUrl, provisionedTenantId, 'waf_posture');
  } catch (err) {
    failures.push({ step: stepPrefix, detail: String(err) });
  }
  return provisionedTenantId;
}

function bodyIncludesSnippet(bodyText, snippet) {
  const alternatives = {
    'Evidence-backed factors': ['Evidence-backed factors', 'Derived summary'],
    'Derived summary': ['Evidence-backed factors', 'Derived summary']
  };
  const candidates = alternatives[snippet] ?? [snippet];
  const lower = bodyText.toLowerCase();
  return candidates.some((candidate) => lower.includes(candidate.toLowerCase()));
}

function isBenignConsoleError(detail, step = '') {
  if (/favicon/i.test(detail)) return true;
  if (step.includes('subscription') && /404/.test(detail) && /tenants\/current/i.test(detail)) return true;
  if (step.includes('subscription') && /Failed to load resource: the server responded with a status of 404/.test(detail)) {
    return true;
  }
  if (/cve-pipeline/i.test(detail) && /409/.test(detail)) return true;
  if (/Failed to load resource: the server responded with a status of 409 \(Conflict\)/.test(detail)) return true;
  if (/429/.test(detail) && /signup-requests/i.test(detail)) return true;
  if (/Failed to load resource: the server responded with a status of 429/.test(detail)) return true;
  return false;
}

function ensurePlaywrightCore() {
  const check = spawnSync('npm', ['ls', 'playwright-core', '--depth=0'], { cwd: REPO_ROOT, encoding: 'utf8' });
  if (check.status !== 0) {
    const install = spawnSync('npm', ['install', '--no-save', 'playwright-core@1.52.0'], {
      cwd: REPO_ROOT,
      stdio: 'inherit'
    });
    if (install.status !== 0) throw new Error('Failed to install playwright-core');
  }
}

async function run() {
  const { baseUrl, help } = parseArgs(process.argv.slice(2));
  if (help) {
    console.log('Usage: node scripts/react-portal-browser-e2e.mjs [--base-url URL]');
    process.exit(0);
  }

  ensurePlaywrightCore();
  const { chromium } = await import('playwright-core');
  const failures = [];

  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  const workspaceIds = await resolveWorkspaceIds(baseUrl);
  await verifySeededSubscription(baseUrl);
  const noSubTenant = await bootstrapTenantWithoutSubscription(baseUrl);

  for (const viewport of [{ name: 'desktop', width: 1440, height: 1000 }, { name: 'mobile', width: 390, height: 844 }]) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    for (const route of PUBLIC_AUTH_ROUTES) {
      const label = `${viewport.name}:public-${route}`;
      try {
        await page.goto(`${baseUrl}/${route}`, { waitUntil: 'networkidle', timeout: 45000 });
        await page.waitForTimeout(400);
        const bodyText = await page.locator('body').innerText();
        for (const snippet of EXPECTED_SNIPPETS[route] ?? []) {
          if (!bodyIncludesSnippet(bodyText, snippet)) {
            failures.push({ step: label, detail: `missing expected text: ${snippet}` });
          }
        }
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
        if (overflow) failures.push({ step: label, detail: 'horizontal overflow detected' });
      } catch (err) {
        failures.push({ step: label, detail: String(err) });
      }
    }
    await context.close();
  }

  for (const viewport of [{ name: 'desktop', width: 1440, height: 1000 }, { name: 'mobile', width: 390, height: 844 }]) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    const failedRequests = [];

    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
    page.on('pageerror', (err) => pageErrors.push(String(err)));
    page.on('requestfailed', (req) => failedRequests.push(`${req.method()} ${req.url()} ${req.failure()?.errorText ?? ''}`));

    for (const scenario of [
      { label: 'seeded', route: 'subscription', snippets: EXPECTED_SNIPPETS.subscription, forbidden: ['No subscription configured', 'Enterprise'] },
      { label: 'empty', route: 'subscription-empty', snippets: EXPECTED_SNIPPETS['subscription-empty'], forbidden: ['Professional', 'Enterprise', 'Monthly developer-validation limit'] }
    ]) {
      const step = `${viewport.name}:subscription-${scenario.label}`;
      try {
        await page.goto(`${baseUrl}/app`, { waitUntil: 'domcontentloaded', timeout: 45000 });
        if (scenario.label === 'empty') {
          await injectCustomerSession(page, noSubTenant.tenantId, noSubTenant.userId);
        } else {
          await injectCustomerSession(page, 'ten_demo', 'usr_admin');
        }
        await page.reload({ waitUntil: 'networkidle', timeout: 45000 });
        await page.goto(`${baseUrl}/app#subscription`, { waitUntil: 'networkidle', timeout: 45000 });
        await page.waitForTimeout(600);
        const bodyText = await page.locator('body').innerText();
        for (const snippet of scenario.snippets ?? []) {
          if (!bodyIncludesSnippet(bodyText, snippet)) {
            failures.push({ step, detail: `missing expected text: ${snippet}` });
          }
        }
        for (const snippet of scenario.forbidden ?? []) {
          if (bodyText.toLowerCase().includes(snippet.toLowerCase())) {
            failures.push({ step, detail: `forbidden text detected: ${snippet}` });
          }
        }
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
        if (overflow) failures.push({ step, detail: 'horizontal overflow detected' });
      } catch (err) {
        failures.push({ step, detail: String(err) });
      }
    }

    for (const err of consoleErrors) {
      if (!isBenignConsoleError(err, `${viewport.name}:subscription-console`)) {
        failures.push({ step: `${viewport.name}:subscription-console`, detail: err });
      }
    }
    for (const err of pageErrors) failures.push({ step: `${viewport.name}:subscription-pageerror`, detail: err });
    for (const err of failedRequests.filter((r) => !r.includes('favicon'))) {
      failures.push({ step: `${viewport.name}:subscription-network`, detail: err });
    }

    await context.close();
  }

  let staffProvisionedTenantId = '';

  for (const viewport of VIEWPORTS) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    const failedRequests = [];

    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
    page.on('pageerror', (err) => pageErrors.push(String(err)));
    page.on('requestfailed', (req) => failedRequests.push(`${req.method()} ${req.url()} ${req.failure()?.errorText ?? ''}`));

    const detailIds = { ...workspaceIds };
    for (const route of ROUTES) {
      const label = `${viewport.name}:${route}`;
      try {
        if (route === 'agents' || route === 'agent-detail' || route === 'onboarding') {
          await ensureAgentFixture(baseUrl, detailIds);
        }
        if (route === 'runs' || route === 'run-detail' || route === 'dashboard') {
          await ensureRunFixture(baseUrl, detailIds);
        }
        if (route === 'waf-posture' || route === 'waf-asset-detail' || route === 'remediation') {
          await ensureWafAssetFixture(baseUrl, detailIds);
        }
        if (route === 'cve-pipeline' || route === 'cve-detail') {
          await ensureCveFixture(baseUrl, detailIds);
        }
        if (route === 'supply-chain' || route === 'supply-chain-detail') {
          await ensureSupplyChainFixture(baseUrl, detailIds);
        }
        if (route === 'remediation') {
          await ensureRemediationFixture(baseUrl, detailIds);
        }
        if (route === 'discovery') {
          await ensureImportableDiscoveryCandidate(baseUrl, detailIds);
        }
        if (route === 'discovery-entity') {
          await ensureDiscoveryFixture(baseUrl, detailIds);
        }
        if (route === 'reports' || route === 'report-detail') {
          await ensureReportFixture(baseUrl, detailIds);
        }
        await page.goto(`${baseUrl}/app#${routeHash(route, detailIds)}`, { waitUntil: 'networkidle', timeout: 45000 });
        if (route === 'discovery') {
          await page.getByRole('button', { name: 'Refresh' }).click({ timeout: 10000 });
          await page.waitForTimeout(800);
        } else {
          await page.waitForTimeout(600);
        }
        const bodyText = await page.locator('body').innerText();
        if (/Workspace tabs|Connector drift snapshot awaiting triage|CVE mitigation playbook needs owner approval|Monthly developer-validation limit/.test(bodyText)) {
          failures.push({ step: label, detail: 'forbidden static prototype copy detected' });
        }
        if (/\bvalue:\s*"Enterprise"/.test(bodyText)) {
          failures.push({ step: label, detail: 'hardcoded Enterprise plan copy detected' });
        }
        const snippets = EXPECTED_SNIPPETS[route] ?? [];
        for (const snippet of snippets) {
          if (!bodyIncludesSnippet(bodyText, snippet)) {
            failures.push({ step: label, detail: `missing expected text: ${snippet}` });
          }
        }
        const overflow = await page.evaluate(() => {
          const doc = document.documentElement;
          return doc.scrollWidth > doc.clientWidth + 2;
        });
        if (overflow) failures.push({ step: label, detail: 'horizontal overflow detected' });
      } catch (err) {
        failures.push({ step: label, detail: String(err) });
      }
    }

    for (const err of consoleErrors) {
      if (!isBenignConsoleError(err, `${viewport.name}:console`)) {
        failures.push({ step: `${viewport.name}:console`, detail: err });
      }
    }
    for (const err of pageErrors) failures.push({ step: `${viewport.name}:pageerror`, detail: err });
    for (const err of failedRequests.filter((r) => !r.includes('favicon'))) {
      failures.push({ step: `${viewport.name}:network`, detail: err });
    }

    for (const route of STAFF_ROUTES) {
      const label = `${viewport.name}:${route}`;
      try {
        await injectStaffSession(page);
        const staffHash = routeHash(route, detailIds);
        await page.goto(`${baseUrl}/internal/admin#${staffHash}`, { waitUntil: 'networkidle', timeout: 45000 });
        await page.waitForTimeout(600);
        const bodyText = await page.locator('body').innerText();
        const snippets = EXPECTED_SNIPPETS[route] ?? [];
        for (const snippet of snippets) {
          if (!bodyIncludesSnippet(bodyText, snippet)) {
            failures.push({ step: label, detail: `missing expected text: ${snippet}` });
          }
        }
        const overflow = await page.evaluate(() => {
          const doc = document.documentElement;
          return doc.scrollWidth > doc.clientWidth + 2;
        });
        if (overflow) failures.push({ step: label, detail: 'horizontal overflow detected' });
      } catch (err) {
        failures.push({ step: label, detail: String(err) });
      }
    }

    for (const route of STAFF_SOC_ROUTES) {
      const label = `${viewport.name}:${route}`;
      try {
        await injectStaffSocSession(page);
        await page.goto(`${baseUrl}/internal/soc`, { waitUntil: 'networkidle', timeout: 45000 });
        await page.waitForTimeout(600);
        const bodyText = await page.locator('body').innerText();
        const snippets = EXPECTED_SNIPPETS[route] ?? [];
        for (const snippet of snippets) {
          if (!bodyIncludesSnippet(bodyText, snippet)) {
            failures.push({ step: label, detail: `missing expected text: ${snippet}` });
          }
        }
        const overflow = await page.evaluate(() => {
          const doc = document.documentElement;
          return doc.scrollWidth > doc.clientWidth + 2;
        });
        if (overflow) failures.push({ step: label, detail: 'horizontal overflow detected' });
      } catch (err) {
        failures.push({ step: label, detail: String(err) });
      }
    }

    if (viewport.name === 'desktop') {
      staffProvisionedTenantId = await runStaffProvisioningBrowserFlow(page, baseUrl, viewport.name, failures);
    } else {
      await validateStaffProvisioningInBrowser(page, baseUrl, viewport.name, staffProvisionedTenantId, failures);
    }

    await context.close();
  }

  await browser.close();

  if (failures.length > 0) {
    console.error(`react-portal-browser-e2e: ${failures.length} failure(s)`);
    for (const failure of failures.slice(0, 30)) {
      console.error(`  - ${failure.step}: ${failure.detail}`);
    }
    process.exit(1);
  }

  const routeCount = ROUTES.length + STAFF_ROUTES.length + STAFF_SOC_ROUTES.length + (PUBLIC_AUTH_ROUTES.length * 2);
  const staffFlowCount = VIEWPORTS.length;
  console.log(`react-portal-browser-e2e: passed ${routeCount} routes + ${staffFlowCount} staff provisioning flows × ${VIEWPORTS.length} viewports at ${baseUrl}`);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});