import { CONTROL_FAMILIES, REMEDIATION_PROVIDERS, getMissingControl } from '../contracts/missingControls/index.mjs';
import { PROVIDER_LABELS, getProviderRemediation } from '../contracts/providerRemediation.mjs';

const GAP_VERDICTS = new Set(['exposed', 'edge_exposed', 'penetrated']);

const PROVIDER_ALIASES = Object.freeze({
  aws: 'aws', amazon: 'aws', awswaf: 'aws', aws_waf: 'aws', cloudfront: 'aws', amazon_cloudfront: 'aws', aws_cloudfront: 'aws',
  aws_shield: 'aws', amazon_web_services: 'aws',
  gcp: 'gcp', google: 'gcp', google_cloud: 'gcp', cloud_armor: 'gcp', google_cloud_armor: 'gcp',
  azure: 'azure', azure_front_door: 'azure', azure_waf: 'azure', microsoft: 'azure', microsoft_azure: 'azure',
  cloudflare: 'cloudflare',
  akamai: 'akamai',
  fastly: 'fastly',
});

const LAYER_DETECTION_FAMILIES = Object.freeze({
  network: ['cloud'],
  origin: ['cloud'],
  edge_waf: ['waf', 'cdn'],
  edge_cdn: ['cdn', 'waf'],
  dns: [],
  operations: [],
});

export function normalizeRemediationProvider(value) {
  const key = String(value ?? '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  return PROVIDER_ALIASES[key] ?? null;
}

function detectedProviders(edgeDetection, detectionFamilies) {
  const rows = [];
  if (!edgeDetection || typeof edgeDetection !== 'object') return rows;
  for (const family of detectionFamilies) {
    const layer = edgeDetection[family];
    const listed = Array.isArray(edgeDetection[`${family}_providers`]) ? edgeDetection[`${family}_providers`] : [];
    const layered = Array.isArray(edgeDetection.layers)
      ? edgeDetection.layers.filter((row) => row?.family === family).map((row) => row?.provider)
      : [];
    const candidates = [layer?.status === 'detected' ? layer?.provider ?? layer?.vendor : null, ...listed, ...layered];
    for (const raw of candidates) {
      if (typeof raw !== 'string' || !raw.trim()) continue;
      const provider = normalizeRemediationProvider(raw);
      if (rows.some((row) => row.detected_as === raw && row.detection_layer === family)) continue;
      rows.push({ provider, detected_as: raw, detection_layer: family });
    }
  }
  return rows;
}

function guidanceFor(controlFamily, provider, detection) {
  const entry = getProviderRemediation(controlFamily, provider);
  if (!entry) return null;
  return {
    provider,
    provider_label: PROVIDER_LABELS[provider] ?? provider,
    source: detection ? 'detected_edge' : provider === 'generic' ? 'generic' : 'catalog',
    detected_as: detection?.detected_as ?? null,
    detection_layer: detection?.detection_layer ?? null,
    control: entry.control,
    steps: [...entry.steps],
    docs: [...entry.docs],
  };
}

export function projectMissingControl({ checkId, verdict = null, explanation = null, edgeDetection = null, gap = false } = {}) {
  const entry = getMissingControl(checkId);
  const family = entry ? CONTROL_FAMILIES[entry.control_family] : null;
  if (!entry || !family) return null;
  const verdictKey = typeof verdict === 'string' ? verdict : verdict?.verdict ?? null;
  const observed = typeof explanation === 'string' && explanation.trim()
    ? explanation.trim()
    : (typeof verdict === 'object' && typeof verdict?.explanation === 'string' ? verdict.explanation.trim() || null : null);
  const detections = detectedProviders(edgeDetection, LAYER_DETECTION_FAMILIES[family.layer] ?? []);
  const guidance = [];
  const unmatched = [];
  for (const detection of detections) {
    if (!detection.provider) {
      if (!unmatched.includes(detection.detected_as)) unmatched.push(detection.detected_as);
      continue;
    }
    if (guidance.some((row) => row.provider === detection.provider)) continue;
    const row = guidanceFor(entry.control_family, detection.provider, detection);
    if (row) guidance.push(row);
  }
  const generic = guidanceFor(entry.control_family, 'generic', null);
  if (generic) guidance.push(generic);
  return {
    check_id: entry.check_id,
    control_family: entry.control_family,
    control_label: family.label,
    layer: family.layer,
    status: gap === true || GAP_VERDICTS.has(verdictKey) ? 'missing' : 'not_established',
    headline: `Missing control: ${family.label}`,
    missing_control: entry.missing_control,
    required_policy: entry.required_policy,
    observed,
    provider_guidance: guidance,
    detected_without_guidance: unmatched,
    other_provider_guidance: REMEDIATION_PROVIDERS
      .filter((provider) => provider !== 'generic' && !guidance.some((row) => row.provider === provider))
      .map((provider) => guidanceFor(entry.control_family, provider, null))
      .filter(Boolean),
    attribution: 'unattributed',
  };
}

export function providerGuidanceFor(controlFamily, provider) {
  return guidanceFor(controlFamily, provider, null);
}
