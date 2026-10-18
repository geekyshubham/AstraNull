import { CONTROL_FAMILIES } from './families.mjs';
import { MISSING_CONTROLS_WAF } from './waf.mjs';
import { MISSING_CONTROLS_APPLICATION } from './application.mjs';
import { MISSING_CONTROLS_NETWORK } from './network.mjs';

export { CONTROL_FAMILIES, CONTROL_LAYERS, REMEDIATION_PROVIDERS } from './families.mjs';

export const MISSING_CONTROL_GROUPS = Object.freeze({
  waf: ['waf'],
  application: ['l7', 'protocol', 'tls', 'origin', 'path', 'pattern', 'exploit'],
  network: ['l3_l4', 'reflection', 'amplification', 'dns', 'operations', 'high_scale'],
});

const merged = {};
for (const group of [MISSING_CONTROLS_WAF, MISSING_CONTROLS_APPLICATION, MISSING_CONTROLS_NETWORK]) {
  for (const [checkId, entry] of Object.entries(group)) {
    if (merged[checkId]) throw new Error(`Duplicate missing-control entry: ${checkId}`);
    merged[checkId] = Object.freeze({ check_id: checkId, ...entry });
  }
}

export const MISSING_CONTROLS = Object.freeze(merged);

export function getMissingControl(checkId) {
  return MISSING_CONTROLS[checkId] ?? null;
}

export function controlFamilyLabel(family) {
  return CONTROL_FAMILIES[family]?.label ?? null;
}
