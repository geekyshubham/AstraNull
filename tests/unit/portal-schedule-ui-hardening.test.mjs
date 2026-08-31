import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const read = (relative) => readFileSync(new URL(`../../${relative}`, import.meta.url), 'utf8');

const picker = read('apps/web/react/src/components/policies/target-group-picker.tsx');
const select = read('apps/web/react/src/components/ui/select.tsx');
const styles = read('apps/web/react/src/styles.css');
const policies = read('apps/web/react/src/pages/page-components.tsx');
const targetGroup = read('apps/web/react/src/pages/target-group-detail-view.tsx');
const details = read('apps/web/react/src/pages/detail-pages.tsx');
const surfaces = read('apps/web/react/src/pages/functional-surfaces.tsx');

describe('portal schedule UI hardening', () => {
  it('mirrors backend target-kind aliases and URL inference in both schedule forms', () => {
    assert.match(picker, /domain: 'fqdn',[\s\S]*hostname: 'fqdn'/);
    assert.match(picker, /if \(\/\^https\?:\\\/\\\/\/i\.test\(value\)\) return 'url'/);
    assert.match(picker, /supportedTargets\.length === 0 \|\| supportedTargets\.includes\(effectivePolicyTargetKind\(target\)\)/);

    assert.match(policies, /compatibleTargets = selectedPolicyCheck[\s\S]*targets\.filter\(\(target\) => isPolicyTargetCompatible\(selectedPolicyCheck, target\)\)/);
    assert.match(policies, /handlePolicyCheckChange[\s\S]*selectedTargetId: nextCheck && selectedTarget && isPolicyTargetCompatible\(nextCheck, selectedTarget\)[\s\S]*: ''/);
    assert.match(policies, /No compatible targets/);
    assert.match(policies, /has no exact target compatible with/);

    assert.match(targetGroup, /compatiblePolicyTargets = selectedPolicyCheck[\s\S]*isPolicyTargetCompatible\(selectedPolicyCheck, target\)/);
    assert.match(targetGroup, /setSelectedPolicyTargetId\(\(current\)[\s\S]*isPolicyTargetCompatible\(item, selectedTarget\) \? current : ''/);
    assert.match(targetGroup, /\{compatiblePolicyTargets\.map\(\(target\) =>/);
    assert.match(targetGroup, /choose another check or add a compatible target/);
  });

  it('defaults to external-only and labels agent assistance only from an explicit mode', () => {
    assert.match(targetGroup, /getString\(entity, \['validation_mode'\], 'external_only'\)/);
    assert.match(details, /getString\(entity, \['validation_mode'\], 'external_only'\)/);
    assert.match(details, /explicitRunValidationMode === 'agent_assisted'[\s\S]*Agent-assisted verdict/);
    assert.match(details, /Correlation mode is not recorded yet\. Pending or incomplete evidence is not labeled agent-assisted/);
    assert.match(details, /External-only is the default:[\s\S]*without an agent/);
    assert.match(surfaces, /observation agents are optional for external readiness validation/);
    assert.match(surfaces, /origin validation must correlate an outside probe with an observation from inside the protected path/);
    assert.doesNotMatch(surfaces, /Readiness still requires correlated probe and agent evidence/);
  });

  it('contains TargetGroupPicker Escape inside the popup and restores trigger focus', () => {
    assert.match(picker, /onKeyDownCapture=\{\(event\) => \{[\s\S]*!open \|\| event\.key !== 'Escape'/);
    assert.match(picker, /event\.preventDefault\(\);[\s\S]*event\.stopPropagation\(\);[\s\S]*setOpen\(false\);[\s\S]*triggerRef\.current\?\.focus\(\{ preventScroll: true \}\)/);
    assert.doesNotMatch(picker, /document\.addEventListener\('keydown'/);
  });

  it('bounds custom Select menus to the nearest form-modal body and viewport', () => {
    assert.match(select, /closest<HTMLElement>\('\.form-modal-body'\)/);
    assert.match(select, /boundaryTop = Math\.max\(SELECT_VIEWPORT_GUTTER, modalRect\?\.top/);
    assert.match(select, /boundaryBottom = Math\.min\([\s\S]*window\.innerHeight - SELECT_VIEWPORT_GUTTER[\s\S]*modalRect\?\.bottom/);
    assert.match(select, /setMenuMaxHeight\(Math\.max\(0, Math\.min\(SELECT_MENU_MAX_HEIGHT, Math\.floor\(available\)\)\)\)/);
    assert.match(select, /modalBody\?\.addEventListener\('scroll', updatePlacement/);
    assert.match(styles, /max-height: var\(--select-menu-max-height, 280px\)/);
    assert.match(select, /event\.key === 'ArrowDown'[\s\S]*focusOption\(index \+ 1\)/);
  });

  it('preserves immediate WAF/CDN baselines after DNS or provider verification', () => {
    assert.match(targetGroup, /DNS ownership verified[\s\S]*Bounded WAF\/CDN detection started through the signed-worker path/);
    assert.match(targetGroup, /The immediate WAF\/CDN baseline could not start/);
    assert.match(targetGroup, /Bounded WAF\/CDN detection started for \$\{baselineLabel\}/);
  });
});
