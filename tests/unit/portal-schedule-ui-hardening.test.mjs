import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const read = (relative) => readFileSync(new URL(`../../${relative}`, import.meta.url), 'utf8');

const picker = read('apps/web/react/src/lib/policy-targets.ts');
const select = read('apps/web/react/src/components/ui/select.tsx');
const styles = read('apps/web/react/src/styles.css');
const policies = read('apps/web/react/src/pages/page-components.tsx');
const scheduleForm = read('apps/web/react/src/pages/refined/policies-refined.tsx');
const targetDetail = read('apps/web/react/src/pages/target-detail-view.tsx');
const details = read('apps/web/react/src/pages/detail-pages.tsx');
const surfaces = read('apps/web/react/src/pages/functional-surfaces.tsx');

describe('portal schedule UI hardening', () => {

  it('treats every group as external-only and never labels agent assistance', () => {
    for (const source of [targetDetail, details, surfaces]) {
      assert.doesNotMatch(source, /agent_assisted|Agent-assisted verdict/);
    }
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


});
