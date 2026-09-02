import { expect, test } from '@playwright/test';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalSessionForSurface,
} from '../../helpers/portal-playwright-session.mjs';

/**
 * Computed-style guard for shell controls whose final cascade spans the shared
 * stylesheet and route-injected layers. Source assertions cannot catch a later
 * selector overriding icon dimensions, coarse targets, or reduced motion.
 */
test.describe('portal shell computed-style regression', () => {
  test.use({ viewport: { width: 375, height: 812 }, hasTouch: true });

  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('mobile shell dimensions and reduced motion survive the final cascade', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await injectPortalSessionForSurface(page, 'customer');
    await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());

    const menu = page.getByRole('button', { name: 'Open navigation', exact: true });
    const theme = page.getByRole('button', { name: /Switch to (light|dark) theme/ });
    await expect(menu).toBeVisible();
    await expect(theme).toBeVisible();

    const styles = await page.evaluate(() => {
      function dimensions(button) {
        const icon = button.querySelector('svg');
        if (!icon) throw new Error(`Missing SVG in ${button.getAttribute('aria-label') ?? 'shell control'}`);
        const iconStyle = getComputedStyle(icon);
        const buttonStyle = getComputedStyle(button);
        const rect = button.getBoundingClientRect();
        return {
          iconWidth: iconStyle.width,
          iconHeight: iconStyle.height,
          buttonWidth: rect.width,
          buttonHeight: rect.height,
          transitionDurations: buttonStyle.transitionDuration.split(',').map((value) => value.trim()),
          animationNames: buttonStyle.animationName.split(',').map((value) => value.trim()),
          animationDurations: buttonStyle.animationDuration.split(',').map((value) => value.trim()),
        };
      }

      const menuButton = document.querySelector('.menu-btn');
      const themeButton = document.querySelector('.theme-toggle');
      if (!(menuButton instanceof HTMLButtonElement) || !(themeButton instanceof HTMLButtonElement)) {
        throw new Error('Shell icon controls did not render.');
      }

      return {
        coarsePointer: matchMedia('(pointer: coarse)').matches,
        menu: dimensions(menuButton),
        theme: dimensions(themeButton),
        scrollBehavior: getComputedStyle(document.documentElement).scrollBehavior,
      };
    });

    expect(styles.coarsePointer).toBe(true);
    for (const control of [styles.menu, styles.theme]) {
      expect(control.iconWidth).toBe('18px');
      expect(control.iconHeight).toBe('18px');
      expect(control.buttonWidth).toBeGreaterThanOrEqual(44);
      expect(control.buttonHeight).toBeGreaterThanOrEqual(44);
      expect(control.transitionDurations.every((duration) => duration === '0s')).toBe(true);
      expect(
        control.animationNames.every((name) => name === 'none')
          || control.animationDurations.every((duration) => duration === '0s')
      ).toBe(true);
    }
    expect(styles.scrollBehavior).toBe('auto');
  });
});

/**
 * Rendered-appearance guard for component variants.
 *
 * The shared foundation declares its bases as `[data-ui='button'].btn` and
 * `[data-ui='badge'].badge` — two classes — so any single-class variant rule
 * loses to the base regardless of source order. That is how the portal shipped
 * with every status chip resolving to the same grey (semantic pass/review/gap
 * colour absent from the dark theme) and with secondary buttons painting a
 * transparent border over a transparent fill.
 *
 * Token-arithmetic tests could not catch it: they assert what the tokens should
 * compose to, and the tokens were always right. Only the browser knows which
 * rule won, so this reads computed style off elements carrying the exact class
 * names the components emit.
 */
test.describe('component variant computed-style regression', () => {
  test.use({ viewport: { width: 1440, height: 900 }, hasTouch: false, isMobile: false });

  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  for (const theme of ['dark', 'light']) {
    test(`${theme} theme keeps status chips semantic and controls visible`, async ({ page }) => {
      await injectPortalSessionForSurface(page, 'customer');
      await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());

      const measured = await page.evaluate((themeName) => {
        if (themeName === 'light') document.documentElement.setAttribute('data-theme', 'light');
        else document.documentElement.removeAttribute('data-theme');

        // Probe elements carry the same markup contract the Badge and Button
        // components emit, so they resolve through the identical cascade.
        const host = document.createElement('div');
        host.style.position = 'fixed';
        host.style.left = '-9999px';
        host.style.top = '0';
        document.body.appendChild(host);

        function chip(tone) {
          const el = document.createElement('span');
          el.setAttribute('data-ui', 'badge');
          el.className = `badge badge-${tone}`;
          el.textContent = tone;
          host.appendChild(el);
          const cs = getComputedStyle(el);
          return { color: cs.color, background: cs.backgroundColor, borderColor: cs.borderTopColor };
        }

        function button(variant, size) {
          const el = document.createElement('button');
          el.setAttribute('data-ui', 'button');
          el.className = `btn btn-${variant}${size ? ` btn-${size}` : ''}`;
          el.textContent = variant;
          host.appendChild(el);
          const cs = getComputedStyle(el);
          return {
            borderColor: cs.borderTopColor,
            background: cs.backgroundColor,
            minHeight: cs.minHeight,
          };
        }

        const result = {
          chips: {
            success: chip('success'),
            warn: chip('warn'),
            danger: chip('danger'),
            info: chip('info'),
            muted: chip('muted'),
          },
          buttons: {
            secondary: button('secondary'),
            secondarySm: button('secondary', 'sm'),
            defaultCta: button('default'),
          },
        };
        host.remove();
        return result;
      }, theme);

      const { chips, buttons } = measured;

      // The regression: every tone collapsing onto the neutral chip's ink.
      for (const tone of ['success', 'warn', 'danger', 'info']) {
        expect(chips[tone].color, `${tone} chip ink must not equal the neutral chip`)
          .not.toBe(chips.muted.color);
        expect(chips[tone].background, `${tone} chip fill must not equal the neutral chip`)
          .not.toBe(chips.muted.background);
        expect(chips[tone].borderColor, `${tone} chip border must not equal the neutral chip`)
          .not.toBe(chips.muted.borderColor);
      }

      // Tones must also stay distinguishable from each other, not merely non-grey.
      const inks = ['success', 'warn', 'danger'].map((tone) => chips[tone].color);
      expect(new Set(inks).size, 'success, warn, and danger must each render a distinct ink')
        .toBe(inks.length);

      // Secondary is an outlined control: a transparent border made it read as
      // a bare text label wherever it appeared.
      expect(buttons.secondary.borderColor).not.toBe('rgba(0, 0, 0, 0)');
      expect(buttons.secondary.borderColor).not.toBe('transparent');
      expect(buttons.secondary.background).not.toBe('rgba(0, 0, 0, 0)');
      expect(buttons.defaultCta.background).not.toBe('rgba(0, 0, 0, 0)');

      // Compact density is a real 34px on fine pointers.
      expect(buttons.secondarySm.minHeight).toBe('34px');
    });
  }
});

/**
 * Guard against breaking inside a word.
 *
 * `overflow-wrap: anywhere` reduces an element's min-content contribution to a
 * single character, so any `minmax(0, 1fr)` column shrinks past the text and
 * splits it mid-token. The portal shipped this twice: a `HOSTNAME` chip
 * rendered as eight stacked letters in a table column, and a `not_exposed`
 * metric value rendered as "not_expose / d". Both read as corrupted data.
 *
 * The target-detail WAF posture strip is the tightest metric row in the portal
 * (seven values, one of them a long snake_case token), so it is the honest
 * place to assert the rule.
 */
test.describe('single-token text never breaks mid-word', () => {
  test.use({ viewport: { width: 1560, height: 1000 }, hasTouch: false, isMobile: false });

  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('target detail metric values and chips stay on one line box', async ({ page }) => {
    await injectPortalSessionForSurface(page, 'customer');
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl());

    const split = await page.evaluate(() => {
      const offenders = [];
      const selector = '.kpi-value, .badge, [data-ui="badge"]';
      for (const el of document.querySelectorAll(selector)) {
        // Only leaf text: a value wrapping a nested <span> legitimately reports
        // one client rect per inline box.
        if (el.children.length > 0) continue;
        const text = (el.textContent ?? '').trim();
        // A single token has no space to break at, so more than one line box
        // means the break happened inside the word.
        if (!text || /\s/.test(text) || text.length < 4) continue;
        const range = document.createRange();
        range.selectNodeContents(el);
        if (range.getClientRects().length > 1) {
          offenders.push(`${text} (${el.className})`);
        }
      }
      return offenders;
    });

    expect(split, 'single-token values and chips must not break inside the word').toEqual([]);
  });
});
