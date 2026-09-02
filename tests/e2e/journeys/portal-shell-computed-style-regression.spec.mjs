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
