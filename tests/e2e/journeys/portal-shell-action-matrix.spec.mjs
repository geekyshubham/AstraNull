import { expect as baseExpect, test } from '@playwright/test';
import { canAccessRoute } from '../../../apps/web/react/src/lib/route-access.mjs';
import { NAV_GROUP_LABELS, NAV_ITEMS, ROUTE_BY_ID, routeCrumb } from '../../../apps/web/react/src/lib/navigation.ts';
import { ROLES } from '../../../src/contracts/roles.mjs';
import { createActionMatrix, matrixIdentities, restoreMatrixSession, runIdentityMatrix, startMatrixPage, PORTAL_SESSION_KEY } from '../../helpers/portal-action-matrix.mjs';
import { getPortalPlaywrightBaseUrl, startPortalPlaywrightServer, stopPortalPlaywrightServer } from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, resolvePortalRouteUrl, waitForPortalRouteSettled } from '../../helpers/portal-playwright-session.mjs';

const expect = baseExpect.configure({ timeout: 20_000 });

const DESKTOP = { width: 1280, height: 900 };
const MOBILE = { width: 800, height: 900 };
const DENIED = 'You do not have access to this page.';
const OUTAGE_PATHS = /^\/(?:v1\/(?:state|tenants\/current|tenant\/deployment-features|targets|checks|test-policies|test-runs|validation-scans|findings|evidence|high-scale-requests|reports|notifications|production-release-evidence|production-release-evidence\/attestation|audit-log|secrets|service-accounts|subscription\/current)|internal\/admin\/(?:overview|signup-requests|tenants|approval-requests|audit-log))$/;
const matrix = createActionMatrix({ files: ['components/layout/app-shell.tsx'] });

const accessOptions = (identity) => ({ principal: identity.principal, staffRole: identity.principal === 'staff' ? identity.role : undefined });
const visibleNav = (identity, role = identity.role) => NAV_ITEMS.filter((item) => !item.id.endsWith('-detail') && canAccessRoute(identity.principal === 'staff' ? undefined : role, item.id, accessOptions(identity)));
const crumbFor = (identity, id) => routeCrumb(ROUTE_BY_ID.get(id), identity.principal);
const titleFor = (identity, id) => `${crumbFor(identity, id).label} · ${NAV_GROUP_LABELS[crumbFor(identity, id).group]} · AstraNull`;
const navItems = (page) => page.locator('nav[aria-label="Portal"] .nav-item');
const storedSession = (page) => page.evaluate((key) => JSON.parse(sessionStorage.getItem(key) ?? 'null'), PORTAL_SESSION_KEY);
const currentHash = (page) => page.evaluate(() => window.location.hash);

async function expectNavMatches(page, identity, role = identity.role) {
  const expected = visibleNav(identity, role).map((item) => item.label).sort();
  await expect.poll(async () => (await navItems(page).allTextContents()).sort()).toEqual(expected);
  return expected;
}

async function expectRouteRendered(page, identity, id, { title = true } = {}) {
  await waitForPortalRouteSettled(page);
  await expect(page.locator('#portal-main')).toHaveAttribute('aria-label', `${crumbFor(identity, id).label} workspace`);
  if (title) await expect(page).toHaveTitle(titleFor(identity, id));
  await expect(page.getByRole('heading', { name: DENIED, exact: true })).toHaveCount(0);
}

function outageControl() {
  const state = { on: false, injected: new Set() };
  return {
    state,
    install: (page) => page.route((url) => OUTAGE_PATHS.test(url.pathname), (route) => {
      if (!state.on || route.request().method() !== 'GET') return route.fallback();
      state.injected.add(route.request().url());
      return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'synthetic_outage', message: 'Synthetic dataset outage' }) });
    }),
  };
}

async function reachOutage(ctx, outage) {
  outage.state.on = true;
  const mark = ctx.requests.mark();
  await ctx.page.reload({ waitUntil: 'networkidle' });
  const banner = ctx.page.getByRole('alert').filter({ hasText: 'Could not load some workspace data' });
  await expect(banner, `A failing dataset read must surface the shell retry banner for ${ctx.identity.label} on ${ctx.route}`).toBeVisible();
  expect(ctx.requests.since(mark).some((entry) => entry.method === 'GET'), 'Hydration issued at least one dataset read').toBe(true);
  return banner;
}

async function clickRetryWhile(ctx, banner, { healthy }) {
  const mark = ctx.requests.mark();
  await banner.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect.poll(() => ctx.requests.since(mark).filter((entry) => entry.method === 'GET').length, { message: 'Retry re-issues dataset reads' }).toBeGreaterThan(0);
  if (healthy) await expect(banner).toHaveCount(0);
  else await expect(banner).toBeVisible();
  expect(ctx.requests.writesSince(mark), 'Retry never writes').toEqual([]);
  return ctx.requests.since(mark).filter((entry) => entry.method === 'GET').length;
}

async function chooseRole(page, role) {
  await page.getByRole('button', { name: /Role \(dev\)/ }).click();
  await page.getByRole('option', { name: new RegExp(`^${role}`) }).click();
}

function alternateRole(identity, route) {
  const others = ROLES.filter((role) => role !== identity.role);
  const role = others.find((candidate) => canAccessRoute(candidate, route, { principal: 'customer' })) ?? others[0];
  return { role, allowed: canAccessRoute(role, route, { principal: 'customer' }) };
}

async function expectRouteOutcome(page, identity, route, alternate) {
  if (alternate.allowed) await expectRouteRendered(page, identity, route, { title: false });
  else {
    await waitForPortalRouteSettled(page);
    await expect(page.getByRole('heading', { name: DENIED, exact: true })).toBeVisible();
  }
}

async function setViewport(page, size) {
  await page.setViewportSize(size);
}

async function openDrawer(page) {
  await setViewport(page, MOBILE);
  await page.getByRole('button', { name: 'Open navigation', exact: true }).click();
  const drawer = page.getByRole('dialog', { name: 'Portal navigation' });
  await expect(drawer).toBeVisible();
  return drawer;
}

const drivers = [
  {
    query: { owner: 'AppShell', label: 'Skip to main content', kind: 'anchor' },
    states: {
      success: async ({ page }) => {
        const before = page.url();
        const link = page.getByRole('link', { name: 'Skip to main content', exact: true });
        await expect(link).toHaveAttribute('href', '#portal-main');
        await link.focus();
        await page.keyboard.press('Enter');
        await expect(page.locator('#portal-main')).toBeFocused();
        expect(page.url()).toBe(before);
        await expect(page.getByRole('heading', { name: 'This page is unavailable.', exact: true })).toHaveCount(0);
        return ['Keyboard activation of the skip link moves focus to the main region', 'The route hash and URL are unchanged, so the routed page is not replaced by a not-found page'];
      },
      reload: async ({ page, identity, route, baseUrl }) => {
        await page.reload({ waitUntil: 'networkidle' });
        await waitForPortalRouteSettled(page);
        const link = page.getByRole('link', { name: 'Skip to main content', exact: true });
        await expect(link).toHaveAttribute('href', '#portal-main');
        await expect(page.locator('main#portal-main')).toHaveAttribute('tabindex', '-1');
        await expect.poll(async () => (await link.boundingBox()).y).toBeLessThan(0);
        await link.focus();
        await expect.poll(async () => (await link.boundingBox()).y).toBeGreaterThanOrEqual(0);
        await page.keyboard.press('Enter');
        await expect(page.locator('#portal-main')).toBeFocused();
        expect(page.url()).toBe(resolvePortalRouteUrl(route, baseUrl));
        return [`After a direct reload of ${route} the skip link is off-screen until focused, appears on focus and still moves focus to the unchanged main region`];
      },
    },
  },
  {
    query: { owner: 'AppShell', label: 'collapseLabel', kind: 'activate' },
    states: {
      success: async ({ page }) => {
        const shell = page.locator('.app-shell');
        const initial = await shell.evaluate((node) => node.classList.contains('sidebar-collapsed'));
        const toggle = page.getByRole('button', { name: initial ? 'Expand sidebar' : 'Collapse sidebar', exact: true });
        await toggle.click();
        await expect(shell).toHaveClass(initial ? /^(?!.*sidebar-collapsed)/ : /sidebar-collapsed/);
        const stored = await page.evaluate(() => localStorage.getItem('astranull.react.sidebar.collapsed'));
        expect(stored).toBe(initial ? '0' : '1');
        const flipped = page.getByRole('button', { name: initial ? 'Collapse sidebar' : 'Expand sidebar', exact: true });
        await expect(flipped).toBeVisible();
        await flipped.click();
        await expect(shell).toHaveClass(initial ? /sidebar-collapsed/ : /^(?!.*sidebar-collapsed)/);
        expect(await page.evaluate(() => localStorage.getItem('astranull.react.sidebar.collapsed'))).toBe(initial ? '1' : '0');
        return ['Activating the collapse control toggles the sidebar-collapsed class, flips its accessible name and persists the preference', 'A second activation restores the exact prior layout and stored preference'];
      },
    },
  },
  {
    query: { owner: 'AppShell', label: 'ThemeToggle', kind: 'activate' },
    states: {
      success: async ({ page }) => {
        const dark = await page.evaluate(() => document.documentElement.dataset.theme !== 'light');
        const toggle = page.getByRole('button', { name: dark ? 'Switch to light theme' : 'Switch to dark theme', exact: true });
        await toggle.click();
        await expect.poll(() => page.evaluate(() => document.documentElement.dataset.theme ?? 'dark')).toBe(dark ? 'light' : 'dark');
        expect(await page.evaluate(() => localStorage.getItem('astranull.theme'))).toBe(dark ? 'light' : 'dark');
        await page.getByRole('button', { name: dark ? 'Switch to dark theme' : 'Switch to light theme', exact: true }).click();
        expect(await page.evaluate(() => localStorage.getItem('astranull.theme'))).toBe(dark ? 'dark' : 'light');
        return ['The theme control flips the document theme and persists the choice', 'A second activation returns the prior theme and persisted value'];
      },
    },
  },
  {
    query: { owner: 'ThemeToggle', label: 'label', kind: 'activate' },
    states: {
      success: async ({ page }) => {
        const dark = await page.evaluate(() => document.documentElement.dataset.theme !== 'light');
        const toggle = page.locator('button.theme-toggle');
        await expect(toggle).toHaveAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
        await expect(toggle).toHaveAttribute('title', dark ? 'Switch to light theme' : 'Switch to dark theme');
        await expect(toggle.locator(dark ? 'svg.lucide-sun' : 'svg.lucide-moon')).toBeVisible();
        const bg = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--bg').trim());
        await toggle.click();
        await expect(toggle.locator(dark ? 'svg.lucide-moon' : 'svg.lucide-sun')).toBeVisible();
        await expect(toggle).toHaveAttribute('aria-label', dark ? 'Switch to dark theme' : 'Switch to light theme');
        const changedBg = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--bg').trim());
        expect(changedBg).not.toBe(bg);
        expect(await page.evaluate(() => document.getElementById('theme-color-meta')?.getAttribute('content'))).toBe(changedBg);
        await toggle.click();
        await expect(toggle).toHaveAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
        return ['The icon button swaps its sun/moon glyph and accessible name with the theme', 'The theme-color meta follows the new background token and the second activation restores it'];
      },
    },
  },
  {
    query: { owner: 'ShellIconButton', label: 'label', kind: 'activate' },
    states: {
      success: async ({ page }) => {
        const collapse = page.locator('button.sidebar-collapse');
        const name = await collapse.getAttribute('aria-label');
        await expect(collapse).toHaveAttribute('title', name);
        await expect(collapse).toHaveAttribute('type', 'button');
        const before = await page.locator('.app-shell').evaluate((node) => node.classList.contains('sidebar-collapsed'));
        await collapse.click();
        expect(await page.locator('.app-shell').evaluate((node) => node.classList.contains('sidebar-collapsed'))).toBe(!before);
        await collapse.click();
        await setViewport(page, MOBILE);
        const menu = page.getByRole('button', { name: 'Open navigation', exact: true });
        await expect(menu).toHaveAttribute('aria-expanded', 'false');
        await expect(menu).toHaveAttribute('aria-controls', 'portal-navigation');
        await expect(page.locator('#portal-navigation')).toHaveCount(1);
        await setViewport(page, DESKTOP);
        return ['The shared icon button forwards its click to the caller callback and mirrors label into aria-label and title', 'Its expanded/controls props render aria-expanded=false and aria-controls pointing at the existing navigation landmark'];
      },
    },
  },
  {
    query: { owner: 'AppShell', label: 'Open navigation', kind: 'activate' },
    states: {
      success: async ({ page }) => {
        const drawer = await openDrawer(page);
        await expect(page.getByRole('button', { name: 'Close navigation', exact: true })).toBeFocused();
        await expect(page.getByRole('button', { name: 'Open navigation', exact: true })).toHaveAttribute('aria-expanded', 'true');
        await expect(drawer).toHaveAttribute('aria-modal', 'true');
        await expect(page.locator('body')).toHaveClass(/nav-drawer-open/);
        expect(await page.locator('#portal-main').evaluate((node) => node.inert)).toBe(true);
        await page.keyboard.press('Escape');
        await expect(drawer).toHaveCount(0);
        await setViewport(page, DESKTOP);
        return ['Open navigation shows the modal drawer, moves focus to Close navigation and marks the page behind inert', 'The trigger reports aria-expanded=true while open'];
      },
    },
  },
  {
    query: { owner: 'AppShell', label: 'Close navigation', kind: 'activate' },
    states: {
      success: async ({ page }) => {
        const drawer = await openDrawer(page);
        await page.getByRole('button', { name: 'Close navigation', exact: true }).click();
        await expect(drawer).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Open navigation', exact: true })).toBeFocused();
        expect(await page.locator('#portal-main').evaluate((node) => node.inert)).toBe(false);
        await expect(page.locator('body')).not.toHaveClass(/nav-drawer-open/);
        await setViewport(page, DESKTOP);
        return ['Close navigation dismisses the drawer, restores focus to the opener and releases the inert page'];
      },
      cancel: async ({ page, requests, route, baseUrl }) => {
        const mark = requests.mark();
        const before = page.url();
        const drawer = await openDrawer(page);
        await page.keyboard.press('Escape');
        await expect(drawer).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Open navigation', exact: true })).toBeFocused();
        expect(page.url()).toBe(before);
        expect(requests.writesSince(mark)).toEqual([]);
        await setViewport(page, DESKTOP);
        return ['Escape cancels the open drawer without changing route, URL or issuing any write, and returns focus to the opener', `The ${route} route address ${resolvePortalRouteUrl(route, baseUrl)} is preserved`];
      },
    },
  },
  {
    query: { owner: 'AppShell', label: 'div', kind: 'activate' },
    states: {
      success: async ({ page }) => {
        const drawer = await openDrawer(page);
        await page.locator('.scrim').click({ position: { x: MOBILE.width - 8, y: 450 } });
        await expect(drawer).toHaveCount(0);
        await expect(page.locator('.scrim')).not.toHaveClass(/open/);
        await setViewport(page, DESKTOP);
        return ['Activating the scrim outside the drawer closes it and clears the open scrim state'];
      },
    },
  },
  {
    query: { owner: 'AppShell', label: 'NavLink', kind: 'activate' },
    states: {
      success: async ({ page, identity, route }) => {
        const expected = await expectNavMatches(page, identity);
        const targets = visibleNav(identity).filter((item) => item.id !== route);
        const target = targets[0] ?? visibleNav(identity)[0];
        const item = navItems(page).filter({ hasText: target.label }).first();
        await item.click();
        await expect.poll(() => currentHash(page)).toBe(`#${target.id}`);
        await expectRouteRendered(page, identity, target.id);
        await expect(item).toHaveAttribute('aria-current', 'page');
        return [`Visible navigation entries exactly equal the routes ${identity.label} may open: ${expected.join(', ')}`, `Activating ${target.label} sets #${target.id}, renders that workspace without an access-denied page and marks it current`];
      },
      reload: async ({ page, identity, route }) => {
        const target = visibleNav(identity).find((item) => item.id !== route) ?? visibleNav(identity)[0];
        await page.reload({ waitUntil: 'networkidle' });
        await expect.poll(() => currentHash(page)).toBe(`#${target.id}`);
        await expectRouteRendered(page, identity, target.id);
        await expect(navItems(page).filter({ hasText: target.label }).first()).toHaveAttribute('aria-current', 'page');
        return [`A direct reload of the navigated address keeps #${target.id} rendered and current for ${identity.label}`];
      },
    },
    settle: async ({ arrive, route }) => arrive(route),
  },
  {
    query: { owner: 'NavLink', label: 'item.label', kind: 'activate' },
    states: {
      success: async ({ page, identity, route }) => {
        const visible = visibleNav(identity);
        const target = visible.find((item) => item.id !== route) ?? visible[0];
        const button = page.getByRole('button', { name: target.label, exact: true });
        await expect(button).toHaveAttribute('type', 'button');
        await expect(button).toHaveAttribute('title', target.label);
        await button.click();
        await expect.poll(() => currentHash(page)).toBe(`#${target.id}`);
        await expect(button).toHaveAttribute('aria-current', 'page');
        const siblings = await navItems(page).evaluateAll((nodes) => nodes.filter((node) => node.getAttribute('aria-current')).length);
        expect(siblings).toBe(1);
        return [`The nav button carries type, title and accessible name ${target.label}`, 'Exactly one nav entry is marked current after activation'];
      },
      reload: async ({ page, identity, route }) => {
        const target = visibleNav(identity).find((item) => item.id !== route) ?? visibleNav(identity)[0];
        await page.reload({ waitUntil: 'networkidle' });
        await expect(page.getByRole('button', { name: target.label, exact: true })).toHaveAttribute('aria-current', 'page');
        return [`After reload the nav entry for ${target.label} is still the single current entry`];
      },
    },
    settle: async ({ arrive, route }) => arrive(route),
  },
  {
    query: { owner: 'AppShell', label: 'Role (dev)', kind: 'select' },
    states: {
      success: async ({ page, identity, route, requests }) => {
        const alternate = alternateRole(identity, route);
        const other = alternate.role;
        const mark = requests.mark();
        await chooseRole(page, other);
        await expect.poll(async () => (await storedSession(page)).role).toBe(other);
        await expect(page.locator('.sidebar-account-meta')).toContainText(other.charAt(0).toUpperCase() + other.slice(1));
        await expectNavMatches(page, identity, other);
        if (alternate.allowed) await expect.poll(() => requests.since(mark).filter((entry) => entry.method === 'GET').length).toBeGreaterThan(0);
        expect(requests.writesSince(mark)).toEqual([]);
        await expectRouteOutcome(page, identity, route, alternate);
        await chooseRole(page, identity.role);
        await expect.poll(async () => (await storedSession(page)).role).toBe(identity.role);
        await expectNavMatches(page, identity);
        await expectRouteRendered(page, identity, route, { title: false });
        return [`Choosing ${other} persists that role, relabels the account, rebuilds navigation to its routes and ${alternate.allowed ? `re-hydrates ${route} with reads only` : `shows the access-denied page for ${route} without hydration`}`, `Choosing ${identity.role} restores the original session role, navigation and routed page with no write`];
      },
      reload: async ({ page, identity, route }) => {
        const alternate = alternateRole(identity, route);
        const other = alternate.role;
        await chooseRole(page, other);
        await expect.poll(async () => (await storedSession(page)).role).toBe(other);
        await page.reload({ waitUntil: 'networkidle' });
        await expect(page.locator('.sidebar-account-meta')).toContainText(other.charAt(0).toUpperCase() + other.slice(1));
        await expectNavMatches(page, identity, other);
        await expectRouteOutcome(page, identity, route, alternate);
        await chooseRole(page, identity.role);
        await expect.poll(async () => (await storedSession(page)).role).toBe(identity.role);
        return [`After reload the switched role ${other}, its navigation and the ${alternate.allowed ? 'rendered' : 'denied'} route persist; ${identity.role} is restored afterwards`];
      },
      'error-retry': async ({ page, identity, route, requests, outage }) => {
        const other = alternateRole(identity, route).role;
        await chooseRole(page, other);
        await expect.poll(async () => (await storedSession(page)).role).toBe(other);
        outage.state.on = true;
        await chooseRole(page, identity.role);
        const banner = page.getByRole('alert').filter({ hasText: 'Could not load some workspace data' });
        await expect(banner).toBeVisible();
        await clickRetryWhile({ page, requests }, banner, { healthy: false });
        outage.state.on = false;
        await clickRetryWhile({ page, requests }, banner, { healthy: true });
        expect((await storedSession(page)).role).toBe(identity.role);
        return [`Switching back to ${identity.role} while dataset reads fail shows the shell banner; an explicit Retry that still fails keeps it`, 'After recovery a Retry clears the banner, keeps the selected role and issues no write'];
      },
      denial: async ({ page, identity, requests }) => {
        const mark = requests.mark();
        await expect(page.getByRole('button', { name: /Role \(dev\)/ })).toHaveCount(0);
        await expect(page.locator('.sidebar-role')).toHaveCount(0);
        expect(requests.writesSince(mark)).toEqual([]);
        expect((await storedSession(page)).role).toBe(identity.session.role);
        return ['A staff session is never offered the local role switcher and its stored role is untouched', 'No write request is issued'];
      },
    },
    settle: async ({ arrive, route }) => arrive(route),
  },
  {
    query: { owner: 'AppShell', label: 'Retry', kind: 'activate' },
    order: ['error-retry', 'success', 'reload'],
    states: {
      'error-retry': async (ctx) => {
        const banner = await reachOutage(ctx, ctx.outage);
        const reads = await clickRetryWhile(ctx, banner, { healthy: false });
        await expect(banner.getByRole('button', { name: 'Retry', exact: true })).toBeEnabled();
        return [`${ctx.route} shows the shell load-error banner while dataset reads fail`, `An explicit Retry re-issued ${reads} dataset reads, the failure stayed visible and no write was sent`];
      },
      success: async (ctx) => {
        const banner = ctx.page.getByRole('alert').filter({ hasText: 'Could not load some workspace data' });
        await expect(banner).toBeVisible();
        ctx.outage.state.on = false;
        const reads = await clickRetryWhile(ctx, banner, { healthy: true });
        await expect(ctx.page.locator('#portal-main')).toBeVisible();
        return [`After the outage ends, Retry re-issued ${reads} reads and removed the banner for ${ctx.identity.label}`];
      },
      reload: async ({ page }) => {
        await page.reload({ waitUntil: 'networkidle' });
        await expect(page.getByRole('alert').filter({ hasText: 'Could not load some workspace data' })).toHaveCount(0);
        await expect(page.locator('#portal-main')).toBeVisible();
        return ['A reload after recovery hydrates cleanly with no stale error banner'];
      },
    },
    settle: async ({ page, outage }) => { outage.state.on = false; await page.reload({ waitUntil: 'networkidle' }); await waitForPortalRouteSettled(page); },
  },
  {
    query: { owner: 'AppShell', label: 'Public site', kind: 'anchor' },
    states: {
      success: async ({ page, baseUrl }) => {
        const link = page.getByRole('link', { name: 'Public site', exact: true });
        await expect(link).toHaveAttribute('href', '/');
        await link.click();
        await expect(page).toHaveURL(`${baseUrl}/`);
        await expect(page.locator('h1').first()).toContainText('DDoS readiness');
        expect(await storedSession(page)).not.toBeNull();
        return ['Public site opens the landing page at / in-app and renders its headline', 'The authenticated session is kept; the link only navigates'];
      },
      reload: async ({ page, baseUrl }) => {
        await page.reload({ waitUntil: 'networkidle' });
        await expect(page).toHaveURL(`${baseUrl}/`);
        await expect(page.locator('h1').first()).toContainText('DDoS readiness');
        return ['A direct reload of / renders the same landing page'];
      },
    },
    settle: async ({ arrive, route }) => arrive(route),
  },
  {
    query: { owner: 'AppShell', label: 'Sign out', kind: 'activate' },
    states: {
      success: async ({ page, identity, baseUrl }) => {
        await page.evaluate((key) => {
          const original = Storage.prototype.removeItem;
          Storage.prototype.removeItem = function removeItem(name) {
            if (this === window.sessionStorage && name === key) window.sessionStorage.setItem('__sessionRemoved', '1');
            return original.call(this, name);
          };
        }, PORTAL_SESSION_KEY);
        await page.getByRole('button', { name: 'Sign out', exact: true }).click();
        const destination = identity.principal === 'staff' ? '/internal/admin/login' : '/login';
        await expect(page).toHaveURL(`${baseUrl}${destination}`);
        expect(await page.evaluate(() => sessionStorage.getItem('__sessionRemoved'))).toBe('1');
        expect(await storedSession(page)).not.toEqual(identity.session);
        await expect(page.locator('h1').first()).toBeVisible();
        return [`Sign out lands on ${destination} for the ${identity.principal} surface`, 'The stored portal session was removed and the previous identity is not restored'];
      },
      reload: async ({ page, identity, route, baseUrl }) => {
        const login = identity.principal === 'staff' ? '/internal/admin/login' : '/login';
        await page.reload({ waitUntil: 'networkidle' });
        await expect(page).toHaveURL(`${baseUrl}${login}`);
        await expect(page.locator('h1').first()).toBeVisible();
        expect(await storedSession(page)).not.toEqual(identity.session);
        return [`A reload of the sign-in surface for ${route} stays there and never resurrects the signed-out identity`];
      },
    },
    settle: async ({ page, identity }) => { await restoreMatrixSession(page, identity); await page.evaluate(() => sessionStorage.removeItem('__sessionRemoved')); },
  },
];

test.describe('app shell: every source action across all customer and staff roles and permitted routes', () => {
  test.beforeAll(async () => { await startPortalPlaywrightServer({ liveSource: true }); });
  test.afterAll(async () => { await stopPortalPlaywrightServer(); });

  for (const identity of matrixIdentities()) {
    test(`${identity.label}: shell actions`, async ({ page }, testInfo) => {
      test.setTimeout(Number(process.env.PORTAL_MATRIX_TIMEOUT_MS ?? 1_800_000));
      await page.setViewportSize(DESKTOP);
      const outage = outageControl();
      const { failures, requests } = await startMatrixPage(page, identity, { allowResponse: (response) => outage.state.injected.has(response.url()) });
      await outage.install(page);
      const executed = await runIdentityMatrix(matrix, { page, testInfo, identity, drivers, failures, requests, context: { outage } });
      if (!process.env.PORTAL_MATRIX_ROUTES) expect(executed.length).toBe(matrix.cellCount(identity));
      failures.assertClean();
      expect(getPortalPlaywrightBaseUrl()).toBeTruthy();
    });
  }
});
