export const PORTAL_FONT_STYLESHEET = 'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap';

const installations = new WeakMap();

/** Deterministic font and favicon fixtures. Browser tests make no external resource requests. */
export async function installPortalBrowserResources(page) {
  let installed = installations.get(page);
  if (!installed) {
    installed = Promise.resolve().then(async () => {
      await page.route('https://icons.duckduckgo.com/**', (route) => route.fulfill({
        contentType: 'image/svg+xml',
        body: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><circle cx="8" cy="8" r="6" fill="gray"/></svg>',
      }));
      await page.route((url) => url.href === PORTAL_FONT_STYLESHEET, async (route) => {
        const request = route.request();
        if (request.url() !== PORTAL_FONT_STYLESHEET || request.method() !== 'GET' || request.resourceType() !== 'stylesheet') return route.fallback();
        return route.fulfill({
          status: 200,
          contentType: 'text/css',
          body: '/* Owned browser fixture: use the application system-font fallbacks. Real Google Fonts are not verified. */',
        });
      });
    });
    installations.set(page, installed);
  }
  try {
    await installed;
  } catch (error) {
    if (installations.get(page) === installed) installations.delete(page);
    throw error;
  }
}
