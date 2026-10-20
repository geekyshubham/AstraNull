import assert from 'node:assert/strict';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer as createViteServer } from 'vite';

let vite;
let DomainFavicon;

before(async () => {
  vite = await createViteServer({ configFile: path.resolve('vite.config.ts'), server: { middlewareMode: true }, appType: 'custom', logLevel: 'silent' });
  ({ DomainFavicon } = await vite.ssrLoadModule('/src/components/targets/domain-favicon.tsx'));
});
after(async () => { await vite?.close(); });

const render = (value, kind = 'fqdn') => renderToStaticMarkup(createElement(DomainFavicon, { value, kind, className: 'target-icon' }));

describe('domain favicon disclosure boundary', () => {
  for (const value of [
    'router.home.arpa', 'service.onion', 'service.alt', 'private.internal',
    'printer.local', 'app.localhost', 'localhost', 'dev.test', 'bad.invalid',
    'demo.example', 'example.com', 'www.example.net', 'docs.example.org',
    'app.home', 'app.lan', 'app.corp', 'app.intranet', 'app.private',
    'https://ROUTER.HOME.ARPA./secret?token=private',
    '203.0.113.42', '127.0.0.1', '[::1]', 'http://[2001:db8::1]:8080/',
    'not a domain', 'https://bad_label.acme.com', 'https://-bad.acme.com',
    'https://bad..acme.com', 'file://checkout.acme.com/file', '',
  ]) {
    it(`renders no external image for ${JSON.stringify(value)}`, () => {
      const html = render(value);
      assert.doesNotMatch(html, /<img|icons\.duckduckgo\.com/);
      assert.match(html, /<svg/);
    });
  }

  it('sends only the public hostname, never URL credentials, port, path or query', () => {
    const html = render('https://user:secret@CHECKOUT.ACME.COM:8443/private?token=hidden#fragment', 'url');
    assert.match(html, /src="https:\/\/icons\.duckduckgo\.com\/ip3\/checkout\.acme\.com\.ico"/);
    assert.match(html, /loading="lazy"/);
    assert.match(html, /referrerPolicy="no-referrer"/i);
    assert.match(html, /alt=""/);
    assert.doesNotMatch(html, /secret|8443|\/private|token=|fragment/);
  });

  it('normalizes a public absolute hostname and retains IP/CIDR type fallbacks', () => {
    assert.match(render('CHECKOUT.ACME.COM.'), /checkout\.acme\.com\.ico/);
    for (const kind of ['ip', 'cidr']) assert.doesNotMatch(render('checkout.acme.com', kind), /<img/);
  });
});
