import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { describe, it } from 'node:test';
import {
  pinnedFetch,
  pinnedWebSocketUpgrade,
  resolvePinnedDestination,
} from '../../src/lib/pinnedHttpRequest.mjs';
import { runProtocolTransportFixture } from './protocol-transport-watchdog.mjs';

function fakeRequest(assertOptions) {
  return (options, callback) => {
    assertOptions(options);
    const request = new EventEmitter();
    request.write = () => {};
    request.destroy = (error) => { if (error) request.emit('error', error); };
    request.end = () => {
      const response = new PassThrough();
      response.statusCode = 204;
      response.headers = {};
      callback(response);
      response.end();
    };
    return request;
  };
}

describe('pinned HTTP destination transport', () => {
  it('rejects any private answer before request creation', async () => {
    const resolved = () => Promise.resolve(['93.184.216.34', '169.254.169.254']);
    await assert.rejects(
      () => pinnedFetch('https://owned.example/health', {}, {
        resolve4Fn: resolved,
        resolve6Fn: async () => [],
        httpsRequestFn: () => { throw new Error('request must not be created'); },
      }),
      (error) => error?.code === 'EDESTINATION' && error?.blockedAddress === '169.254.169.254',
    );
  });

  it('consumes an injected preflight set without any resolver call', async () => {
    let resolverCalls = 0;
    const response = await pinnedFetch('https://owned.example/check', { method: 'HEAD' }, {
      vettedHost: 'owned.example',
      vettedAddresses: ['203.0.113.10'],
      resolve4Fn: async () => { resolverCalls += 1; return ['198.51.100.99', '10.0.0.8']; },
      resolve6Fn: async () => { resolverCalls += 1; return []; },
      httpsRequestFn: fakeRequest((options) => {
        assert.equal(options.hostname, '203.0.113.10');
        assert.equal(options.servername, 'owned.example');
        assert.equal(options.headers.Host, 'owned.example');
      }),
    });
    assert.equal(response.pinnedAddress, '203.0.113.10');
    assert.equal(resolverCalls, 0);
    await response.body.cancel();
  });

  it('rejects incomplete or malformed injected destination sets before transport creation', async () => {
    const invalid = [
      { vettedHost: 'owned.example' },
      { vettedAddresses: ['203.0.113.10'] },
      { vettedHost: 'owned.example', vettedAddresses: [] },
      { vettedHost: 'owned.example', vettedAddresses: ['not-an-ip'] },
      { vettedHost: 'owned.example', vettedAddresses: ['203.0.113.10', '203.0.113.10'] },
      { vettedHost: '203.0.113.10', vettedAddresses: ['198.51.100.20'] },
    ];
    for (const deps of invalid) {
      await assert.rejects(
        () => pinnedFetch('https://owned.example/', {}, {
          ...deps,
          httpsRequestFn: () => { throw new Error('request must not be created'); },
        }),
        (error) => error?.code === 'EDESTINATION',
      );
    }
  });

  it('re-checks policy on an injected set before transport creation', async () => {
    await assert.rejects(
      () => pinnedFetch('https://owned.example/', {}, {
        vettedHost: 'owned.example',
        vettedAddresses: ['10.0.0.8'],
        httpsRequestFn: () => { throw new Error('request must not be created'); },
      }),
      (error) => error?.code === 'EDESTINATION' && error?.blockedAddress === '10.0.0.8',
    );
  });

  it('classifies a genuinely different host instead of reusing the original set', async () => {
    let resolverCalls = 0;
    const response = await pinnedFetch('http://redirected.example/next', {}, {
      vettedHost: 'owned.example',
      vettedAddresses: ['203.0.113.10'],
      resolve4Fn: async (host) => {
        resolverCalls += 1;
        assert.equal(host, 'redirected.example');
        return ['198.51.100.20'];
      },
      resolve6Fn: async () => [],
      httpRequestFn: fakeRequest((options) => {
        assert.equal(options.hostname, '198.51.100.20');
        assert.equal(options.headers.Host, 'redirected.example');
      }),
    });
    assert.equal(response.pinnedAddress, '198.51.100.20');
    assert.equal(resolverCalls, 1);
    await response.body.cancel();
  });

  it('sends no request when a hostname has zero A/AAAA answers', async () => {
    let requests = 0;
    await assert.rejects(
      () => pinnedFetch('https://missing.example/', {}, {
        resolve4Fn: async () => [],
        resolve6Fn: async () => [],
        httpsRequestFn: () => { requests += 1; throw new Error('must not request'); },
      }),
      (error) => error?.code === 'ENOTFOUND',
    );
    assert.equal(requests, 0);
  });

  it('connects to the vetted answer while preserving Host and TLS SNI', async () => {
    let resolutions = 0;
    const response = await pinnedFetch('https://owned.example/check?q=1', { method: 'HEAD' }, {
      resolve4Fn: async () => {
        resolutions += 1;
        return resolutions === 1 ? ['93.184.216.34'] : ['169.254.169.254'];
      },
      resolve6Fn: async () => [],
      httpsRequestFn: fakeRequest((options) => {
        assert.equal(options.hostname, '93.184.216.34');
        assert.equal(options.servername, 'owned.example');
        assert.equal(options.headers.Host, 'owned.example');
        assert.equal(options.path, '/check?q=1');
      }),
    });
    assert.equal(response.status, 204);
    assert.equal(response.pinnedAddress, '93.184.216.34');
    assert.equal(resolutions, 1);
    await response.body.cancel();
  });

  it('classifies a direct metadata literal without DNS', async () => {
    await assert.rejects(
      () => resolvePinnedDestination('169.254.169.254'),
      (error) => error?.code === 'EDESTINATION',
    );
  });

  it('destroys a bounded upgrade request on timeout', async () => {
    let destroyed = false;
    await assert.rejects(
      () => pinnedWebSocketUpgrade('http://owned.example/socket', { timeoutMs: 20 }, {
        resolve4Fn: async () => ['93.184.216.34'],
        resolve6Fn: async () => [],
        httpRequestFn: () => {
          const request = new EventEmitter();
          request.write = () => {};
          request.end = () => {};
          request.destroy = (error) => {
            destroyed = true;
            queueMicrotask(() => request.emit('error', error));
          };
          return request;
        },
      }),
      (error) => error?.name === 'AbortError' && error?.code === 'ETIMEOUT',
    );
    assert.equal(destroyed, true);
  });

  it('honors an already-aborted upgrade without creating a request', async () => {
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      () => pinnedWebSocketUpgrade('http://owned.example/socket', {
        signal: controller.signal,
        timeoutMs: 100,
      }, {
        httpRequestFn: () => { throw new Error('request must not be created'); },
      }),
      (error) => error?.name === 'AbortError',
    );
  });

  it('settles real 101 sockets and never follows upgrade redirects', { timeout: 6000 }, async () => {
    const output = await runProtocolTransportFixture('websocket');
    assert.match(output.stdout, /websocket:ok/);
  });
});
