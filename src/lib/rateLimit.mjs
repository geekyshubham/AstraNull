/**
 * In-process fixed-window rate limiter (no external deps).
 *
 * Two design properties matter under flood, because this is the control plane of
 * a DDoS-readiness product:
 *
 * 1. `check()` is O(1). The previous implementation swept the whole bucket Map on
 *    every request, which is quadratic exactly when a flood makes the Map large.
 *    Expiry is handled by a two-generation current/previous Map pair swapped in
 *    O(1) when the window advances, so stale keys are dropped wholesale instead
 *    of being scanned.
 * 2. Distinct keys are bounded. A spoofed-source flood would otherwise grow the
 *    Map without limit and turn a request flood into a memory exhaustion bug.
 *    `maxKeys` caps live keys with LRU eviction (Map preserves insertion order,
 *    so the oldest entry is the first key).
 */

const DEFAULT_MAX_KEYS = 100_000;

/**
 * Derive the rate-limit bucket key for a request.
 *
 * IMPORTANT — why this stays address-based:
 *
 * This limiter runs BEFORE authentication, which is the point: it protects the
 * auth path itself from being a DoS amplifier. That means the key must be
 * something the caller cannot choose. Keying on a caller-supplied credential
 * (e.g. a fingerprint of the Authorization header) would let an attacker mint a
 * fresh, empty bucket per request just by rotating a random token — turning the
 * limiter off entirely. So only the transport address is used here.
 *
 * KNOWN DEPLOYMENT LIMITATION: with `trustProxyHeaders` off behind a load
 * balancer, every connection presents the balancer's address, so all callers
 * share a single bucket. That is a real fairness problem (one noisy tenant can
 * spend the limit for everybody), but it is a CONFIGURATION issue, not something
 * this function can fix safely: the only trustworthy source of the real client
 * IP is a forwarding header, and trusting that header when the deployment does
 * not guarantee it is overwritten at the edge reintroduces spoofable keys.
 * Remediation is to enable `ASTRANULL_TRUST_PROXY_HEADERS=1` in deployments
 * whose edge overwrites `X-Forwarded-For`. Per-tenant fairness beyond that
 * belongs in a post-auth limiter keyed by the verified tenant.
 *
 * @param {{ headers?: Record<string, unknown>, socket?: { remoteAddress?: string } }} req
 * @param {{ trustProxyHeaders?: boolean }} [options]
 */
export function deriveClientKey(req, { trustProxyHeaders = false } = {}) {
  if (trustProxyHeaders) {
    const forwarded = req.headers?.['x-forwarded-for'];
    if (forwarded) {
      const first = String(forwarded).split(',')[0].trim();
      if (first) return `ip:${first}`;
    }
    const realIp = req.headers?.['x-real-ip'];
    if (realIp) {
      const trimmed = String(realIp).trim();
      if (trimmed) return `ip:${trimmed}`;
    }
  }
  const addr = req.socket?.remoteAddress ?? 'unknown';
  return `ip:${addr}`;
}

/**
 * @param {{
 *   windowMs: number,
 *   maxRequests: number,
 *   maxKeys?: number,
 *   now?: () => number,
 * }} options
 */
export function createFixedWindowRateLimiter({
  windowMs,
  maxRequests,
  maxKeys = DEFAULT_MAX_KEYS,
  now = () => Date.now(),
}) {
  if (!Number.isInteger(windowMs) || windowMs < 1) {
    throw new Error('createFixedWindowRateLimiter requires a positive integer windowMs');
  }
  if (!Number.isInteger(maxRequests) || maxRequests < 1) {
    throw new Error('createFixedWindowRateLimiter requires a positive integer maxRequests');
  }
  if (!Number.isInteger(maxKeys) || maxKeys < 1) {
    throw new Error('createFixedWindowRateLimiter requires a positive integer maxKeys');
  }

  /** Counts for the window currently in progress. @type {Map<string, number>} */
  let current = new Map();
  let currentWindowIndex = Math.floor(now() / windowMs);
  let evictedTotal = 0;

  /**
   * Drop the previous generation wholesale when the clock crosses a window edge.
   *
   * This is the O(1) replacement for the old per-request sweep: expiry costs one
   * Map allocation per window instead of one full scan per request. Counts reset
   * at the boundary, which is the same fixed-window semantics as before.
   */
  function rollWindows(windowIndex) {
    if (windowIndex === currentWindowIndex) return;
    current = new Map();
    currentWindowIndex = windowIndex;
  }

  /**
   * Enforce the distinct-key ceiling with LRU eviction. Map iteration order is
   * insertion order and `check` re-inserts on every hit, so the first key is the
   * least recently *used*.
   *
   * Tradeoff, stated plainly: evicting a key also forgets its count, so a flood
   * of distinct keys can evict a legitimate caller and hand it a fresh
   * allowance. That is accepted deliberately — an unbounded Map would convert a
   * request flood into memory exhaustion, which is the worse failure for a
   * control plane. Accuracy degrades; the process survives.
   */
  function enforceKeyCeiling() {
    while (current.size > maxKeys) {
      const oldest = current.keys().next();
      if (oldest.done) break;
      current.delete(oldest.value);
      evictedTotal += 1;
    }
  }

  function check(key) {
    const t = now();
    rollWindows(Math.floor(t / windowMs));

    const count = (current.get(key) ?? 0) + 1;
    if (current.has(key)) {
      // Refresh recency so an active key is not evicted ahead of an idle one.
      current.delete(key);
    }
    current.set(key, count);
    if (current.size > maxKeys) enforceKeyCeiling();

    const allowed = count <= maxRequests;
    const windowEndMs = (currentWindowIndex + 1) * windowMs;
    const retryAfterSeconds = Math.max(1, Math.ceil((windowEndMs - t) / 1000));
    return {
      allowed,
      retryAfterSeconds,
      remaining: Math.max(0, maxRequests - count),
    };
  }

  return {
    check,
    bucketCount: () => current.size,
    /** Diagnostics: how many keys the ceiling has discarded. */
    evictedCount: () => evictedTotal,
  };
}
