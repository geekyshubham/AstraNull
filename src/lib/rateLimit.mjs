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
 * spend the limit for everybody), but it is a CONFIGURATION issue: the only
 * source of the real client IP is a forwarding header, and a header is only
 * trustworthy at positions written by infrastructure you control.
 *
 * WHICH POSITION IS TRUSTWORTHY — this is the whole subtlety:
 *
 * Conforming proxies APPEND the address of the peer they received from. So for
 * `client → LB → app` the LB appends the client, giving `XFF: client`. A client
 * that sends its own `XFF: evil` first produces `XFF: evil, client` — the
 * LEFTMOST entry is attacker-chosen and the RIGHTMOST entries are the ones your
 * own infrastructure wrote. Reading `split(',')[0]` therefore hands the limiter
 * a key the attacker picks: they rotate it per request, every bucket is fresh,
 * and the limiter is effectively off. That is strictly worse than the collapsed
 * single bucket, which at least still counts.
 *
 * So the real client sits at `list.length - trustedProxyHops`, counted from the
 * right past the entries your infrastructure appended.
 *
 * The error directions are deliberately asymmetric:
 *   - hops too LOW  → index lands on a trusted proxy's own address. Callers
 *     collapse into one bucket: today's fairness problem, still not spoofable.
 *   - hops too HIGH → index reaches into caller-supplied entries, which is the
 *     spoofable case above.
 * Under-counting is safe and over-counting is not, so the default is 1 (a single
 * balancer) and a short list degrades to the socket address rather than reaching
 * left into attacker-controlled territory.
 *
 * `x-real-ip` is deliberately NOT consulted. It carries a single value with no
 * positional information, so there is no way to tell an edge-written value from
 * one the caller supplied — exactly the ambiguity the hop count resolves for
 * `x-forwarded-for`.
 *
 * Per-tenant fairness beyond this belongs in a post-auth limiter keyed by the
 * verified tenant.
 *
 * @param {{ headers?: Record<string, unknown>, socket?: { remoteAddress?: string } }} req
 * @param {{ trustProxyHeaders?: boolean, trustedProxyHops?: number }} [options]
 */
export function deriveClientKey(req, { trustProxyHeaders = false, trustedProxyHops = 1 } = {}) {
  if (trustProxyHeaders) {
    const forwarded = req.headers?.['x-forwarded-for'];
    if (forwarded != null && forwarded !== '') {
      // Node delivers a repeated header as an array; joining recovers the full
      // left-to-right chain so hop counting stays correct either way.
      const chain = Array.isArray(forwarded) ? forwarded.join(',') : String(forwarded);
      const list = chain.split(',').map((entry) => entry.trim()).filter(Boolean);
      const hops = Number.isInteger(trustedProxyHops) && trustedProxyHops >= 1
        ? trustedProxyHops
        : 1;
      const index = list.length - hops;
      // A negative index means the chain is shorter than the trusted hop count: the request did not
      // traverse the expected proxies, or `hops` is misconfigured. Either way, fall through to the
      // socket address rather than reading further left into caller-supplied entries.
      //
      // `index >= 0` is stated for intent, not for effect: JS has no negative array indexing, so
      // `list[-1]` is already undefined and the `list[index]` check alone would fall through. Do not
      // read this clause as the thing keeping a short chain out — the truthiness check is.
      if (index >= 0 && list[index]) return `ip:${list[index]}`;
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
