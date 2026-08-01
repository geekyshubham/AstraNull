/**
 * Opaque cursor helpers for portal revamp list endpoints.
 */

export function encodeCursor(payload) {
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
}

export function decodeCursor(cursor) {
  if (!cursor) return null;
  try {
    const parsed = JSON.parse(Buffer.from(String(cursor), 'base64url').toString('utf8'));
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * Server-side page-size clamp shared by in-memory and SQL keyset pagination.
 *
 * Never trust a client-supplied limit: values are coerced to a number, floored at 1
 * and capped at `max` so a hostile `?limit=1000000` cannot force an unbounded read.
 *
 * @param {unknown} limit
 * @param {{ max?: number, fallback?: number }} [options]
 * @returns {number}
 */
export function clampPageLimit(limit, options = {}) {
  const max = Number(options.max) || 100;
  const fallback = Number(options.fallback) || 50;
  const requested = Number(limit) || fallback;
  return Math.max(1, Math.min(Math.floor(requested), max));
}

/**
 * Encode a keyset (seek) cursor carrying the full sort tuple.
 *
 * Keyset pagination needs every column of the ORDER BY to resolve a page boundary by
 * index seek. A bare `id` is not enough when the leading sort column is a non-unique
 * timestamp, so both parts of the tuple travel in the cursor.
 *
 * @param {{ [key: string]: unknown }} tuple
 * @returns {string}
 */
export function encodeKeysetCursor(tuple) {
  return encodeCursor(tuple);
}

/**
 * Decode a keyset cursor into its sort tuple.
 *
 * Returns `null` for absent/corrupt cursors. When the cursor carries an id but no
 * timestamp it is a LEGACY cursor minted before keyset pagination existed; that case
 * is reported via `legacy: true` so the caller can decide how to resolve it rather
 * than silently paging from a different ordering.
 *
 * @param {string | null | undefined} cursor
 * @param {{ timeField?: string, idField?: string }} [options]
 * @returns {{ id: string, legacy: boolean, [key: string]: unknown } | null}
 */
export function decodeKeysetCursor(cursor, options = {}) {
  const timeField = options.timeField ?? 'created_at';
  const idField = options.idField ?? 'id';
  const decoded = decodeCursor(cursor);
  if (!decoded) return null;

  const rawId = decoded[idField];
  if (rawId == null || String(rawId) === '') return null;

  const rawTime = decoded[timeField];
  const time =
    rawTime == null
      ? null
      : rawTime instanceof Date
        ? rawTime.toISOString()
        : String(rawTime);

  return { id: String(rawId), [timeField]: time, legacy: time === null };
}

/**
 * @template T
 * @param {T[]} items
 * @param {{ limit?: number, cursor?: string | null, cursorField?: string }} options
 */
export function paginateItems(items, options = {}) {
  const limit = clampPageLimit(options.limit);
  const cursorField = options.cursorField ?? 'id';
  const decoded = decodeCursor(options.cursor);
  let startIndex = 0;
  if (decoded && decoded[cursorField] != null) {
    const idx = items.findIndex((item) => item[cursorField] === decoded[cursorField]);
    startIndex = idx >= 0 ? idx + 1 : 0;
  }
  const page = items.slice(startIndex, startIndex + limit);
  const last = page[page.length - 1];
  const next_cursor =
    startIndex + limit < items.length && last
      ? encodeCursor({ [cursorField]: last[cursorField] })
      : null;
  return { items: page, next_cursor, count: page.length };
}