/**
 * Safe markdown for assistant answers: text in, a small block/inline tree out. Rendering never
 * uses raw HTML, and only http(s) links survive; everything else stays as visible text.
 */

const MAX_INPUT = 40_000;

/** @param {unknown} value */
export function safeHref(value) {
  const raw = String(value ?? '').trim();
  if (!/^https?:\/\//i.test(raw)) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    if (url.username || url.password) return null;
    return url.href;
  } catch {
    return null;
  }
}

/** @param {string} value */
export function hostOf(value) {
  try {
    return new URL(value).hostname.replace(/^www\./, '');
  } catch {
    return '';
  }
}

const INLINE = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|(__[^_\n]+__)|(\*[^*\s][^*\n]*\*)|(\[[^\]\n]+\]\((?:[^()\s]|\([^()\s]*\))+\))|(https?:\/\/[^\s<>()]+[^\s<>().,;:!?'"])/g;

/**
 * @param {string} text
 * @returns {Array<any>}
 */
export function parseInline(text) {
  const out = [];
  const source = String(text ?? '');
  let last = 0;
  for (const match of source.matchAll(INLINE)) {
    const index = match.index ?? 0;
    if (index > last) out.push({ type: 'text', text: source.slice(last, index) });
    const token = match[0];
    if (match[1]) out.push({ type: 'code', text: token.slice(1, -1) });
    else if (match[2] || match[3]) out.push({ type: 'strong', children: parseInline(token.slice(2, -2)) });
    else if (match[4]) out.push({ type: 'em', children: parseInline(token.slice(1, -1)) });
    else if (match[5]) {
      const split = token.indexOf('](');
      const label = token.slice(1, split);
      const href = safeHref(token.slice(split + 2, -1));
      out.push(href ? { type: 'link', href, children: parseInline(label) } : { type: 'text', text: label });
    } else if (match[6]) {
      const href = safeHref(token);
      out.push(href ? { type: 'link', href, children: [{ type: 'text', text: token }] } : { type: 'text', text: token });
    }
    last = index + token.length;
  }
  if (last < source.length) out.push({ type: 'text', text: source.slice(last) });
  return out;
}

function tableCells(line) {
  return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((cell) => cell.trim());
}

/**
 * @param {unknown} input
 * @returns {Array<any>}
 */
export function parseMarkdown(input) {
  const lines = String(input ?? '').slice(0, MAX_INPUT).replace(/\r\n?/g, '\n').split('\n');
  const blocks = [];
  let paragraph = [];
  let list = null;
  const flushParagraph = () => {
    if (paragraph.length) blocks.push({ type: 'paragraph', children: parseInline(paragraph.join(' ')) });
    paragraph = [];
  };
  const flushList = () => {
    if (list) blocks.push(list);
    list = null;
  };
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const fence = line.match(/^\s*```\s*([\w+-]*)\s*$/);
    if (fence) {
      flushParagraph();
      flushList();
      const code = [];
      i += 1;
      while (i < lines.length && !/^\s*```\s*$/.test(lines[i])) {
        code.push(lines[i]);
        i += 1;
      }
      blocks.push({ type: 'code', lang: fence[1] || '', text: code.join('\n') });
      continue;
    }
    if (!line.trim()) {
      flushParagraph();
      flushList();
      continue;
    }
    const heading = line.match(/^\s*(#{1,6})\s+(.*)$/);
    if (heading) {
      flushParagraph();
      flushList();
      blocks.push({ type: 'heading', level: Math.min(heading[1].length + 2, 6), children: parseInline(heading[2].replace(/\s+#+\s*$/, '')) });
      continue;
    }
    if (/^\s*\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1])) {
      flushParagraph();
      flushList();
      const header = tableCells(line).map(parseInline);
      const rows = [];
      i += 2;
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) {
        rows.push(tableCells(lines[i]).map(parseInline));
        i += 1;
      }
      i -= 1;
      blocks.push({ type: 'table', header, rows });
      continue;
    }
    const item = line.match(/^\s*([-*+]|\d+[.)])\s+(.*)$/);
    if (item) {
      flushParagraph();
      const ordered = /\d/.test(item[1]);
      if (!list || list.ordered !== ordered) {
        flushList();
        list = { type: 'list', ordered, start: ordered ? Number.parseInt(item[1], 10) || 1 : 1, items: [] };
      }
      list.items.push(parseInline(item[2]));
      continue;
    }
    if (list && /^\s{2,}\S/.test(line)) {
      const lastItem = list.items[list.items.length - 1];
      lastItem.push({ type: 'text', text: ' ' }, ...parseInline(line.trim()));
      continue;
    }
    if (/^\s*>\s?/.test(line)) {
      flushParagraph();
      flushList();
      blocks.push({ type: 'quote', children: parseInline(line.replace(/^\s*>\s?/, '')) });
      continue;
    }
    flushList();
    paragraph.push(line.trim());
  }
  flushParagraph();
  flushList();
  return blocks;
}

/** Plain text of a parsed answer, for copy and for screen-reader announcements. */
export function markdownToPlainText(input) {
  const inline = (nodes) => nodes.map((node) => (node.type === 'text' || node.type === 'code' ? node.text : inline(node.children ?? []))).join('');
  return parseMarkdown(input).map((block) => {
    if (block.type === 'code') return block.text;
    if (block.type === 'list') return block.items.map((itemNodes, index) => `${block.ordered ? `${block.start + index}.` : '-'} ${inline(itemNodes)}`).join('\n');
    if (block.type === 'table') return [block.header, ...block.rows].map((row) => row.map(inline).join(' | ')).join('\n');
    return inline(block.children ?? []);
  }).join('\n\n');
}
