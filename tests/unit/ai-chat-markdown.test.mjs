import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { markdownToPlainText, parseInline, parseMarkdown, safeHref } from '../../apps/web/react/src/lib/assistant-markdown.mjs';

describe('assistant markdown', () => {
  it('keeps only http(s) links and drops credentials and script schemes', () => {
    assert.equal(safeHref('https://developers.cloudflare.com/waf/'), 'https://developers.cloudflare.com/waf/');
    assert.equal(safeHref('javascript:alert(1)'), null);
    assert.equal(safeHref('data:text/html,<b>x</b>'), null);
    assert.equal(safeHref('https://user:pass@example.com/'), null);
    assert.equal(safeHref('//example.com'), null);
  });

  it('turns unsafe markdown links into plain text', () => {
    const nodes = parseInline('click [here](javascript:alert(1)) or [docs](https://example.com/a)');
    assert.deepEqual(nodes.map((node) => node.type), ['text', 'text', 'text', 'link']);
    assert.equal(nodes[1].text, 'here');
    assert.equal(nodes[3].href, 'https://example.com/a');
  });

  it('never produces raw HTML nodes', () => {
    const blocks = parseMarkdown('<img src=x onerror=alert(1)>\n\n<script>alert(1)</script>');
    const flat = JSON.stringify(blocks);
    assert.ok(blocks.every((block) => block.type === 'paragraph'));
    assert.match(flat, /"type":"text","text":"<img src=x onerror=alert\(1\)>"/);
  });

  it('parses headings, lists, code fences, tables and bare links', () => {
    const blocks = parseMarkdown([
      '## Fix it',
      '1. Open **Security** > WAF',
      '2. Add a rule',
      '- note `code`',
      '```bash',
      'gcloud compute firewall-rules list',
      '```',
      '| Provider | Control |',
      '| --- | --- |',
      '| AWS | Security group |',
      'See https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html.',
    ].join('\n'));
    assert.deepEqual(blocks.map((block) => block.type), ['heading', 'list', 'list', 'code', 'table', 'paragraph']);
    assert.equal(blocks[0].level, 4);
    assert.equal(blocks[1].ordered, true);
    assert.equal(blocks[1].items.length, 2);
    assert.equal(blocks[3].lang, 'bash');
    assert.equal(blocks[4].rows.length, 1);
    const link = blocks[5].children.find((node) => node.type === 'link');
    assert.equal(link.href, 'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html');
  });

  it('produces plain text for copying', () => {
    assert.equal(markdownToPlainText('**Bold** and [link](https://example.com)\n\n- one\n- two'), 'Bold and link\n\n- one\n- two');
  });
});

describe('assistant markdown link edge cases', () => {
  it('drops a blocked link without leaving a stray bracket and keeps nested-paren URLs', async () => {
    const { parseInline } = await import('../../apps/web/react/src/lib/assistant-markdown.mjs');
    assert.deepEqual(parseInline('[bad](javascript:alert(1)) and [ok](https://example.com/a_(b))'), [
      { type: 'text', text: 'bad' },
      { type: 'text', text: ' and ' },
      { type: 'link', href: 'https://example.com/a_(b)', children: [{ type: 'text', text: 'ok' }] },
    ]);
  });
});
