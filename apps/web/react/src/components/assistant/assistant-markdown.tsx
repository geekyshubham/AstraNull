import { Fragment, useMemo, type ReactNode } from 'react';
import { parseMarkdown, type MarkdownBlock, type MarkdownInline } from '../../lib/assistant-markdown.mjs';

function renderInline(nodes: MarkdownInline[], keyPrefix: string): ReactNode[] {
  return nodes.map((node, index) => {
    const key = `${keyPrefix}-${index}`;
    if (node.type === 'text') return <Fragment key={key}>{node.text}</Fragment>;
    if (node.type === 'code') return <code key={key}>{node.text}</code>;
    if (node.type === 'strong') return <strong key={key}>{renderInline(node.children, key)}</strong>;
    if (node.type === 'em') return <em key={key}>{renderInline(node.children, key)}</em>;
    return (
      <a key={key} href={node.href} target="_blank" rel="noopener noreferrer nofollow">
        {renderInline(node.children, key)}
      </a>
    );
  });
}

function renderBlock(block: MarkdownBlock, index: number): ReactNode {
  const key = `b${index}`;
  if (block.type === 'heading') {
    const Tag = (`h${block.level}`) as 'h3' | 'h4' | 'h5' | 'h6';
    return <Tag key={key}>{renderInline(block.children, key)}</Tag>;
  }
  if (block.type === 'paragraph') return <p key={key}>{renderInline(block.children, key)}</p>;
  if (block.type === 'quote') return <blockquote key={key}>{renderInline(block.children, key)}</blockquote>;
  if (block.type === 'code') return <pre key={key}><code>{block.text}</code></pre>;
  if (block.type === 'list') {
    const items = block.items.map((item, itemIndex) => <li key={`${key}-${itemIndex}`}>{renderInline(item, `${key}-${itemIndex}`)}</li>);
    return block.ordered ? <ol key={key} start={block.start}>{items}</ol> : <ul key={key}>{items}</ul>;
  }
  return (
    <div key={key} className="as-md-table" role="region" tabIndex={0} aria-label="Table">
      <table>
        <thead><tr>{block.header.map((cell, cellIndex) => <th key={cellIndex} scope="col">{renderInline(cell, `${key}-h${cellIndex}`)}</th>)}</tr></thead>
        <tbody>
          {block.rows.map((row, rowIndex) => (
            <tr key={rowIndex}>{row.map((cell, cellIndex) => <td key={cellIndex}>{renderInline(cell, `${key}-${rowIndex}-${cellIndex}`)}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function AssistantMarkdown({ content }: { content: string }) {
  const blocks = useMemo(() => parseMarkdown(content), [content]);
  return <div className="as-md">{blocks.map(renderBlock)}</div>;
}
