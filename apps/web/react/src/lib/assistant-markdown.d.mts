export type MarkdownInline =
  | { type: 'text'; text: string }
  | { type: 'code'; text: string }
  | { type: 'strong'; children: MarkdownInline[] }
  | { type: 'em'; children: MarkdownInline[] }
  | { type: 'link'; href: string; children: MarkdownInline[] };

export type MarkdownBlock =
  | { type: 'heading'; level: number; children: MarkdownInline[] }
  | { type: 'paragraph'; children: MarkdownInline[] }
  | { type: 'quote'; children: MarkdownInline[] }
  | { type: 'code'; lang: string; text: string }
  | { type: 'list'; ordered: boolean; start: number; items: MarkdownInline[][] }
  | { type: 'table'; header: MarkdownInline[][]; rows: MarkdownInline[][][] };

export function safeHref(value: unknown): string | null;
export function hostOf(value: string): string;
export function parseInline(text: string): MarkdownInline[];
export function parseMarkdown(input: unknown): MarkdownBlock[];
export function markdownToPlainText(input: unknown): string;
