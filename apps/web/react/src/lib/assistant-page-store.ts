import { useEffect, useState } from 'react';
import {
  buildPageContext,
  parseRouteHash,
  type AssistantPageContext,
  type PublishedPageContext,
} from './assistant-page-context.mjs';

let published: PublishedPageContext | null = null;
const listeners = new Set<() => void>();

function notify() {
  for (const listener of listeners) listener();
}

/**
 * A page shares what it shows with the assistant. The latest call for the open route wins and is
 * cleared when the page unmounts, so a stale page never answers for the next one.
 */
export function usePublishAssistantContext(context: PublishedPageContext | null) {
  const signature = context ? JSON.stringify(context) : '';
  useEffect(() => {
    if (!context) return undefined;
    const value = JSON.parse(signature) as PublishedPageContext;
    published = value;
    notify();
    return () => {
      if (published && JSON.stringify(published) === signature) {
        published = null;
        notify();
      }
    };
  }, [signature]);
}

function pageTitle() {
  if (typeof document === 'undefined') return '';
  const heading = document.querySelector('#portal-main h1, main h1');
  const text = heading?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
  return text.slice(0, 120);
}

/** The context for the page open right now: route identity, portal data facts and published facts. */
export function capturePageContext(data: unknown): AssistantPageContext | null {
  if (typeof window === 'undefined') return null;
  const { route, params } = parseRouteHash(window.location.hash);
  return buildPageContext({ route, params, title: pageTitle(), data, published });
}

/** Re-renders when the route or the published page context changes. */
export function useAssistantPageContext(data: unknown, enabled = true) {
  const [version, setVersion] = useState(0);
  useEffect(() => {
    if (!enabled) return undefined;
    const bump = () => setVersion((value) => value + 1);
    listeners.add(bump);
    window.addEventListener('hashchange', bump);
    const timer = window.setTimeout(bump, 300);
    return () => {
      listeners.delete(bump);
      window.removeEventListener('hashchange', bump);
      window.clearTimeout(timer);
    };
  }, [enabled]);
  const [context, setContext] = useState<AssistantPageContext | null>(null);
  useEffect(() => {
    if (enabled) setContext(capturePageContext(data));
  }, [enabled, data, version]);
  return context;
}
