import { sanitizeContext, type AssistantContext } from './assistant-storage.mjs';

export const ASSISTANT_OPEN_EVENT = 'astranull:assistant-open';

export type AssistantOpenRequest = {
  prompt?: string;
  context?: AssistantContext | null;
  send?: boolean;
};

export function openAssistant(request: AssistantOpenRequest = {}) {
  if (typeof window === 'undefined') return;
  const detail: AssistantOpenRequest = {
    prompt: typeof request.prompt === 'string' ? request.prompt.slice(0, 4000) : undefined,
    context: sanitizeContext(request.context),
    send: request.send === true,
  };
  window.dispatchEvent(new CustomEvent(ASSISTANT_OPEN_EVENT, { detail }));
}

export function onAssistantOpen(handler: (request: AssistantOpenRequest) => void) {
  const listener = (event: Event) => {
    const detail = (event as CustomEvent<AssistantOpenRequest>).detail ?? {};
    handler({
      prompt: typeof detail.prompt === 'string' ? detail.prompt.slice(0, 4000) : undefined,
      context: sanitizeContext(detail.context),
      send: detail.send === true,
    });
  };
  window.addEventListener(ASSISTANT_OPEN_EVENT, listener);
  return () => window.removeEventListener(ASSISTANT_OPEN_EVENT, listener);
}
