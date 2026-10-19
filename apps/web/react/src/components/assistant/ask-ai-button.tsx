import { Sparkles } from 'lucide-react';
import { assistantAvailable, useAssistantStatus } from '../../lib/assistant-api';
import { openAssistant } from '../../lib/assistant-bus';
import type { AssistantContext } from '../../lib/assistant-storage.mjs';
import type { PortalConfig, Session } from '../../lib/types';
import { Button } from '../ui/button';

export const ASK_FIX_PROMPT = 'What is missing in my environment and how do I fix it for my provider?';

export function AskAiButton({ config, session, context, size = 'sm', variant = 'secondary' }: {
  config: PortalConfig;
  session: Session;
  context: AssistantContext;
  size?: 'sm' | 'default';
  variant?: 'secondary' | 'ghost' | 'default';
}) {
  const { status } = useAssistantStatus(config, session);
  if (session.principal === 'staff' || !assistantAvailable(status)) return null;
  return (
    <Button
      size={size}
      variant={variant}
      className="as-ask-btn"
      onClick={() => openAssistant({ context, prompt: ASK_FIX_PROMPT, send: true })}
    >
      <Sparkles size={14} aria-hidden="true" />Ask AI how to fix
    </Button>
  );
}
