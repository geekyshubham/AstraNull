import { useEffect, useRef } from 'react';
import { MessageSquare, Trash2 } from 'lucide-react';
import type { AssistantSession } from '../../lib/assistant-storage.mjs';
import { formatDate } from '../../lib/utils';

export function AssistantHistory({ sessions, activeId, onSelect, onDelete, onClose }: {
  sessions: AssistantSession[];
  activeId: string | null;
  onSelect: (id: string) => void;
  onDelete: (id: string) => void;
  onClose: () => void;
}) {
  const panel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    panel.current?.querySelector<HTMLElement>('button')?.focus();
    const onPointer = (event: PointerEvent) => {
      if (panel.current && !panel.current.contains(event.target as Node)) onClose();
    };
    document.addEventListener('pointerdown', onPointer);
    return () => document.removeEventListener('pointerdown', onPointer);
  }, [onClose]);

  return (
    <div className="as-history" ref={panel} role="group" aria-label="Chat history" onKeyDown={(event) => { if (event.key === 'Escape') { event.stopPropagation(); onClose(); } }}>
      <span className="as-history-title">Recent chats</span>
      {sessions.length === 0 ? <p className="as-history-empty">No saved chats yet. Chats stay in this browser only.</p> : (
        <ul>
          {sessions.map((item) => (
            <li key={item.id} data-active={item.id === activeId || undefined}>
              <button type="button" className="as-history-open" onClick={() => onSelect(item.id)}>
                <MessageSquare size={14} aria-hidden="true" />
                <span className="as-history-name">{item.title}</span>
                <span className="as-history-date">{formatDate(item.updated_at)}</span>
              </button>
              <button type="button" className="as-icon-btn" aria-label={`Delete chat ${item.title}`} onClick={() => onDelete(item.id)}>
                <Trash2 size={14} aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
