import { useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowDown,
  Check,
  ChevronDown,
  ChevronUp,
  Copy,
  Filter,
  Maximize2,
  Minimize2,
  Search,
  Terminal,
} from 'lucide-react';
import type { LiveLogEntry, LiveLogLevel } from '../../lib/live-probe-logs';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';

export type LiveProbeTerminalProps = {
  entries: LiveLogEntry[];
  active?: boolean;
  title?: string;
  subtitle?: string;
  activeCheckLabel?: string;
  requestsSent?: number | null;
  maxRequests?: number | null;
  elapsedSeconds?: number | null;
  compact?: boolean;
  emptyMessage?: string;
  className?: string;
  defaultExpanded?: boolean;
};

const TAG_TONE: Record<string, 'default' | 'info' | 'success' | 'warn' | 'danger' | 'muted'> = {
  INIT: 'muted',
  DNS: 'info',
  TLS: 'info',
  PROBE: 'info',
  RECV: 'success',
  MARKER: 'warn',
  EVASION: 'warn',
  CONFUSION: 'warn',
  BYPASS: 'danger',
  ANALYSIS: 'default',
  VERDICT: 'success',
  WAIT: 'info',
  START: 'info',
  SCAN: 'muted',
  INFO: 'muted',
  WARN: 'warn',
  ERROR: 'danger',
};

export function LiveProbeTerminal({
  entries,
  active = false,
  title = 'Live Probe Logs',
  subtitle,
  activeCheckLabel,
  requestsSent,
  maxRequests,
  elapsedSeconds,
  compact = false,
  emptyMessage = 'No execution logs recorded yet.',
  className = '',
  defaultExpanded = true,
}: LiveProbeTerminalProps) {
  const [autoScroll, setAutoScroll] = useState(true);
  const [filterText, setFilterText] = useState('');
  const [filterLevel, setFilterLevel] = useState<string>('all');
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(defaultExpanded);
  const [userScrolledUp, setUserScrolledUp] = useState(false);
  const viewportRef = useRef<HTMLDivElement | null>(null);

  // Filter logs based on search text and tag filter
  const filteredEntries = useMemo(() => {
    let list = entries;
    if (filterLevel !== 'all') {
      if (filterLevel === 'probes') {
        list = list.filter((e) => ['probe', 'recv', 'dns', 'tls'].includes(e.level));
      } else if (filterLevel === 'markers') {
        list = list.filter((e) => ['marker', 'evasion', 'confusion', 'bypass'].includes(e.level));
      } else if (filterLevel === 'analysis') {
        list = list.filter((e) => ['analysis', 'verdict'].includes(e.level));
      }
    }
    if (filterText.trim()) {
      const q = filterText.toLowerCase();
      list = list.filter(
        (e) =>
          e.message.toLowerCase().includes(q) ||
          e.tag.toLowerCase().includes(q) ||
          (e.checkName && e.checkName.toLowerCase().includes(q)) ||
          (e.checkId && e.checkId.toLowerCase().includes(q))
      );
    }
    return list;
  }, [entries, filterText, filterLevel]);

  // Handle scroll events to detect if user manually scrolled up
  const handleScroll = () => {
    const el = viewportRef.current;
    if (!el) return;
    const isAtBottom = el.scrollHeight - el.scrollTop - el.clientHeight <= 25;
    if (!isAtBottom) {
      setUserScrolledUp(true);
      setAutoScroll(false);
    } else {
      setUserScrolledUp(false);
      setAutoScroll(true);
    }
  };

  const scrollToBottom = () => {
    const el = viewportRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
    setUserScrolledUp(false);
    setAutoScroll(true);
  };

  // Auto-scroll effect
  useEffect(() => {
    if (!autoScroll || userScrolledUp) return;
    const el = viewportRef.current;
    if (el) {
      el.scrollTop = el.scrollHeight;
    }
  }, [filteredEntries.length, autoScroll, userScrolledUp]);

  // Copy logs handler
  const handleCopy = async () => {
    const lines = filteredEntries.map((e) => `[${e.timeDisplay}] [${e.tag}] ${e.message}`);
    const text = lines.join('\n');
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
      setCopied(false);
    }
  };

  return (
    <div
      className={`td-terminal ${compact ? 'td-terminal--compact' : ''} ${className}`}
      data-active={active ? 'true' : undefined}
      role="region"
      aria-label="Live probe logs console"
    >
      {/* Terminal Toolbar */}
      <div className="td-terminal-toolbar">
        <div className="td-terminal-cluster">
          <span className="td-terminal-icon" aria-hidden="true">
            <Terminal size={14} />
          </span>
          <span className="td-terminal-status">
            {active ? (
              <span className="td-pulse-badge">
                <span className="td-pulse-beacon" aria-hidden="true" />
                <strong>LIVE</strong>
              </span>
            ) : (
              <span className="td-idle-badge">LOGS</span>
            )}
          </span>
          <span className="td-terminal-title">{title}</span>
          {activeCheckLabel ? (
            <code className="td-terminal-active-check" title={`Check: ${activeCheckLabel}`}>
              {activeCheckLabel}
            </code>
          ) : null}
          {requestsSent !== null && requestsSent !== undefined ? (
            <span className="td-terminal-stat" title="Probes dispatched">
              <strong className="tabular-nums">{requestsSent}</strong>
              {maxRequests ? ` / ${maxRequests}` : ''} probes
            </span>
          ) : null}
          {elapsedSeconds !== null && elapsedSeconds !== undefined && elapsedSeconds > 0 ? (
            <span className="td-terminal-stat" title="Elapsed test duration">
              +{elapsedSeconds}s
            </span>
          ) : null}
        </div>

        <div className="td-terminal-actions">
          {/* Filter Pills */}
          <div className="td-terminal-filters" role="group" aria-label="Filter log categories">
            <button
              type="button"
              className={`td-term-filter ${filterLevel === 'all' ? 'active' : ''}`}
              onClick={() => setFilterLevel('all')}
              title="Show all log events"
            >
              Logs ({entries.length})
            </button>
            <button
              type="button"
              className={`td-term-filter ${filterLevel === 'probes' ? 'active' : ''}`}
              onClick={() => setFilterLevel('probes')}
              title="Show transport and HTTP probe events"
            >
              Probes
            </button>
            <button
              type="button"
              className={`td-term-filter ${filterLevel === 'markers' ? 'active' : ''}`}
              onClick={() => setFilterLevel('markers')}
              title="Show benign marker and evasion probes"
            >
              Markers
            </button>
            <button
              type="button"
              className={`td-term-filter ${filterLevel === 'analysis' ? 'active' : ''}`}
              onClick={() => setFilterLevel('analysis')}
              title="Show edge signature and verdict analysis"
            >
              Analysis
            </button>
          </div>

          {/* Quick Search */}
          <div className="td-terminal-search">
            <Search size={12} className="td-search-icon" aria-hidden="true" />
            <input
              type="search"
              placeholder="Search logs..."
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              aria-label="Search probe logs"
            />
          </div>

          {/* Auto-scroll button */}
          <Button
            size="sm"
            variant="ghost"
            className={`td-term-btn ${autoScroll ? 'td-term-btn--active' : ''}`}
            onClick={() => (autoScroll ? setAutoScroll(false) : scrollToBottom())}
            title={autoScroll ? 'Auto-scroll enabled (click to pause)' : 'Click to resume auto-scroll to latest log'}
            aria-pressed={autoScroll}
          >
            <ArrowDown size={13} aria-hidden="true" />
            <span className="td-btn-label">Follow</span>
          </Button>

          {/* Copy logs */}
          <Button
            size="sm"
            variant="ghost"
            className="td-term-btn"
            onClick={handleCopy}
            title="Copy logs to clipboard"
          >
            {copied ? <Check size={13} className="td-green" /> : <Copy size={13} aria-hidden="true" />}
            <span className="td-btn-label">{copied ? 'Copied' : 'Copy'}</span>
          </Button>

          {/* Expand / Collapse toggle */}
          <Button
            size="sm"
            variant="ghost"
            className="td-term-btn"
            onClick={() => setExpanded(!expanded)}
            title={expanded ? 'Minimize terminal' : 'Expand terminal'}
            aria-expanded={expanded}
          >
            {expanded ? <ChevronUp size={14} aria-hidden="true" /> : <ChevronDown size={14} aria-hidden="true" />}
          </Button>
        </div>
      </div>

      {subtitle ? <div className="td-terminal-subtitle">{subtitle}</div> : null}

      {/* Terminal Viewport */}
      {expanded ? (
        <div
          ref={viewportRef}
          className="td-terminal-viewport"
          onScroll={handleScroll}
          tabIndex={0}
          role="log"
          aria-live="polite"
        >
          {filteredEntries.length === 0 ? (
            <div className="td-terminal-empty">{emptyMessage}</div>
          ) : (
            <ol className="td-terminal-lines">
              {filteredEntries.map((entry, index) => {
                const tone = TAG_TONE[entry.tag] ?? 'default';
                return (
                  <li key={entry.id || index} className="td-terminal-line" data-level={entry.level}>
                    <time className="td-term-time" dateTime={entry.timestamp}>
                      {entry.timeDisplay}
                    </time>
                    <span className="td-term-tag" data-tone={tone}>
                      [{entry.tag}]
                    </span>
                    <span className="td-term-msg">
                      {entry.message}
                      {entry.detail ? <span className="td-term-detail"> · {entry.detail}</span> : null}
                    </span>
                  </li>
                );
              })}
              {active ? (
                <li className="td-terminal-line td-terminal-line--active" aria-hidden="true">
                  <span className="td-term-time">&nbsp;</span>
                  <span className="td-term-tag" data-tone="info">[RUN]</span>
                  <span className="td-term-msg">
                    <span className="td-term-cursor">▌</span>
                  </span>
                </li>
              ) : null}
            </ol>
          )}

          {/* Floating Jump to Bottom Button if user scrolled up */}
          {userScrolledUp ? (
            <button
              type="button"
              className="td-jump-bottom-btn"
              onClick={scrollToBottom}
              title="Jump to latest probe logs"
            >
              <ArrowDown size={12} aria-hidden="true" /> Latest logs
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
