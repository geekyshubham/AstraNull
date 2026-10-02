import { Mail, Webhook } from 'lucide-react';
import { useId } from 'react';
import { cn } from '../../lib/utils';

/**
 * Brand marks for notification channels.
 *
 * - Slack: the official four-colour Slack mark (same path data as the verified mark used in the
 *   DNS Migrator channel logo). Colours come from the `--brand-slack-*` tokens declared in
 *   notification-channels-styles.ts, which are exact OKLCH conversions of Slack's published brand
 *   colours. Used only to identify the Slack integration, per Slack's brand guidelines.
 * - Microsoft Teams: the official Teams product icon, path data taken verbatim from Microsoft's
 *   Fluent UI brand-icons CDN (assets/brand-icons/product/svg/teams_48x1.svg). Used under the
 *   Microsoft Fabric Assets License, section 1(b): "To illustrate that Application integrates with
 *   one or more Microsoft products and services". Microsoft and Microsoft Teams are trademarks of
 *   the Microsoft group of companies. Colours come from `--brand-teams-*` tokens (exact OKLCH
 *   conversions of the source fills).
 * - Email and Webhook: generic lucide-react glyphs tinted with design tokens; there is no third
 *   party brand to represent.
 *
 * All marks are decorative (`aria-hidden`); the visible channel name next to them is the label.
 * The wrapper uses the shared `integration-logo-well` (integration-tile-styles.ts), the same
 * neutral well as the DNS/edge provider logos, so both card families match.
 */

export type ChannelLogoId = 'slack' | 'teams' | 'email' | 'webhook';

function SlackMark() {
  return (
    <svg viewBox="0 0 122.8 122.8" aria-hidden="true" focusable="false" className="channel-mark">
      <path
        className="slack-red"
        d="M25.8 77.6c0 7.1-5.8 12.9-12.9 12.9S0 84.7 0 77.6s5.8-12.9 12.9-12.9h12.9v12.9zm6.5 0c0-7.1 5.8-12.9 12.9-12.9s12.9 5.8 12.9 12.9v32.3c0 7.1-5.8 12.9-12.9 12.9s-12.9-5.8-12.9-12.9V77.6z"
      />
      <path
        className="slack-blue"
        d="M45.2 25.8c-7.1 0-12.9-5.8-12.9-12.9S38.1 0 45.2 0s12.9 5.8 12.9 12.9v12.9H45.2zm0 6.5c7.1 0 12.9 5.8 12.9 12.9s-5.8 12.9-12.9 12.9H12.9C5.8 58.1 0 52.3 0 45.2s5.8-12.9 12.9-12.9h32.3z"
      />
      <path
        className="slack-green"
        d="M97 45.2c0-7.1 5.8-12.9 12.9-12.9s12.9 5.8 12.9 12.9-5.8 12.9-12.9 12.9H97V45.2zm-6.5 0c0 7.1-5.8 12.9-12.9 12.9s-12.9-5.8-12.9-12.9V12.9C64.7 5.8 70.5 0 77.6 0s12.9 5.8 12.9 12.9v32.3z"
      />
      <path
        className="slack-yellow"
        d="M77.6 97c7.1 0 12.9 5.8 12.9 12.9s-5.8 12.9-12.9 12.9-12.9-5.8-12.9-12.9V97h12.9zm0-6.5c-7.1 0-12.9-5.8-12.9-12.9s5.8-12.9 12.9-12.9h32.3c7.1 0 12.9 5.8 12.9 12.9s-5.8 12.9-12.9 12.9H77.6z"
      />
    </svg>
  );
}

function TeamsMark() {
  // useId output can contain characters that are awkward inside url(#…); keep it alphanumeric.
  const gradientId = `teams-tile-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`;
  return (
    <svg viewBox="0 0 48 48" aria-hidden="true" focusable="false" className="channel-mark">
      <defs>
        <linearGradient id={gradientId} x1="5.822" y1="11.568" x2="20.178" y2="36.432" gradientUnits="userSpaceOnUse">
          <stop offset="0" className="teams-stop-1" />
          <stop offset=".5" className="teams-stop-2" />
          <stop offset="1" className="teams-stop-3" />
        </linearGradient>
      </defs>
      <path className="teams-deep" d="M31.993 19H43.1a1.9 1.9 0 0 1 1.9 1.9v10.117A6.983 6.983 0 0 1 38.017 38h-.033A6.983 6.983 0 0 1 31 31.017V19.993a.993.993 0 0 1 .993-.993z" />
      <circle className="teams-deep" cx="39.5" cy="12.5" r="4.5" />
      <circle className="teams-light" cx="25.5" cy="10.5" r="6.5" />
      <path className="teams-light" d="M34.167 19H15.833A1.88 1.88 0 0 0 14 20.923v11.539A11.279 11.279 0 0 0 25 44a11.279 11.279 0 0 0 11-11.538V20.923A1.88 1.88 0 0 0 34.167 19z" />
      <path className="teams-shade" opacity=".1" d="M26 19v16.17a1.841 1.841 0 0 1-1.14 1.69 1.772 1.772 0 0 1-.69.14h-9.29c-.13-.33-.25-.66-.35-1a12.179 12.179 0 0 1-.53-3.54V20.92A1.877 1.877 0 0 1 15.83 19z" />
      <path className="teams-shade" opacity=".2" d="M25 19v17.17a1.772 1.772 0 0 1-.14.69A1.841 1.841 0 0 1 23.17 38h-7.82c-.17-.33-.33-.66-.47-1s-.25-.66-.35-1a12.179 12.179 0 0 1-.53-3.54V20.92A1.877 1.877 0 0 1 15.83 19z" />
      <path className="teams-shade" opacity=".2" d="M25 19v15.17A1.844 1.844 0 0 1 23.17 36h-8.64a12.179 12.179 0 0 1-.53-3.54V20.92A1.877 1.877 0 0 1 15.83 19z" />
      <path className="teams-shade" opacity=".2" d="M24 19v15.17A1.844 1.844 0 0 1 22.17 36h-7.64a12.179 12.179 0 0 1-.53-3.54V20.92A1.877 1.877 0 0 1 15.83 19z" />
      <path className="teams-shade" opacity=".1" d="M26 13.83v3.15c-.17.01-.33.02-.5.02s-.33-.01-.5-.02a5.489 5.489 0 0 1-1-.16A6.5 6.5 0 0 1 19.5 13a5.556 5.556 0 0 1-.32-1h4.99A1.837 1.837 0 0 1 26 13.83z" />
      <path className="teams-shade" opacity=".2" d="M25 14.83v2.15a5.489 5.489 0 0 1-1-.16A6.5 6.5 0 0 1 19.5 13h3.67A1.837 1.837 0 0 1 25 14.83z" />
      <path className="teams-shade" opacity=".2" d="M25 14.83v2.15a5.489 5.489 0 0 1-1-.16A6.5 6.5 0 0 1 19.5 13h3.67A1.837 1.837 0 0 1 25 14.83z" />
      <path className="teams-shade" opacity=".2" d="M24 14.83v1.99A6.5 6.5 0 0 1 19.5 13h2.67A1.837 1.837 0 0 1 24 14.83z" />
      <rect x="2" y="13" width="22" height="22" rx="1.833" fill={`url(#${gradientId})`} />
      <path className="teams-glyph" d="M17.824 19.978h-3.665v9.98h-2.335v-9.98H8.176v-1.936h9.648z" />
    </svg>
  );
}

export function ChannelLogo({ channel, size = 'md', className }: { channel: ChannelLogoId | string; size?: 'sm' | 'md'; className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn('integration-logo-well', 'channel-logo', size === 'sm' && 'integration-logo-well-sm', className)}
      data-channel={channel}
    >
      {channel === 'slack' ? <SlackMark /> : null}
      {channel === 'teams' ? <TeamsMark /> : null}
      {channel === 'email' ? <Mail className="channel-glyph" strokeWidth={1.75} aria-hidden="true" focusable="false" /> : null}
      {channel !== 'slack' && channel !== 'teams' && channel !== 'email' ? (
        <Webhook className="channel-glyph" strokeWidth={1.75} aria-hidden="true" focusable="false" />
      ) : null}
    </span>
  );
}
