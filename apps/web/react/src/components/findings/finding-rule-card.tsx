import type { FindingRuleGroup } from '../../lib/findings-helpers';
import { findingRuleDetailHash, previewRuleAssets } from '../../lib/findings-helpers';
import type { DataItem } from '../../lib/types';
import { formatSeverityLabel } from '../../lib/utils';
// @ts-ignore Plain ESM keeps executive labels directly testable with node:test.
import { plainCheckName } from '../../lib/plain-language.mjs';
import './findings-groups.css';

function checkLabel(checkId: string, checks: DataItem[]) {
  if (!checkId) return '';
  const check = checks.find((entry) => String(entry.check_id ?? entry.id ?? '') === checkId);
  const name = check ? String(check.name ?? check.title ?? '') : '';
  return plainCheckName(name || checkId);
}

/**
 * Primary cell of a grouped finding-queue row: one rule, the assets it was observed on.
 * The anchor is the row's single keyboard stop; the hash opens the finding directly for a
 * single-asset rule, or the representative finding focused on its affected-asset list.
 */
export function FindingRuleCard({
  group,
  checks,
  onOpen
}: {
  group: FindingRuleGroup;
  checks: DataItem[];
  onOpen?: (hash: string) => void;
}) {
  const hash = findingRuleDetailHash(group);
  const assetCount = group.assets.length;
  const { shown, remaining } = previewRuleAssets(group.assets, 2);
  const checkIds = group.checkIds.length ? group.checkIds : (group.checkId ? [group.checkId] : []);
  const check = checkLabel(checkIds[0] ?? '', checks);
  const moreChecks = Math.max(0, checkIds.length - 1);
  const findingCount = group.members.length;
  const href = hash ? `${window.location.pathname}${window.location.search}#${hash}` : '#findings';
  const assetNoun = assetCount === 1 ? 'affected asset' : 'affected assets';
  const openLabel = group.members.length > 1
    ? `Open ${group.title}, ${formatSeverityLabel(group.worstSeverity)}, ${assetCount} ${assetNoun}`
    : `Open finding ${group.title} on ${shown[0] ?? 'an unrecorded asset'}, ${formatSeverityLabel(group.worstSeverity)}`;

  return (
    <a
      className="finding-row-primary finding-rule-card"
      href={href}
      aria-label={openLabel}
      onClick={(event) => {
        // Let modified clicks (new tab, new window) fall through to the native href.
        if (!hash || !onOpen || event.defaultPrevented || event.button !== 0) return;
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        event.preventDefault();
        onOpen(hash);
      }}
    >
      <span className="fc-headline">
        <strong>{group.title}</strong>
      </span>
      <span className="frc-assets">
        <span className="frc-asset-count tabular-nums">{assetCount} {assetNoun}</span>
        <span className="frc-asset-names">
          {shown.map((label, index) => <span key={`${index}-${label}`} className="frc-asset mono">{label}</span>)}
          {remaining > 0 ? <span className="frc-asset-more">+{remaining} more</span> : null}
        </span>
      </span>
      {check || findingCount > assetCount ? (
        <span className="frc-check">
          {check ? <><span className="frc-key">{moreChecks ? 'Checks:' : 'Check:'}</span> {check}{moreChecks ? ` and ${moreChecks} more` : ''}</> : null}
          {findingCount > assetCount ? <span className="frc-findings tabular-nums">{check ? ', ' : ''}{findingCount} findings</span> : null}
        </span>
      ) : null}
    </a>
  );
}
