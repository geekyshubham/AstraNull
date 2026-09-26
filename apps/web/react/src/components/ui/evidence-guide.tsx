import { CircleHelp } from 'lucide-react';
// @ts-ignore Plain ESM keeps language mappings directly testable with node:test.
import { EVIDENCE_TIERS, plainVerdictDescription, plainVerdictLabel } from '../../lib/plain-language.mjs';

const VERDICT_EXAMPLES = ['protected', 'penetrated', 'inconclusive'] as const;

export function EvidenceGuide({ compact = false }: { compact?: boolean }) {
  return (
    <details className={`evidence-guide${compact ? ' evidence-guide--compact' : ''}`}>
      <summary>
        <CircleHelp size={16} aria-hidden="true" />
        Understand evidence and result labels
      </summary>
      <div className="evidence-guide-body">
        <section>
          <h3>Evidence strength</h3>
          <dl className="evidence-guide-list">
            {EVIDENCE_TIERS.map((tier) => (
              <div key={tier.code}>
                <dt>
                  <span>{tier.label}</span>
                  <code title={`Technical evidence tier ${tier.code}`}>{tier.code}</code>
                </dt>
                <dd>{tier.description}</dd>
              </div>
            ))}
          </dl>
        </section>
        <section>
          <h3>Result language</h3>
          <dl className="evidence-guide-list">
            {VERDICT_EXAMPLES.map((verdict) => (
              <div key={verdict}>
                <dt>
                  <span>{plainVerdictLabel(verdict)}</span>
                  <code title={`Technical verdict ${verdict}`}>{verdict}</code>
                </dt>
                <dd>{plainVerdictDescription(verdict)}</dd>
              </div>
            ))}
          </dl>
        </section>
        <p className="evidence-guide-note">
          A detected CDN or WAF is not automatically effective. AstraNull calls protection verified only when the returned evidence supports that conclusion.
        </p>
      </div>
    </details>
  );
}
