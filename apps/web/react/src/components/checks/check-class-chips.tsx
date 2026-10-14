import { FileText, Layers, ShieldCheck } from 'lucide-react';
import { CHECK_PROTECTION_CONTROLS, classifyCheck } from '../../lib/check-classification.mjs';
import { Badge } from '../ui/badge';
import './check-class-chips.css';

type CheckLike = Record<string, unknown> | null | undefined;

export function CheckClassChips({ check, className }: { check: CheckLike; className?: string }) {
  const { layer, controls, declaration_only: declarationOnly } = classifyCheck(check);
  if (!layer && controls.length === 0 && !declarationOnly) return null;
  return (
    <span className={`check-class-chips${className ? ` ${className}` : ''}`} data-check-class="">
      {layer ? (
        <Badge tone="muted" className="check-class-chip check-class-chip--layer" data-layer={layer.osi}>
          <Layers aria-hidden="true" focusable="false" size={12} strokeWidth={2.25} />
          <span className="sr-only">Network layer </span>
          {layer.label}
        </Badge>
      ) : null}
      {controls.map((control) => (
        <Badge key={control.id} tone="default" className="check-class-chip check-class-chip--control" data-control={control.id}>
          <ShieldCheck aria-hidden="true" focusable="false" size={12} strokeWidth={2.25} />
          <span className="sr-only">Tests the {control.label} </span>
          <span aria-hidden="true">{control.short}</span>
        </Badge>
      ))}
      {declarationOnly ? (
        <Badge tone="muted" className="check-class-chip check-class-chip--declaration" data-declaration-only="">
          <FileText aria-hidden="true" focusable="false" size={12} strokeWidth={2.25} />
          Declaration only
          <span className="sr-only">: records your statement and sends no traffic</span>
        </Badge>
      ) : null}
    </span>
  );
}

export function CheckClassLegend({ className }: { className?: string }) {
  return (
    <p className={`check-class-legend muted small${className ? ` ${className}` : ''}`}>
      <span className="check-class-legend-term">
        <Layers aria-hidden="true" focusable="false" size={12} strokeWidth={2.25} />
        Layer the check exercises
      </span>
      <span className="check-class-legend-term">
        <ShieldCheck aria-hidden="true" focusable="false" size={12} strokeWidth={2.25} />
        Control it tests:
      </span>
      {Object.values(CHECK_PROTECTION_CONTROLS).map((control) => (
        <span key={control.id} className="check-class-legend-term">
          <b>{control.short}</b> {control.label}
        </span>
      ))}
      <span className="check-class-legend-term">
        <FileText aria-hidden="true" focusable="false" size={12} strokeWidth={2.25} />
        Declaration only: your statement, no traffic sent
      </span>
    </p>
  );
}

export function CheckClassSummary({ check }: { check: CheckLike }) {
  const { layer, controls, declaration_only: declarationOnly } = classifyCheck(check);
  if (!layer && controls.length === 0 && !declarationOnly) return <p className="muted">Process or multi-layer check; no single network layer or control.</p>;
  const controlCopy = controls.map((control) => `${control.label} (${control.short})`).join(' and ');
  return (
    <div className="stack-tight">
      <CheckClassChips check={check} />
      <p className="check-detail-text">
        {layer ? `Exercises ${layer.label}.` : 'Spans several network layers.'}
        {controlCopy ? ` ${declarationOnly ? 'Relates to' : 'Tests'} the ${controlCopy}.` : ''}
        {declarationOnly ? ' Declaration only: it records what you state and sends no traffic, so it never proves the control works.' : ''}
      </p>
    </div>
  );
}
