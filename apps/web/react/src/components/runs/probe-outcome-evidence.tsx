import { useEffect, useId, useMemo, useState } from 'react';
import { CircleHelp, ShieldQuestion, TriangleAlert } from 'lucide-react';
import { requestJson } from '../../lib/api';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { networkOutcomeSentence, PERSPECTIVE_UNAUTHENTICATED, probeEvidenceModel, probeResultEvents, TERM_HELP, type ProbeEvidenceModel } from '../../lib/probe-evidence.mjs';
import { Badge } from '../ui/badge';
import './probe-outcome-evidence.css';

function Term({ label, help }: { label: string; help: string }) {
  const tipId = useId();
  return (
    <span className="poe-term">
      {label}
      <button
        type="button"
        className="poe-help"
        aria-label={`What ${label.toLowerCase()} means`}
        aria-describedby={tipId}
        onKeyDown={(event) => { if (event.key === 'Escape') (event.currentTarget as HTMLButtonElement).blur(); }}
      >
        <CircleHelp size={13} aria-hidden="true" />
      </button>
      <span className="poe-tip" role="tooltip" id={tipId}>{help}</span>
    </span>
  );
}

function OutcomeChips({ model }: { model: ProbeEvidenceModel }) {
  if (!model.chips.length) return null;
  return (
    <div className="poe-chips" aria-label="Recorded outcomes">
      {model.chips.map((chip) => <Badge key={chip.id} tone={chip.tone} title={chip.help}>{chip.label}</Badge>)}
    </div>
  );
}

function PlacementTable({ model }: { model: ProbeEvidenceModel }) {
  if (!model.placements.length) return null;
  return (
    <>
      <div className="poe-table-wrap" role="region" aria-label="Result per marker placement" tabIndex={0}>
        <table className="data-table poe-table">
          <caption className="sr-only">Each marker placement was graded on its own: outcome, HTTP status, matched block signature and CDN cache status.</caption>
          <thead>
            <tr>
              <th scope="col">Placement</th>
              <th scope="col">Outcome</th>
              <th scope="col">Status</th>
              <th scope="col">Signature</th>
              <th scope="col">Cache</th>
            </tr>
          </thead>
          <tbody>
            {model.placements.map((row, index) => (
              <tr key={`${row.placement}-${index}`}>
                <th scope="row">{row.placementLabel}</th>
                <td><Badge tone={row.tone} title={row.help}>{row.outcomeLabel}</Badge>{row.locationChanged ? <small className="poe-sub">Redirect target differs from baseline</small> : null}{row.reasonLabel ? <small className="poe-sub">{row.reasonLabel}</small> : null}</td>
                <td className="tabular-nums">{row.statusCode ?? <span className="poe-muted">Not recorded</span>}</td>
                <td>{row.signature ? <code>{row.signature}</code> : <span className="poe-muted">None matched</span>}</td>
                <td>{row.cacheStatus ? <code>{row.cacheStatus}</code> : <span className="poe-muted">Not recorded</span>}</td>
              </tr>
            ))}
            {model.trailing ? (
              <tr className="poe-control-row">
                <th scope="row">Follow-up control</th>
                <td><Badge tone={model.trailing.outcome === 'allowed' ? 'muted' : 'warn'}>{model.trailing.outcomeLabel}</Badge></td>
                <td className="tabular-nums">{model.trailing.statusCode ?? <span className="poe-muted">Not recorded</span>}</td>
                <td colSpan={2}><span className="poe-muted">{model.trailing.outcome === 'allowed' ? 'Answered normally, so the marker results above stand.' : 'Also refused, so the marker results are not trusted.'}</span></td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
        <p className="poe-footnote"><b>Signature:</b> {TERM_HELP.signature} <b>Cache:</b> {TERM_HELP.cache}{model.trailing ? <> <b>Follow-up control:</b> a harmless request sent after the markers; if it is refused too, the edge was blocking the probe address, not the marker.</> : null}</p>
    </>
  );
}

function PortResultsTable({ model }: { model: ProbeEvidenceModel }) {
  const network = model.network;
  if (!network || (!network.portResults.length && !network.unprobedDenyPorts.length)) return null;
  const showResult = network.portResults.some((row) => row.resultLabel);
  return (
    <div className="poe-ports">
      {network.portResults.length ? (
        <div className="poe-table-wrap" role="region" aria-label="Result per declared deny port" tabIndex={0}>
          <table className="data-table poe-table poe-port-table">
            <caption className="sr-only">Each declared deny port probed in this run: protocol and port{showResult ? ', whether it breaks your rule' : ''}, what came back and IPv4 and IPv6 parity.</caption>
            <thead>
              <tr>
                <th scope="col">Port</th>
                {showResult ? <th scope="col">Against your rule</th> : null}
                <th scope="col">What came back</th>
                <th scope="col">IPv4 and IPv6</th>
              </tr>
            </thead>
            <tbody>
              {network.portResults.map((row) => (
                <tr key={`${row.protocol}-${row.port}`}>
                  <th scope="row" className="mono">{row.protocol} {row.port}</th>
                  {showResult ? <td>{row.resultLabel ? <Badge tone={row.resultTone} title={row.resultHelp}>{row.resultLabel}</Badge> : <span className="poe-muted">Not graded</span>}</td> : null}
                  <td>{row.outcomeLabel}{row.icmp ? <small className="poe-sub">{row.icmp}</small> : null}</td>
                  <td>{row.parity ? <Badge tone={row.parity.tone} title={row.parity.help}>{row.parity.label}</Badge> : <span className="poe-muted">Not compared</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {network.portResults.length ? (
        <p className="poe-footnote">
          {[...new Map(network.portResults.filter((row) => row.help).map((row) => [row.outcomeLabel, row.help])).entries()].map(([label, help]) => <span key={label}><b>{label}:</b> {help} </span>)}
          {showResult ? <><b>Against your rule:</b> only a port you declared denied that still answers is a violation; no violation seen is not proof of protection.</> : null}
        </p>
      ) : null}
      {network.unprobedDenyPorts.length ? (
        <p className="poe-note" role="note">
          <ShieldQuestion size={15} aria-hidden="true" />
          <span>
            <b>Not probed within the safe request budget:</b> <span className="mono">{network.unprobedDenyPorts.join(', ')}</span>.{' '}
            {TERM_HELP.request_budget} No result is shown for these ports, and none is implied.
          </span>
        </p>
      ) : null}
    </div>
  );
}

function PerspectiveLine({ model }: { model: ProbeEvidenceModel }) {
  const perspective = model.perspective;
  if (!perspective) return null;
  return (
    <div className="poe-perspective-block">
      <p className="poe-muted poe-perspective">
        <Term label="Probe perspective" help={TERM_HELP.perspective} />
        <span>{perspective.label}{perspective.id && perspective.id !== perspective.label ? <> <span className="mono">({perspective.id})</span></> : null}</span>
        {perspective.authenticated === true ? <Badge tone="muted">Authenticated with its own key</Badge> : null}
      </p>
      {perspective.authenticated === false ? (
        <p className="poe-note" role="note">
          <ShieldQuestion size={15} aria-hidden="true" />
          <span><b>{PERSPECTIVE_UNAUTHENTICATED}.</b> {TERM_HELP.perspective_authentication}</span>
        </p>
      ) : null}
    </div>
  );
}

function NetworkBlock({ model }: { model: ProbeEvidenceModel }) {
  const network = model.network;
  if (!network) return null;
  return (
    <div className="poe-network">
      {network.reflectorReachable ? <p className="poe-callout" role="note"><TriangleAlert size={15} aria-hidden="true" /><span><b>Open reflector reachable.</b> A protocol-checked reply came back, so this service can be abused to reflect traffic. This is an exposure of the service itself, not a violation of a firewall rule you declared.</span></p> : null}
      <dl className="poe-facts">
        <div><dt>Protocol and port</dt><dd className="mono">{[network.protocol, network.port ?? ''].filter(Boolean).join(' ') || 'Not recorded'}</dd></div>
        <div><dt>Address family</dt><dd>{network.family || 'Not recorded'}</dd></div>
        <div><dt>{network.protocol === 'UDP' ? 'UDP outcome' : 'TCP outcome'}</dt><dd><Badge tone={network.tone} title={network.help}>{network.outcomeLabel}</Badge><small className="poe-sub">{network.help}</small></dd></div>
        {network.icmp ? <div><dt>ICMP message</dt><dd>{network.icmp}</dd></div> : null}
        {network.serviceValidated !== null ? <div><dt>Service check</dt><dd>{network.serviceValidated ? 'Reply matched the expected protocol' : 'No protocol-matched reply'}</dd></div> : null}
        {network.peerIsCdn !== null ? <div><dt>Answered by</dt><dd>{network.peerIsCdn ? 'A CDN edge address (not your origin)' : 'A non-CDN address'}</dd></div> : null}
        {network.sampleAgreement ? <div><dt>Samples</dt><dd>{network.sampleAgreement === 'agree' ? `${network.sampleCount || 'All'} samples agreed` : network.sampleAgreement === 'disagree' ? 'Samples disagreed, so the result is inconclusive' : 'One sample'}</dd></div> : null}
      </dl>
      <PortResultsTable model={model} />
      {network.families.length && !network.portResults.length ? (
        <div className="poe-parity">
          <p className="poe-label">IPv4 and IPv6 {network.parity ? <Badge tone={network.parity.tone} title={network.parity.help}>{network.parity.label}</Badge> : null}</p>
          <ul>
            {network.families.map((entry) => (
              <li key={entry.key}><b>{entry.label}</b>{entry.result?.address ? <code>{entry.result.address}</code> : null}<span>{entry.result?.label}</span></li>
            ))}
          </ul>
          {network.parity?.help ? <p className="poe-muted">{network.parity.help}</p> : null}
        </div>
      ) : null}
    </div>
  );
}

/** Plain-language rendering of one probe result's WAF/NFW evidence; renders nothing for other probes. */
export function ProbeOutcomeEvidence({ metadata, compact = false, verdictPortResults }: { metadata: unknown; compact?: boolean; verdictPortResults?: unknown }) {
  const model = useMemo(() => probeEvidenceModel(metadata, { verdictPortResults }), [metadata, verdictPortResults]);
  if (!model) return null;
  return (
    <div className="poe" data-compact={compact || undefined}>
      <OutcomeChips model={model} />
      {model.scope ? <p className="poe-scope"><Term label={model.scope.label} help={model.scope.help} />{model.enforcement ? <span> · {model.enforcement.text}</span> : null}</p> : model.enforcement ? <p className="poe-scope">{model.enforcement.text}</p> : null}
      {model.inconclusiveReason ? (
        <p className="poe-callout" role="note"><TriangleAlert size={15} aria-hidden="true" /><span><b>{model.inconclusiveReason}.</b> The response looked like a block, but it is treated as inconclusive until the match is certain.</span></p>
      ) : null}
      {model.sourcePenalized ? (
        <p className="poe-callout" role="note"><TriangleAlert size={15} aria-hidden="true" /><span><b>Source penalized.</b> A harmless follow-up from the same probe was refused too, so the edge was blocking the probe address rather than the marker. This result is inconclusive; it is not a block.</span></p>
      ) : null}
      {model.evasion?.normalizationGap ? (
        <p className="poe-callout" data-tone="danger" role="note"><TriangleAlert size={15} aria-hidden="true" /><span><b>Normalization gap{model.evasion.transform ? ` (${model.evasion.transform})` : ''}.</b> {TERM_HELP.normalization_gap}</span></p>
      ) : null}
      {model.evasion ? (
        <dl className="poe-facts">
          <div><dt>Plain marker</dt><dd><Badge tone={model.evasion.referenceTone}>{model.evasion.referenceLabel}</Badge></dd></div>
          <div><dt>Encoded marker{model.evasion.transform ? ` · ${model.evasion.transform}` : ''}</dt><dd><Badge tone={model.evasion.transformedTone}>{model.evasion.transformedLabel}</Badge></dd></div>
          {model.evasion.referenceNotEnforced ? <div><dt>Meaning</dt><dd>The plain marker was not blocked either, so this check cannot judge the encoding trick. Fix the base rule first.</dd></div> : null}
        </dl>
      ) : null}
      {model.paths.length > 1 ? <p className="poe-muted">Paths tested: <span className="mono">{model.paths.join(', ')}</span></p> : null}
      <PlacementTable model={model} />
      {model.methodResults.length ? (
        <ul className="poe-methods" aria-label="Result per HTTP method">
          {model.methodResults.map((row) => <li key={row.method}><code>{row.method}</code><Badge tone={row.tone}>{row.outcomeLabel}</Badge>{row.statusCode !== null ? <span className="tabular-nums poe-muted">HTTP {row.statusCode}</span> : null}</li>)}
        </ul>
      ) : null}
      <NetworkBlock model={model} />
      {model.connectionLimit ? (
        <dl className="poe-facts">
          <div><dt>Connection limit</dt><dd>{model.connectionLimit.declaredLimit !== null ? `${model.connectionLimit.declaredLimit} per source declared` : 'No limit declared'}{model.connectionLimit.port !== null ? ` on TCP ${model.connectionLimit.port}` : ''}</dd></div>
          <div><dt>Attempted</dt><dd className="tabular-nums">{model.connectionLimit.attempted} connections (cap 12)</dd></div>
          <div><dt>Accepted</dt><dd className="tabular-nums">{model.connectionLimit.accepted ?? 'Not recorded'}</dd></div>
          <div><dt>Refused from</dt><dd>{model.connectionLimit.refusedAfter !== null ? `Connection ${model.connectionLimit.refusedAfter + 1}` : 'None refused'}</dd></div>
        </dl>
      ) : null}
      {model.rateLimit ? (
        <dl className="poe-facts">
          <div><dt>Declared limit</dt><dd>{model.rateLimit.threshold ?? '?'} requests per {model.rateLimit.windowSeconds ?? '?'} s</dd></div>
          <div><dt>Requests sent</dt><dd className="tabular-nums">{model.rateLimit.requestsSent ?? 'Not recorded'}</dd></div>
          <div><dt>First limited</dt><dd>{model.rateLimit.firstLimitedAt !== null ? `Request ${model.rateLimit.firstLimitedAt} · ${model.rateLimit.limitedLabel}` : 'Never limited within the window'}</dd></div>
        </dl>
      ) : null}
      <PerspectiveLine model={model} />
      {model.metaRows.length ? (
        <dl className="poe-meta" aria-label="Grading metadata">
          {model.metaRows.map((row) => <div key={row.label}><dt>{row.label}</dt><dd className="mono">{row.value}</dd></div>)}
        </dl>
      ) : null}
    </div>
  );
}

type EventsLoad = { key: string; status: 'loading' | 'ready' | 'error'; events: DataItem[] };

/** Loads one run's signed probe results and renders their WAF/NFW evidence. */
export function RunProbeEvidence({ config, session, runId, revision = 0 }: { config: PortalConfig; session: Session; runId: string; revision?: number }) {
  const key = `${runId}|${revision}`;
  const [load, setLoad] = useState<EventsLoad>({ key: '', status: 'loading', events: [] });
  useEffect(() => {
    if (!runId) return undefined;
    let cancelled = false;
    requestJson(config, session, `/v1/test-runs/${encodeURIComponent(runId)}/events`)
      .then((payload) => {
        if (cancelled) return;
        const items = Array.isArray((payload as DataItem)?.items) ? ((payload as DataItem).items as DataItem[]) : [];
        setLoad({ key, status: 'ready', events: items.filter((item) => !item.test_run_id || item.test_run_id === runId) });
      })
      .catch(() => { if (!cancelled) setLoad({ key, status: 'error', events: [] }); });
    return () => { cancelled = true; };
  }, [config, session, runId, key]);
  if (!runId || load.key !== key) return null;
  if (load.status === 'error') return <p className="ei-note" role="note">Probe result details could not load. The verdict above is unchanged.</p>;
  const results = probeResultEvents(load.events).filter((event) => probeEvidenceModel(event.metadata));
  if (!results.length) return null;
  return (
    <section className="poe-run" aria-label="What the probe observed">
      <strong>What the probe observed</strong>
      {results.map((event, index) => {
        const network = probeEvidenceModel(event.metadata)?.network ?? null;
        return (
          <div key={String(event.id ?? index)} className="poe-run-item">
            {results.length > 1 ? <p className="poe-label">Result {index + 1}{network ? ` · ${networkOutcomeSentence(network)}` : ''}</p> : null}
            <ProbeOutcomeEvidence metadata={event.metadata} compact />
          </div>
        );
      })}
    </section>
  );
}
