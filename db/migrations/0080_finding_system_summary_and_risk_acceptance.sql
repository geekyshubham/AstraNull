-- Machine verdict text moves out of the customer-editable notes field (ADR-0027).
ALTER TABLE findings ADD COLUMN IF NOT EXISTS system_summary TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_acceptance JSONB;
ALTER TABLE findings ADD CONSTRAINT findings_risk_acceptance_shape_check CHECK (
  risk_acceptance IS NULL OR (
    jsonb_typeof(risk_acceptance) = 'object'
    AND risk_acceptance ?& ARRAY['reason', 'review_at', 'accepted_by', 'accepted_at']
    AND jsonb_typeof(risk_acceptance->'reason') = 'string'
    AND char_length(risk_acceptance->>'reason') BETWEEN 20 AND 2000
  )
);

-- Verdict-linked findings take the verdict explanation; notes are never copied into it.
UPDATE findings AS f
SET system_summary = v.explanation
FROM verdicts v
WHERE f.system_summary IS NULL
  AND v.tenant_id = f.tenant_id
  AND v.id = COALESCE(f.last_verdict_id, f.verdict_id)
  AND v.explanation IS NOT NULL;

-- Findings without a verdict move notes only when they hold unedited server text.
UPDATE findings
SET system_summary = notes
WHERE system_summary IS NULL
  AND notes IS NOT NULL
  AND (
    (
      check_id LIKE 'waf.posture.%'
      AND (
        notes ~ '^WAF posture finding\. reason_codes: .* waf_validation_run_id: \S+ waf_asset_id: \S+ Retest with a safe WAF validation after remediation\.$'
        OR notes ~ '^Posture status: [a-z_]+\. Reason codes: [^.]*\. WAF asset id: \S+\. WAF validation run id: \S+\. Last WAF validation run id: \S+\. Retest: run a safe marker validation after WAF rule or edge changes\.$'
      )
    )
    OR (
      source = 'protection_validation'
      AND notes IN (
        'A nonce-bound application response was observed on this declared path while the primary route enforced the same scenario. The conclusion is limited to the tested path, source, scenario, and time; the responsible control is not identified.',
        'A response was observed on a path the customer declared must not be reachable. This is an observed reachability exposure for the tested path, source, and time; the responsible control is not identified.',
        'A response was observed on this declared path but enforcement of the scenario was not measured. Treat this as a suspected bypass until application identity and enforcement are established.',
        'The primary route enforced this scenario and this path returned a non-enforced response, but application identity was not confirmed by a nonce-bound canary. This is suspected, not a confirmed bypass.',
        'The scenario was only partially enforced on this path while the primary route enforced it. The conclusion is limited to the tested path, source, scenario, and time.',
        'Sampled public-ingress evidence observed reachability where the declared expectation is deny, and the pre-change baseline did not. Reachability does not establish which rule or device is responsible.',
        'Sampled public-ingress evidence did not observe the required service response after the change, and the pre-change baseline did. No rule or root cause is established.',
        'Sampled public-ingress evidence observed reachability on both sides of the change where the declared expectation is deny.',
        'Sampled public-ingress evidence did not observe the required service response on either side of the change.'
      )
    )
  );

-- Clear notes only where they are an exact copy of the server text; edited notes stay editable.
UPDATE findings
SET notes = NULL
WHERE notes IS NOT NULL AND system_summary IS NOT NULL AND notes = system_summary;
