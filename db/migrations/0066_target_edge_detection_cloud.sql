-- Cloud hosting family as first-class columns so list reads never touch evidence_json (ADR-0015).
ALTER TABLE target_edge_detections
  ADD COLUMN IF NOT EXISTS cloud_status TEXT NOT NULL DEFAULT 'inconclusive',
  ADD COLUMN IF NOT EXISTS cloud_provider TEXT;

UPDATE target_edge_detections
SET
  cloud_status = CASE
    WHEN evidence_json -> 'cloud' ->> 'status' IN ('detected', 'not_detected', 'inconclusive')
      THEN evidence_json -> 'cloud' ->> 'status'
    ELSE 'inconclusive'
  END,
  cloud_provider = CASE
    WHEN evidence_json -> 'cloud' ->> 'status' = 'detected'
      THEN NULLIF(btrim(evidence_json -> 'cloud' ->> 'provider'), '')
    ELSE NULL
  END
WHERE jsonb_typeof(evidence_json -> 'cloud') = 'object';

ALTER TABLE target_edge_detections
  DROP CONSTRAINT IF EXISTS target_edge_detections_cloud_status_check;
ALTER TABLE target_edge_detections
  ADD CONSTRAINT target_edge_detections_cloud_status_check
  CHECK (cloud_status IN ('detected', 'not_detected', 'inconclusive'));
