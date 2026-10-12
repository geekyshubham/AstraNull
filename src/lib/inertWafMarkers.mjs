/** Shared inert marker tokens, isolated from scanner/executor imports. */
export const BENIGN_CLASS_MARKERS = Object.freeze({
  xss: '<astranull-xss-probe/>',
  sqli: "astranull' OR '1'='0",
  path_traversal: '../../astranull-probe',
});

export const EVASION_VARIANT_MARKERS = Object.freeze({
  sqli_encoded: encodeURIComponent(encodeURIComponent(BENIGN_CLASS_MARKERS.sqli)),
  sqli_case: "AsTrAnUlL' oR '1'='0",
  sqli_comment: "astranull' O/**/R '1'='0",
  xss_encoded: encodeURIComponent(BENIGN_CLASS_MARKERS.xss),
  path_encoded: encodeURIComponent(BENIGN_CLASS_MARKERS.path_traversal),
});
