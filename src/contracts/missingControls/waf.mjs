export const MISSING_CONTROLS_WAF = Object.freeze({
  'waf.body_form_marker.soc': {
    control_family: 'waf_body_inspection',
    missing_control: 'The edge WAF does not inspect application/x-www-form-urlencoded request bodies, so an attack marker submitted in a form field passes through to the application.',
    required_policy: 'Enable request-body inspection for urlencoded form content on all POST/PUT routes and apply the managed injection rule sets to decoded form parameters in blocking mode.',
  },
  'waf.body_inspection_limit.soc': {
    control_family: 'waf_body_inspection',
    missing_control: 'The edge WAF stops inspecting request bodies after a size limit and fails open, so a marker placed after 8-128 KB of padding is forwarded to the origin uninspected.',
    required_policy: 'Raise the body inspection limit to cover the largest legitimate payload and configure the WAF to block (not pass) any request whose body exceeds the inspected size on protected routes.',
  },
  'waf.body_json_marker.soc': {
    control_family: 'waf_body_inspection',
    missing_control: 'The edge WAF does not parse and inspect JSON request bodies, so an injection marker inside a JSON field value reaches the application unblocked.',
    required_policy: 'Enable JSON body parsing on the WAF for application/json requests and apply managed injection rules to every parsed JSON key and value in blocking mode.',
  },
  'waf.body_multipart_marker.soc': {
    control_family: 'waf_body_inspection',
    missing_control: 'The edge WAF does not inspect multipart/form-data parts, so an attack marker carried in a multipart field or file part is passed to the application.',
    required_policy: 'Enable multipart/form-data parsing on the WAF, inspect each part name, header and content with the managed rule sets, and block malformed multipart boundaries.',
  },
  'waf.crlf_injection_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for CRLF/Response-Splitting is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the CRLF/Response-Splitting attack itself.',
    required_policy: 'Install your custom canary rule for CRLF/Response-Splitting on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
  'waf.csv_formula_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for CSV/Formula is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the CSV/Formula attack itself.',
    required_policy: 'Install your custom canary rule for CSV/Formula on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
  'waf.deserialization_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for Unsafe Deserialization is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the Unsafe Deserialization attack itself.',
    required_policy: 'Install your custom canary rule for Unsafe Deserialization on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
  'waf.enforcement.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'The declared WAF rule is not enforcing on this hostname: a request carrying the declared marker is answered by the application instead of the WAF block response.',
    required_policy: 'Switch the declared marker rule from log/count mode to block mode on the hostname and confirm the WAF returns its documented block status and signature for the marker.',
  },
  'waf.entry_path_api_marker.safe': {
    control_family: 'waf_managed_rules',
    missing_control: 'Managed injection rules are not enforced on the declared API path: an inert SQL-injection marker in the query, a header, double-encoded or after padding is not blocked.',
    required_policy: 'Attach the managed injection rule sets in blocking mode to the API route, including JSON content types and double-decoded input, and keep inspection coverage past bounded padding.',
  },
  'waf.entry_path_login_marker.safe': {
    control_family: 'waf_managed_rules',
    missing_control: 'Managed injection rules are not enforced on the declared login path: an inert SQL-injection marker in the query, a header, percent-encoded or after padding is not blocked.',
    required_policy: 'Apply the managed injection rule sets in blocking mode to the login route, including form content types and decoded input, with no rule exclusions for authentication paths.',
  },
  'waf.evasion_alt_charset.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not decode input declared in an alternate character set before matching, so an injection marker re-encoded with a different charset evades the rules.',
    required_policy: 'Restrict accepted request charsets to UTF-8 (block or normalise others) and enable charset-aware decoding before managed rule evaluation.',
  },
  'waf.evasion_base64_wrap.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not decode Base64 or similar textual wrapping before rule matching, so an injection marker wrapped in Base64 passes the edge undetected.',
    required_policy: 'Enable Base64-decode transformations on parameters that may carry encoded data and evaluate the managed injection rules against both the raw and decoded values.',
  },
  'waf.evasion_benign_padding.safe': {
    control_family: 'waf_managed_rules',
    missing_control: 'The WAF anomaly scoring is diluted by benign padding, so an injection marker surrounded by harmless content falls below the blocking threshold.',
    required_policy: 'Use per-rule blocking for high-confidence injection signatures instead of relying only on a cumulative anomaly score, and keep the anomaly threshold low enough that padding cannot dilute it.',
  },
  'waf.evasion_body_gzip.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not decompress gzip-encoded request bodies before inspection, so a marker inside a compressed body is forwarded without being matched.',
    required_policy: 'Either decompress Content-Encoding: gzip request bodies before rule evaluation or block compressed request bodies on routes that do not legitimately require them.',
  },
  'waf.evasion_body_nested_encoding.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not unwrap nested or stacked content encodings, so a marker hidden under multiple encoding layers reaches the origin without inspection.',
    required_policy: 'Enable recursive decoding up to a safe depth before rule matching and block requests whose encoding nesting exceeds that depth.',
  },
  'waf.evasion_cache_key_mismatch.posture': {
    control_family: 'cache_policy',
    missing_control: 'No declared cache-key normalization aligns the edge cache key with origin routing, so requests that differ only in unkeyed headers or parameters can poison shared cached responses.',
    required_policy: 'Normalise the cache key (path case, encoding, query order) and include every header or parameter the origin uses for routing, or strip unkeyed inputs before they reach the origin.',
  },
  'waf.evasion_case_fold.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF matches injection keywords case-sensitively, so a marker with mixed-case keywords is not recognised and reaches the application.',
    required_policy: 'Apply a lowercase (case-fold) transformation before injection rule matching on all request inputs.',
  },
  'waf.evasion_connection_coalescing.posture': {
    control_family: 'http2_http3_protection',
    missing_control: 'No declared per-host policy prevents HTTP/2 connection coalescing, so a request for one hostname can ride a connection authorised for another and bypass that host WAF policy.',
    required_policy: 'Enforce per-host WAF policy on every request regardless of connection, return 421 Misdirected Request when the authority does not match the TLS certificate, and avoid broad shared certificates.',
  },
  'waf.evasion_content_type_binary.safe': {
    control_family: 'waf_body_inspection',
    missing_control: 'The WAF skips inspection when the request declares a binary or protobuf content type, so a marker in an opaque body is forwarded uninspected.',
    required_policy: 'Allow binary or protobuf content types only on routes that need them, and block or inspect requests whose declared content type does not match the route schema.',
  },
  'waf.evasion_control_char.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not strip or reject null bytes and control characters, so a marker split by inserted control characters is not matched.',
    required_policy: 'Block requests containing null bytes or non-printable control characters in URLs, headers and parameters, or remove them before rule matching.',
  },
  'waf.evasion_css_escape.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not decode CSS escape sequences before XSS matching, so a cross-site scripting marker written with CSS escapes is not detected.',
    required_policy: 'Enable CSS-decode transformations before evaluating the managed XSS rule set on all request inputs.',
  },
  'waf.evasion_double_url.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF decodes URL encoding only once, so a double-URL-encoded injection marker survives inspection and is decoded again by the application.',
    required_policy: 'Apply recursive URL decoding before rule matching, and block input that still contains percent-encoded sequences after one decode pass.',
  },
  'waf.evasion_ech_routing_metadata.posture': {
    control_family: 'tls_configuration',
    missing_control: 'No declared control ensures the edge applies host-specific WAF policy when Encrypted ClientHello hides the SNI, so routing metadata can differ from the inspected host.',
    required_policy: 'Terminate ECH at the edge, bind WAF policy to the decrypted inner SNI and HTTP authority, and reject requests where the inner SNI and Host header disagree.',
  },
  'waf.evasion_encrypted_payload.posture': {
    control_family: 'waf_body_inspection',
    missing_control: 'No declared decryption or inspection point exists for application-layer encrypted payloads, so content inside an opaque encrypted body is never checked by the WAF.',
    required_policy: 'Decrypt and inspect application-layer encrypted payloads at a trusted gateway before the application processes them, or enforce strict schema validation after decryption.',
  },
  'waf.evasion_framing_chunk_ext.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The edge does not reject chunk extensions or trailers, so the WAF and origin can disagree on chunked-body framing and an injection marker can slip through.',
    required_policy: 'Reject or strip chunk extensions and request trailers at the edge and re-frame chunked bodies before forwarding them to the origin.',
  },
  'waf.evasion_framing_cl_te.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The edge accepts requests carrying both Content-Length and Transfer-Encoding, creating a request-smuggling ambiguity that lets a marker bypass WAF inspection.',
    required_policy: 'Reject any request that carries both Content-Length and Transfer-Encoding or multiple conflicting lengths, and normalise framing before forwarding to the origin.',
  },
  'waf.evasion_framing_h2_h1.safe': {
    control_family: 'http2_http3_protection',
    missing_control: 'The edge HTTP/2-to-HTTP/1.1 translation does not normalise framing, so a request inspected as HTTP/2 can be re-framed differently at the origin and bypass the WAF.',
    required_policy: 'Reject HTTP/2 requests containing connection-specific headers, CR/LF in header values or conflicting content-length, and use HTTP/2 end-to-end or strict downgrade validation.',
  },
  'waf.evasion_framing_line_ending.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The edge tolerates bare LF or non-standard line endings in the request head, so the WAF and origin can parse requests differently and a marker escapes inspection.',
    required_policy: 'Enforce strict CRLF line endings in the request line and headers and reject requests with bare LF, bare CR or obsolete header line folding.',
  },
  'waf.evasion_framing_transfer_coding.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The edge accepts obfuscated Transfer-Encoding values such as unusual casing, whitespace or duplicates, so body framing can be hidden from the WAF.',
    required_policy: 'Accept only an exact chunked Transfer-Encoding value, reject any other or duplicated transfer-coding header, and normalise framing before inspection.',
  },
  'waf.evasion_homoglyph.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not map Unicode confusable characters to their ASCII equivalents, so an injection marker spelled with homoglyphs is not recognised.',
    required_policy: 'Apply Unicode confusable and compatibility normalisation before rule matching, or block non-ASCII characters in parameters that should be ASCII-only.',
  },
  'waf.evasion_html_entity.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not decode HTML entities before XSS matching, so a cross-site scripting marker written with entity encoding is not detected.',
    required_policy: 'Enable HTML-entity decoding transformations before the managed XSS rule set evaluates query, header, cookie and body input.',
  },
  'waf.evasion_ip_representation.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not normalise alternative IP-address notations (decimal, octal, hex, IPv6-mapped), so address-based rules can be bypassed with a non-canonical form.',
    required_policy: 'Canonicalise IP addresses in parameters and headers before matching, and block internal or metadata addresses in any notation.',
  },
  'waf.evasion_js_escape.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not decode JavaScript string or Unicode escape sequences before XSS matching, so an escaped cross-site scripting marker is not detected.',
    required_policy: 'Enable JavaScript-decode and Unicode-escape transformations before evaluating the managed XSS rule set on every request input.',
  },
  'waf.evasion_json_unicode_escape.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not decode JSON \\u escape sequences before matching, so an XSS marker expressed with JSON Unicode escapes passes inspection.',
    required_policy: 'Parse JSON input and decode \\u escapes into their characters before applying the managed XSS and injection rules.',
  },
  'waf.evasion_lexical_literal.safe': {
    control_family: 'waf_managed_rules',
    missing_control: 'The WAF SQL-injection detection relies on exact literal patterns, so a marker using reshuffled numbers or alternate literal forms is not matched.',
    required_policy: 'Use a tokenising (lexical) SQL-injection detector or the highest-coverage managed SQLi rules rather than fixed literal signatures, in blocking mode.',
  },
  'waf.evasion_lexical_operator.safe': {
    control_family: 'waf_managed_rules',
    missing_control: 'The WAF SQL-injection rules do not cover substituted operators or equivalent functions, so a marker rewritten with alternate operators is not detected.',
    required_policy: 'Enable SQL-injection rules that detect operator and function substitution (for example tokenised SQL grammar matching) at a paranoia level that covers equivalent operators.',
  },
  'waf.evasion_lexical_tautology.safe': {
    control_family: 'waf_managed_rules',
    missing_control: 'The WAF detects only the canonical tautology form, so a SQL-injection marker using a mutated logical invariant is not blocked.',
    required_policy: 'Enable SQL-injection detection that evaluates boolean tautology structure rather than literal strings, with blocking enabled for those rules.',
  },
  'waf.evasion_method_override.safe': {
    control_family: 'http_method_policy',
    missing_control: 'The edge honours method-override headers or parameters without applying the overridden method policy, so a request can bypass method-scoped WAF rules.',
    required_policy: 'Strip X-HTTP-Method-Override and similar headers or parameters at the edge, or evaluate WAF and method policy against the effective overridden method.',
  },
  'waf.evasion_mixed_url.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not fully decode mixed URL encodings (partially encoded, %u or mixed case hex), so an injection marker in mixed encoding is not matched.',
    required_policy: 'Apply full URL and %u decoding with case-insensitive hex handling before rule matching, and block non-standard %u encodings.',
  },
  'waf.evasion_multipart_charset.safe': {
    control_family: 'waf_body_inspection',
    missing_control: 'The WAF ignores per-part charset declarations in multipart bodies, so a cross-site scripting marker in a part with a non-default charset is not inspected.',
    required_policy: 'Decode each multipart part according to its declared charset before inspection, or reject parts that declare a charset other than UTF-8.',
  },
  'waf.evasion_numeric_repr.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not recognise hex, octal or other numeric representations in SQL input, so a marker rewritten with numeric literals bypasses detection.',
    required_policy: 'Enable SQL-injection rules that decode hex and numeric literal forms, or block hex-encoded strings in parameters that should contain plain text.',
  },
  'waf.evasion_overlong_utf8.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF accepts invalid or overlong UTF-8 sequences that the origin decodes differently, so an injection marker can be hidden from rule matching.',
    required_policy: 'Reject requests containing invalid or overlong UTF-8 sequences at the edge, and validate UTF-8 before any rule evaluation.',
  },
  'waf.evasion_parameter_location.safe': {
    control_family: 'waf_managed_rules',
    missing_control: 'The WAF inspects only some parameter locations, so an injection marker moved to another location such as a cookie, path segment or alternate header is not checked.',
    required_policy: 'Apply the managed injection rules to every input location: query, path segments, all headers, cookies and body parameters.',
  },
  'waf.evasion_parser_header_dup.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The edge forwards duplicate or conflicting HTTP headers, so the WAF may inspect one copy while the origin uses another that carries the marker.',
    required_policy: 'Reject requests with duplicated single-value headers (Host, Content-Type, Content-Length and similar) and inspect every instance of repeatable headers.',
  },
  'waf.evasion_parser_hpp.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not handle HTTP parameter pollution, so a marker split across repeated parameters with the same name is reassembled by the application unseen.',
    required_policy: 'Inspect every occurrence and the concatenated value of repeated parameters, or block duplicate parameter names on routes that do not expect them.',
  },
  'waf.evasion_parser_json_dup.safe': {
    control_family: 'waf_body_inspection',
    missing_control: 'The WAF JSON parser and the application resolve duplicate JSON keys differently, so a marker in the key copy the WAF ignores reaches the application.',
    required_policy: 'Reject JSON bodies containing duplicate keys at the edge or API gateway, and inspect every key occurrence when duplicates must be allowed.',
  },
  'waf.evasion_path_matrix.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not normalise matrix or path parameters (;param segments), so a path-traversal marker hidden in a path parameter evades path rules.',
    required_policy: 'Strip or reject semicolon path parameters at the edge and normalise the path before path-traversal and access rules are evaluated.',
  },
  'waf.evasion_path_suffix.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not canonicalise trailing dots, slashes or suffixes in the path, so a path-traversal marker with an ambiguous suffix escapes path-based rules.',
    required_policy: 'Canonicalise paths (remove trailing dots, collapse slashes, resolve dot segments) before rule matching, and block requests that still contain traversal sequences.',
  },
  'waf.evasion_polyglot_content.safe': {
    control_family: 'waf_body_inspection',
    missing_control: 'The WAF inspects input under a single parser context, so a polyglot payload that is valid in several formats can carry an XSS marker past inspection.',
    required_policy: 'Enforce strict content-type to route matching, apply XSS rules across all decoded contexts, and reject bodies that do not parse as the declared content type.',
  },
  'waf.evasion_protocol_h3_h1.safe': {
    control_family: 'http2_http3_protection',
    missing_control: 'The edge HTTP/3-to-HTTP/1.1 translation is not normalised, so a request inspected over HTTP/3 can be re-framed at the origin in a way that hides the marker.',
    required_policy: 'Apply the same WAF policy and strict header validation to HTTP/3 traffic as to HTTP/1.1, and reject HTTP/3 requests with invalid pseudo-headers or CR/LF in fields.',
  },
  'waf.evasion_protocol_qpack_hpack.safe': {
    control_family: 'http2_http3_protection',
    missing_control: 'Headers delivered through QPACK or HPACK compression are not normalised before inspection, so header-borne markers can differ between the WAF and origin view.',
    required_policy: 'Inspect fully decompressed HTTP/2 and HTTP/3 header fields, reject non-lowercase or invalid field names, and enforce header list size limits.',
  },
  'waf.evasion_protocol_upgrade.safe': {
    control_family: 'api_surface_protection',
    missing_control: 'The edge permits protocol upgrades such as WebSocket on routes that do not need them, and traffic after the upgrade is not inspected, so an XSS marker can bypass the WAF.',
    required_policy: 'Allow Upgrade/WebSocket only on declared WebSocket routes, block it elsewhere, and inspect upgrade handshake headers and parameters with the managed rules.',
  },
  'waf.evasion_protocol_version.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The edge accepts legacy or unusual HTTP versions (such as HTTP/1.0 or 0.9) that are inspected differently, letting an injection marker bypass WAF rules.',
    required_policy: 'Accept only HTTP/1.1, HTTP/2 and HTTP/3 at the edge, reject other protocol versions, and apply identical WAF policy to every accepted version.',
  },
  'waf.evasion_reassembly_differential.posture': {
    control_family: 'l3_l4_ddos_protection',
    missing_control: 'No declared reassembly normalisation exists at the edge, so overlapping IP fragments or TCP segments can be reassembled differently by inspection devices and the origin.',
    required_policy: 'Enable IP fragment and TCP stream reassembly normalisation at the network edge, drop overlapping or tiny fragments, and inspect only the fully reassembled stream.',
  },
  'waf.evasion_rule_gap.posture': {
    control_family: 'exploit_mitigation',
    missing_control: 'No declared managed-ruleset update or virtual-patching process exists, so a newly disclosed attack pattern without a signature would pass the WAF unblocked.',
    required_policy: 'Subscribe to automatically updated managed rule sets, define a virtual-patching procedure with a target deployment time for new critical vulnerabilities, and keep it documented.',
  },
  'waf.evasion_second_order.posture': {
    control_family: 'waf_body_inspection',
    missing_control: 'No declared inspection covers content that is stored and later rendered or executed, so a second-order payload accepted on write can trigger later without WAF visibility.',
    required_policy: 'Inspect write requests with blocking injection rules, validate and encode stored content at the application, and scan stored content before it is rendered or processed.',
  },
  'waf.evasion_signed_structured_data.posture': {
    control_family: 'api_surface_protection',
    missing_control: 'No declared schema validation is applied after signature verification, so signed tokens or documents with malicious field contents are trusted without inspection.',
    required_policy: 'Validate signed structured data against a strict schema after signature verification and apply injection inspection to its decoded claims or fields.',
  },
  'waf.evasion_struct_deep_nesting.safe': {
    control_family: 'waf_body_inspection',
    missing_control: 'The WAF stops parsing structured input beyond a nesting depth or sparse index, so a marker buried deep in a nested structure is not inspected.',
    required_policy: 'Set a maximum nesting depth and array index for JSON and form structures at the edge, block requests that exceed it, and inspect all values within the limit.',
  },
  'waf.evasion_struct_type_confusion.safe': {
    control_family: 'waf_body_inspection',
    missing_control: 'The WAF inspects only scalar string values, so a marker placed inside an array or object where a string was expected is not matched.',
    required_policy: 'Enforce schema types for structured parameters at the edge or API gateway and apply injection rules to values inside arrays and objects as well as scalars.',
  },
  'waf.evasion_unicode_normalization.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not apply the same Unicode normalisation form as the application, so a marker written with compatibility characters is normalised into an attack only after inspection.',
    required_policy: 'Apply NFKC Unicode normalisation before rule matching, matching the normalisation the application performs, or reject non-normalised input.',
  },
  'waf.evasion_whitespace.safe': {
    control_family: 'waf_request_normalization',
    missing_control: 'The WAF does not normalise alternative whitespace such as tabs, comments or newlines between keywords, so a SQL-injection marker with substituted whitespace is not detected.',
    required_policy: 'Enable whitespace compression and SQL comment removal transformations before evaluating the managed SQL-injection rules.',
  },
  'waf.evasion_xml_attribute.safe': {
    control_family: 'waf_body_inspection',
    missing_control: 'The WAF does not inspect XML attribute values, so a cross-site scripting marker carried in an XML attribute passes the edge.',
    required_policy: 'Enable XML body parsing and apply the managed XSS and injection rules to element text and attribute values on routes that accept XML.',
  },
  'waf.file_upload_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for File Upload is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the File Upload attack itself.',
    required_policy: 'Install your custom canary rule for File Upload on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
  'waf.fingerprint.safe': {
    control_family: 'waf_managed_rules',
    missing_control: 'No identifiable WAF or CDN enforcement layer was observed in front of this declared asset, so requests appear to be served without an inspecting edge.',
    required_policy: 'Place the hostname behind a WAF-enabled edge with managed rule sets in blocking mode, and ensure DNS resolves only to the protected edge.',
  },
  'waf.http_method_policy_enforced.safe': {
    control_family: 'http_method_policy',
    missing_control: 'The edge does not refuse TRACE or nonstandard HTTP methods, so arbitrary method tokens reach the application while normal GET traffic is served.',
    required_policy: 'Configure an HTTP method allow-list at the edge (for example GET, HEAD, POST and the methods each route needs) and block TRACE and unknown method tokens with a distinct deny response.',
  },
  'waf.http_method_policy_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for HTTP Method/Protocol Policy is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the HTTP Method/Protocol Policy attack itself.',
    required_policy: 'Install your custom canary rule for HTTP Method/Protocol Policy on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
  'waf.http_routing_trust.posture': {
    control_family: 'origin_protection',
    missing_control: 'No declared proxy-trust boundary limits which forwarded headers the origin trusts, so client-supplied X-Forwarded-*, Forwarded, Proxy or Host values can alter routing or identity.',
    required_policy: 'Have the edge overwrite or strip X-Forwarded-For, Forwarded, X-Forwarded-Host and Proxy headers, and have the origin trust them only from edge IP ranges.',
  },
  'waf.inspection_limit.safe': {
    control_family: 'waf_body_inspection',
    missing_control: 'The WAF stops inspecting input after its inspection limit and allows the remainder, so a marker placed beyond the limit passes through (fail-open).',
    required_policy: 'Configure the WAF to block requests that exceed its inspection size limit on protected routes instead of passing them uninspected.',
  },
  'waf.jndi_ldap_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for JNDI/LDAP is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the JNDI/LDAP attack itself.',
    required_policy: 'Install your custom canary rule for JNDI/LDAP on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
  'waf.jsonp_css_policy.posture': {
    control_family: 'waf_custom_rules',
    missing_control: 'No declared Content-Security-Policy or content-type policy limits JSONP callbacks and injected stylesheets, leaving JSONP hijacking and CSS injection unmitigated.',
    required_policy: 'Send a Content-Security-Policy restricting script and style sources, set X-Content-Type-Options: nosniff, and remove or allow-list JSONP callback parameters.',
  },
  'waf.jwt_tamper_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for JWT Tamper is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the JWT Tamper attack itself.',
    required_policy: 'Install your custom canary rule for JWT Tamper on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
  'waf.low_rate_limit.safe': {
    control_family: 'waf_rate_limiting',
    missing_control: 'No rate-limiting rule throttles a single client sending repeated requests at a low rate, so slow sustained request floods are not limited.',
    required_policy: 'Add a per-client rate-limiting rule with a threshold suited to the route, returning 429 or a block when it is exceeded, and log the limited requests.',
  },
  'waf.marker_rule.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'The declared custom marker rule does not block a request carrying the marker header, so the WAF custom rule set is not enforcing on this hostname.',
    required_policy: 'Deploy the marker rule in blocking mode on the hostname, match the declared header, and return the declared block status and signature.',
  },
  'waf.nosql_injection_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for NoSQL Injection is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the NoSQL Injection attack itself.',
    required_policy: 'Install your custom canary rule for NoSQL Injection on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
  'waf.offensive_combined.soc': {
    control_family: 'waf_managed_rules',
    missing_control: 'Managed WAF rules do not block a combined set of injection, traversal, template and command-execution attack classes on the declared asset.',
    required_policy: 'Enable the full managed OWASP core rule set in blocking mode on the asset, with rule exclusions limited to documented false positives.',
  },
  'waf.offensive_command_injection.soc': {
    control_family: 'waf_managed_rules',
    missing_control: 'Managed WAF rules do not block OS command-injection payloads such as shell metacharacters and command chaining in request input.',
    required_policy: 'Enable the managed command-injection (Unix and Windows shell) rule groups in blocking mode across query, header, cookie and body input.',
  },
  'waf.offensive_ldap_injection.soc': {
    control_family: 'waf_managed_rules',
    missing_control: 'Managed WAF rules do not block LDAP-injection payloads that alter directory filter queries.',
    required_policy: 'Enable managed LDAP-injection rules in blocking mode on routes that query directory services, and block LDAP filter metacharacters in those parameters.',
  },
  'waf.offensive_path_traversal.soc': {
    control_family: 'waf_managed_rules',
    missing_control: 'Managed WAF rules do not block path-traversal payloads, including encoded dot-dot-slash sequences, used to read files outside the web root.',
    required_policy: 'Enable managed local-file-inclusion and path-traversal rules in blocking mode with URL decoding and path normalisation applied first.',
  },
  'waf.offensive_rce.soc': {
    control_family: 'waf_managed_rules',
    missing_control: 'Managed WAF rules do not block remote-code-execution payloads that target interpreters, expression languages or known framework exploits.',
    required_policy: 'Enable the managed RCE and known-exploit rule groups in blocking mode, and keep them updated for newly disclosed framework vulnerabilities.',
  },
  'waf.offensive_sqli.soc': {
    control_family: 'waf_managed_rules',
    missing_control: 'Managed WAF rules do not block a realistic SQL-injection suite, including union, boolean, time-based and error-based variants.',
    required_policy: 'Enable the managed SQL-injection rule group in blocking mode at a paranoia level that covers union, blind and error-based techniques on all routes.',
  },
  'waf.offensive_ssti.soc': {
    control_family: 'waf_managed_rules',
    missing_control: 'Managed WAF rules do not block server-side template injection expressions that execute in the application template engine.',
    required_policy: 'Enable managed template-injection rules in blocking mode, adding custom rules for template delimiters used by the application frameworks.',
  },
  'waf.offensive_xss.soc': {
    control_family: 'waf_managed_rules',
    missing_control: 'Managed WAF rules do not block a realistic cross-site scripting suite, including reflected script, event-handler and encoded variants.',
    required_policy: 'Enable the managed XSS rule group in blocking mode with HTML, JavaScript and URL decoding transformations on all request inputs.',
  },
  'waf.open_redirect_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for Open Redirect / Parameter Policy is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the Open Redirect / Parameter Policy attack itself.',
    required_policy: 'Install your custom canary rule for Open Redirect / Parameter Policy on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
  'waf.origin_bypass.safe': {
    control_family: 'origin_protection',
    missing_control: 'The origin answers requests sent directly to its address with the protected hostname, so attackers can skip the WAF and DDoS edge entirely.',
    required_policy: 'Restrict origin ingress to the edge provider IP ranges or an authenticated tunnel, and require an edge-injected secret header or mutual TLS on every origin request.',
  },
  'waf.path_traversal_managed_marker.safe': {
    control_family: 'waf_managed_rules',
    missing_control: 'The edge WAF does not block a plain dot-dot-slash path-traversal pattern on the probed path, so file-traversal attempts reach the origin.',
    required_policy: 'Enable the managed path-traversal and local-file-inclusion rules in blocking mode on every route served by the hostname, returning a recognisable block signature.',
  },
  'waf.prototype_pollution_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for Prototype Pollution is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the Prototype Pollution attack itself.',
    required_policy: 'Install your custom canary rule for Prototype Pollution on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
  'waf.rate_limit_canary.validation': {
    control_family: 'waf_rate_limiting',
    missing_control: 'The declared rate-limit canary route is not throttled: requests above the declared threshold within the window are still served normally.',
    required_policy: 'Enforce the declared rate-limit rule on the canary route so that exceeding the threshold within the window returns 429 or a block for the rest of the window.',
  },
  'waf.request_smuggling_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for Request Smuggling is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the Request Smuggling attack itself.',
    required_policy: 'Install your custom canary rule for Request Smuggling on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
  'waf.response_dlp_canary.soc': {
    control_family: 'waf_custom_rules',
    missing_control: 'No response-inspection rule blocks or masks sensitive data patterns in response bodies, so data leakage from the application leaves through the edge.',
    required_policy: 'Enable response-body data-loss-prevention rules for card numbers, credentials and other sensitive patterns, set to block or mask on protected routes.',
  },
  'waf.scanner_signature_marker.safe': {
    control_family: 'waf_bot_management',
    missing_control: 'The edge does not block requests from a known vulnerability-scanner user agent, so automated scanning tools reach the application unchallenged.',
    required_policy: 'Enable the managed scanner and bad-bot signature rules in blocking mode, covering known scanner user agents, on every route served by the hostname.',
  },
  'waf.sqli_managed_marker.safe': {
    control_family: 'waf_managed_rules',
    missing_control: 'The edge WAF does not block requests carrying a SQL-injection pattern in the query, headers or path, so injection attempts reach the origin.',
    required_policy: 'Enable the managed SQL-injection rule set in blocking (not detection/count) mode on every route served by this hostname, and return a recognisable block signature.',
  },
  'waf.ssrf_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for SSRF is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the SSRF attack itself.',
    required_policy: 'Install your custom canary rule for SSRF on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
  'waf.ssti_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for SSTI is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the SSTI attack itself.',
    required_policy: 'Install your custom canary rule for SSTI on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
  'waf.xpath_injection_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for XPath/XML Injection is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the XPath/XML Injection attack itself.',
    required_policy: 'Install your custom canary rule for XPath/XML Injection on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
  'waf.xss_managed_marker.safe': {
    control_family: 'waf_managed_rules',
    missing_control: 'The edge WAF does not block a plain cross-site scripting tag pattern in the query, headers or path, so XSS attempts reach the origin.',
    required_policy: 'Enable the managed XSS rule set in blocking mode on every route served by the hostname, returning a recognisable block signature.',
  },
  'waf.xxe_marker.safe': {
    control_family: 'waf_custom_rules',
    missing_control: 'Your custom canary rule for XXE is not blocking: AstraNull\'s opaque inert test token passed the edge, so this rule cannot be shown to protect the hostname. This does not test the XXE attack itself.',
    required_policy: 'Install your custom canary rule for XXE on this hostname in blocking mode, matching AstraNull\'s declared test token in the query, path and header and returning your declared block signature.',
  },
});
