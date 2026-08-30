.PHONY: lint test-unit test-integration test-e2e-first-slice safety-check validate-db-schema postgres-tenant-query-audit vector-taxonomy check-library edge-corpus-parity oidc-fixture verify

# Prefer `node` on PATH; fall back to Codex runtime; override with `make NODE=/path/to/node verify`.
CODEX_NODE := /Users/checkred_admin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node
NODE ?= $(shell command -v node 2>/dev/null || (test -x "$(CODEX_NODE)" && echo "$(CODEX_NODE)"))

lint:
	"$(NODE)" scripts/lint.mjs

# The bundled staging OIDC fixture holds a token-signing private key, so it is gitignored and
# absent from fresh clones. These targets invoke node directly and bypass npm's pretest hooks,
# so they have to ensure it themselves. Existing fixtures are left alone (no --force).
oidc-fixture:
	"$(NODE)" scripts/generate-bundled-oidc-fixture.mjs --quiet

test-unit: oidc-fixture
	"$(NODE)" --test tests/unit/*.test.mjs

test-integration: oidc-fixture
	"$(NODE)" --test tests/integration/*.test.mjs

test-e2e-first-slice: oidc-fixture
	"$(NODE)" --test tests/e2e/*.test.mjs

safety-check:
	"$(NODE)" scripts/safety-check.mjs

validate-db-schema:
	"$(NODE)" scripts/validate-db-schema.mjs

postgres-tenant-query-audit:
	"$(NODE)" scripts/postgres-tenant-query-audit.mjs

# DET-025: registry ↔ catalog cross-check plus per-check resource-exhaustion metadata.
vector-taxonomy:
	"$(NODE)" scripts/validate-resource-exhaustion-taxonomy.mjs

# Generated check catalog must exactly match deterministic catalog output.
check-library:
	"$(NODE)" scripts/generate-check-library-html.mjs --check

# Dedicated provenance/hash/inventory parity gate for the vendored edge corpus.
edge-corpus-parity:
	"$(NODE)" --test tests/unit/edge-signature-corpus.test.mjs

verify: lint test-unit test-integration test-e2e-first-slice safety-check validate-db-schema postgres-tenant-query-audit vector-taxonomy check-library edge-corpus-parity