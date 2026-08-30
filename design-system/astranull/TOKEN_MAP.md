# Token map

| Design role | Runtime token |
|---|---|
| Canvas | `--bg`, `--void-black` |
| Panel | `--surface`, `--surface-raised`, `--surface-2` |
| Primary text | `--fg` |
| Secondary/meta | `--fg-2`, `--muted`, `--meta` |
| Structure | `--border`, `--border-soft`, `--border-strong` |
| Primary action | `--accent`, `--accent-on`, `--accent-hover`, `--accent-active` |
| Live instrument | `--signal`, `--signal-soft` |
| Semantic states | `--success`, `--warn`, `--danger`, `--info` |
| Focus | `--focus-ring` |
| Spacing | `--space-1` … `--space-12` |
| Radius | `--radius-sm`, `--radius-md`, `--radius-lg`, `--radius-pill` |
| Motion | `--motion-fast`, `--motion-base`, `--motion-ease` |
| Type | `--font-display`, `--font-body`, `--font-mono`, `--text-*` |

Rules: extend this namespace only when a semantic gap exists; never add a per-page palette or raw color in TSX.
