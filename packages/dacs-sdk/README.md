# DACS SDK

Repo-local TypeScript package for DACS v0.1 helper APIs.

Current scope is scaffold-only:

- `artifacts/*`
- `validators/*`
- `rails/demos/*`
- `conformance/*`

The package targets DACS v0.1 and is intentionally private until the first
vector-backed APIs are implemented. Demos integration belongs under
`rails/demos/*` and should wrap `@kynesyslabs/demosdk` as a rail/substrate
adapter, not as the normative source of DACS behavior.

Local checks:

```bash
bun install
bun run sdk:build
bun run sdk:test
```
