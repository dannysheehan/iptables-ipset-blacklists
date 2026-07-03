# Contributing

This repository contains `nft-blocklist`, a Go CLI that maintains nftables
blocklist sets from curated threat-intelligence feeds. The legacy v1 Bash
script lives frozen in `legacy/` and does not accept changes.

## Toolchain

- Go 1.26+ (`go.mod` is authoritative)
- `nft` (nftables) for integration tests
- `golangci-lint` for linting, `nfpm` for packaging, Vagrant + libvirt (or
  VirtualBox) for the e2e matrix. On Linux with KVM, set
  `VAGRANT_DEFAULT_PROVIDER=libvirt`; the matrix uses `cloud-image/*` boxes
  for libvirt and `bento/*` for VirtualBox.

## Commands

| Command            | What it does                                              |
|--------------------|-----------------------------------------------------------|
| `make build`       | static binary at `bin/nft-blocklist`                      |
| `make test`        | unit tests (no root, no network)                          |
| `make golden`      | regenerate nftgen golden files after changes              |
| `make lint`        | go vet + golangci-lint                                    |
| `make integration` | real-kernel tests in network namespaces (sudo)            |
| `make e2e BOX=…`   | Vagrant matrix: ubuntu2404 debian12 rocky9 leap156 fedora |

## Code standards

- **Comment the why.** Every package and every exported function carries a
  doc comment that explains *why* it exists and why it behaves the way it
  does (safety rationale, upstream quirks, kernel behavior), not a
  restatement of the signature. If a decision came from a real incident or
  a research finding, say so in the comment.
- **Documentation is a deliverable.** Behavior changes update `docs/`.
  Architecture and flow explanations use [mermaid](https://mermaid.js.org/)
  diagrams (flowchart for pipelines/structure, sequence for interactions) —
  see `docs/architecture.md` for the house style.
- `gofmt` clean; `golangci-lint` clean (config in `.golangci.yml`).
- Errors are wrapped with context: `fmt.Errorf("fetching %s: %w", name, err)`.
- No global state; packages under `internal/` expose small interfaces so unit
  tests can mock the filesystem/network/nft boundary (see `nftctl.Runner`).
- Anything that touches the network or the kernel is behind an interface;
  pure logic (parsing, IP math, rendering) must stay pure and unit-tested.
- Table-driven tests; fixtures in `test/fixtures/`; golden files in
  `internal/nftgen/testdata/` (regenerate with `make golden`, review the diff).
- Safety rails are contract, not implementation detail. Never weaken:
  atomic apply, shrink guard, bogon rejection, allowlist-wins, and the
  rule that feed updates never touch the `dynamic4`/`dynamic6` sets.

## Task briefs (for delegated / AI-assisted work)

Every delegated task should be written as a brief with these sections, and a
task is done only when `make lint test` passes plus the brief's own
acceptance commands:

```markdown
## Goal
One paragraph. What behavior exists after this task that didn't before.

## Files in scope
Exact paths the task may create/modify. Anything else is out of bounds.

## Interfaces
Signatures/types to implement or consume (copy them in, don't paraphrase).

## Fixtures
Which files under test/fixtures/ to use; add new ones if listed here.

## Acceptance
Exact commands and expected observable results, e.g.
  go test ./internal/feed -run TestParseIpsum
  bin/nft-blocklist update --dry-run --config test/fixtures/config-min.yaml
```

## Commit style

Small, single-purpose commits; imperative subject lines
(`feed: reject prefixes broader than /8`). Reference the phase/task from
`docs/architecture.md` where relevant.
