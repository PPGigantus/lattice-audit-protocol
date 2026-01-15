# Formal spec: Budget invariants

This folder contains a small TLA+ model of LAP's reserve/mint/spend state machine.
It is intended to model-check key safety invariants under arbitrary interleavings.

## How to run with TLC (local)

1) Install the TLA+ tools (tla2tools.jar).
2) From repo root:

```bash
java -cp /path/to/tla2tools.jar tlc2.TLC -config spec/BudgetInvariants.cfg spec/BudgetInvariants.tla
```

## What it checks

- `BudgetSafety`: reserved + spent <= TotalBudget
- `TokenWithinReserve`: TotalIssued <= reserved
- `NoDoubleMint`: any issued token ID must be recorded in jtiSeen

This is a *skeleton* spec intended to be expanded to include crash-recovery and
multi-node replay behavior.

## Replay + binding invariants

`spec/ReplayBindingInvariants.tla` adds a second minimal model focused on:

- receipt hash-chain integrity under arbitrary interleavings
- monotonic per-token counters that survive restarts (Crash keeps state)
- a decision-hash binding to (action_id, token_jti)

Run it with:

```bash
java -cp /path/to/tla2tools.jar tlc2.TLC -config spec/ReplayBindingInvariants.cfg spec/ReplayBindingInvariants.tla
```

## Interop and standardization

- `spec/CANONICAL_JSON.md` — the exact canonical JSON rules used for hash commitments.
- `spec/INTEROP.md` — MUST/SHOULD compliance notes for cross-language implementations.
- `spec/schemas/` — JSON Schemas for stable LAP artifacts (evidence, decisions, tokens, receipts, external approvals, audit-pack manifests).
- `spec/test_vectors/` — deterministic interoperability test vectors.
- `spec/golden_packs/` — end-to-end portable audit-pack fixtures.
- `spec/golden_packs/` — end-to-end portable audit-pack fixtures for offline verification.
