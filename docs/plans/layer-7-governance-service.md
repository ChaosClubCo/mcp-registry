# Layer 7 Persistent Governance Service — Implementation Plan

## Goal

Turn the Layer 6/6.1 in-memory governance primitives into a durable, evidence-backed service without introducing a database dependency or weakening routing/certification boundaries.

## Phase 1 — RED acceptance contract

Add tests before production code for:

1. durable file-store persistence across service restart,
2. global snapshot CAS conflict rejection,
3. record-revision conflict rejection for lifecycle transitions,
4. certified transition receipt validation and immutable receipt archival,
5. material drift atomically demoting a certified connector,
6. Ed25519 grant issuance, persistence, verification, and exact-resource routing,
7. tampered, expired, revoked, and unpersisted grant rejection,
8. evidence-ledger hash-chain verification and tamper detection,
9. file-store `0600` snapshot permissions and symlink rejection,
10. private signing key bytes never appearing in persisted state.

The red commit must precede all production implementation commits.

## Phase 2 — Persistence primitives

Implement:

- `GovernanceSnapshot`
- `GovernanceStore`
- `MemoryGovernanceStore` for deterministic unit tests
- `FileGovernanceStore`
- `ErrConflict`
- snapshot cloning/normalization
- atomic write + parent-directory fsync

Verification gate: store tests green; existing governance suite remains green.

## Phase 3 — Evidence ledger

Implement:

- `GovernanceEvent`
- immutable receipt hash/archive helpers
- `EvidenceEntry`
- append helper
- `VerifyEvidenceLedger`

Verification gate: historical tampering, event substitution, sequence changes, and previous-hash changes are detected.

## Phase 4 — Signed grants

Implement:

- `AuthorizationGrant`
- `SignedAuthorizationGrant`
- `StoredAuthorizationGrant`
- Ed25519 signer/verifier
- canonical grant payload normalization
- issue/persist/revoke/verify methods

Verification gate: only persisted, unrevoked, unexpired, untampered grants verify.

## Phase 5 — Governance service

Implement:

- `GovernanceService`
- stable connector identity keys
- record registration
- record lookup/list
- revision-guarded lifecycle transitions
- drift observation/demotion
- router-facing `SelectWithGrant`

Verification gate: transitions, drift, receipt archive, events, ledger, and routing occur in one snapshot CAS commit where applicable.

## Phase 6 — Review and merge gate

Run:

- `go test ./...`
- `go test -race ./...`
- `go vet ./...`

Then request Codex/Sourcery/CodeRabbit review, address valid findings test-first, require green Snyk/CodeRabbit status, reconcile all review threads, and merge only after fresh verification on the final head.

## Implementation constraints

- Go standard library only for Layer 7 implementation.
- No private signing key persistence.
- No caller-supplied authorization accepted by the router service.
- No silent retry of revision conflicts.
- No mutable receipt history.
- No persistence write without atomic replacement.
- No production-state mutation without an evidence event and ledger append.
