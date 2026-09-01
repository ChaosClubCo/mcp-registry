# Layer 7 — Persistent Governance Service

## Status

Approved implementation design for the persistent runtime built on the Layer 6/6.1 governance primitives.

## Purpose

Layer 6 makes certification, authorization, routing, and drift decisions deterministic in memory. Layer 7 makes those decisions durable and replayable across process restarts while preserving fail-closed behavior.

Layer 7 is intentionally storage-engine-neutral. The first concrete backend is a standard-library file store with atomic replacement and optimistic compare-and-swap. SQLite/Postgres can implement the same store contract later without changing the governance service API.

## Components

### GovernanceStore

The store persists a complete `GovernanceSnapshot` and exposes optimistic CAS semantics:

- `Load(ctx)` returns the latest snapshot and global revision.
- `Commit(ctx, expectedRevision, next)` succeeds only if the durable snapshot still has `expectedRevision`.
- conflicting writers receive `ErrConflict` and must reload before retrying.

### FileGovernanceStore

The v1 durable backend:

- JSON snapshot format with an explicit schema version.
- creates parent directory with `0700` permissions.
- writes temporary files with `0600` permissions.
- `fsync` temp file → atomic rename → `fsync` parent directory.
- rejects symlinks in the configured snapshot path.
- serializes in-process access across store instances that point at the same canonical absolute path.
- returns path-canonicalization failures rather than collapsing them into a shared lock identity.
- uses snapshot revision CAS to reject stale writers.

This backend is designed for one OS process boundary. Cross-host/multi-process production deployments should use a transactional implementation of `GovernanceStore`.

### Stored registry records

Each registry record has its own monotonically increasing revision in addition to the global snapshot revision. Lifecycle changes require the caller's expected record revision so stale transition requests cannot overwrite newer state.

A stable connector identity key is the SHA-256 digest of the canonical connector ID, connector version, and schema-hash tuple. This avoids delimiter ambiguity while keeping certification bound to the exact identity.

### Receipt archive

Every supplied certification receipt is validated and bound to the exact record before archival. Receipts used by registration or promotion are stored immutably with their SHA-256 content reference. Updating a connector never destroys earlier certification evidence.

### Signed authorization grants

Layer 7 uses Ed25519 signatures from the Go standard library.

A signed grant binds:

- a CSPRNG-generated grant ID
- signing key ID
- principal
- exact resource domain
- exact resource reference
- normalized granted scopes
- issued-at timestamp
- expiration timestamp

The grant ID provides uniqueness; there is no separate nonce field. Grant payloads are canonicalized before signing. Grant signatures are persisted, but private signing keys are never written to the governance snapshot. Entropy failures return an error and fail the operation closed.

A grant is usable only when:

1. its signature verifies against the configured key,
2. its time window is valid,
3. it exists in durable governance state,
4. it has not been revoked,
5. its exact principal/resource/scope data matches the persisted grant.

The router never trusts caller-supplied `AuthorizationContext`; the service derives authorization from the verified persisted grant and overwrites request authorization before calling Layer 6 `Select`.

### Evidence ledger

State-changing governance operations append a `GovernanceEvent` and a corresponding `EvidenceEntry`.

`GovernanceEvent` carries the event ID, timestamp, operation metadata, and a hash of the resulting durable governance state. `EvidenceEntry` carries:

- sequence number
- event SHA-256
- previous ledger-entry hash
- current ledger-entry hash

`VerifyEvidenceLedger` validates sequence continuity, event hashes, previous-hash links, entry hashes, and the final event's state hash against the current persisted registry/receipt/grant state. Historical evidence edits and direct current-state edits are therefore detectable.

This is tamper-evident integrity, not a keyed authenticity guarantee against an attacker who can rewrite the entire snapshot and recompute every unkeyed hash. Stronger external anchoring belongs to a later backend/evidence layer.

### Atomic lifecycle transitions

`Transition` performs one durable CAS operation that:

1. loads the latest stored record,
2. validates the caller's expected record revision,
3. validates `CanTransition`,
4. validates certification evidence when entering a certified state,
5. updates the record and record revision,
6. archives any new receipt,
7. appends an event and evidence-ledger entry,
8. commits against the loaded global snapshot revision.

No intermediate lifecycle state is durable.

### Drift handling

`ObserveDrift` runs Layer 6 `DetectDrift` against the latest record. Material drift captures one operation timestamp, appends a drift event, and atomically persists the detected next state and updated record revision in the same snapshot commit.

### Router-facing API

`SelectWithGrant`:

1. verifies and loads the persisted signed grant,
2. derives `AuthorizationContext`,
3. loads the latest records,
4. calls Layer 6 deterministic `Select`,
5. returns the selected stored record, grant ID, and verified snapshot revision.

Revoked, expired, tampered, or unpersisted grants fail before connector selection.

## Failure model

Layer 7 fails closed on:

- stale snapshot revision
- stale record revision
- invalid lifecycle transition
- invalid or mismatched certification evidence
- corrupted snapshot JSON
- evidence-ledger or current-state integrity failure
- invalid/tampered/expired/revoked/unissued authorization grants
- symlinked file-store paths
- path canonicalization failure
- entropy failure while generating persistent IDs
- atomic persistence failure

## Non-goals for v1

- distributed consensus
- cross-host locking
- SQL migrations
- secret/private-key storage
- automatic retry of CAS conflicts
- policy-language evaluation
- network HTTP server

Those belong to later adapters/runtime layers, not the persistence contract itself.
