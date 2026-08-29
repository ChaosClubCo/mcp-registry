# MCP Ecosystem Architecture

Status: proposed architecture baseline

This document captures the five-layer MCP ecosystem model used to turn connector discovery into deterministic, governed, evidence-backed runtime selection.

## Layer 1 — Ecosystem inventory

Purpose: maintain a normalized inventory of available MCPs/connectors and classify each by its primary capability domain.

Canonical capability domains include:

- app builders and web development
- cloud, infrastructure, and backend
- developer tools and platform engineering
- AI agents, automation, and orchestration
- work, knowledge, and collaboration
- communication, calendar, and contacts
- CRM, sales, marketing, and advertising
- commerce and shopping
- research, search, and education
- media, design, and creative tooling
- identity, authentication, security, and compliance
- finance and health
- specialized utilities
- plugin and system utilities

Inventory records are descriptive only. Presence in the inventory MUST NOT imply production eligibility.

## Layer 2 — Semantic capability graph

Purpose: model what each MCP can do and how capability domains relate.

Normalized semantic operations:

- `discover`
- `search`
- `read`
- `write`
- `execute`
- `automate`
- `deploy`
- `observe`
- `authorize`
- `govern`
- `generate_media`
- `store_knowledge`
- `communicate`
- `schedule`
- `sell`
- `analyze`

Edges SHOULD describe typed relationships rather than generic adjacency. Examples:

- `deploys_through`
- `reads_from`
- `writes_to`
- `authenticates_with`
- `observes`
- `verifies`
- `orchestrates`
- `produces_for`
- `fulfills_for`
- `grounds`

## Layer 3 — Runtime routing, trust, and evidence

Purpose: execute requests through explicit control, read, write, agent, trust, evidence, and failure-containment planes.

### Control plane

Every request MUST pass through:

1. intent normalization
2. capability resolution
3. identity/principal resolution
4. resource and scope binding
5. risk classification
6. approval evaluation
7. idempotency/replay evaluation for mutations
8. deterministic planning

### Risk classes

| Class | Meaning | Typical examples |
| --- | --- | --- |
| `R0` | public/read-only | public search, public repo metadata |
| `R1` | authenticated read | private docs, inbox reads, CRM reads |
| `R2` | reversible low-risk write | draft creation, labels, non-production metadata |
| `R3` | material external mutation | email send, calendar change, CRM mutation, deployment |
| `R4` | sensitive or potentially irreversible | payments, destructive operations, privileged security changes |

### Evidence plane

Each meaningful execution SHOULD emit or contribute to an `ExecutionReceipt/v1` containing at minimum:

- `request_id`
- selected `mcp_id`
- operation name
- principal identity or stable principal reference
- granted scopes
- canonical input hash
- precondition hash when applicable
- provider result identifiers
- independently verified post-state hash when applicable
- start and completion timestamps
- status and normalized error class

Write operations MUST use independent read-back verification whenever the provider exposes a separately queryable resulting state.

### Failure containment

Mutation-capable MCPs MUST declare whether operations are:

- idempotent
- replay-safe
- compensatable
- irreversible

Retries MUST be bounded. Non-replay-safe failures MUST move to compensation or manual review rather than blind retry.

## Layer 4 — Canonical registry and deterministic selection

Purpose: make MCP selection reproducible rather than model-improvised.

Each MCP registry record SHOULD contain:

```text
identity
  connector_id
  canonical_name
  vendor
  version

capabilities[]
resource_domains[]
risk_ceiling
auth_model
required_scopes[]
mutation_semantics
verification_contract
operational_limits
fallbacks[]
prohibitions[]
certification_state
certification_receipt_ref
```

### Hard eligibility filter

A candidate MUST be rejected before scoring when any of the following is false:

1. required capability is supported
2. resource/domain matches the target
3. authenticated principal is authorized
4. required scopes are present
5. requested risk level is permitted
6. connector is not revoked or quarantined
7. certification state is sufficient for the operation

### Deterministic scoring

Eligible candidates MAY be scored using weighted dimensions such as:

- capability fit
- native authority / system ownership
- verification strength
- recent reliability
- latency and cost
- least privilege
- explicit canonical-system preference

Native system ownership SHOULD outrank indirect integrations when both can safely perform the same operation. For example, repository mutations should normally prefer GitHub for GitHub resources rather than an unrelated automation bridge.

## Layer 5 — Certification, drift detection, and promotion lifecycle

Purpose: determine which discovered MCPs are trusted enough for Layer 4 routing.

Canonical lifecycle states:

```text
DISCOVERED
CANDIDATE
READ_CERTIFIED
WRITE_CERTIFIED
PRODUCTION_CERTIFIED
RECERTIFICATION_REQUIRED
QUARANTINED
REVOKED
```

### Static certification gates

A candidate MUST pass:

- schema parsing and canonicalization
- capability classification
- resource-domain classification
- auth and scope declaration
- side-effect labeling
- idempotency declaration
- verification-strategy declaration
- fallback/prohibition declaration

### Runtime certification gates

At minimum:

1. discovery handshake or provider-equivalent capability discovery
2. tool listing and schema parity
3. read-only smoke test
4. scope-boundary test
5. credential revocation test
6. timeout/retry behavior test
7. normalized error taxonomy test
8. rate-limit behavior test when observable

### Mutation certification gates

Write-capable MCPs MUST additionally prove:

1. provider pre-state snapshot
2. exactly one bounded mutation
3. provider result and request identifier capture
4. independent read-back
5. exactly one intended state transition
6. replay/idempotency behavior
7. conflict or stale-version behavior when supported
8. out-of-scope provider denial
9. rollback or compensating-action behavior when supported
10. credential revocation followed by confirmed execution failure

A write-capable connector MUST NOT receive `WRITE_CERTIFIED` solely because the mutation call returned success.

### Certification score

Certification scoring SHOULD include:

- contract correctness
- least privilege
- read-back strength
- idempotency/replay safety
- deterministic error behavior
- availability/latency
- revocation enforcement
- evidence completeness

The score is advisory unless paired with explicit promotion thresholds. Hard safety gates MUST NOT be overridden by a high aggregate score.

### Drift detection

A production-certified connector MUST be monitored for material drift including:

- manifest/schema hash changes
- tool additions, removals, or renames
- scope changes
- auth behavior changes
- verification behavior changes
- reliability threshold breaches
- provider policy/version changes

Material drift MUST move the connector to `RECERTIFICATION_REQUIRED` or `QUARANTINED` according to policy. A `REVOKED` connector is a hard exclusion from routing.

## MCPCertificationReceipt/v1

The certification receipt binds the evidence used to promote a connector.

Required semantic fields:

- `schema_version`
- `connector_id`
- `connector_version`
- `schema_hash`
- `principal`
- `scopes`
- `test_run_id`
- case-level outcomes
- provider pre/post state hashes when applicable
- credential lifecycle proof
- certification state
- `certified_at`
- `expires_at` or explicit non-expiring policy

The machine-readable schema lives at:

`docs/schemas/mcp-certification-receipt-v1.schema.json`

The Layer 5 source diagram lives at:

`docs/architecture/layer-5-certification-lifecycle.mmd`

## Implementation considerations

- Registry identity should be stable across display-name changes.
- Tool schemas should be canonicalized before hashing to avoid meaningless drift from formatting or property order.
- Scope comparisons should use normalized provider-specific scope identifiers.
- Certification test targets must be isolated from production user data.
- Mutation verification must query provider state independently of the mutation response where possible.
- Promotion decisions should be bound to immutable evidence and the exact connector/schema version tested.

## Performance and security notes

- Cache read-only registry metadata, but never cache authorization decisions beyond their safe validity window.
- Keep credentials out of certification receipts; store only stable references, fingerprints, or lifecycle evidence.
- Treat personal health, financial, authentication, payment, destructive, and privileged security operations as elevated-risk regardless of connector marketing claims.
- Auto-demotion on material drift is safer than attempting to infer backward compatibility.
- Evidence storage should be append-only or tamper-evident for production certification.

## Recommended next implementation phase

1. Add canonical registry record types to the registry service.
2. Add the certification state machine and transition guards.
3. Add receipt validation against `MCPCertificationReceipt/v1`.
4. Implement schema canonicalization and hashing.
5. Add certification runner interfaces for static, runtime, and mutation test suites.
6. Make router eligibility depend on certification state.
7. Add drift detection and automatic demotion.
8. Add tests proving quarantined and revoked connectors are never routed.

## Claims check

- This document defines an architecture contract; it does not claim that every connector in the ecosystem has already passed these certification gates.
- `PRODUCTION_CERTIFIED` is meaningful only when bound to immutable, version-specific evidence.
- Successful provider responses are insufficient proof of successful mutation without independent state verification when such verification is possible.
