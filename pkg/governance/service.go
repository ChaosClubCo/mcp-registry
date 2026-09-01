/*
Copyright © 2025 Docker, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type GovernanceService struct {
	store  GovernanceStore
	signer GrantSigner
	clock  func() time.Time
}

type RouteDecision struct {
	Record           StoredRegistryRecord
	GrantID          string
	SnapshotRevision uint64
}

func NewGovernanceService(store GovernanceStore, signer GrantSigner, clock func() time.Time) (*GovernanceService, error) {
	if store == nil || signer == nil || clock == nil {
		return nil, fmt.Errorf("store signer and clock are required")
	}
	return &GovernanceService{store: store, signer: signer, clock: clock}, nil
}

func recordKey(record RegistryRecord) string {
	raw, _ := json.Marshal(struct {
		ConnectorID string `json:"connector_id"`
		Version     string `json:"version"`
		SchemaHash  string `json:"schema_hash"`
	}{record.ConnectorID, record.Version, record.SchemaHash})
	return "mcp:" + sha256Hex(raw)
}

func (s *GovernanceService) load(ctx context.Context) (GovernanceSnapshot, error) {
	snapshot, err := s.store.Load(ctx)
	if err != nil {
		return GovernanceSnapshot{}, err
	}
	snapshot = normalizeSnapshot(snapshot)
	if err := VerifyEvidenceLedger(snapshot); err != nil {
		return GovernanceSnapshot{}, fmt.Errorf("evidence ledger invalid: %w", err)
	}
	return snapshot, nil
}

func (s *GovernanceService) Snapshot(ctx context.Context) (GovernanceSnapshot, error) {
	snapshot, err := s.load(ctx)
	if err != nil {
		return GovernanceSnapshot{}, err
	}
	return cloneSnapshot(snapshot)
}

func (s *GovernanceService) Register(ctx context.Context, record RegistryRecord) (StoredRegistryRecord, error) {
	now := s.clock()
	if isCertifiedState(record.CertificationState) || record.CertificationReceipt.SchemaVersion != "" {
		if err := ValidateReceiptBinding(record, record.CertificationReceipt, now); err != nil {
			return StoredRegistryRecord{}, err
		}
	}

	snapshot, err := s.load(ctx)
	if err != nil {
		return StoredRegistryRecord{}, err
	}
	key := recordKey(record)
	if _, exists := snapshot.Records[key]; exists {
		return StoredRegistryRecord{}, ErrConflict
	}

	stored := StoredRegistryRecord{Key: key, Revision: 1, Record: record}
	snapshot.Records[key] = stored
	receiptHashValue := ""
	if record.CertificationReceipt.SchemaVersion != "" {
		archived, err := archiveReceipt(key, record.CertificationReceipt, now)
		if err != nil {
			return StoredRegistryRecord{}, err
		}
		snapshot.Receipts = append(snapshot.Receipts, archived)
		receiptHashValue = archived.ReceiptHash
	}
	eventID, err := newID()
	if err != nil {
		return StoredRegistryRecord{}, err
	}
	event := GovernanceEvent{
		ID:          eventID,
		Type:        EventRecordRegistered,
		RecordKey:   key,
		At:          now,
		ToState:     record.CertificationState,
		ReceiptHash: receiptHashValue,
	}
	if err := appendGovernanceEvent(&snapshot, event); err != nil {
		return StoredRegistryRecord{}, err
	}
	if err := s.store.Commit(ctx, snapshot.Revision, snapshot); err != nil {
		return StoredRegistryRecord{}, err
	}
	return stored, nil
}

func (s *GovernanceService) GetRecord(ctx context.Context, key string) (StoredRegistryRecord, error) {
	snapshot, err := s.load(ctx)
	if err != nil {
		return StoredRegistryRecord{}, err
	}
	stored, ok := snapshot.Records[key]
	if !ok {
		return StoredRegistryRecord{}, ErrNotFound
	}
	return stored, nil
}

func (s *GovernanceService) Transition(ctx context.Context, key string, expectedRecordRevision uint64, to CertificationState, receipt *CertificationReceipt) (StoredRegistryRecord, error) {
	snapshot, err := s.load(ctx)
	if err != nil {
		return StoredRegistryRecord{}, err
	}
	stored, ok := snapshot.Records[key]
	if !ok {
		return StoredRegistryRecord{}, ErrNotFound
	}
	if stored.Revision != expectedRecordRevision {
		return StoredRegistryRecord{}, ErrConflict
	}

	from := stored.Record.CertificationState
	if !CanTransition(from, to) {
		return StoredRegistryRecord{}, fmt.Errorf("invalid certification transition %s -> %s", from, to)
	}

	now := s.clock()
	nextRecord := stored.Record
	nextRecord.CertificationState = to
	receiptHashValue := ""
	if isCertifiedState(to) {
		if receipt == nil {
			return StoredRegistryRecord{}, fmt.Errorf("certified transition requires receipt")
		}
		nextRecord.CertificationReceipt = *receipt
		if err := ValidateReceiptBinding(nextRecord, *receipt, now); err != nil {
			return StoredRegistryRecord{}, err
		}
		archived, err := archiveReceipt(key, *receipt, now)
		if err != nil {
			return StoredRegistryRecord{}, err
		}
		snapshot.Receipts = append(snapshot.Receipts, archived)
		receiptHashValue = archived.ReceiptHash
	} else if receipt != nil {
		return StoredRegistryRecord{}, fmt.Errorf("receipt only allowed for certified transition")
	}

	stored.Record = nextRecord
	stored.Revision++
	snapshot.Records[key] = stored
	eventID, err := newID()
	if err != nil {
		return StoredRegistryRecord{}, err
	}
	if err := appendGovernanceEvent(&snapshot, GovernanceEvent{
		ID:          eventID,
		Type:        EventStateTransition,
		RecordKey:   key,
		At:          now,
		FromState:   from,
		ToState:     to,
		ReceiptHash: receiptHashValue,
	}); err != nil {
		return StoredRegistryRecord{}, err
	}
	if err := s.store.Commit(ctx, snapshot.Revision, snapshot); err != nil {
		return StoredRegistryRecord{}, err
	}
	return stored, nil
}

func (s *GovernanceService) ObserveDrift(ctx context.Context, key string, expectedRecordRevision uint64, observation Observation) (DriftResult, StoredRegistryRecord, error) {
	snapshot, err := s.load(ctx)
	if err != nil {
		return DriftResult{}, StoredRegistryRecord{}, err
	}
	stored, ok := snapshot.Records[key]
	if !ok {
		return DriftResult{}, StoredRegistryRecord{}, ErrNotFound
	}
	if stored.Revision != expectedRecordRevision {
		return DriftResult{}, StoredRegistryRecord{}, ErrConflict
	}

	result := DetectDrift(stored.Record, observation)
	if !result.Material {
		return result, stored, nil
	}

	now := s.clock()
	from := stored.Record.CertificationState
	stored.Record.CertificationState = result.NextState
	stored.Revision++
	snapshot.Records[key] = stored
	eventID, err := newID()
	if err != nil {
		return DriftResult{}, StoredRegistryRecord{}, err
	}
	if err := appendGovernanceEvent(&snapshot, GovernanceEvent{
		ID:        eventID,
		Type:      EventDriftDetected,
		RecordKey: key,
		At:        now,
		FromState: from,
		ToState:   result.NextState,
		Reasons:   append([]string(nil), result.Reasons...),
	}); err != nil {
		return DriftResult{}, StoredRegistryRecord{}, err
	}
	if err := s.store.Commit(ctx, snapshot.Revision, snapshot); err != nil {
		return DriftResult{}, StoredRegistryRecord{}, err
	}
	return result, stored, nil
}

func (s *GovernanceService) IssueGrant(ctx context.Context, spec GrantSpec) (SignedAuthorizationGrant, error) {
	now := s.clock()
	if !validPrincipal(spec.Principal) {
		return SignedAuthorizationGrant{}, ErrUnauthorizedGrant
	}
	domain := strings.TrimSpace(spec.ResourceDomain)
	resourceRef := strings.TrimSpace(spec.ResourceRef)
	if domain == "" || domain != spec.ResourceDomain || resourceRef == "" || resourceRef != spec.ResourceRef || !spec.ExpiresAt.After(now) {
		return SignedAuthorizationGrant{}, ErrUnauthorizedGrant
	}
	grantID, err := newID()
	if err != nil {
		return SignedAuthorizationGrant{}, err
	}
	grant := AuthorizationGrant{
		GrantID:        grantID,
		Principal:      spec.Principal,
		ResourceDomain: domain,
		ResourceRef:    resourceRef,
		Scopes:         append([]string(nil), spec.Scopes...),
		IssuedAt:       now,
		ExpiresAt:      spec.ExpiresAt,
	}
	signed, err := s.signer.Sign(grant)
	if err != nil {
		return SignedAuthorizationGrant{}, err
	}

	snapshot, err := s.load(ctx)
	if err != nil {
		return SignedAuthorizationGrant{}, err
	}
	eventID, err := newID()
	if err != nil {
		return SignedAuthorizationGrant{}, err
	}
	snapshot.Grants[grant.GrantID] = StoredAuthorizationGrant{Signed: signed}
	if err := appendGovernanceEvent(&snapshot, GovernanceEvent{ID: eventID, Type: EventGrantIssued, GrantID: grant.GrantID, At: now}); err != nil {
		return SignedAuthorizationGrant{}, err
	}
	if err := s.store.Commit(ctx, snapshot.Revision, snapshot); err != nil {
		return SignedAuthorizationGrant{}, err
	}
	return signed, nil
}

func (s *GovernanceService) RevokeGrant(ctx context.Context, grantID string) error {
	snapshot, err := s.load(ctx)
	if err != nil {
		return err
	}
	stored, ok := snapshot.Grants[grantID]
	if !ok {
		return ErrNotFound
	}
	if stored.RevokedAt != nil {
		return nil
	}
	now := s.clock()
	eventID, err := newID()
	if err != nil {
		return err
	}
	stored.RevokedAt = &now
	snapshot.Grants[grantID] = stored
	if err := appendGovernanceEvent(&snapshot, GovernanceEvent{ID: eventID, Type: EventGrantRevoked, GrantID: grantID, At: now}); err != nil {
		return err
	}
	return s.store.Commit(ctx, snapshot.Revision, snapshot)
}

func signedGrantEqual(a, b SignedAuthorizationGrant) bool {
	aRaw, _ := json.Marshal(a)
	bRaw, _ := json.Marshal(b)
	return string(aRaw) == string(bRaw)
}

func (s *GovernanceService) SelectWithGrant(ctx context.Context, req Request, signed SignedAuthorizationGrant) (RouteDecision, error) {
	if err := s.signer.Verify(signed); err != nil {
		return RouteDecision{}, ErrUnauthorizedGrant
	}
	snapshot, err := s.load(ctx)
	if err != nil {
		return RouteDecision{}, err
	}
	now := s.clock()
	storedGrant, ok := snapshot.Grants[signed.Grant.GrantID]
	if !ok || storedGrant.RevokedAt != nil || !signedGrantEqual(storedGrant.Signed, signed) || !now.Before(signed.Grant.ExpiresAt) {
		return RouteDecision{}, ErrUnauthorizedGrant
	}
	if req.ResourceDomain != signed.Grant.ResourceDomain || req.ResourceRef != signed.Grant.ResourceRef {
		return RouteDecision{}, ErrUnauthorizedGrant
	}

	// Caller-supplied authorization is deliberately discarded. The persisted,
	// verified grant is the only source of routing authorization.
	req.Authorization = AuthorizationContext{
		Principal:              signed.Grant.Principal,
		GrantedScopes:          append([]string(nil), signed.Grant.Scopes...),
		AllowedResourceDomains: []string{signed.Grant.ResourceDomain},
		AllowedResourceRefs:    []string{signed.Grant.ResourceRef},
	}
	req.GrantedScopes = nil

	records := make([]RegistryRecord, 0, len(snapshot.Records))
	for _, stored := range snapshot.Records {
		records = append(records, stored.Record)
	}
	selected, err := Select(records, req, now)
	if err != nil {
		return RouteDecision{}, err
	}
	key := recordKey(selected)
	stored, ok := snapshot.Records[key]
	if !ok {
		return RouteDecision{}, errors.New("selected record missing from snapshot")
	}
	return RouteDecision{Record: stored, GrantID: signed.Grant.GrantID, SnapshotRevision: snapshot.Revision}, nil
}
