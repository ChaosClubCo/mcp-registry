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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestFileGovernanceStorePersistsAcrossServiceRestart(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 6, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "governance", "snapshot.json")
	signer := testGrantSigner(t)

	service := testGovernanceService(t, NewFileGovernanceStore(path), signer, func() time.Time { return now })
	stored, err := service.Register(ctx, validRecord(validReceipt(now)))
	if err != nil {
		t.Fatal(err)
	}

	restarted := testGovernanceService(t, NewFileGovernanceStore(path), signer, func() time.Time { return now })
	got, err := restarted.GetRecord(ctx, stored.Key)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != stored.Key || got.Revision != stored.Revision || got.Record.ConnectorID != stored.Record.ConnectorID {
		t.Fatalf("record changed across restart: got %+v want %+v", got, stored)
	}

	snapshot, err := restarted.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Receipts) != 1 || len(snapshot.Events) == 0 || len(snapshot.Ledger) == 0 {
		t.Fatalf("durable evidence missing after restart: %+v", snapshot)
	}
	if err := VerifyEvidenceLedger(snapshot); err != nil {
		t.Fatalf("persisted evidence ledger invalid: %v", err)
	}
}

func TestFileGovernanceStoreRejectsStaleSnapshotCommit(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "governance.json")
	storeA := NewFileGovernanceStore(path)
	storeB := NewFileGovernanceStore(path)

	a, err := storeA.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := storeB.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}

	a.Events = append(a.Events, GovernanceEvent{ID: "event-a", Type: "test"})
	if err := storeA.Commit(ctx, a.Revision, a); err != nil {
		t.Fatal(err)
	}
	b.Events = append(b.Events, GovernanceEvent{ID: "event-b", Type: "test"})
	if err := storeB.Commit(ctx, b.Revision, b); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected stale snapshot conflict, got %v", err)
	}
}

func TestTransitionUsesRecordRevisionAndArchivesCertificationEvidence(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 6, 0, 0, 0, time.UTC)
	service := testGovernanceService(t, NewMemoryGovernanceStore(), testGrantSigner(t), func() time.Time { return now })

	writeReceipt := validReceipt(now)
	writeReceipt.CertificationState = StateWriteCertified
	writeRecord := validRecord(writeReceipt)
	writeRecord.CertificationState = StateWriteCertified
	stored, err := service.Register(ctx, writeRecord)
	if err != nil {
		t.Fatal(err)
	}

	productionReceipt := validReceipt(now.Add(time.Minute))
	promoted, err := service.Transition(ctx, stored.Key, stored.Revision, StateProductionCertified, &productionReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Record.CertificationState != StateProductionCertified || promoted.Revision != stored.Revision+1 {
		t.Fatalf("unexpected promoted record: %+v", promoted)
	}

	if _, err := service.Transition(ctx, stored.Key, stored.Revision, StateRecertificationRequired, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected stale record revision conflict, got %v", err)
	}

	snapshot, err := service.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Receipts) != 2 {
		t.Fatalf("expected immutable receipt history, got %d receipts", len(snapshot.Receipts))
	}
	if err := VerifyEvidenceLedger(snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestMaterialDriftAtomicallyDemotesAndPersistsEvidence(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 6, 0, 0, 0, time.UTC)
	service := testGovernanceService(t, NewMemoryGovernanceStore(), testGrantSigner(t), func() time.Time { return now })
	record := validRecord(validReceipt(now))
	record.MinimumReliabilityBasisPoints = 9500
	stored, err := service.Register(ctx, record)
	if err != nil {
		t.Fatal(err)
	}

	observed := 9200
	result, demoted, err := service.ObserveDrift(ctx, stored.Key, stored.Revision, Observation{ReliabilityBasisPoints: &observed})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Material || demoted.Record.CertificationState != StateRecertificationRequired {
		t.Fatalf("material drift was not atomically demoted: result=%+v record=%+v", result, demoted)
	}

	snapshot, err := service.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Events) < 2 || snapshot.Events[len(snapshot.Events)-1].Type != EventDriftDetected {
		t.Fatalf("drift event not persisted: %+v", snapshot.Events)
	}
	if err := VerifyEvidenceLedger(snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestSignedGrantDrivesRoutingAndFailsClosedOnTamperExpiryRevocationAndNonIssuance(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 6, 0, 0, 0, time.UTC)
	current := now
	signer := testGrantSigner(t)
	service := testGovernanceService(t, NewMemoryGovernanceStore(), signer, func() time.Time { return current })
	stored, err := service.Register(ctx, validRecord(validReceipt(now)))
	if err != nil {
		t.Fatal(err)
	}

	grant, err := service.IssueGrant(ctx, GrantSpec{
		Principal:      Principal{Type: "user", SubjectRef: "user:test"},
		ResourceDomain: "repository",
		ResourceRef:    "repo:test",
		Scopes:         []string{"repo:read"},
		ExpiresAt:      now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	decision, err := service.SelectWithGrant(ctx, Request{
		Capability:     CapabilityRead,
		ResourceDomain: "repository",
		ResourceRef:    "repo:test",
		Risk:           RiskR1,
	}, grant)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Record.Key != stored.Key || decision.GrantID != grant.Grant.GrantID {
		t.Fatalf("unexpected route decision: %+v", decision)
	}

	tampered := grant
	tampered.Grant.ResourceRef = "repo:other"
	if _, err := service.SelectWithGrant(ctx, Request{Capability: CapabilityRead, ResourceDomain: "repository", ResourceRef: "repo:other", Risk: RiskR1}, tampered); !errors.Is(err, ErrUnauthorizedGrant) {
		t.Fatalf("tampered grant should fail signature verification, got %v", err)
	}

	otherService := testGovernanceService(t, NewMemoryGovernanceStore(), signer, func() time.Time { return current })
	if _, err := otherService.SelectWithGrant(ctx, Request{Capability: CapabilityRead, ResourceDomain: "repository", ResourceRef: "repo:test", Risk: RiskR1}, grant); !errors.Is(err, ErrUnauthorizedGrant) {
		t.Fatalf("valid but unpersisted grant should fail, got %v", err)
	}

	current = now.Add(2 * time.Hour)
	if _, err := service.SelectWithGrant(ctx, Request{Capability: CapabilityRead, ResourceDomain: "repository", ResourceRef: "repo:test", Risk: RiskR1}, grant); !errors.Is(err, ErrUnauthorizedGrant) {
		t.Fatalf("expired grant should fail, got %v", err)
	}
	current = now

	if err := service.RevokeGrant(ctx, grant.Grant.GrantID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SelectWithGrant(ctx, Request{Capability: CapabilityRead, ResourceDomain: "repository", ResourceRef: "repo:test", Risk: RiskR1}, grant); !errors.Is(err, ErrUnauthorizedGrant) {
		t.Fatalf("revoked grant should fail, got %v", err)
	}
}

func TestEvidenceLedgerDetectsHistoricalTampering(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 6, 0, 0, 0, time.UTC)
	service := testGovernanceService(t, NewMemoryGovernanceStore(), testGrantSigner(t), func() time.Time { return now })
	if _, err := service.Register(ctx, validRecord(validReceipt(now))); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueGrant(ctx, GrantSpec{Principal: Principal{Type: "user", SubjectRef: "user:test"}, ResourceDomain: "repository", ResourceRef: "repo:test", Scopes: []string{"repo:read"}, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	snapshot, err := service.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidenceLedger(snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Ledger) < 2 {
		t.Fatalf("expected multiple ledger entries, got %d", len(snapshot.Ledger))
	}

	tampered := snapshot
	tampered.Ledger = append([]EvidenceEntry(nil), snapshot.Ledger...)
	tampered.Ledger[0].EventHash = strings.Repeat("0", 64)
	if err := VerifyEvidenceLedger(tampered); err == nil {
		t.Fatal("tampered ledger must fail verification")
	}
}

func TestFileStoreUsesRestrictedPermissionsRejectsSymlinkAndDoesNotPersistPrivateKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permission and symlink semantics")
	}
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 6, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519GrantSigner("key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !publicKey.Equal(signer.PublicKey()) {
		t.Fatal("signer public key mismatch")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "state", "governance.json")
	service := testGovernanceService(t, NewFileGovernanceStore(path), signer, func() time.Time { return now })
	if _, err := service.Register(ctx, validRecord(validReceipt(now))); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueGrant(ctx, GrantSpec{Principal: Principal{Type: "user", SubjectRef: "user:test"}, ResourceDomain: "repository", ResourceRef: "repo:test", Scopes: []string{"repo:read"}, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("snapshot permissions = %o, want 600", got)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), base64.StdEncoding.EncodeToString(privateKey)) || strings.Contains(string(persisted), hex.EncodeToString(privateKey)) {
		t.Fatal("private signing key leaked into governance snapshot")
	}

	realTarget := filepath.Join(dir, "real.json")
	if err := os.WriteFile(realTarget, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink.json")
	if err := os.Symlink(realTarget, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileGovernanceStore(symlink).Load(ctx); !errors.Is(err, ErrUnsafeStorePath) {
		t.Fatalf("expected unsafe symlink rejection, got %v", err)
	}
}

func testGrantSigner(t *testing.T) *Ed25519GrantSigner {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519GrantSigner("test-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func testGovernanceService(t *testing.T, store GovernanceStore, signer GrantSigner, clock func() time.Time) *GovernanceService {
	t.Helper()
	service, err := NewGovernanceService(store, signer, clock)
	if err != nil {
		t.Fatal(err)
	}
	return service
}
