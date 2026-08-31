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
	"testing"
	"time"
)

func TestTransitionGuardRejectsIllegalPromotionAndAllowsRevocation(t *testing.T) {
	if CanTransition(StateDiscovered, StateProductionCertified) {
		t.Fatal("DISCOVERED must not transition directly to PRODUCTION_CERTIFIED")
	}
	if !CanTransition(StateCandidate, StateReadCertified) {
		t.Fatal("CANDIDATE should transition to READ_CERTIFIED")
	}
	if !CanTransition(StateReadCertified, StateWriteCertified) {
		t.Fatal("READ_CERTIFIED should transition to WRITE_CERTIFIED")
	}
	if !CanTransition(StateWriteCertified, StateProductionCertified) {
		t.Fatal("WRITE_CERTIFIED should transition to PRODUCTION_CERTIFIED")
	}
	if !CanTransition(StateProductionCertified, StateRecertificationRequired) {
		t.Fatal("PRODUCTION_CERTIFIED should demote to RECERTIFICATION_REQUIRED")
	}
	if !CanTransition(StateProductionCertified, StateRevoked) {
		t.Fatal("any active state should be revocable")
	}
	if CanTransition(StateRevoked, StateProductionCertified) {
		t.Fatal("REVOKED must be terminal")
	}
}

func TestCanonicalSchemaHashIgnoresJSONFormattingAndObjectKeyOrder(t *testing.T) {
	a := []byte(`{"type":"object","properties":{"b":{"type":"string"},"a":{"type":"number"}}}`)
	b := []byte(`{
		"properties": {
			"a": {"type": "number"},
			"b": {"type": "string"}
		},
		"type": "object"
	}`)

	ha, err := CanonicalSchemaHash(a)
	if err != nil {
		t.Fatalf("hash first schema: %v", err)
	}
	hb, err := CanonicalSchemaHash(b)
	if err != nil {
		t.Fatalf("hash second schema: %v", err)
	}
	if ha != hb {
		t.Fatalf("canonical hashes differ: %s != %s", ha, hb)
	}
}

func TestReceiptValidationBindsCertificationToExactConnectorVersionAndSchema(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)

	if err := receipt.Validate(now); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}

	record := validRecord(receipt)
	record.Version = "2.0.0"
	if err := ValidateReceiptBinding(record, receipt, now); err == nil {
		t.Fatal("expected version mismatch to reject certification binding")
	}

	record = validRecord(receipt)
	record.SchemaHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := ValidateReceiptBinding(record, receipt, now); err == nil {
		t.Fatal("expected schema mismatch to reject certification binding")
	}
}

func TestEligibilityFailsClosedForCertificationScopeAndWriteLevel(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)
	record := validRecord(receipt)
	req := authorizedRequest(CapabilityRead, RiskR1, []string{"repo:read"})

	for _, state := range []CertificationState{StateRevoked, StateQuarantined, StateRecertificationRequired} {
		record.CertificationState = state
		if err := Eligible(record, req, now); err == nil {
			t.Fatalf("state %s must not be routable", state)
		}
	}

	record = validRecord(receipt)
	record.CertificationState = StateReadCertified
	writeReq := req
	writeReq.Capability = CapabilityWrite
	writeReq.Risk = RiskR2
	if err := Eligible(record, writeReq, now); err == nil {
		t.Fatal("READ_CERTIFIED must not authorize writes")
	}

	record = validRecord(receipt)
	req.Authorization.GrantedScopes = []string{"repo:metadata"}
	if err := Eligible(record, req, now); err == nil {
		t.Fatal("missing required provider scope must fail closed")
	}
}

func TestRouterIsDeterministicAndPrefersEligibleNativeAuthority(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)
	native := validRecord(receipt)
	native.ConnectorID = "github-native"
	native.NativeAuthority = true
	native.ReliabilityBasisPoints = 9700
	native.LatencyMillis = 200

	bridge := validRecord(receipt)
	bridge.ConnectorID = "automation-bridge"
	bridge.NativeAuthority = false
	bridge.ReliabilityBasisPoints = 9999
	bridge.LatencyMillis = 5
	bridge.CertificationReceipt.ConnectorID = bridge.ConnectorID

	req := authorizedRequest(CapabilityRead, RiskR1, []string{"repo:read"})

	selected, err := Select([]RegistryRecord{bridge, native}, req, now)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if selected.ConnectorID != "github-native" {
		t.Fatalf("expected native authority, got %s", selected.ConnectorID)
	}

	selectedAgain, err := Select([]RegistryRecord{native, bridge}, req, now)
	if err != nil {
		t.Fatalf("select again: %v", err)
	}
	if selectedAgain.ConnectorID != selected.ConnectorID {
		t.Fatalf("selection changed with input ordering: %s vs %s", selected.ConnectorID, selectedAgain.ConnectorID)
	}
}

func TestMaterialDriftDemotesCertifiedConnector(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	record := validRecord(validReceipt(now))
	record.CertificationState = StateProductionCertified
	record.AuthModel = "oauth"
	record.ToolNames = []string{"issues.read", "issues.write"}

	result := DetectDrift(record, Observation{
		SchemaHash:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RequiredScopes: []string{"repo:read", "repo:write"},
		AuthModel:      "oauth",
		ToolNames:      []string{"issues.read", "issues.write"},
	})
	if !result.Material {
		t.Fatal("schema drift should be material")
	}
	if result.NextState != StateRecertificationRequired {
		t.Fatalf("expected RECERTIFICATION_REQUIRED, got %s", result.NextState)
	}

	result = DetectDrift(record, Observation{
		SchemaHash:     record.SchemaHash,
		RequiredScopes: []string{"repo:read", "repo:write", "admin:org"},
		AuthModel:      "oauth",
		ToolNames:      []string{"issues.read", "issues.write"},
	})
	if !result.Material {
		t.Fatal("scope drift should be material")
	}
}

func validRecord(receipt CertificationReceipt) RegistryRecord {
	return RegistryRecord{
		ConnectorID:             receipt.ConnectorID,
		Version:                 receipt.ConnectorVersion,
		SchemaHash:              receipt.SchemaHash,
		Capabilities:            []Capability{CapabilityRead, CapabilityWrite},
		ResourceDomains:         []string{"repository"},
		RiskCeiling:             RiskR3,
		RequiredScopes:          []string{"repo:read"},
		CertificationState:      StateProductionCertified,
		CertificationReceipt:    receipt,
		VerificationStrength:    100,
		ReliabilityBasisPoints:  9900,
		LatencyMillis:           50,
		CostUnits:               10,
		AuthModel:               "oauth",
		ToolNames:               []string{"issues.read", "issues.write"},
	}
}

func validReceipt(now time.Time) CertificationReceipt {
	return CertificationReceipt{
		SchemaVersion:    "MCPCertificationReceipt/v1",
		ConnectorID:      "github-native",
		ConnectorVersion: "1.0.0",
		SchemaHash:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Principal: Principal{
			Type:       "user",
			SubjectRef: "user:test",
		},
		Scopes:         []string{"repo:read", "repo:write"},
		RequiredScopes: []string{"repo:read"},
		TestRunID:      "run-1",
		CaseOutcomes: []CaseOutcome{
			{CaseID: "static.contract", Gate: "static", Status: "PASS"},
			{CaseID: "runtime.read", Gate: "runtime", Status: "PASS"},
			{CaseID: "mutation.write", Gate: "mutation", Status: "PASS"},
		},
		ProviderState: &ProviderState{
			PreStateHash:  "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			PostStateHash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			TargetRef:     "repo:test",
		},
		CredentialLifecycle: CredentialLifecycle{
			CredentialRef:      "cred:test",
			Fingerprint:        "fp:test",
			RevocationTested:   true,
			RevocationEnforced: true,
		},
		CertificationState: StateProductionCertified,
		CertifiedAt:        now.Add(-time.Hour),
		ExpiresAt:          ptrTime(now.Add(24 * time.Hour)),
	}
}

func authorizedRequest(capability Capability, risk RiskClass, scopes []string) Request {
	return Request{
		Capability:     capability,
		ResourceDomain: "repository",
		ResourceRef:    "repo:test",
		Risk:           risk,
		Authorization: AuthorizationContext{
			Principal:              Principal{Type: "user", SubjectRef: "user:test"},
			GrantedScopes:          scopes,
			AllowedResourceDomains: []string{"repository"},
			AllowedResourceRefs:    []string{"repo:test"},
		},
	}
}

func ptrTime(v time.Time) *time.Time { return &v }
