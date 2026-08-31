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
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCertifiedReceiptRequiresPassingApplicableGates(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)

	readReceipt := validReceipt(now)
	readReceipt.CertificationState = StateReadCertified
	readReceipt.ProviderState = nil
	readReceipt.CaseOutcomes = []CaseOutcome{
		{CaseID: "static.contract", Gate: "static", Status: "PASS"},
		{CaseID: "runtime.read", Gate: "runtime", Status: "SKIP"},
	}
	if err := readReceipt.Validate(now); err == nil {
		t.Fatal("READ_CERTIFIED must require at least one passing runtime case")
	}

	writeReceipt := validReceipt(now)
	writeReceipt.CaseOutcomes = []CaseOutcome{
		{CaseID: "static.contract", Gate: "static", Status: "PASS"},
		{CaseID: "runtime.read", Gate: "runtime", Status: "PASS"},
		{CaseID: "mutation.write", Gate: "mutation", Status: "SKIP"},
	}
	if err := writeReceipt.Validate(now); err == nil {
		t.Fatal("PRODUCTION_CERTIFIED must require at least one passing mutation case")
	}
}

func TestMutationReceiptRequiresPreAndPostStateProof(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)
	receipt.ProviderState.PreStateHash = ""
	if err := receipt.Validate(now); err == nil {
		t.Fatal("mutation certification without provider pre-state hash must fail")
	}
}

func TestCertificationReceiptUsesCanonicalJSONFieldNames(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)

	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, key := range []string{"schema_version", "connector_id", "connector_version", "schema_hash", "subject_ref", "scopes", "required_scopes", "test_run_id", "case_outcomes", "credential_lifecycle", "certification_state", "certified_at"} {
		if !strings.Contains(text, `"`+key+`"`) {
			t.Fatalf("canonical receipt JSON missing key %q: %s", key, text)
		}
	}
	if strings.Contains(text, `"SchemaVersion"`) || strings.Contains(text, `"ConnectorID"`) {
		t.Fatalf("receipt leaked Go field names: %s", text)
	}

	var roundTrip CertificationReceipt
	if err := json.Unmarshal(raw, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.ConnectorID != receipt.ConnectorID || roundTrip.Principal.SubjectRef != receipt.Principal.SubjectRef {
		t.Fatalf("canonical JSON round trip lost identity: %+v", roundTrip)
	}
}

func TestEligibilityRequiresPrincipalAndTargetAuthorization(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	record := validRecord(validReceipt(now))
	base := Request{
		Capability:     CapabilityRead,
		ResourceDomain: "repository",
		ResourceRef:    "repo:test",
		Risk:           RiskR1,
	}

	if err := Eligible(record, base, now); err == nil {
		t.Fatal("missing authorization context must fail closed")
	}

	good := base
	good.Authorization = AuthorizationContext{
		Principal:              record.CertificationReceipt.Principal,
		GrantedScopes:          []string{"repo:read"},
		AllowedResourceDomains: []string{"repository"},
		AllowedResourceRefs:    []string{"repo:test"},
	}
	if err := Eligible(record, good, now); err != nil {
		t.Fatalf("valid authorization rejected: %v", err)
	}

	wrongPrincipal := good
	wrongPrincipal.Authorization.Principal.SubjectRef = "user:other"
	if err := Eligible(record, wrongPrincipal, now); err == nil {
		t.Fatal("authorization principal must be bound to certification principal")
	}

	wrongTarget := good
	wrongTarget.Authorization.AllowedResourceDomains = []string{"calendar"}
	if err := Eligible(record, wrongTarget, now); err == nil {
		t.Fatal("principal not authorized for target resource domain must fail")
	}
}

func TestSideEffectClassificationFailsClosed(t *testing.T) {
	for _, capability := range []Capability{CapabilityWrite, CapabilityExecute, CapabilityAutomate, CapabilityDeploy, CapabilityGovern, CapabilityGenerateMedia, CapabilityStoreKnowledge, CapabilityCommunicate, CapabilitySchedule, CapabilitySell} {
		if !requiresWriteCertification(capability) {
			t.Fatalf("side-effect capability %s must require write certification", capability)
		}
	}
	for _, capability := range []Capability{CapabilityDiscover, CapabilitySearch, CapabilityRead, CapabilityObserve, CapabilityAnalyze} {
		if requiresWriteCertification(capability) {
			t.Fatalf("read-only capability %s unexpectedly requires write certification", capability)
		}
	}
}

func TestScopeCountIsNotUsedAsLeastPrivilegeRanking(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)

	narrowReceipt := validReceipt(now)
	narrowReceipt.ConnectorID = "a-two-narrow"
	narrowReceipt.Scopes = []string{"repo:read", "repo:metadata", "repo:write"}
	narrowReceipt.RequiredScopes = []string{"repo:read", "repo:metadata"}
	narrow := validRecord(narrowReceipt)
	narrow.ConnectorID = narrowReceipt.ConnectorID
	narrow.RequiredScopes = []string{"repo:read", "repo:metadata"}

	adminReceipt := validReceipt(now)
	adminReceipt.ConnectorID = "z-one-admin"
	adminReceipt.Scopes = []string{"admin:*", "repo:read", "repo:metadata"}
	adminReceipt.RequiredScopes = []string{"admin:*"}
	admin := validRecord(adminReceipt)
	admin.ConnectorID = adminReceipt.ConnectorID
	admin.RequiredScopes = []string{"admin:*"}

	req := Request{
		Capability:     CapabilityRead,
		ResourceDomain: "repository",
		ResourceRef:    "repo:test",
		Risk:           RiskR1,
		Authorization: AuthorizationContext{
			Principal:              narrowReceipt.Principal,
			GrantedScopes:          []string{"repo:read", "repo:metadata", "admin:*"},
			AllowedResourceDomains: []string{"repository"},
			AllowedResourceRefs:    []string{"repo:test"},
		},
	}

	selected, err := Select([]RegistryRecord{admin, narrow}, req, now)
	if err != nil {
		t.Fatal(err)
	}
	if selected.ConnectorID != narrow.ConnectorID {
		t.Fatalf("scope count biased routing toward broader privilege: got %s", selected.ConnectorID)
	}
}
