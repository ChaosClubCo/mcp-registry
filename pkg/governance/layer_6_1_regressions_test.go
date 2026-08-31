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

func TestEligibilityBindsAuthorizationToConcreteResource(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	record := validRecord(validReceipt(now))
	req := authorizedRequest(CapabilityRead, RiskR1, []string{"repo:read"})
	req.ResourceRef = "repo:allowed"
	req.Authorization.AllowedResourceRefs = []string{"repo:allowed"}

	if err := Eligible(record, req, now); err != nil {
		t.Fatalf("authorized concrete resource rejected: %v", err)
	}

	req.ResourceRef = "repo:other"
	if err := Eligible(record, req, now); err == nil {
		t.Fatal("authorization for one repository must not authorize another repository in the same domain")
	}
}

func TestCertifiedReceiptRequiresPassingStaticGate(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)
	receipt.CaseOutcomes = []CaseOutcome{
		{CaseID: "static.contract", Gate: "static", Status: "SKIP"},
		{CaseID: "runtime.read", Gate: "runtime", Status: "PASS"},
		{CaseID: "mutation.write", Gate: "mutation", Status: "PASS"},
	}
	if err := receipt.Validate(now); err == nil {
		t.Fatal("certified receipt without passing static evidence must fail")
	}
}

func TestMutationReceiptRejectsUnchangedProviderState(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)
	receipt.ProviderState.PostStateHash = receipt.ProviderState.PreStateHash
	if err := receipt.Validate(now); err == nil {
		t.Fatal("mutation certification must prove an actual state transition")
	}
}

func TestAuthModelRemovalIsMaterialDrift(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	record := validRecord(validReceipt(now))
	record.AuthModel = "oauth"

	result := DetectDrift(record, Observation{
		AuthModelObserved: true,
		AuthModel:         "",
	})
	if !result.Material || !hasReason(result.Reasons, "auth_model") {
		t.Fatalf("removal of auth model must be material drift: %+v", result)
	}
}

func TestTransitionGuardRejectsUnknownSameState(t *testing.T) {
	unknown := CertificationState("TYPO_CERTIFIED")
	if CanTransition(unknown, unknown) {
		t.Fatal("unknown lifecycle states must never be accepted, including no-op transitions")
	}
}

func TestReliabilityBelowCertifiedFloorIsMaterialDrift(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	record := validRecord(validReceipt(now))
	record.MinimumReliabilityBasisPoints = 9500
	observed := 9400

	result := DetectDrift(record, Observation{ReliabilityBasisPoints: &observed})
	if !result.Material || !hasReason(result.Reasons, "reliability_threshold") {
		t.Fatalf("reliability below certified floor must demote connector: %+v", result)
	}
	if result.NextState != StateRecertificationRequired {
		t.Fatalf("expected recertification after reliability breach, got %s", result.NextState)
	}
}

func TestCanonicalSchemaHashRejectsDuplicateObjectKeys(t *testing.T) {
	_, err := CanonicalSchemaHash([]byte(`{"type":"string","type":"number"}`))
	if err == nil {
		t.Fatal("ambiguous JSON with duplicate object keys must be rejected")
	}
}

func TestReceiptBindingRequiresExactCertifiedRequiredScopes(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)
	receipt.RequiredScopes = []string{"repo:read", "admin:*"}
	record := validRecord(receipt)
	record.RequiredScopes = []string{"repo:read", "admin:*"}

	if err := ValidateReceiptBinding(record, receipt, now); err != nil {
		t.Fatalf("exact certified required scopes rejected: %v", err)
	}

	record.RequiredScopes = []string{"repo:read"}
	if err := ValidateReceiptBinding(record, receipt, now); err == nil {
		t.Fatal("changing the required-scope boundary must invalidate the certification binding")
	}
}

func hasReason(reasons []string, wanted string) bool {
	for _, reason := range reasons {
		if reason == wanted {
			return true
		}
	}
	return false
}
