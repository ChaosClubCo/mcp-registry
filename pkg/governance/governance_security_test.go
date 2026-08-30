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

func TestSideEffectCapabilitiesRequireWriteCertification(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)
	record := validRecord(receipt)
	record.CertificationState = StateReadCertified
	record.Capabilities = append(record.Capabilities, CapabilityDeploy, CapabilityCommunicate, CapabilityExecute)

	for _, capability := range []Capability{CapabilityDeploy, CapabilityCommunicate, CapabilityExecute} {
		req := Request{
			Capability:     capability,
			ResourceDomain: "repository",
			Risk:           RiskR3,
			GrantedScopes:  []string{"repo:read"},
		}
		if err := Eligible(record, req, now); err == nil {
			t.Fatalf("READ_CERTIFIED must not authorize side-effect capability %s", capability)
		}
	}
}

func TestCertifiedWriteReceiptRequiresIndependentPostStateProof(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)
	receipt.ProviderState = nil
	if err := receipt.Validate(now); err == nil {
		t.Fatal("certified mutation without provider post-state proof must fail")
	}

	receipt = validReceipt(now)
	receipt.ProviderState.PostStateHash = ""
	if err := receipt.Validate(now); err == nil {
		t.Fatal("certified mutation without verified post-state hash must fail")
	}
}

func TestPreferredConnectorCannotBypassEligibility(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)
	preferred := validRecord(receipt)
	preferred.ConnectorID = "preferred-but-revoked"
	preferred.CertificationReceipt.ConnectorID = preferred.ConnectorID
	preferred.CertificationState = StateRevoked

	fallback := validRecord(receipt)
	fallback.ConnectorID = "eligible-fallback"
	fallback.CertificationReceipt.ConnectorID = fallback.ConnectorID

	req := Request{
		Capability:            CapabilityRead,
		ResourceDomain:        "repository",
		Risk:                  RiskR1,
		GrantedScopes:         []string{"repo:read"},
		PreferredConnectorID: "preferred-but-revoked",
	}

	selected, err := Select([]RegistryRecord{preferred, fallback}, req, now)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if selected.ConnectorID != fallback.ConnectorID {
		t.Fatalf("ineligible preferred connector bypassed policy: got %s", selected.ConnectorID)
	}
}
