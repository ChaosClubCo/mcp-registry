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

func TestStoreKnowledgeRequiresWriteCertification(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)
	receipt.CertificationState = StateReadCertified
	receipt.ProviderState = nil
	record := validRecord(receipt)
	record.CertificationState = StateReadCertified
	record.Capabilities = append(record.Capabilities, CapabilityStoreKnowledge)

	if err := Eligible(record, Request{
		Capability:     CapabilityStoreKnowledge,
		ResourceDomain: "repository",
		Risk:           RiskR2,
		GrantedScopes:  []string{"repo:read"},
	}, now); err == nil {
		t.Fatal("READ_CERTIFIED must not authorize persistent knowledge writes")
	}
}

func TestReadCertificationRequiresCredentialRevocationProof(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)
	receipt.CertificationState = StateReadCertified
	receipt.ProviderState = nil
	receipt.CredentialLifecycle = CredentialLifecycle{}

	if err := receipt.Validate(now); err == nil {
		t.Fatal("READ_CERTIFIED without revocation proof must fail")
	}
}

func TestReceiptRejectsUnknownStateAndInvalidScopes(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)

	receipt := validReceipt(now)
	receipt.CertificationState = CertificationState("BOGUS")
	if err := receipt.Validate(now); err == nil {
		t.Fatal("unknown certification state must fail")
	}

	receipt = validReceipt(now)
	receipt.Scopes = []string{"repo:read", "repo:read"}
	if err := receipt.Validate(now); err == nil {
		t.Fatal("duplicate scopes must fail")
	}

	receipt = validReceipt(now)
	receipt.Scopes = []string{"repo:read", "  "}
	if err := receipt.Validate(now); err == nil {
		t.Fatal("blank scope must fail")
	}
}

func TestCanonicalSchemaHashNormalizesEquivalentJSONNumbers(t *testing.T) {
	a := []byte(`{"type":"number","minimum":1,"maximum":1000}`)
	b := []byte(`{"maximum":1e3,"minimum":1.0,"type":"number"}`)

	ha, err := CanonicalSchemaHash(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := CanonicalSchemaHash(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("equivalent numeric schemas must hash identically: %s != %s", ha, hb)
	}
}
