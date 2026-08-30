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
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

func (r CertificationReceipt) Validate(now time.Time) error {
	if r.SchemaVersion != "MCPCertificationReceipt/v1" {
		return fmt.Errorf("unsupported receipt schema %q", r.SchemaVersion)
	}
	if strings.TrimSpace(r.ConnectorID) == "" || strings.TrimSpace(r.ConnectorVersion) == "" {
		return fmt.Errorf("connector id and version are required")
	}
	if !validSHA256Ref(r.SchemaHash) {
		return fmt.Errorf("invalid schema hash")
	}
	if !validPrincipal(r.Principal) {
		return fmt.Errorf("invalid principal")
	}
	if !validCertificationState(r.CertificationState) {
		return fmt.Errorf("invalid certification state %q", r.CertificationState)
	}

	seenScopes := make(map[string]struct{}, len(r.Scopes))
	for _, scope := range r.Scopes {
		canonical := strings.TrimSpace(scope)
		if canonical == "" || canonical != scope {
			return fmt.Errorf("invalid scope %q", scope)
		}
		if _, exists := seenScopes[canonical]; exists {
			return fmt.Errorf("duplicate scope %q", canonical)
		}
		seenScopes[canonical] = struct{}{}
	}

	if strings.TrimSpace(r.TestRunID) == "" {
		return fmt.Errorf("test run id is required")
	}
	if len(r.CaseOutcomes) == 0 {
		return fmt.Errorf("case outcomes are required")
	}

	passedGates := map[string]bool{}
	for _, c := range r.CaseOutcomes {
		if c.CaseID == "" {
			return fmt.Errorf("case id is required")
		}
		switch c.Gate {
		case "static", "runtime", "mutation", "drift":
		default:
			return fmt.Errorf("invalid gate %q", c.Gate)
		}
		switch c.Status {
		case "PASS":
			passedGates[c.Gate] = true
		case "SKIP":
		case "FAIL":
			if isCertifiedState(r.CertificationState) {
				return fmt.Errorf("certified receipt contains failed case %s", c.CaseID)
			}
		default:
			return fmt.Errorf("invalid status %q", c.Status)
		}
	}
	if isCertifiedState(r.CertificationState) && !passedGates["runtime"] {
		return fmt.Errorf("certified receipt requires passing runtime evidence")
	}
	if (r.CertificationState == StateWriteCertified || r.CertificationState == StateProductionCertified) && !passedGates["mutation"] {
		return fmt.Errorf("mutation certification requires passing mutation evidence")
	}

	if r.CertifiedAt.IsZero() || r.CertifiedAt.After(now) {
		return fmt.Errorf("invalid certified_at")
	}
	if r.ExpiresAt == nil && (r.NonExpiringPolicyRef == nil || strings.TrimSpace(*r.NonExpiringPolicyRef) == "") {
		return fmt.Errorf("expiry or non-expiring policy is required")
	}
	if r.ExpiresAt != nil {
		if !r.ExpiresAt.After(r.CertifiedAt) {
			return fmt.Errorf("expiry must be after certification")
		}
		if !now.Before(*r.ExpiresAt) {
			return fmt.Errorf("certification expired")
		}
	}

	if isCertifiedState(r.CertificationState) {
		if !r.CredentialLifecycle.RevocationTested || !r.CredentialLifecycle.RevocationEnforced {
			return fmt.Errorf("credential revocation proof is required")
		}
	}
	if r.CertificationState == StateWriteCertified || r.CertificationState == StateProductionCertified {
		if r.ProviderState == nil || !validSHA256Ref(r.ProviderState.PreStateHash) || !validSHA256Ref(r.ProviderState.PostStateHash) {
			return fmt.Errorf("verified provider pre- and post-state are required")
		}
	}
	return nil
}

func ValidateReceiptBinding(record RegistryRecord, receipt CertificationReceipt, now time.Time) error {
	if err := receipt.Validate(now); err != nil {
		return err
	}
	if record.CertificationState != receipt.CertificationState {
		return fmt.Errorf("receipt certification state mismatch")
	}
	if record.ConnectorID != receipt.ConnectorID {
		return fmt.Errorf("receipt connector mismatch")
	}
	if record.Version != receipt.ConnectorVersion {
		return fmt.Errorf("receipt version mismatch")
	}
	if record.SchemaHash != receipt.SchemaHash {
		return fmt.Errorf("receipt schema mismatch")
	}
	for _, scope := range record.RequiredScopes {
		if !containsString(receipt.Scopes, scope) {
			return fmt.Errorf("receipt did not certify scope %q", scope)
		}
	}
	return nil
}

func validSHA256Ref(s string) bool {
	if !strings.HasPrefix(s, "sha256:") {
		return false
	}
	b, err := hex.DecodeString(strings.TrimPrefix(s, "sha256:"))
	return err == nil && len(b) == 32
}

func validPrincipal(p Principal) bool {
	if strings.TrimSpace(p.SubjectRef) == "" {
		return false
	}
	switch p.Type {
	case "user", "service", "workspace", "delegated":
		return true
	default:
		return false
	}
}

func samePrincipal(a, b Principal) bool {
	return a.Type == b.Type && a.SubjectRef == b.SubjectRef
}

func isCertifiedState(s CertificationState) bool {
	return s == StateReadCertified || s == StateWriteCertified || s == StateProductionCertified
}

func validCertificationState(s CertificationState) bool {
	switch s {
	case StateDiscovered, StateCandidate, StateReadCertified, StateWriteCertified, StateProductionCertified, StateRecertificationRequired, StateQuarantined, StateRevoked:
		return true
	default:
		return false
	}
}
