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
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

func Eligible(record RegistryRecord, req Request, now time.Time) error {
	if record.CertificationState != StateReadCertified && record.CertificationState != StateWriteCertified && record.CertificationState != StateProductionCertified {
		return fmt.Errorf("connector state %s is not routable", record.CertificationState)
	}
	if requiresWriteCertification(req.Capability) && record.CertificationState != StateWriteCertified && record.CertificationState != StateProductionCertified {
		return fmt.Errorf("capability %s requires write certification", req.Capability)
	}
	if !containsCapability(record.Capabilities, req.Capability) {
		return fmt.Errorf("capability %s not supported", req.Capability)
	}
	if !containsStringFold(record.ResourceDomains, req.ResourceDomain) {
		return fmt.Errorf("resource domain %q not supported", req.ResourceDomain)
	}
	if req.Risk > record.RiskCeiling {
		return fmt.Errorf("risk %d exceeds ceiling %d", req.Risk, record.RiskCeiling)
	}
	for _, scope := range record.RequiredScopes {
		if !containsString(req.GrantedScopes, scope) {
			return fmt.Errorf("required scope %q not granted", scope)
		}
	}
	if err := ValidateReceiptBinding(record, record.CertificationReceipt, now); err != nil {
		return fmt.Errorf("certification binding invalid: %w", err)
	}
	return nil
}

func Select(records []RegistryRecord, req Request, now time.Time) (RegistryRecord, error) {
	eligible := make([]RegistryRecord, 0, len(records))
	var rejected []error
	for _, record := range records {
		if err := Eligible(record, req, now); err != nil {
			rejected = append(rejected, fmt.Errorf("%s: %w", record.ConnectorID, err))
			continue
		}
		eligible = append(eligible, record)
	}
	if len(eligible) == 0 {
		return RegistryRecord{}, fmt.Errorf("no eligible connector: %w", errors.Join(rejected...))
	}

	sort.SliceStable(eligible, func(i, j int) bool {
		return betterCandidate(eligible[i], eligible[j], req)
	})
	return eligible[0], nil
}

func requiresWriteCertification(c Capability) bool {
	switch c {
	case CapabilityWrite, CapabilityExecute, CapabilityAutomate, CapabilityDeploy, CapabilityCommunicate, CapabilitySchedule, CapabilitySell:
		return true
	default:
		return false
	}
}

func betterCandidate(a, b RegistryRecord, req Request) bool {
	aPreferred := a.ConnectorID == req.PreferredConnectorID
	bPreferred := b.ConnectorID == req.PreferredConnectorID
	if aPreferred != bPreferred {
		return aPreferred
	}
	if a.NativeAuthority != b.NativeAuthority {
		return a.NativeAuthority
	}
	if aRank, bRank := rankCertification(a.CertificationState), rankCertification(b.CertificationState); aRank != bRank {
		return aRank > bRank
	}
	if a.VerificationStrength != b.VerificationStrength {
		return a.VerificationStrength > b.VerificationStrength
	}
	if a.ReliabilityBasisPoints != b.ReliabilityBasisPoints {
		return a.ReliabilityBasisPoints > b.ReliabilityBasisPoints
	}
	if len(a.RequiredScopes) != len(b.RequiredScopes) {
		return len(a.RequiredScopes) < len(b.RequiredScopes)
	}
	if a.LatencyMillis != b.LatencyMillis {
		return a.LatencyMillis < b.LatencyMillis
	}
	if a.CostUnits != b.CostUnits {
		return a.CostUnits < b.CostUnits
	}
	return a.ConnectorID < b.ConnectorID
}

func rankCertification(s CertificationState) int {
	switch s {
	case StateProductionCertified:
		return 3
	case StateWriteCertified:
		return 2
	case StateReadCertified:
		return 1
	default:
		return 0
	}
}

func containsCapability(values []Capability, wanted Capability) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsStringFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(wanted)) {
			return true
		}
	}
	return false
}
