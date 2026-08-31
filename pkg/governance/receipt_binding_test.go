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

func TestRegistryCertificationStateCannotOutrankReceipt(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)
	receipt.CertificationState = StateReadCertified
	receipt.ProviderState = nil

	record := validRecord(receipt)
	record.CertificationState = StateProductionCertified

	if err := ValidateReceiptBinding(record, receipt, now); err == nil {
		t.Fatal("production registry state must not be backed by read-only certification evidence")
	}
}

func TestExpiredReceiptCannotRemainEligible(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	receipt := validReceipt(now)
	expired := now.Add(-time.Minute)
	receipt.ExpiresAt = &expired

	record := validRecord(receipt)
	req := authorizedRequest(CapabilityRead, RiskR1, []string{"repo:read"})
	if err := Eligible(record, req, now); err == nil {
		t.Fatal("expired certification receipt must fail routing eligibility")
	}
}
