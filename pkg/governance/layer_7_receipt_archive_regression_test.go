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
	"testing"
	"time"
)

func TestRegisterRejectsUnboundReceiptOnNonCertifiedRecord(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 7, 15, 0, 0, time.UTC)
	service := testGovernanceService(t, NewMemoryGovernanceStore(), testGrantSigner(t), func() time.Time { return now })

	record := validRecord(validReceipt(now))
	record.CertificationState = StateCandidate
	// Leave the embedded receipt PRODUCTION_CERTIFIED. It must not be archived
	// as evidence for a candidate record.
	if _, err := service.Register(ctx, record); err == nil {
		t.Fatal("non-certified record must not archive an unbound certification receipt")
	}

	snapshot, err := service.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Receipts) != 0 || len(snapshot.Records) != 0 {
		t.Fatalf("rejected registration mutated persistent governance state: %+v", snapshot)
	}
}
