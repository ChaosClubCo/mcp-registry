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

func TestEvidenceLedgerBindsCommittedSnapshotRevision(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	service := testGovernanceService(t, NewMemoryGovernanceStore(), testGrantSigner(t), func() time.Time { return now })
	if _, err := service.Register(ctx, validRecord(validReceipt(now))); err != nil {
		t.Fatal(err)
	}

	snapshot, err := service.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidenceLedger(snapshot); err != nil {
		t.Fatal(err)
	}

	tampered := snapshot
	tampered.Revision++
	if err := VerifyEvidenceLedger(tampered); err == nil {
		t.Fatal("snapshot revision tampering must invalidate the governance state commitment")
	}
}
