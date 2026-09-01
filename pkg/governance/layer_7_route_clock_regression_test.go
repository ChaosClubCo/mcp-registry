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

func TestSelectWithGrantSamplesClockOncePerRoutingDecision(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 31, 8, 15, 0, 0, time.UTC)
	store := NewMemoryGovernanceStore()
	signer := testGrantSigner(t)
	setup := testGovernanceService(t, store, signer, func() time.Time { return base })
	if _, err := setup.Register(ctx, validRecord(validReceipt(base))); err != nil {
		t.Fatal(err)
	}
	grant, err := setup.IssueGrant(ctx, GrantSpec{
		Principal:      Principal{Type: "user", SubjectRef: "user:test"},
		ResourceDomain: "repository",
		ResourceRef:    "repo:test",
		Scopes:         []string{"repo:read"},
		ExpiresAt:      base.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	calls := 0
	router := testGovernanceService(t, store, signer, func() time.Time {
		calls++
		return base.Add(time.Minute)
	})
	if _, err := router.SelectWithGrant(ctx, Request{
		Capability:     CapabilityRead,
		ResourceDomain: "repository",
		ResourceRef:    "repo:test",
		Risk:           RiskR1,
	}, grant); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("routing clock sampled %d times, want exactly 1", calls)
	}
}
