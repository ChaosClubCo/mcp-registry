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

func TestDriftExplicitEmptyToolSetDetectsAllToolsRemoved(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	record := validRecord(validReceipt(now))

	result := DetectDrift(record, Observation{ToolNames: []string{}})
	if !result.Material {
		t.Fatal("explicitly observed empty tool set must detect removal drift")
	}
}

func TestRouterTieBreaksSameConnectorIDByVersionThenSchemaHash(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	baseReceipt := validReceipt(now)

	a := validRecord(baseReceipt)
	a.ConnectorID = "same-connector"
	a.Version = "1.0.0"
	a.CertificationReceipt.ConnectorID = a.ConnectorID
	a.CertificationReceipt.ConnectorVersion = a.Version

	b := validRecord(baseReceipt)
	b.ConnectorID = "same-connector"
	b.Version = "2.0.0"
	b.CertificationReceipt.ConnectorID = b.ConnectorID
	b.CertificationReceipt.ConnectorVersion = b.Version

	req := Request{
		Capability:     CapabilityRead,
		ResourceDomain: "repository",
		Risk:           RiskR1,
		GrantedScopes:  []string{"repo:read"},
	}

	first, err := Select([]RegistryRecord{b, a}, req, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Select([]RegistryRecord{a, b}, req, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != second.Version {
		t.Fatalf("selection changed with ordering: %s vs %s", first.Version, second.Version)
	}
	if first.Version != "1.0.0" {
		t.Fatalf("expected lexical version tie-break, got %s", first.Version)
	}
}
