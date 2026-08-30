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
	"sort"
	"strings"
)

func DetectDrift(record RegistryRecord, observation Observation) DriftResult {
	if record.CertificationState == StateRevoked {
		return DriftResult{NextState: StateRevoked}
	}

	reasons := []string{}
	if observation.Version != "" && observation.Version != record.Version {
		reasons = append(reasons, "connector_version")
	}
	if observation.SchemaHash != "" && observation.SchemaHash != record.SchemaHash {
		reasons = append(reasons, "schema_hash")
	}
	if observation.RequiredScopes != nil && !sameStringSet(record.RequiredScopes, observation.RequiredScopes) {
		reasons = append(reasons, "required_scopes")
	}
	if strings.TrimSpace(observation.AuthModel) != "" && !strings.EqualFold(strings.TrimSpace(record.AuthModel), strings.TrimSpace(observation.AuthModel)) {
		reasons = append(reasons, "auth_model")
	}
	if len(observation.ToolNames) > 0 && !sameStringSet(record.ToolNames, observation.ToolNames) {
		reasons = append(reasons, "tool_names")
	}

	if len(reasons) == 0 {
		return DriftResult{Material: false, NextState: record.CertificationState}
	}

	next := record.CertificationState
	switch record.CertificationState {
	case StateReadCertified, StateWriteCertified, StateProductionCertified:
		next = StateRecertificationRequired
	case StateQuarantined:
		next = StateQuarantined
	}
	return DriftResult{Material: true, Reasons: reasons, NextState: next}
}

func sameStringSet(a, b []string) bool {
	aa := normalizeSet(a)
	bb := normalizeSet(b)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func normalizeSet(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
