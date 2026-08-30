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

func CanTransition(from, to CertificationState) bool {
	if from == to {
		return true
	}
	if from == StateRevoked {
		return false
	}
	if to == StateRevoked {
		return true
	}

	allowed := map[CertificationState]map[CertificationState]bool{
		StateDiscovered: {
			StateCandidate:   true,
			StateQuarantined: true,
		},
		StateCandidate: {
			StateReadCertified: true,
			StateQuarantined:   true,
		},
		StateReadCertified: {
			StateWriteCertified:          true,
			StateRecertificationRequired: true,
			StateQuarantined:             true,
		},
		StateWriteCertified: {
			StateProductionCertified:     true,
			StateRecertificationRequired: true,
			StateQuarantined:             true,
		},
		StateProductionCertified: {
			StateRecertificationRequired: true,
			StateQuarantined:             true,
		},
		StateRecertificationRequired: {
			StateCandidate:      true,
			StateReadCertified:  true,
			StateWriteCertified: true,
			StateQuarantined:    true,
		},
		StateQuarantined: {
			StateCandidate: true,
		},
	}

	return allowed[from][to]
}
