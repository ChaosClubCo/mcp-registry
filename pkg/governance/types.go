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

import "time"

type CertificationState string

const (
	StateDiscovered              CertificationState = "DISCOVERED"
	StateCandidate               CertificationState = "CANDIDATE"
	StateReadCertified           CertificationState = "READ_CERTIFIED"
	StateWriteCertified          CertificationState = "WRITE_CERTIFIED"
	StateProductionCertified     CertificationState = "PRODUCTION_CERTIFIED"
	StateRecertificationRequired CertificationState = "RECERTIFICATION_REQUIRED"
	StateQuarantined             CertificationState = "QUARANTINED"
	StateRevoked                 CertificationState = "REVOKED"
)

type Capability string

const (
	CapabilityDiscover       Capability = "discover"
	CapabilitySearch         Capability = "search"
	CapabilityRead           Capability = "read"
	CapabilityWrite          Capability = "write"
	CapabilityExecute        Capability = "execute"
	CapabilityAutomate       Capability = "automate"
	CapabilityDeploy         Capability = "deploy"
	CapabilityObserve        Capability = "observe"
	CapabilityGovern         Capability = "govern"
	CapabilityGenerateMedia  Capability = "generate_media"
	CapabilityStoreKnowledge Capability = "store_knowledge"
	CapabilityCommunicate    Capability = "communicate"
	CapabilitySchedule       Capability = "schedule"
	CapabilitySell           Capability = "sell"
	CapabilityAnalyze        Capability = "analyze"
)

type RiskClass uint8

const (
	RiskR0 RiskClass = iota
	RiskR1
	RiskR2
	RiskR3
	RiskR4
)

type Principal struct {
	Type       string
	SubjectRef string
}

type CaseOutcome struct {
	CaseID      string
	Gate        string
	Status      string
	EvidenceRef string
	ErrorClass  string
}

type ProviderState struct {
	PreStateHash  string
	PostStateHash string
	TargetRef     string
}

type CredentialLifecycle struct {
	CredentialRef      string
	Fingerprint        string
	RevocationTested   bool
	RevocationEnforced bool
	RevokedAt          *time.Time
}

type CertificationReceipt struct {
	SchemaVersion          string
	ConnectorID            string
	ConnectorVersion       string
	SchemaHash             string
	Principal              Principal
	Scopes                 []string
	TestRunID              string
	CaseOutcomes           []CaseOutcome
	ProviderState          *ProviderState
	CredentialLifecycle    CredentialLifecycle
	CertificationState     CertificationState
	CertifiedAt            time.Time
	ExpiresAt              *time.Time
	NonExpiringPolicyRef   *string
}

type RegistryRecord struct {
	ConnectorID            string
	Version                string
	SchemaHash             string
	Capabilities           []Capability
	ResourceDomains        []string
	RiskCeiling            RiskClass
	RequiredScopes         []string
	CertificationState     CertificationState
	CertificationReceipt   CertificationReceipt
	NativeAuthority        bool
	VerificationStrength   int
	ReliabilityBasisPoints int
	LatencyMillis          int
	CostUnits              int
	AuthModel              string
	ToolNames              []string
}

type Request struct {
	Capability            Capability
	ResourceDomain        string
	Risk                  RiskClass
	GrantedScopes         []string
	PreferredConnectorID string
}

type Observation struct {
	Version        string
	SchemaHash     string
	RequiredScopes []string
	AuthModel      string
	ToolNames      []string
}

type DriftResult struct {
	Material  bool
	Reasons   []string
	NextState CertificationState
}
