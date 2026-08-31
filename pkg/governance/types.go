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
	Type       string `json:"type"`
	SubjectRef string `json:"subject_ref"`
}

type CaseOutcome struct {
	CaseID      string `json:"case_id"`
	Gate        string `json:"gate"`
	Status      string `json:"status"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
	ErrorClass  string `json:"error_class,omitempty"`
}

type ProviderState struct {
	PreStateHash  string `json:"pre_state_hash,omitempty"`
	PostStateHash string `json:"post_state_hash,omitempty"`
	TargetRef     string `json:"target_ref,omitempty"`
}

type CredentialLifecycle struct {
	CredentialRef      string     `json:"credential_ref,omitempty"`
	Fingerprint        string     `json:"fingerprint,omitempty"`
	RevocationTested   bool       `json:"revocation_tested"`
	RevocationEnforced bool       `json:"revocation_enforced"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
}

type CertificationReceipt struct {
	SchemaVersion        string              `json:"schema_version"`
	ConnectorID          string              `json:"connector_id"`
	ConnectorVersion     string              `json:"connector_version"`
	SchemaHash           string              `json:"schema_hash"`
	Principal            Principal           `json:"principal"`
	Scopes               []string            `json:"scopes"`
	RequiredScopes       []string            `json:"required_scopes"`
	TestRunID            string              `json:"test_run_id"`
	CaseOutcomes         []CaseOutcome        `json:"case_outcomes"`
	ProviderState        *ProviderState       `json:"provider_state,omitempty"`
	CredentialLifecycle CredentialLifecycle `json:"credential_lifecycle"`
	CertificationState   CertificationState  `json:"certification_state"`
	CertifiedAt          time.Time           `json:"certified_at"`
	ExpiresAt            *time.Time          `json:"expires_at,omitempty"`
	NonExpiringPolicyRef *string             `json:"non_expiring_policy_ref,omitempty"`
}

type RegistryRecord struct {
	ConnectorID                    string
	Version                        string
	SchemaHash                     string
	Capabilities                   []Capability
	ResourceDomains                []string
	RiskCeiling                    RiskClass
	RequiredScopes                 []string
	CertificationState             CertificationState
	CertificationReceipt           CertificationReceipt
	NativeAuthority                bool
	VerificationStrength           int
	ReliabilityBasisPoints         int
	MinimumReliabilityBasisPoints  int
	LatencyMillis                  int
	CostUnits                      int
	AuthModel                      string
	ToolNames                      []string
}

type AuthorizationContext struct {
	Principal              Principal
	GrantedScopes          []string
	AllowedResourceDomains []string
	AllowedResourceRefs    []string
}

type Request struct {
	Capability            Capability
	ResourceDomain        string
	ResourceRef           string
	Risk                  RiskClass
	GrantedScopes         []string // Deprecated: use Authorization.GrantedScopes.
	Authorization         AuthorizationContext
	PreferredConnectorID string
}

type Observation struct {
	Version                string
	SchemaHash             string
	RequiredScopes         []string
	AuthModel              string
	AuthModelObserved      bool
	ToolNames              []string
	ReliabilityBasisPoints *int
}

type DriftResult struct {
	Material  bool
	Reasons   []string
	NextState CertificationState
}
