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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	EventRecordRegistered = "record_registered"
	EventStateTransition  = "state_transition"
	EventDriftDetected    = "drift_detected"
	EventGrantIssued      = "grant_issued"
	EventGrantRevoked     = "grant_revoked"
)

type GovernanceEvent struct {
	ID          string             `json:"id"`
	Type        string             `json:"type"`
	RecordKey   string             `json:"record_key,omitempty"`
	GrantID     string             `json:"grant_id,omitempty"`
	At          time.Time          `json:"at"`
	FromState   CertificationState `json:"from_state,omitempty"`
	ToState     CertificationState `json:"to_state,omitempty"`
	Reasons     []string           `json:"reasons,omitempty"`
	ReceiptHash string             `json:"receipt_hash,omitempty"`
}

type EvidenceEntry struct {
	Sequence     uint64 `json:"sequence"`
	PreviousHash string `json:"previous_hash,omitempty"`
	EventHash    string `json:"event_hash"`
	EntryHash    string `json:"entry_hash"`
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func receiptHash(r CertificationReceipt) (string, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return "sha256:" + sha256Hex(raw), nil
}

func archiveReceipt(key string, r CertificationReceipt, at time.Time) (ArchivedReceipt, error) {
	h, err := receiptHash(r)
	if err != nil {
		return ArchivedReceipt{}, err
	}
	return ArchivedReceipt{ID: newID(), RecordKey: key, ReceiptHash: h, Receipt: r, ArchivedAt: at}, nil
}

func appendGovernanceEvent(s *GovernanceSnapshot, event GovernanceEvent) error {
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	eventHash := sha256Hex(raw)
	sequence := uint64(len(s.Ledger) + 1)
	previousHash := ""
	if len(s.Ledger) > 0 {
		previousHash = s.Ledger[len(s.Ledger)-1].EntryHash
	}
	payload, err := json.Marshal(struct {
		Sequence     uint64 `json:"sequence"`
		PreviousHash string `json:"previous_hash"`
		EventHash    string `json:"event_hash"`
	}{sequence, previousHash, eventHash})
	if err != nil {
		return err
	}
	entry := EvidenceEntry{
		Sequence:     sequence,
		PreviousHash: previousHash,
		EventHash:    eventHash,
		EntryHash:    sha256Hex(payload),
	}
	s.Events = append(s.Events, event)
	s.Ledger = append(s.Ledger, entry)
	return nil
}

func VerifyEvidenceLedger(s GovernanceSnapshot) error {
	if len(s.Events) != len(s.Ledger) {
		return fmt.Errorf("event/ledger length mismatch")
	}
	previousHash := ""
	for i, event := range s.Events {
		entry := s.Ledger[i]
		sequence := uint64(i + 1)
		if entry.Sequence != sequence {
			return fmt.Errorf("ledger sequence mismatch at %d", i)
		}
		if entry.PreviousHash != previousHash {
			return fmt.Errorf("ledger previous hash mismatch at %d", i)
		}
		raw, err := json.Marshal(event)
		if err != nil {
			return err
		}
		eventHash := sha256Hex(raw)
		if entry.EventHash != eventHash {
			return fmt.Errorf("ledger event hash mismatch at %d", i)
		}
		payload, err := json.Marshal(struct {
			Sequence     uint64 `json:"sequence"`
			PreviousHash string `json:"previous_hash"`
			EventHash    string `json:"event_hash"`
		}{sequence, previousHash, eventHash})
		if err != nil {
			return err
		}
		if entry.EntryHash != sha256Hex(payload) {
			return fmt.Errorf("ledger entry hash mismatch at %d", i)
		}
		previousHash = entry.EntryHash
	}
	return nil
}
