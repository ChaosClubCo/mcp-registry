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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrConflict        = errors.New("governance revision conflict")
	ErrUnsafeStorePath = errors.New("unsafe governance store path")
	ErrNotFound        = errors.New("governance record not found")
)

type StoredRegistryRecord struct {
	Key      string         `json:"key"`
	Revision uint64         `json:"revision"`
	Record   RegistryRecord `json:"record"`
}

type ArchivedReceipt struct {
	ID          string               `json:"id"`
	RecordKey   string               `json:"record_key"`
	ReceiptHash string               `json:"receipt_hash"`
	Receipt     CertificationReceipt `json:"receipt"`
	ArchivedAt  time.Time            `json:"archived_at"`
}

type GovernanceSnapshot struct {
	SchemaVersion string                              `json:"schema_version"`
	Revision      uint64                              `json:"revision"`
	Records       map[string]StoredRegistryRecord     `json:"records"`
	Receipts      []ArchivedReceipt                   `json:"receipts"`
	Events        []GovernanceEvent                   `json:"events"`
	Ledger        []EvidenceEntry                     `json:"ledger"`
	Grants        map[string]StoredAuthorizationGrant `json:"grants"`
}

type GovernanceStore interface {
	Load(context.Context) (GovernanceSnapshot, error)
	Commit(context.Context, uint64, GovernanceSnapshot) error
}

func emptyGovernanceSnapshot() GovernanceSnapshot {
	return GovernanceSnapshot{
		SchemaVersion: "GovernanceSnapshot/v1",
		Records:       map[string]StoredRegistryRecord{},
		Grants:        map[string]StoredAuthorizationGrant{},
	}
}

func normalizeSnapshot(s GovernanceSnapshot) GovernanceSnapshot {
	if s.SchemaVersion == "" {
		s.SchemaVersion = "GovernanceSnapshot/v1"
	}
	if s.Records == nil {
		s.Records = map[string]StoredRegistryRecord{}
	}
	if s.Grants == nil {
		s.Grants = map[string]StoredAuthorizationGrant{}
	}
	if s.Receipts == nil {
		s.Receipts = []ArchivedReceipt{}
	}
	if s.Events == nil {
		s.Events = []GovernanceEvent{}
	}
	if s.Ledger == nil {
		s.Ledger = []EvidenceEntry{}
	}
	return s
}

func cloneSnapshot(s GovernanceSnapshot) (GovernanceSnapshot, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return GovernanceSnapshot{}, err
	}
	var out GovernanceSnapshot
	if err := json.Unmarshal(raw, &out); err != nil {
		return GovernanceSnapshot{}, err
	}
	return normalizeSnapshot(out), nil
}

type MemoryGovernanceStore struct {
	mu       sync.Mutex
	snapshot GovernanceSnapshot
}

func NewMemoryGovernanceStore() *MemoryGovernanceStore {
	return &MemoryGovernanceStore{snapshot: emptyGovernanceSnapshot()}
}

func (s *MemoryGovernanceStore) Load(ctx context.Context) (GovernanceSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return GovernanceSnapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneSnapshot(s.snapshot)
}

func (s *MemoryGovernanceStore) Commit(ctx context.Context, expected uint64, next GovernanceSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshot.Revision != expected {
		return ErrConflict
	}
	copy, err := cloneSnapshot(next)
	if err != nil {
		return err
	}
	copy.Revision = expected + 1
	s.snapshot = copy
	return nil
}

type FileGovernanceStore struct{ path string }

func NewFileGovernanceStore(path string) *FileGovernanceStore {
	return &FileGovernanceStore{path: path}
}

var fileStoreLocks sync.Map

func storeLock(path string) *sync.Mutex {
	absolute, _ := filepath.Abs(path)
	value, _ := fileStoreLocks.LoadOrStore(absolute, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func (s *FileGovernanceStore) Load(ctx context.Context) (GovernanceSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return GovernanceSnapshot{}, err
	}
	if err := ensureSafeStorePath(s.path); err != nil {
		return GovernanceSnapshot{}, err
	}
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return emptyGovernanceSnapshot(), nil
	}
	if err != nil {
		return GovernanceSnapshot{}, err
	}
	var snapshot GovernanceSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return GovernanceSnapshot{}, fmt.Errorf("decode governance snapshot: %w", err)
	}
	return normalizeSnapshot(snapshot), nil
}

func (s *FileGovernanceStore) Commit(ctx context.Context, expected uint64, next GovernanceSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	lock := storeLock(s.path)
	lock.Lock()
	defer lock.Unlock()

	if err := ensureSafeStorePath(s.path); err != nil {
		return err
	}
	current, err := s.Load(ctx)
	if err != nil {
		return err
	}
	if current.Revision != expected {
		return ErrConflict
	}

	next = normalizeSnapshot(next)
	next.Revision = expected + 1
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}

	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := ensureSafeStorePath(s.path); err != nil {
		return err
	}

	temporary, err := os.CreateTemp(directory, ".governance-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryName)
		return err
	}
	if err := os.Rename(temporaryName, s.path); err != nil {
		_ = os.Remove(temporaryName)
		return err
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		return err
	}

	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return err
	}
	return nil
}

func ensureSafeStorePath(path string) error {
	if strings.TrimSpace(path) == "" {
		return ErrUnsafeStorePath
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	current := filepath.VolumeName(absolute) + string(os.PathSeparator)
	parts := strings.Split(strings.TrimPrefix(absolute, current), string(os.PathSeparator))
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafeStorePath
		}
	}
	return nil
}
