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
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var ErrUnauthorizedGrant = errors.New("unauthorized governance grant")

type GrantSpec struct {
	Principal      Principal
	ResourceDomain string
	ResourceRef    string
	Scopes         []string
	ExpiresAt      time.Time
}

type AuthorizationGrant struct {
	GrantID        string    `json:"grant_id"`
	Principal      Principal `json:"principal"`
	ResourceDomain string    `json:"resource_domain"`
	ResourceRef    string    `json:"resource_ref"`
	Scopes         []string  `json:"scopes"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type SignedAuthorizationGrant struct {
	Grant     AuthorizationGrant `json:"grant"`
	KeyID     string             `json:"key_id"`
	Signature string             `json:"signature"`
}

type StoredAuthorizationGrant struct {
	Signed    SignedAuthorizationGrant `json:"signed"`
	RevokedAt *time.Time               `json:"revoked_at,omitempty"`
}

type GrantSigner interface {
	Sign(AuthorizationGrant) (SignedAuthorizationGrant, error)
	Verify(SignedAuthorizationGrant) error
}

type Ed25519GrantSigner struct {
	keyID   string
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func NewEd25519GrantSigner(keyID string, private ed25519.PrivateKey) (*Ed25519GrantSigner, error) {
	if strings.TrimSpace(keyID) == "" || keyID != strings.TrimSpace(keyID) {
		return nil, fmt.Errorf("canonical key id required")
	}
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key")
	}
	privateCopy := append(ed25519.PrivateKey(nil), private...)
	publicCopy := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	return &Ed25519GrantSigner{keyID: keyID, private: privateCopy, public: publicCopy}, nil
}

func (s *Ed25519GrantSigner) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.public...)
}

func canonicalGrant(g AuthorizationGrant) (AuthorizationGrant, []byte, error) {
	g.Principal.Type = strings.TrimSpace(g.Principal.Type)
	g.Principal.SubjectRef = strings.TrimSpace(g.Principal.SubjectRef)
	g.ResourceDomain = strings.TrimSpace(g.ResourceDomain)
	g.ResourceRef = strings.TrimSpace(g.ResourceRef)
	if !validPrincipal(g.Principal) || g.ResourceDomain == "" || g.ResourceRef == "" {
		return g, nil, ErrUnauthorizedGrant
	}
	scopes := append([]string(nil), g.Scopes...)
	for i, scope := range scopes {
		if strings.TrimSpace(scope) == "" || strings.TrimSpace(scope) != scope {
			return g, nil, ErrUnauthorizedGrant
		}
		scopes[i] = scope
	}
	sort.Strings(scopes)
	for i := 1; i < len(scopes); i++ {
		if scopes[i] == scopes[i-1] {
			return g, nil, ErrUnauthorizedGrant
		}
	}
	g.Scopes = scopes
	raw, err := json.Marshal(g)
	return g, raw, err
}

func (s *Ed25519GrantSigner) Sign(g AuthorizationGrant) (SignedAuthorizationGrant, error) {
	g, raw, err := canonicalGrant(g)
	if err != nil {
		return SignedAuthorizationGrant{}, err
	}
	signature := ed25519.Sign(s.private, raw)
	return SignedAuthorizationGrant{
		Grant:     g,
		KeyID:     s.keyID,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func (s *Ed25519GrantSigner) Verify(signed SignedAuthorizationGrant) error {
	if signed.KeyID != s.keyID {
		return ErrUnauthorizedGrant
	}
	canonical, raw, err := canonicalGrant(signed.Grant)
	if err != nil || !sameGrant(canonical, signed.Grant) {
		return ErrUnauthorizedGrant
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(s.public, raw, signature) {
		return ErrUnauthorizedGrant
	}
	return nil
}

func sameGrant(a, b AuthorizationGrant) bool {
	if a.GrantID != b.GrantID || !samePrincipal(a.Principal, b.Principal) || a.ResourceDomain != b.ResourceDomain || a.ResourceRef != b.ResourceRef || !a.IssuedAt.Equal(b.IssuedAt) || !a.ExpiresAt.Equal(b.ExpiresAt) || len(a.Scopes) != len(b.Scopes) {
		return false
	}
	for i := range a.Scopes {
		if a.Scopes[i] != b.Scopes[i] {
			return false
		}
	}
	return true
}
