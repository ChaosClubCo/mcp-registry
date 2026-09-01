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
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStoreLockReturnsCanonicalizationError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("deleted-current-directory semantics are platform-specific")
	}

	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	deleted := filepath.Join(parent, "deleted-cwd")
	if err := os.Mkdir(deleted, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(deleted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	if err := os.Remove(deleted); err != nil {
		t.Fatal(err)
	}

	if _, err := storeLock("snapshot.json"); err == nil {
		t.Fatal("store lock must return filepath canonicalization errors instead of collapsing them into a shared lock key")
	}
}
