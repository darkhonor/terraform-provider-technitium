// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	copyrightLine = "// Copyright (c) 2026 Alex Ackerman"
	spdxLine      = "// SPDX-License-Identifier: MPL-2.0"
)

// Every Go file carries a copyright notice and an SPDX identifier. MPL-2.0
// section 3.4 requires those notices to survive redistribution, and this
// provider is published for environments where license and provenance metadata
// is inspected rather than assumed. A file without them is also invisible to
// SPDX and REUSE tooling.
//
// Three files drifted without one before this check existed, and nothing
// surfaced it: not the linter, not CI, not review.
func TestEveryGoFileCarriesLicenseHeader(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving repository root: %v", err)
	}

	var scanned int
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip VCS metadata and any vendored third-party source, whose
			// headers belong to their own authors.
			if name := d.Name(); name == ".git" || name == "vendor" || name == ".testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		body, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			return readErr
		}
		scanned++

		rel, _ := filepath.Rel(root, path)
		head := string(body)
		if len(head) > 200 {
			head = head[:200]
		}
		if !strings.Contains(head, copyrightLine) {
			t.Errorf("%s is missing the copyright notice %q", rel, copyrightLine)
		}
		if !strings.Contains(head, spdxLine) {
			t.Errorf("%s is missing the SPDX identifier %q", rel, spdxLine)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking repository: %v", err)
	}

	// Guard against the walk silently matching nothing and reporting success.
	if scanned < 50 {
		t.Fatalf("only scanned %d Go files; the walk is not reaching the repository", scanned)
	}
}
