package lap

import (
	"path/filepath"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	// from go/lapverify/internal/lap -> repo root is ../../../../
	return filepath.Clean(filepath.Join(".", "..", "..", "..", ".."))
}

func TestVectors(t *testing.T) {
	root := repoRoot(t)
	vdir := filepath.Join(root, "spec", "test_vectors")
	_, err := VerifyVectorsDir(vdir)
	if err != nil {
		t.Fatalf("vectors failed: %v", err)
	}
}

func TestGoldenPack(t *testing.T) {
	root := repoRoot(t)
	p := filepath.Join(root, "spec", "golden_packs", "golden_pack_basic.zip")
	if err := VerifyAuditPack(p, true); err != nil {
		t.Fatalf("audit pack failed: %v", err)
	}
}
