//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSetupStorage_DirPermissionsUnderRestrictiveUmask(t *testing.T) {
	saveAndRestoreStorageGlobals(t)

	// Simulate a device whose umask would otherwise strip group/other bits.
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	dir := t.TempDir()
	custom := filepath.Join(dir, "picogrid", "auth")

	if err := setupStorage(custom); err != nil {
		t.Fatalf("setupStorage failed: %v", err)
	}

	info, err := os.Stat(custom)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	// Assumes no "pg" user on the host: when pg exists, setOwnership bumps the
	// dir to 0755 (still group-traversable). CI/dev machines have no pg user, so
	// the unconditional 0750 from setupStorage stands.
	if info.Mode().Perm() != 0o750 {
		t.Errorf("storage dir perm = %o, want 0750 (group must be able to traverse)", info.Mode().Perm())
	}
}
