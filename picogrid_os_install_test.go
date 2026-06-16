//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSameFileFollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "legion-auth")
	link := filepath.Join(dir, "legion-auth-link")

	if err := os.WriteFile(target, []byte("binary"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	got, err := sameFile(target, link)
	if err != nil {
		t.Fatalf("sameFile returned error: %v", err)
	}
	if !got {
		t.Fatal("sameFile returned false for a symlink to the same file")
	}
}

func TestSameFileReturnsFalseForMissingPath(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "legion-auth")
	missing := filepath.Join(dir, "missing-legion-auth")

	if err := os.WriteFile(existing, []byte("binary"), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := sameFile(existing, missing)
	if err != nil {
		t.Fatalf("sameFile returned error: %v", err)
	}
	if got {
		t.Fatal("sameFile returned true for a missing path")
	}
}
