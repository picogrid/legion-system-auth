package install

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"testing"
	"time"
)

func nonexistentName(prefix string) string {
	return fmt.Sprintf("%s_%d_%d", prefix, os.Getpid(), time.Now().UnixNano())
}

func TestInstallDefaultServiceUser(t *testing.T) {
	_, pgErr := user.Lookup("pg")

	var got string
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DefaultServiceUser() panicked: %v", r)
			}
		}()
		got = DefaultServiceUser()
	}()

	if pgErr == nil {
		if got != "pg" {
			t.Fatalf("DefaultServiceUser() = %q, want %q when user \"pg\" exists", got, "pg")
		}
		return
	}
	if got != "root" {
		t.Fatalf("DefaultServiceUser() = %q, want %q when user \"pg\" does not exist", got, "root")
	}
}

func TestInstallServiceUserValidationPattern(t *testing.T) {
	nonexistentUser := nonexistentName("legion_auth_no_such_user")
	if _, err := user.Lookup(nonexistentUser); err == nil {
		t.Fatalf("user.Lookup(%q) unexpectedly succeeded", nonexistentUser)
	}

	root, err := user.Lookup("root")
	if runtime.GOOS == "linux" && err != nil {
		t.Fatalf("user.Lookup(%q) failed on Linux: %v", "root", err)
	}
	if err == nil && root == nil {
		t.Fatalf("user.Lookup(%q) returned nil user without error", "root")
	}
}

func TestInstallServiceGroupValidationPattern(t *testing.T) {
	nonexistentGroup := nonexistentName("legion_auth_no_such_group")
	if _, err := user.LookupGroup(nonexistentGroup); err == nil {
		t.Fatalf("user.LookupGroup(%q) unexpectedly succeeded", nonexistentGroup)
	}

	group, err := user.LookupGroup("root")
	if runtime.GOOS == "linux" && err != nil {
		t.Fatalf("user.LookupGroup(%q) failed on Linux: %v", "root", err)
	}
	if err == nil && group == nil {
		t.Fatalf("user.LookupGroup(%q) returned nil group without error", "root")
	}

	current, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current() failed: %v", err)
	}

	g, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatalf("user.LookupGroupId(%q) failed: %v", current.Gid, err)
	}
	if g == nil {
		t.Fatalf("user.LookupGroupId(%q) returned nil group without error", current.Gid)
	}
}

func TestInstallGroupResolutionFromUserAccount(t *testing.T) {
	root, err := user.Lookup("root")
	if runtime.GOOS == "linux" && err != nil {
		t.Fatalf("user.Lookup(%q) failed on Linux: %v", "root", err)
	}
	if err != nil {
		t.Skipf("skipping: user.Lookup(%q) failed on %s: %v", "root", runtime.GOOS, err)
	}

	group, err := user.LookupGroupId(root.Gid)
	if err != nil {
		t.Fatalf("user.LookupGroupId(%q) failed: %v", root.Gid, err)
	}
	if group == nil {
		t.Fatalf("user.LookupGroupId(%q) returned nil group without error", root.Gid)
	}
	if group.Name == "" {
		t.Fatalf("resolved group for gid %q has empty name", root.Gid)
	}
}
