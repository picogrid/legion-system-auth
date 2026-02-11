package install

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"testing"
	"time"
)

func TestPicogridConstants(t *testing.T) {
	if PicogridGroupName != "picogrid" {
		t.Fatalf("PicogridGroupName = %q, want %q", PicogridGroupName, "picogrid")
	}
	if PicogridGroupPreferredGID != 65532 {
		t.Fatalf("PicogridGroupPreferredGID = %d, want %d", PicogridGroupPreferredGID, 65532)
	}
}

func TestLookupPicogridGID(t *testing.T) {
	gid := LookupPicogridGID()
	// On most CI/dev machines the group won't exist.
	if _, err := user.LookupGroup(PicogridGroupName); err != nil {
		if gid != -1 {
			t.Fatalf("LookupPicogridGID() = %d, want -1 when group absent", gid)
		}
	} else {
		if gid < 0 {
			t.Fatalf("LookupPicogridGID() = %d, want >= 0 when group exists", gid)
		}
	}
}

func TestEnsurePicogridGroupNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test requires non-root")
	}
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}

	gid, err := EnsurePicogridGroup()
	if err != nil {
		t.Fatalf("EnsurePicogridGroup() returned error for non-root: %v", err)
	}
	if gid != -1 {
		t.Fatalf("EnsurePicogridGroup() = %d, want -1 for non-root", gid)
	}
}

func TestEnsureUserInGroupBadUser(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	badUser := nonexistentName("no_such_user")
	err := EnsureUserInGroup(badUser)
	if err == nil {
		t.Fatalf("EnsureUserInGroup(%q) succeeded, want error", badUser)
	}
}

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

	_, err := user.Lookup("root")
	if runtime.GOOS == "linux" && err != nil {
		t.Fatalf("user.Lookup(%q) failed on Linux: %v", "root", err)
	}
}

func TestInstallServiceGroupValidationPattern(t *testing.T) {
	nonexistentGroup := nonexistentName("legion_auth_no_such_group")
	if _, err := user.LookupGroup(nonexistentGroup); err == nil {
		t.Fatalf("user.LookupGroup(%q) unexpectedly succeeded", nonexistentGroup)
	}

	_, err := user.LookupGroup("root")
	if runtime.GOOS == "linux" && err != nil {
		t.Fatalf("user.LookupGroup(%q) failed on Linux: %v", "root", err)
	}
	current, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current() failed: %v", err)
	}

	_, err = user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatalf("user.LookupGroupId(%q) failed: %v", current.Gid, err)
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
	if group.Name == "" {
		t.Fatalf("resolved group for gid %q has empty name", root.Gid)
	}
}
