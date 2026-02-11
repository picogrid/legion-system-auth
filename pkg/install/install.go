package install

import (
	"fmt"
	"log"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
)

const (
	// PicogridGroupName is the system group shared between host services and
	// Chainguard-based containers (which run as nonroot UID/GID 65532).
	PicogridGroupName = "picogrid"

	// PicogridGroupPreferredGID is the GID we request when creating the
	// picogrid group. It matches Chainguard's nonroot GID so that
	// containers can read files owned by this group without remapping.
	PicogridGroupPreferredGID = 65532
)

// DefaultServiceUser returns the default user for running the legion-auth service.
// It returns "pg" if that user exists on the system (to match storage ownership),
// otherwise falls back to "root".
func DefaultServiceUser() string {
	if _, err := user.Lookup("pg"); err == nil {
		return "pg"
	}
	return "root"
}

// LookupPicogridGID returns the GID of the picogrid group, or -1 if the
// group does not exist.
func LookupPicogridGID() int {
	g, err := user.LookupGroup(PicogridGroupName)
	if err != nil {
		return -1
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1
	}
	return gid
}

// EnsurePicogridGroup idempotently creates the picogrid system group.
// On success it returns the resolved GID. It returns -1 when running on
// a non-Linux platform or when not running as root.
func EnsurePicogridGroup() (int, error) {
	if runtime.GOOS != "linux" {
		return -1, nil
	}
	if !isRoot() {
		log.Printf("Warning: not running as root, skipping picogrid group creation")
		return -1, nil
	}

	// Already exists — use it as-is.
	if g, err := user.LookupGroup(PicogridGroupName); err == nil {
		gid, _ := strconv.Atoi(g.Gid)
		if gid != PicogridGroupPreferredGID {
			log.Printf("Warning: picogrid group exists with GID %d (preferred %d)", gid, PicogridGroupPreferredGID)
		}
		return gid, nil
	}

	// Try with preferred GID first.
	if err := runGroupadd("--gid", strconv.Itoa(PicogridGroupPreferredGID), "--system", PicogridGroupName); err == nil {
		return PicogridGroupPreferredGID, nil
	}

	// GID may be taken — fall back to system-assigned.
	log.Printf("Warning: GID %d unavailable, falling back to system-assigned GID for picogrid group", PicogridGroupPreferredGID)
	if err := runGroupadd("--system", PicogridGroupName); err != nil {
		return -1, fmt.Errorf("creating picogrid group: %w", err)
	}

	g, err := user.LookupGroup(PicogridGroupName)
	if err != nil {
		return -1, fmt.Errorf("looking up picogrid group after creation: %w", err)
	}
	gid, _ := strconv.Atoi(g.Gid)
	return gid, nil
}

// EnsureUserInGroup adds the given user to the picogrid group if not
// already a member.
func EnsureUserInGroup(username string) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	// Check current membership.
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("looking up user %q: %w", username, err)
	}
	gids, err := u.GroupIds()
	if err != nil {
		return fmt.Errorf("listing groups for user %q: %w", username, err)
	}
	pgGroup, err := user.LookupGroup(PicogridGroupName)
	if err != nil {
		return fmt.Errorf("picogrid group does not exist: %w", err)
	}
	for _, gid := range gids {
		if gid == pgGroup.Gid {
			return nil // already a member
		}
	}

	cmd := exec.Command("usermod", "-aG", PicogridGroupName, username)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("adding %s to picogrid group: %w (%s)", username, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runGroupadd(args ...string) error {
	cmd := exec.Command("groupadd", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func isRoot() bool {
	u, err := user.Current()
	if err != nil {
		return false
	}
	return u.Uid == "0"
}
