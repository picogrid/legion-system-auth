package install

import "os/user"

// DefaultServiceUser returns the default user for running the legion-auth service.
// It returns "pg" if that user exists on the system (to match storage ownership),
// otherwise falls back to "root".
func DefaultServiceUser() string {
	if _, err := user.Lookup("pg"); err == nil {
		return "pg"
	}
	return "root"
}
