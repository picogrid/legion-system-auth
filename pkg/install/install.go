package install

import "os/user"

func DefaultServiceUser() string {
	if _, err := user.Lookup("pg"); err == nil {
		return "pg"
	}
	return "root"
}
