package install

import "os/user"

const PicogridGroupName = "picogrid"

func DefaultServiceUser() string {
	if _, err := user.Lookup("pg"); err == nil {
		return "pg"
	}
	return "root"
}

func DefaultServiceGroup() string {
	if _, err := user.LookupGroup(PicogridGroupName); err == nil {
		return PicogridGroupName
	}
	return ""
}
