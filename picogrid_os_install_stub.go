//go:build !linux

package main

import "errors"

func runPicogridOSInstall() error {
	return errors.New("picogrid-os-install is only supported on Linux")
}
