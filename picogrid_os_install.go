//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Picogrid Edge (Yocto) image layout. The image bakes legion-auth at
// picogridOSBakedBinary and ships a legion-auth-launch wrapper that runs a
// strictly-newer binary from picogridOSBinaryDir in preference to the baked
// copy (so an A/B image update always wins over a stale drop). This is the
// Picogrid-OS analogue of install.sh's generic /usr/local/bin install -- a drop
// in /usr/local/bin is invisible to the launcher and must not be used here.
const (
	picogridOSBinaryDir   = "/var/lib/picogrid/bin"
	picogridOSBakedBinary = "/usr/bin/legion-auth"
	picogridOSLauncher    = "/usr/bin/legion-auth-launch"
	picogridOSServiceName = "legion-auth"
	picogridOSLegacyUnit  = "/etc/systemd/system/legion-auth.service"
)

// runPicogridOSInstall drops the running binary into the auto-update directory
// where legion-auth-launch picks it up (when strictly newer than the baked
// copy), then restarts the image-provided service. Invoked by the
// "picogrid-os-install" subcommand and by install.sh on Picogrid OS.
func runPicogridOSInstall() error {
	dest, err := installPicogridOSBinary()
	if err != nil {
		return err
	}
	if dest == picogridOSBakedBinary {
		printSuccess("Running the image-baked binary - nothing to install")
		return nil
	}
	printSuccess(fmt.Sprintf("Binary installed to %s (used by legion-auth-launch when newer than the baked %s)", dest, picogridOSBakedBinary))
	return activatePicogridOSService()
}

// installPicogridOSBinary places the running binary in the auto-update drop
// directory. It refuses on images that predate the launcher, since a drop there
// would never be executed.
func installPicogridOSBinary() (string, error) {
	src, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	src, _ = filepath.Abs(src)

	if same, err := sameFile(src, picogridOSBakedBinary); err != nil {
		return "", err
	} else if same {
		// Running the image-baked binary: nothing newer to drop.
		return picogridOSBakedBinary, nil
	}

	if _, err := os.Stat(picogridOSLauncher); err != nil {
		return "", fmt.Errorf("%s not found - this image predates auto-update support; update legion-auth by flashing a newer image", picogridOSLauncher)
	}

	dest := filepath.Join(picogridOSBinaryDir, "legion-auth")
	if same, err := sameFile(src, dest); err != nil {
		return "", err
	} else if same {
		return dest, nil
	}

	if err := os.MkdirAll(picogridOSBinaryDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create %s: %w", picogridOSBinaryDir, err)
	}

	if err := installBinaryFile(src, dest); err != nil {
		return "", err
	}
	return dest, nil
}

func sameFile(pathA, pathB string) (bool, error) {
	infoA, err := os.Stat(pathA)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to stat %s: %w", pathA, err)
	}

	infoB, err := os.Stat(pathB)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to stat %s: %w", pathB, err)
	}

	return os.SameFile(infoA, infoB), nil
}

// installBinaryFile copies src to dest atomically: a temp file in the same
// directory, chmod 0755, fsync, then rename -- so the launcher never observes a
// half-written binary.
func installBinaryFile(src, dest string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source binary: %w", err)
	}
	defer srcFile.Close()

	tempFile, err := os.CreateTemp(filepath.Dir(dest), filepath.Base(dest)+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create a temp file in %s (try running with sudo): %w", filepath.Dir(dest), err)
	}
	tempPath := tempFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()

	if err := tempFile.Chmod(0755); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to chmod %s: %w", tempPath, err)
	}
	if _, err := io.Copy(tempFile, srcFile); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to copy binary to %s: %w", tempPath, err)
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to sync %s: %w", tempPath, err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close %s: %w", tempPath, err)
	}
	if err := os.Rename(tempPath, dest); err != nil {
		return fmt.Errorf("failed to move the binary into %s atomically: %w", dest, err)
	}
	cleanup = false
	return nil
}

// activatePicogridOSService restarts the image-provided systemd unit. A unit
// left at picogridOSLegacyUnit by an older /usr/local/bin installer would
// shadow the baked unit forever via the persistent /etc overlay, so remove it.
func activatePicogridOSService() error {
	if _, err := os.Stat(picogridOSLegacyUnit); err == nil {
		printInfo(fmt.Sprintf("Removing legacy installer unit %s (the image provides the unit)...", picogridOSLegacyUnit))
		if err := os.Remove(picogridOSLegacyUnit); err != nil {
			return fmt.Errorf("failed to remove %s: %w", picogridOSLegacyUnit, err)
		}
	}

	printInfo("Reloading systemd daemon...")
	output, err := exec.Command("systemctl", "daemon-reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to reload the systemd daemon: %w; output: %s", err, strings.TrimSpace(string(output)))
	}
	printInfo(fmt.Sprintf("Restarting %s service...", picogridOSServiceName))
	output, err = exec.Command("systemctl", "restart", picogridOSServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restart %s (run as root?): %w; output: %s", picogridOSServiceName, err, strings.TrimSpace(string(output)))
	}
	printSuccess("Service restarted using the image-provided unit")
	return nil
}
