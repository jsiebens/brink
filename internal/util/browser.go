package util

import (
	"fmt"
	"github.com/hashicorp/go-multierror"
	"io/ioutil"
	"os/exec"
	"runtime"
	"strings"
)

// IsWSL tests if the binary is being run in Windows Subsystem for Linux
func IsWSL() (bool, error) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return false, nil
	}
	data, err := ioutil.ReadFile("/proc/version")
	if err != nil {
		return false, fmt.Errorf("Unable to read /proc/version: %w", err)
	}
	return strings.Contains(strings.ToLower(string(data)), "microsoft"), nil
}

// OpenURL opens the specified URL in the default browser of the user. Source:
// https://stackoverflow.com/a/39324149/453290
func OpenURL(url string) error {
	var cmd string
	var args []string

	var mErr *multierror.Error
	wsl, err := IsWSL()
	if err != nil {
		mErr = multierror.Append(err)
	}
	switch {
	case "windows" == runtime.GOOS || wsl:
		cmd = "cmd.exe"
		args = []string{"/c", "start"}
		url = strings.Replace(url, "&", "^&", -1)
	case "darwin" == runtime.GOOS:
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	if err := exec.Command(cmd, args...).Start(); err != nil {
		mErr = multierror.Append(err)
	}
	return mErr.ErrorOrNil()
}
