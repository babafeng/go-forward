//go:build !windows

package route

import "os"

func IsCurrentUserPrivileged() bool {
	return os.Geteuid() == 0
}
