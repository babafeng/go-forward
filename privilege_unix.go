//go:build !windows

package main

import "os"

func isCurrentUserPrivileged() bool {
	return os.Geteuid() == 0
}
