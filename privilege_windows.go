//go:build windows

package main

func isCurrentUserPrivileged() bool {
	return true
}
