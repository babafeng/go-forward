//go:build windows

package route

func IsCurrentUserPrivileged() bool {
	return true
}
