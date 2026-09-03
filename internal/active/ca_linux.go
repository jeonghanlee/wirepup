//go:build linux

package active

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// setBroadcast allows sending to directed broadcast addresses.
func setBroadcast(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("active: %w", err)
	}
	var serr error
	err = raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
	})
	if err != nil {
		return fmt.Errorf("active: %w", err)
	}
	if serr != nil {
		return fmt.Errorf("active: SO_BROADCAST: %w", serr)
	}
	return nil
}
