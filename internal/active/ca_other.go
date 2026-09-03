//go:build !linux

package active

import "net"

func setBroadcast(conn *net.UDPConn) error { return nil }
