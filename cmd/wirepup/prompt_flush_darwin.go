package main

import "golang.org/x/sys/unix"

func flushPromptInput(fd int) error {
	return unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, unix.TCIFLUSH)
}
