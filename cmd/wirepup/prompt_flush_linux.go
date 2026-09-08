package main

import "golang.org/x/sys/unix"

func flushPromptInput(fd int) error {
	return unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
}
