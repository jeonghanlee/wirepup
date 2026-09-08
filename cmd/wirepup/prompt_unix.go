//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const promptPollMillis = 100

// Consume queued complete lines first so a pending EOF still cancels the
// guide. Always discard canonical type-ahead, including input after EOF
// and an unfinished line, before returning control to the terminal owner.
// Only this descriptor owner performs reads or flushes.
func discardPromptInput(ctx context.Context, f *os.File) (result error) {
	fd := int(f.Fd())
	defer func() { result = errors.Join(result, flushPromptInput(fd)) }()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(p, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		if p[0].Revents&unix.POLLNVAL != 0 {
			return os.ErrClosed
		}
		var queued [256]byte
		n, err = unix.Read(fd, queued[:])
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.EOF
		}
	}
}

// Polling keeps terminal reads cancellable without a blocked reader
// goroutine or changing the caller's descriptor flags/terminal settings.
func promptByte(ctx context.Context, f *os.File) (byte, error) {
	fd := int(f.Fd())
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(p, promptPollMillis)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if p[0].Revents&unix.POLLNVAL != 0 {
			return 0, os.ErrClosed
		}
		var b [1]byte
		n, err = unix.Read(fd, b[:])
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}
		return b[0], nil
	}
}
