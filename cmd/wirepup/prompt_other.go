//go:build !linux && !darwin

package main

import (
	"context"
	"fmt"
	"os"
)

// Interactive guidance requires a cancellable terminal reader. Explicit
// commands and file replay remain available on other build targets.
func promptByte(ctx context.Context, f *os.File) (byte, error) {
	return 0, fmt.Errorf("interactive input is supported on Linux and macOS; use an explicit command")
}

func discardPromptInput(ctx context.Context, f *os.File) error {
	_, err := promptByte(ctx, f)
	return err
}
