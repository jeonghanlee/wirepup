package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// Keep the answer plus its newline below POSIX's minimum canonical line
// capacity (255 bytes). A limit above the terminal's own capacity cannot
// detect the discarded suffix of an overlong affirmative answer. Canonical
// editing and signal handling remain with the terminal, unchanged.
const maxPromptBytes = 253

var errPromptTooLong = fmt.Errorf("input exceeds %d bytes; use shorter input or an explicit command", maxPromptBytes)

// promptInput has one descriptor reader for the entire interaction. It
// watches EOF during operations as well as prompts. Only a requested line
// is retained; input outside a prompt cannot become a later confirmation.
type promptInput struct {
	requests chan promptRequest
	done     chan struct{}
	err      error
}

type promptRequest struct {
	ready chan struct{}
	start chan struct{}
	line  chan string
}

func newPromptInput(ctx context.Context, file *os.File, end context.CancelFunc) *promptInput {
	p := &promptInput{requests: make(chan promptRequest), done: make(chan struct{})}
	go p.read(ctx, file, end)
	return p
}

func terminalFile(f *os.File) bool    { return f != nil && term.IsTerminal(int(f.Fd())) }
func terminalWriter(w io.Writer) bool { f, ok := w.(*os.File); return ok && terminalFile(f) }
func (e *env) inputFile() *os.File {
	if e.stdin != nil {
		return e.stdin
	}
	return os.Stdin
}

func (p *promptInput) read(ctx context.Context, file *os.File, end context.CancelFunc) {
	defer close(p.done)
	var request *promptRequest
	var line strings.Builder
	for {
		if err := ctx.Err(); err != nil {
			p.err = err
			return
		}
		select {
		case next := <-p.requests:
			if err := discardPromptInput(ctx, file); err != nil {
				p.err = err
				if end != nil {
					end()
				}
				return
			}
			request = &next
			line.Reset()
			close(next.ready)
			select {
			case <-next.start:
			case <-ctx.Done():
				p.err = ctx.Err()
				return
			}
		default:
		}
		readCtx, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		b, err := promptByte(readCtx, file)
		stop()
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			continue
		}
		if err != nil {
			p.err = err
			if end != nil {
				end()
			}
			return
		}
		if request == nil {
			continue
		}
		if b == '\n' {
			request.line <- strings.TrimSuffix(line.String(), "\r")
			request = nil
			line.Reset()
			continue
		}
		if line.Len() >= maxPromptBytes {
			// The pending prompt owns this failure; let it report the reason
			// before the guide cancels and performs any required cleanup.
			// Discard the rejected line and queued tail so they cannot become
			// input to the invoking shell after the interaction exits.
			discardCtx, stopDiscard := context.WithTimeout(ctx, 100*time.Millisecond)
			p.err = errors.Join(errPromptTooLong, discardPromptInput(discardCtx, file))
			stopDiscard()
			return
		}
		line.WriteByte(b)
	}
}

// The owner acknowledges the request before printing the prompt. No other
// goroutine reads the descriptor, and no answer is carried across prompts.
func (p *promptInput) line(ctx context.Context, prompt func()) (string, error) {
	r := promptRequest{ready: make(chan struct{}), start: make(chan struct{}), line: make(chan string, 1)}
	select {
	case p.requests <- r:
	case <-p.done:
		return "", p.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
	select {
	case <-r.ready:
		prompt()
		close(r.start)
	case <-p.done:
		return "", p.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
	select {
	case line := <-r.line:
		return line, nil
	case <-p.done:
		return "", p.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
