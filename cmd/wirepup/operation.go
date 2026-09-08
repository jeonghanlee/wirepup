package main

import (
	"context"
	"time"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/decode"
	"github.com/jeonghanlee/wirepup/internal/diagnose"
	"github.com/jeonghanlee/wirepup/internal/networkcfg"
	"github.com/jeonghanlee/wirepup/internal/output"
)

// operationResult carries the existing commands' typed outcomes before
// rendering. Guidance never infers state by parsing rendered output.
type operationResult struct {
	Devices *output.Devices
	Report  *diagnose.Report
	Source  string
	At      time.Time
	Decode  decode.Stats
	Capture capture.Stats
	Added   []networkcfg.Entry
	Code    int
}

func (e *env) recordReport(source string, at time.Time, report diagnose.Report) {
	if e.result != nil {
		e.result.Report, e.result.Source, e.result.At = &report, source, at
	}
}

func (e *env) recordStats(ds decode.Stats, cs capture.Stats) {
	if e.result != nil {
		e.result.Decode, e.result.Capture = ds, cs
	}
}

// executeOperation uses the same dispatcher, arguments and renderers as
// explicit invocation. Its context belongs to the whole interaction.
func executeOperation(ctx context.Context, e *env, args []string) operationResult {
	result := operationResult{}
	if ctx.Err() != nil {
		result.Code = exitError
		return result
	}
	call := *e
	call.result = &result
	result.Code = run(ctx, &call, args)
	if ctx.Err() != nil {
		result.Code = exitError
	}
	return result
}
