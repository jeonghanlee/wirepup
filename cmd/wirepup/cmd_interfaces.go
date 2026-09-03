package main

import (
	"context"
	"fmt"

	"github.com/jeonghanlee/wirepup/internal/interfaces"
	"github.com/jeonghanlee/wirepup/internal/output"
	jsonout "github.com/jeonghanlee/wirepup/internal/output/json"
	"github.com/jeonghanlee/wirepup/internal/output/text"
)

func runInterfaces(ctx context.Context, e *env, args []string) int {
	var g globalFlags
	fs := newFlagSet("interfaces", e)
	g.register(fs)
	if ok, code := parse(fs, args); !ok {
		return code
	}
	ifs, err := interfaces.List()
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitError
	}
	doc := output.InterfacesFrom(ifs)
	if g.json {
		if err := jsonout.Document(e.stdout, doc); err != nil {
			return exitError
		}
		return exitOK
	}
	if err := text.Interfaces(e.stdout, doc); err != nil {
		return exitError
	}
	return exitOK
}
