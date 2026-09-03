package main

import (
	"context"
	"fmt"
)

// runRead replays a capture file through the same pipeline as live
// capture: an event stream by default, the device view with --devices.
func runRead(ctx context.Context, e *env, args []string) int {
	var g globalFlags
	var devices bool
	fs := newFlagSet("read", e)
	g.register(fs)
	fs.BoolVar(&devices, "devices", false, "show device discovery instead of the event stream")
	file, rest, err := positional(fs, args)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitUsage
	}
	if ok, code := parse(fs, rest); !ok {
		return code
	}
	if file == "" {
		fmt.Fprintf(e.stderr, "wirepup: %v: a capture file is required\n", errUsage)
		return exitUsage
	}
	g.pcap = file
	if devices {
		return discoverWith(ctx, e, &g)
	}
	return observeWith(ctx, e, &g)
}

// positional splits one leading or trailing positional argument from
// the flags so that both "read file --json" and "read --json file" work.
func positional(fs interface{ Parse([]string) error }, args []string) (string, []string, error) {
	var file string
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 0 && a[0] == '-' {
			rest = append(rest, a)
			if !hasValue(a) && i+1 < len(args) && needsValue(a) {
				rest = append(rest, args[i+1])
				i++
			}
			continue
		}
		if file != "" {
			return "", nil, fmt.Errorf("%w: unexpected argument %q", errUsage, a)
		}
		file = a
	}
	return file, rest, nil
}

func hasValue(a string) bool {
	for _, c := range a {
		if c == '=' {
			return true
		}
	}
	return false
}

// needsValue lists the flags that take a separate value argument.
func needsValue(a string) bool {
	switch trimDashes(a) {
	case "i", "interface", "timeout", "oui-file", "protocol", "pcap", "local":
		return true
	}
	return false
}

func trimDashes(a string) string {
	for len(a) > 0 && a[0] == '-' {
		a = a[1:]
	}
	return a
}
