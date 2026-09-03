//go:build linux

package interfaces

import "testing"

func TestRoutesReadsMainTable(t *testing.T) {
	routes, err := Routes()
	if err != nil {
		t.Fatal(err)
	}
	ifs, _ := List()
	hasV4 := false
	for _, i := range ifs {
		if !i.Loopback && len(i.IPv4) > 0 && i.Up {
			hasV4 = true
		}
	}
	if hasV4 && len(routes) == 0 {
		t.Fatal("an interface has an IPv4 address but no route was read")
	}
	for _, r := range routes {
		if !r.Dst.IsValid() {
			t.Fatalf("invalid destination in %+v", r)
		}
	}
}
