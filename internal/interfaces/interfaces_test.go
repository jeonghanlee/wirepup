package interfaces

import "testing"

func TestListIncludesLoopback(t *testing.T) {
	ifs, err := List()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ifs {
		if i.Loopback {
			if len(i.IPv4) == 0 && len(i.IPv6) == 0 {
				t.Skip("loopback has no address in this environment")
			}
			if i.OperState == "" {
				t.Fatal("empty operstate")
			}
			return
		}
	}
	t.Fatal("no loopback interface found")
}

func TestByNameUnknown(t *testing.T) {
	if _, err := ByName("no-such-interface-0"); err == nil {
		t.Fatal("expected error")
	}
}
