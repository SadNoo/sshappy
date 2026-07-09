package sstest

import "testing"

func TestDefaultUDPMTU(t *testing.T) {
	t.Setenv("UDP_MTU", "")
	if got := LoadConfig().UDPMTU; got != 1496 {
		t.Fatalf("UDPMTU = %d, want 1496", got)
	}
}
