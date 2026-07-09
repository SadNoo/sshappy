package sstest

import "testing"

func TestDefaultUDPMTU(t *testing.T) {
	t.Setenv("UDP_MTU", "")
	t.Setenv("UDP_RELAY_BATCH_SIZE", "")
	t.Setenv("UDP_SERVER_RECV_BATCH_SIZE", "")
	config := LoadConfig()
	if got := config.UDPMTU; got != 1496 {
		t.Fatalf("UDPMTU = %d, want 1496", got)
	}
	if got := config.UDPRelayBatchSize; got != 8 {
		t.Fatalf("UDPRelayBatchSize = %d, want 8", got)
	}
	if got := config.UDPServerBatchSize; got != 64 {
		t.Fatalf("UDPServerBatchSize = %d, want 64", got)
	}
}
