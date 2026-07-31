package ssm

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/stats"
)

func TestUserSummariesNeverExposeUPSK(t *testing.T) {
	credentials := []cred.UserCredential{
		{Name: "alice", UPSK: []byte("secret-user-psk")},
		{Name: "bob", UPSK: []byte("another-secret-user-psk")},
	}

	data, err := json.Marshal(userListResponse{Users: summarizeUserCredentials(credentials)})
	if err != nil {
		t.Fatalf("marshal user list response: %v", err)
	}

	body := string(data)
	for _, value := range []string{"alice", "bob"} {
		if !strings.Contains(body, value) {
			t.Fatalf("response does not contain username %q: %s", value, body)
		}
	}
	for _, value := range []string{"uPSK", "secret-user-psk", "another-secret-user-psk"} {
		if strings.Contains(body, value) {
			t.Fatalf("response contains sensitive value %q: %s", value, body)
		}
	}
}

func TestUserDetailResponseNeverExposeUPSK(t *testing.T) {
	data, err := json.Marshal(userDetailResponse{Username: "alice"})
	if err != nil {
		t.Fatalf("marshal user detail response: %v", err)
	}

	if body := string(data); strings.Contains(body, "uPSK") {
		t.Fatalf("response contains sensitive field: %s", body)
	}
}

func TestUserTrafficReturnsOnlyRequestedUser(t *testing.T) {
	collector := stats.NewServerCollector()
	collector.CollectTCPSessionStart("alice")
	collector.CollectTCPSession("alice", 10, 20)
	collector.CollectTCPSessionStart("bob")
	collector.CollectTCPSession("bob", 100, 200)
	collector.CollectUDPSessionUplink("", 1, 1000)

	want := stats.Traffic{DownlinkBytes: 10, UplinkBytes: 20, TCPSessions: 1}
	if got := userTraffic(collector, "alice"); got != want {
		t.Fatalf("alice traffic = %+v, want %+v", got, want)
	}
	if got := userTraffic(collector, "unknown"); got != (stats.Traffic{}) {
		t.Fatalf("unknown user traffic = %+v, want zero", got)
	}
}
