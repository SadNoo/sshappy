package ssm

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/database64128/shadowsocks-go/cred"
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
