package certmgr

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/database64128/shadowsocks-go/tlscerts"
)

func TestCertificateSummariesDoNotExposePaths(t *testing.T) {
	certList, err := json.Marshal(summarizeCertList(tlscerts.TLSCertListConfig{
		Name: "server",
		Certs: []tlscerts.TLSCertConfig{{CertPath: "/secret/server.crt", KeyPath: "/secret/server.key"}},
	}))
	if err != nil {
		t.Fatalf("marshal certificate list summary: %v", err)
	}
	certPool, err := json.Marshal(summarizeCertPool(tlscerts.X509CertPoolConfig{
		Name: "clients",
		CertPaths: []string{"/secret/ca.pem"},
	}))
	if err != nil {
		t.Fatalf("marshal certificate pool summary: %v", err)
	}

	for _, body := range []string{string(certList), string(certPool)} {
		for _, value := range []string{"CertPath", "KeyPath", "CertPaths", "/secret/"} {
			if strings.Contains(body, value) {
				t.Fatalf("certificate summary contains sensitive path data %q: %s", value, body)
			}
		}
	}
}
