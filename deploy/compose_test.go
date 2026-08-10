package deploy

import (
	"os"
	"strings"
	"testing"
)

func TestComposeCapsDockerJSONLogs(t *testing.T) {
	content, err := os.ReadFile("compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	for _, setting := range []string{
		"    logging:\n",
		"      driver: json-file\n",
		"        max-size: \"10m\"\n",
		"        max-file: \"3\"\n",
	} {
		if !strings.Contains(source, setting) {
			t.Fatalf("Node compose template must cap Docker JSON logs with %q", strings.TrimSpace(setting))
		}
	}
}

func TestComposeRequiresExplicitOfflineCandidate(t *testing.T) {
	content, err := os.ReadFile("compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	if strings.Contains(source, "${SSBAD_IMAGE:-") || strings.Contains(source, "sadno/flyskynode:3.3}") {
		t.Fatal("Node compose template must not fall back to quarantined Node 3.3")
	}
	if !strings.Contains(source, "image: ${SSBAD_IMAGE:?") {
		t.Fatal("Node compose template must require an explicitly approved image")
	}
	if !strings.Contains(source, "name: ${SSBAD_PROJECT_NAME:?") {
		t.Fatal("Node compose template must require a unique explicit project name")
	}
	if !strings.Contains(source, "pull_policy: ${SSBAD_PULL_POLICY:-never}") {
		t.Fatal("Node compose template must default to offline --pull never semantics")
	}
	for _, required := range []string{
		"${SSBAD_ENV_FILE:?",
		"${SSBAD_STATE_DIR:?",
		"${SSBAD_SECRET_DIR:?",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("Node compose template must require node-specific storage setting %q", required)
		}
	}
	for _, forbidden := range []string{
		"${SSBAD_ENV_FILE:-",
		"${SSBAD_STATE_DIR:-",
		"${SSBAD_SECRET_DIR:-",
		"/var/lib/flysky/ssbad",
		"/etc/flysky/ssbad/secrets",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("Node compose template must not retain shared state fallback %q", forbidden)
		}
	}
	if !strings.Contains(source, "restart: \"${SSBAD_RESTART_POLICY:-no}\"") {
		t.Fatal("Node compose template must default to no automatic restart during canary validation")
	}
}
