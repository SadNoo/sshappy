package flyskyapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientNodeAPIFlow(t *testing.T) {
	t.Parallel()

	accessToken := "fnode_" + strings.Repeat("a", 43)
	enrollmentToken := "fenr_" + strings.Repeat("b", 43)
	nodeID := "10000000-0000-4000-8000-000000000001"
	servingGeneration := "90000000-0000-4000-8000-000000000009"
	cursor := "cursor+/with symbols="
	report := testCapabilityReport()
	generatedAt := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept header = %q", got)
		}
		if got := request.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control header = %q", got)
		}
		if got := request.Header.Get("User-Agent"); got != "ssbad-flysky/test-version" {
			t.Errorf("User-Agent header = %q", got)
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")

		switch request.URL.Path {
		case "/api/node/v1/capabilities":
			writeTestSuccess(t, response, map[string]any{
				"api_version": "v1", "schema_versions": []int{1},
				"features": []string{"snapshot_v1"},
				"protocols": map[string]any{"ss2022": map[string]any{
					"methods": []string{"2022-blake3-aes-256-gcm"}, "tcp": true, "udp": true,
					"single_port_multi_user": true,
				}},
				"limits": map[string]any{"usage_report_max_bytes": 4194304, "usage_report_max_items": 10000},
			})
		case "/api/node/v1/enroll":
			if got := request.Header.Get("Authorization"); got != "" {
				t.Errorf("enrollment Authorization header = %q", got)
			}
			var enrollment EnrollmentRequest
			if err := json.NewDecoder(request.Body).Decode(&enrollment); err != nil {
				t.Fatal(err)
			}
			if enrollment.EnrollmentToken != enrollmentToken || enrollment.Runtime != report.Runtime {
				t.Fatalf("unexpected enrollment: %+v", enrollment)
			}
			response.WriteHeader(http.StatusCreated)
			writeTestSuccess(t, response, map[string]any{
				"node_id": nodeID, "access_token": accessToken, "token_type": "Bearer",
				"expires_at": generatedAt.Add(24 * time.Hour),
			})
		case "/api/node/v1/credentials/rotate":
			assertBearer(t, request, accessToken)
			writeTestSuccess(t, response, map[string]any{
				"node_id": nodeID, "access_token": accessToken, "token_type": "Bearer",
				"expires_at": generatedAt.Add(48 * time.Hour),
			})
		case "/api/node/v1/status":
			assertBearer(t, request, accessToken)
			var status StatusRequest
			if err := json.NewDecoder(request.Body).Decode(&status); err != nil ||
				status.AppliedServingGeneration != servingGeneration || status.AppliedCursor != cursor {
				t.Fatalf("status report = %+v, err=%v", status, err)
			}
			writeTestSuccess(t, response, map[string]any{
				"state": "online", "state_version": 2, "last_seen_at": generatedAt,
				"next_heartbeat_seconds": 60,
			})
		case "/api/node/v1/snapshot":
			assertBearer(t, request, accessToken)
			assertResourceVersionFence(t, request)
			writeTestSuccess(t, response, map[string]any{
				"schema_version": 1, "serving_generation": servingGeneration,
				"config_version": "12", "cursor": "cursor-12",
				"generated_at": generatedAt, "valid_until": generatedAt.Add(time.Hour),
				"node": map[string]any{
					"node_id": nodeID, "protocol": "ss2022", "method": "2022-blake3-aes-256-gcm",
					"listen_port": 443, "server_secret_version": 3, "server_key": "c2VydmVyLWtleQ==",
				},
				"users": []any{map[string]any{
					"user_id": "20000000-0000-4000-8000-000000000002", "credential_version": 4,
					"user_key": "dXNlci1rZXk=", "valid_until": generatedAt.Add(time.Hour),
					"quota_remaining_bytes": 1024, "policy_version": 5,
				}},
				"resource_versions": map[string]any{"20000000-0000-4000-8000-000000000002": 5},
			})
		case "/api/node/v1/changes":
			assertBearer(t, request, accessToken)
			assertResourceVersionFence(t, request)
			if got := request.URL.Query().Get("since"); got != cursor {
				t.Errorf("since query = %q, want %q", got, cursor)
			}
			writeTestSuccess(t, response, map[string]any{
				"serving_generation": servingGeneration,
				"changes": []any{map[string]any{
					"sequence": 13, "operation": "revoke_user", "resource_id": nodeID,
					"resource_version": 6, "payload": map[string]any{"user_id": nodeID},
				}},
				"next_cursor": "cursor-13",
			})
		case "/api/node/v1/usage-reports":
			assertBearer(t, request, accessToken)
			var usage UsageReport
			if err := json.NewDecoder(request.Body).Decode(&usage); err != nil || usage.NodeID != nodeID || len(usage.Items) != 1 {
				t.Fatalf("usage report = %+v, err=%v", usage, err)
			}
			response.WriteHeader(http.StatusAccepted)
			writeTestSuccess(t, response, map[string]any{
				"receipt_id": usage.ReportID, "report_id": usage.ReportID, "state": "accepted",
			})
		case "/api/node/v1/alive-ips":
			assertBearer(t, request, accessToken)
			var alive AliveIPReport
			if err := json.NewDecoder(request.Body).Decode(&alive); err != nil || alive.NodeID != nodeID || alive.OnlineIPCount != 2 {
				t.Fatalf("alive IP report = %+v, err=%v", alive, err)
			}
			response.WriteHeader(http.StatusAccepted)
			writeTestSuccess(t, response, map[string]any{
				"receipt_id": alive.ReportID, "report_id": alive.ReportID, "state": "accepted",
			})
		default:
			t.Fatalf("unexpected path: %s", request.URL.Path)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	ctx := context.Background()
	capabilities, err := client.Capabilities(ctx)
	if err != nil || capabilities.APIVersion != "v1" || !capabilities.Protocols["ss2022"].SinglePortMultiUser {
		t.Fatalf("Capabilities() = %+v, %v", capabilities, err)
	}
	credential, err := client.Enroll(ctx, enrollmentToken, report)
	if err != nil || credential.NodeID != nodeID || credential.AccessToken != accessToken {
		t.Fatalf("Enroll() = %+v, %v", credential, err)
	}
	if _, err := client.RotateCredential(ctx, accessToken); err != nil {
		t.Fatalf("RotateCredential(): %v", err)
	}
	state, err := client.ReportStatus(ctx, accessToken, StatusRequest{
		CapabilityReport:         report,
		AppliedServingGeneration: servingGeneration,
		AppliedCursor:            cursor,
		Health:                   HealthReport{Status: "healthy", ActiveConnections: 2, Load1: 0.25, MemoryUsedBytes: 4096},
	})
	if err != nil || state.State != "online" || state.NextHeartbeatSeconds != 60 {
		t.Fatalf("ReportStatus() = %+v, %v", state, err)
	}
	snapshot, err := client.Snapshot(ctx, accessToken)
	if err != nil || snapshot.ServingGeneration != servingGeneration || snapshot.ConfigVersion != "12" || len(snapshot.Users) != 1 {
		t.Fatalf("Snapshot() = %+v, %v", snapshot, err)
	}
	changes, err := client.Changes(ctx, accessToken, cursor)
	if err != nil || changes.ServingGeneration != servingGeneration || changes.NextCursor != "cursor-13" || len(changes.Changes) != 1 {
		t.Fatalf("Changes() = %+v, %v", changes, err)
	}
	usageReceipt, err := client.SubmitUsage(ctx, accessToken, UsageReport{
		SchemaVersion: 1, ReportID: nodeID, Sequence: 1, NodeID: nodeID, ConfigVersion: "12",
		WindowStart: generatedAt.Add(-time.Minute), WindowEnd: generatedAt,
		Items: []UsageItem{{ItemIndex: 0, UserID: nodeID, CredentialVersion: 1, UploadBytes: 1}},
	})
	if err != nil || usageReceipt.State != "accepted" {
		t.Fatalf("SubmitUsage() = %+v, %v", usageReceipt, err)
	}
	aliveReceipt, err := client.SubmitAliveIPs(ctx, accessToken, AliveIPReport{
		SchemaVersion: 1, ReportID: nodeID, NodeID: nodeID, ObservedAt: generatedAt,
		WindowSeconds: 60, OnlineIPCount: 2, ActiveUsers: 1,
	})
	if err != nil || aliveReceipt.State != "accepted" {
		t.Fatalf("SubmitAliveIPs() = %+v, %v", aliveReceipt, err)
	}
}

func TestClientErrorsDoNotExposeTokens(t *testing.T) {
	t.Parallel()

	accessToken := "fnode_" + strings.Repeat("s", 43)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(response, `{"ok":false,"error":{"code":"UNAUTHORIZED","message":%q,"retryable":false},"meta":{"request_id":"request-1"}}`, accessToken)
	}))
	defer server.Close()

	_, err := newTestClient(t, server.URL).Snapshot(context.Background(), accessToken)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized || apiErr.RequestID != "request-1" {
		t.Fatalf("Snapshot() error = %#v", err)
	}
	if strings.Contains(err.Error(), accessToken) {
		t.Fatal("API error exposed the access token")
	}
}

func TestReportStatusRequiresAppliedGenerationCursorPair(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, "https://panel.example.test")
	for _, report := range []StatusRequest{
		{AppliedServingGeneration: "90000000-0000-4000-8000-000000000009"},
		{AppliedCursor: "cursor-9"},
		{AppliedServingGeneration: "not-a-uuid", AppliedCursor: "cursor-9"},
		{StoppedServingGeneration: "not-a-uuid"},
		{
			AppliedServingGeneration: "90000000-0000-4000-8000-000000000009", AppliedCursor: "cursor-9",
			StoppedServingGeneration: "80000000-0000-4000-8000-000000000008",
		},
	} {
		if _, err := client.ReportStatus(context.Background(), "token", report); err == nil {
			t.Fatalf("invalid applied acknowledgement was accepted: %+v", report)
		}
	}
}

func TestClientMarksExpiredCursor(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusGone)
		_, _ = response.Write([]byte(`{"ok":false,"error":{"code":"CURSOR_EXPIRED","retryable":false},"meta":{"request_id":"request-2"}}`))
	}))
	defer server.Close()

	_, err := newTestClient(t, server.URL).Changes(context.Background(), "token", "old-cursor")
	if !errors.Is(err, ErrCursorExpired) {
		t.Fatalf("Changes() error = %v", err)
	}
}

func TestAPIErrorRetryClassificationAndRetryAfter(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 1, 2, 3, 4, 0, time.UTC)
	tests := []struct {
		name       string
		statusCode int
		retryAfter string
		body       string
		wantRetry  bool
		wantDelay  time.Duration
		wantParsed bool
	}{
		{
			name: "server error without usable envelope", statusCode: http.StatusInternalServerError,
			body: `not-json`, wantRetry: true,
		},
		{
			name: "rate limited delta seconds", statusCode: http.StatusTooManyRequests,
			retryAfter: "120", body: `{"ok":false,"error":{"code":"RATE_LIMITED","retryable":false}}`,
			wantRetry: true, wantDelay: 2 * time.Minute, wantParsed: true,
		},
		{
			name: "rate limited HTTP date", statusCode: http.StatusTooManyRequests,
			retryAfter: now.Add(90 * time.Second).Format(http.TimeFormat), body: `{}`,
			wantRetry: true, wantDelay: 90 * time.Second, wantParsed: true,
		},
		{
			name: "permanent validation", statusCode: http.StatusUnprocessableEntity,
			body: `{"ok":false,"error":{"code":"VALIDATION_FAILED","retryable":false}}`,
		},
		{
			name: "server declared retryable", statusCode: http.StatusConflict,
			body: `{"ok":false,"error":{"code":"TEMPORARY_CONFLICT","retryable":true}}`, wantRetry: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := &http.Response{StatusCode: test.statusCode, Header: make(http.Header)}
			response.Header.Set("Retry-After", test.retryAfter)
			var apiErr *APIError
			if err := decodeAPIError(response, []byte(test.body)); !errors.As(err, &apiErr) {
				t.Fatalf("decodeAPIError() = %T %v", err, err)
			}
			if apiErr.Retryable != test.wantRetry {
				t.Fatalf("Retryable = %v, want %v", apiErr.Retryable, test.wantRetry)
			}
			delay, parsed := apiErr.RetryDelay(now)
			if parsed != test.wantParsed || delay != test.wantDelay {
				t.Fatalf("RetryDelay() = %v, %v; want %v, %v", delay, parsed, test.wantDelay, test.wantParsed)
			}
		})
	}
}

func TestClientDoesNotFollowAuthenticationRedirect(t *testing.T) {
	t.Parallel()

	var targetRequests atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetRequests.Add(1)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	_, err := newTestClient(t, source.URL).Snapshot(context.Background(), "sensitive-token")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if targetRequests.Load() != 0 {
		t.Fatal("redirect target received the authenticated request")
	}
}

func TestClientLimitsAndValidatesResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		body        string
		maxBytes    int64
		want        error
	}{
		{name: "too large", contentType: "application/json", body: strings.Repeat("x", 20), maxBytes: 8, want: ErrResponseTooLarge},
		{name: "wrong content type", contentType: "text/html", body: `{}`, maxBytes: 1024},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", test.contentType)
				_, _ = response.Write([]byte(test.body))
			}))
			defer server.Close()
			client, err := NewClient(Config{BaseURL: server.URL, AllowInsecureHTTP: true, MaxBodyBytes: test.maxBytes})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Capabilities(context.Background())
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("Capabilities() error = %v", err)
			}
			if test.want == nil && err == nil {
				t.Fatal("Capabilities() unexpectedly succeeded")
			}
		})
	}
}

func TestClientUsesEndpointSpecificResponseLimitsAndFenceScope(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/node/v1/snapshot":
			assertResourceVersionFence(t, request)
			writeTestSuccess(t, response, map[string]any{})
		case "/api/node/v1/changes":
			assertResourceVersionFence(t, request)
			writeTestSuccess(t, response, map[string]any{"changes": []any{}, "next_cursor": "cursor-2"})
		case "/api/node/v1/capabilities":
			if got := request.Header.Get(resourceVersionFenceHeader); got != "" {
				t.Errorf("capabilities unexpectedly carried %s=%q", resourceVersionFenceHeader, got)
			}
			writeTestSuccess(t, response, map[string]any{})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	client.maxBodyBytes = 1
	client.maxSnapshotBodyBytes = 1024
	client.maxChangesBodyBytes = 1024
	if _, err := client.Snapshot(context.Background(), "token"); err != nil {
		t.Fatalf("Snapshot() did not use snapshot response limit: %v", err)
	}
	if _, err := client.Changes(context.Background(), "token", "cursor-1"); err != nil {
		t.Fatalf("Changes() did not use changes response limit: %v", err)
	}
	if _, err := client.Capabilities(context.Background()); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Capabilities() error = %v, want ErrResponseTooLarge", err)
	}
}

func TestReadLimitedRejectsExactlyOneByteOverLimit(t *testing.T) {
	t.Parallel()

	const limit = int64(128)
	if data, err := readLimited(strings.NewReader(strings.Repeat("x", int(limit))), limit); err != nil || int64(len(data)) != limit {
		t.Fatalf("exact-limit response = %d bytes, %v", len(data), err)
	}
	if _, err := readLimited(strings.NewReader(strings.Repeat("x", int(limit+1))), limit); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("limit+1 response error = %v, want ErrResponseTooLarge", err)
	}
}

func TestDefaultResponseLimitsAreBoundedByEndpoint(t *testing.T) {
	t.Parallel()

	client, err := NewClient(Config{BaseURL: "http://127.0.0.1", AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if client.maxBodyBytes != defaultMaxBodyBytes ||
		client.maxSnapshotBodyBytes != defaultMaxSnapshotBodyBytes ||
		client.maxChangesBodyBytes != defaultMaxChangesBodyBytes {
		t.Fatalf("response limits = small:%d snapshot:%d changes:%d", client.maxBodyBytes, client.maxSnapshotBodyBytes, client.maxChangesBodyBytes)
	}
	clamped, err := NewClient(Config{
		BaseURL: "http://127.0.0.1", AllowInsecureHTTP: true, MaxBodyBytes: 64 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if clamped.maxBodyBytes != defaultMaxBodyBytes ||
		clamped.maxSnapshotBodyBytes != defaultMaxSnapshotBodyBytes ||
		clamped.maxChangesBodyBytes != defaultMaxChangesBodyBytes {
		t.Fatalf("oversized override escaped response caps: small:%d snapshot:%d changes:%d", clamped.maxBodyBytes, clamped.maxSnapshotBodyBytes, clamped.maxChangesBodyBytes)
	}
}

func TestNilClientFailsWithoutPanicking(t *testing.T) {
	t.Parallel()

	var client *Client
	if _, err := client.Snapshot(context.Background(), "token"); err == nil {
		t.Fatal("nil Snapshot client was accepted")
	}
	if _, err := client.Changes(context.Background(), "token", "cursor-1"); err == nil {
		t.Fatal("nil Changes client was accepted")
	}
}

func TestClientRequiresHTTPSOutsideLoopback(t *testing.T) {
	t.Parallel()

	invalid := []Config{
		{BaseURL: "http://panel.example"},
		{BaseURL: "http://panel.example", AllowInsecureHTTP: true},
		{BaseURL: "https://user:password@panel.example"},
		{BaseURL: "/relative"},
	}
	for _, config := range invalid {
		if _, err := NewClient(config); err == nil {
			t.Fatalf("NewClient(%q) unexpectedly succeeded", config.BaseURL)
		}
	}
	if _, err := NewClient(Config{BaseURL: "http://127.0.0.1:8080", AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("loopback development URL rejected: %v", err)
	}
	if _, err := NewClient(Config{BaseURL: "https://panel.example"}); err != nil {
		t.Fatalf("HTTPS URL rejected: %v", err)
	}
}

func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	client, err := NewClient(Config{
		BaseURL: baseURL, AllowInsecureHTTP: true, ClientVersion: "test-version",
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testCapabilityReport() CapabilityReport {
	return CapabilityReport{
		Runtime: "ssbad", Version: "test-version", SchemaVersions: []int{1},
		Protocols: map[string]ProtocolCapability{
			"ss2022": {
				Methods: []string{"2022-blake3-aes-256-gcm"}, TCP: true, UDP: true,
				SinglePortMultiUser: true,
			},
		},
		Features: []string{"snapshot_v1", "cursor_changes_v1"},
	}
}

func assertBearer(t *testing.T, request *http.Request, token string) {
	t.Helper()
	if got := request.Header.Get("Authorization"); got != "Bearer "+token {
		t.Errorf("Authorization header = %q", got)
	}
}

func assertResourceVersionFence(t *testing.T, request *http.Request) {
	t.Helper()
	if got := request.Header.Get(resourceVersionFenceHeader); got != resourceVersionFenceHeaderValue {
		t.Errorf("%s header = %q, want %q", resourceVersionFenceHeader, got, resourceVersionFenceHeaderValue)
	}
}

func writeTestSuccess(t *testing.T, response http.ResponseWriter, data any) {
	t.Helper()
	if err := json.NewEncoder(response).Encode(map[string]any{
		"ok": true, "data": data, "meta": map[string]any{"request_id": "request-test", "api_version": "1"},
	}); err != nil {
		t.Fatal(err)
	}
}
