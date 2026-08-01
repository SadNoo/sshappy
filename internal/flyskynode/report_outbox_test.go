package flyskynode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/internal/flyskyapi"
)

type reportClientStub struct {
	usageErr     error
	aliveErr     error
	usageErrorAt func(int, flyskyapi.UsageReport) error
	aliveErrorAt func(int, flyskyapi.AliveIPReport) error
	badReceipt   bool
	usage        []flyskyapi.UsageReport
	alive        []flyskyapi.AliveIPReport
}

func (client *reportClientStub) SubmitUsage(_ context.Context, _ string, report flyskyapi.UsageReport) (flyskyapi.ReportReceipt, error) {
	client.usage = append(client.usage, report)
	if client.usageErrorAt != nil {
		if err := client.usageErrorAt(len(client.usage)-1, report); err != nil {
			return flyskyapi.ReportReceipt{}, err
		}
	}
	if client.usageErr != nil {
		return flyskyapi.ReportReceipt{}, client.usageErr
	}
	reportID := report.ReportID
	if client.badReceipt {
		reportID = "10000000-0000-4000-8000-000000000001"
	}
	return flyskyapi.ReportReceipt{ReceiptID: reportID, ReportID: reportID, State: "accepted"}, nil
}

func (client *reportClientStub) SubmitAliveIPs(_ context.Context, _ string, report flyskyapi.AliveIPReport) (flyskyapi.ReportReceipt, error) {
	client.alive = append(client.alive, report)
	if client.aliveErrorAt != nil {
		if err := client.aliveErrorAt(len(client.alive)-1, report); err != nil {
			return flyskyapi.ReportReceipt{}, err
		}
	}
	if client.aliveErr != nil {
		return flyskyapi.ReportReceipt{}, client.aliveErr
	}
	return flyskyapi.ReportReceipt{ReceiptID: report.ReportID, ReportID: report.ReportID, State: "accepted"}, nil
}

const reportTestNodeID = "10000000-0000-4000-8000-000000000001"

func reportTestUserID(index int) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", index+1, index+1)
}

func reportTestDeltas(count int) []TrafficDelta {
	deltas := make([]TrafficDelta, count)
	for index := range deltas {
		deltas[index] = TrafficDelta{
			UserID: reportTestUserID(index), CredentialVersion: 1, UploadBytes: int64(index + 1),
		}
	}
	return deltas
}

func captureReportTestUsage(t *testing.T, outbox *reportOutbox, deltas []TrafficDelta) {
	t.Helper()
	now := time.Date(2026, time.August, 1, 1, 2, 3, 0, time.UTC)
	if err := outbox.CaptureUsage(reportTestNodeID, "config-42", now.Add(-time.Minute), now, deltas); err != nil {
		t.Fatal(err)
	}
}

func TestReportOutboxPersistsAndFlushesReports(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "reports.json")
	outbox, err := newReportOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.UTC)
	nodeID := "10000000-0000-4000-8000-000000000001"
	if err := outbox.CaptureUsage(nodeID, "42", now.Add(-time.Minute), now, []TrafficDelta{{
		UserID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 3,
		UploadBytes: 10, DownloadBytes: 20,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := outbox.CaptureAliveIP(flyskyapi.AliveIPReport{
		NodeID: nodeID, ObservedAt: now, WindowSeconds: 60, OnlineIPCount: 2, ActiveUsers: 3,
	}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("outbox permissions = %v", info.Mode())
	}
	reloaded, err := newReportOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	usage, alive := reloaded.Pending()
	if usage != 1 || alive != 1 || reloaded.state.NextSequence != 2 {
		t.Fatalf("pending usage=%d alive=%d next=%d", usage, alive, reloaded.state.NextSequence)
	}
	if err := reloaded.ValidateNode(nodeID); err != nil {
		t.Fatal(err)
	}
	if err := reloaded.ValidateNode("30000000-0000-4000-8000-000000000003"); err == nil {
		t.Fatal("outbox was accepted for a different node")
	}
	client := &reportClientStub{}
	if err := reloaded.Flush(context.Background(), client, "token"); err != nil {
		t.Fatal(err)
	}
	usage, alive = reloaded.Pending()
	if usage != 0 || alive != 0 || len(client.usage) != 1 || len(client.alive) != 1 {
		t.Fatalf("pending usage=%d alive=%d sentUsage=%d sentAlive=%d", usage, alive, len(client.usage), len(client.alive))
	}
	afterFlush, err := newReportOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	if afterFlush.state.NextSequence != 2 {
		t.Fatalf("next sequence after flush = %d", afterFlush.state.NextSequence)
	}
}

func TestReportOutboxRetainsStableReportAcrossRetry(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "reports.json")
	outbox, err := newReportOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := outbox.CaptureUsage(
		"10000000-0000-4000-8000-000000000001", "1", now.Add(-time.Minute), now,
		[]TrafficDelta{{UserID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1, UploadBytes: 1}},
	); err != nil {
		t.Fatal(err)
	}
	client := &reportClientStub{usageErr: errors.New("offline")}
	if err := outbox.Flush(context.Background(), client, "token"); err == nil {
		t.Fatal("offline report unexpectedly flushed")
	}
	client.usageErr = nil
	if err := outbox.Flush(context.Background(), client, "token"); err != nil {
		t.Fatal(err)
	}
	if len(client.usage) != 2 || client.usage[0].ReportID != client.usage[1].ReportID || client.usage[0].Sequence != client.usage[1].Sequence {
		t.Fatalf("retry changed report identity: %+v", client.usage)
	}
}

func TestReportOutboxRetainsReportOnMismatchedAcknowledgement(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "reports.json")
	outbox, err := newReportOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := outbox.CaptureUsage(
		"10000000-0000-4000-8000-000000000001", "1", now.Add(-time.Minute), now,
		[]TrafficDelta{{UserID: "20000000-0000-4000-8000-000000000002", CredentialVersion: 1, DownloadBytes: 1}},
	); err != nil {
		t.Fatal(err)
	}
	if err := outbox.Flush(context.Background(), &reportClientStub{badReceipt: true}, "token"); err == nil {
		t.Fatal("mismatched acknowledgement was accepted")
	}
	usage, _ := outbox.Pending()
	if usage != 1 {
		t.Fatalf("pending usage = %d", usage)
	}
}

func TestReportOutboxSplitsLargeUsageCaptureAndPersistsOnce(t *testing.T) {
	tests := []struct {
		name       string
		itemCount  int
		wantCounts []int
	}{
		{name: "exactly 10k", itemCount: 10000, wantCounts: []int{10000}},
		{name: "10k plus one", itemCount: 10001, wantCounts: []int{10000, 1}},
		{name: "30k", itemCount: 30000, wantCounts: []int{10000, 10000, 10000}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "reports.json")
			outbox, err := newReportOutbox(path)
			if err != nil {
				t.Fatal(err)
			}
			writes := 0
			outbox.write = func(path string, data []byte) error {
				writes++
				return writeReportOutbox(path, data)
			}
			captureReportTestUsage(t, outbox, reportTestDeltas(test.itemCount))
			if writes != 1 {
				t.Fatalf("capture persisted %d times, want one atomic write", writes)
			}
			if len(outbox.state.UsageReports) != len(test.wantCounts) {
				t.Fatalf("reports = %d, want %d", len(outbox.state.UsageReports), len(test.wantCounts))
			}
			total := 0
			for reportIndex, report := range outbox.state.UsageReports {
				if report.Sequence != int64(reportIndex+1) {
					t.Fatalf("report %d sequence = %d", reportIndex, report.Sequence)
				}
				if len(report.Items) != test.wantCounts[reportIndex] {
					t.Fatalf("report %d items = %d, want %d", reportIndex, len(report.Items), test.wantCounts[reportIndex])
				}
				encoded, err := json.Marshal(report)
				if err != nil {
					t.Fatal(err)
				}
				if int64(len(encoded)) > maxUsageReportEncodedBytes {
					t.Fatalf("report %d encoded bytes = %d", reportIndex, len(encoded))
				}
				for itemIndex, item := range report.Items {
					if item.ItemIndex != itemIndex {
						t.Fatalf("report %d item %d index = %d", reportIndex, itemIndex, item.ItemIndex)
					}
				}
				total += len(report.Items)
			}
			if total != test.itemCount || outbox.state.NextSequence != int64(len(test.wantCounts)+1) {
				t.Fatalf("total=%d next=%d", total, outbox.state.NextSequence)
			}

			reloaded, err := newReportOutbox(path)
			if err != nil {
				t.Fatal(err)
			}
			for index := range outbox.state.UsageReports {
				if reloaded.state.UsageReports[index].ReportID != outbox.state.UsageReports[index].ReportID {
					t.Fatalf("report %d identity changed on reload", index)
				}
			}
		})
	}
}

func TestReportOutboxSortsByUserAndCredentialVersion(t *testing.T) {
	t.Parallel()
	outbox, err := newReportOutbox(filepath.Join(t.TempDir(), "reports.json"))
	if err != nil {
		t.Fatal(err)
	}
	firstUser := reportTestUserID(0)
	secondUser := reportTestUserID(1)
	captureReportTestUsage(t, outbox, []TrafficDelta{
		{UserID: secondUser, CredentialVersion: 1, UploadBytes: 1},
		{UserID: firstUser, CredentialVersion: 2, UploadBytes: 1},
		{UserID: firstUser, CredentialVersion: 1, UploadBytes: 1},
	})
	items := outbox.state.UsageReports[0].Items
	if len(items) != 3 ||
		items[0].UserID != firstUser || items[0].CredentialVersion != 1 ||
		items[1].UserID != firstUser || items[1].CredentialVersion != 2 ||
		items[2].UserID != secondUser || items[2].CredentialVersion != 1 {
		t.Fatalf("unexpected deterministic order: %+v", items)
	}

	duplicate, err := newReportOutbox(filepath.Join(t.TempDir(), "reports.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 1, 1, 2, 3, 0, time.UTC)
	err = duplicate.CaptureUsage(reportTestNodeID, "config-42", now.Add(-time.Minute), now, []TrafficDelta{
		{UserID: firstUser, CredentialVersion: 1, UploadBytes: 1},
		{UserID: firstUser, CredentialVersion: 1, DownloadBytes: 1},
	})
	if err == nil {
		t.Fatal("duplicate user and credential version was accepted")
	}
}

func TestReportOutboxAppliesDynamicAndEncodedByteLimits(t *testing.T) {
	t.Run("dynamic item limit", func(t *testing.T) {
		outbox, err := newReportOutbox(filepath.Join(t.TempDir(), "reports.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := outbox.SetUsageReportLimits(usageReportLimits{MaxItems: 2, MaxEncodedBytes: maxUsageReportEncodedBytes}); err != nil {
			t.Fatal(err)
		}
		captureReportTestUsage(t, outbox, reportTestDeltas(5))
		if err := outbox.SetUsageReportLimits(usageReportLimits{MaxItems: 3, MaxEncodedBytes: maxUsageReportEncodedBytes}); err != nil {
			t.Fatal(err)
		}
		captureReportTestUsage(t, outbox, reportTestDeltas(7))
		want := []int{2, 2, 1, 3, 3, 1}
		if len(outbox.state.UsageReports) != len(want) {
			t.Fatalf("reports = %d", len(outbox.state.UsageReports))
		}
		for index, report := range outbox.state.UsageReports {
			if len(report.Items) != want[index] || report.Sequence != int64(index+1) {
				t.Fatalf("report %d items=%d sequence=%d", index, len(report.Items), report.Sequence)
			}
		}
	})

	t.Run("encoded bytes", func(t *testing.T) {
		outbox, err := newReportOutbox(filepath.Join(t.TempDir(), "reports.json"))
		if err != nil {
			t.Fatal(err)
		}
		const byteLimit = int64(500)
		if err := outbox.SetUsageReportLimits(usageReportLimits{MaxItems: 100, MaxEncodedBytes: byteLimit}); err != nil {
			t.Fatal(err)
		}
		captureReportTestUsage(t, outbox, reportTestDeltas(7))
		if len(outbox.state.UsageReports) < 2 {
			t.Fatal("encoded byte limit did not split the report")
		}
		total := 0
		for _, report := range outbox.state.UsageReports {
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			if int64(len(encoded)) > byteLimit {
				t.Fatalf("encoded report = %d bytes, limit = %d", len(encoded), byteLimit)
			}
			total += len(report.Items)
		}
		if total != 7 {
			t.Fatalf("captured items = %d", total)
		}
	})

	t.Run("single item too large is atomic", func(t *testing.T) {
		outbox, err := newReportOutbox(filepath.Join(t.TempDir(), "reports.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := outbox.SetUsageReportLimits(usageReportLimits{MaxItems: 1, MaxEncodedBytes: 1}); err != nil {
			t.Fatal(err)
		}
		now := time.Date(2026, time.August, 1, 1, 2, 3, 0, time.UTC)
		err = outbox.CaptureUsage(reportTestNodeID, "config-42", now.Add(-time.Minute), now, reportTestDeltas(1))
		if err == nil {
			t.Fatal("oversized item was accepted")
		}
		usage, alive := outbox.Pending()
		if usage != 0 || alive != 0 || outbox.state.NextSequence != 1 {
			t.Fatalf("failed capture mutated state: usage=%d alive=%d next=%d", usage, alive, outbox.state.NextSequence)
		}
	})
}

func TestReportOutboxMigratesV1OnRead(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "reports.json")
	outbox, err := newReportOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	captureReportTestUsage(t, outbox, reportTestDeltas(1))
	original := outbox.state.UsageReports[0]
	legacy := struct {
		Version        int                       `json:"version"`
		NextSequence   int64                     `json:"next_sequence"`
		UsageReports   []flyskyapi.UsageReport   `json:"usage_reports"`
		AliveIPReports []flyskyapi.AliveIPReport `json:"alive_ip_reports"`
	}{Version: legacyReportOutboxVersion, NextSequence: 2, UsageReports: []flyskyapi.UsageReport{original}}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	migrated, err := newReportOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.state.Version != reportOutboxVersion || migrated.state.UsageReports[0].ReportID != original.ReportID {
		t.Fatalf("v1 migration lost state: %+v", migrated.state)
	}
	if err := migrated.Flush(context.Background(), &reportClientStub{}, "token"); err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(persisted), `"version":2`) {
		t.Fatalf("migrated state was not persisted as v2: %s", persisted)
	}
	if _, err := newReportOutbox(path); err != nil {
		t.Fatalf("persisted v2 state did not reload: %v", err)
	}
}

func TestReportOutboxReconcilesPermanentUsageFailuresAndContinues(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "reports.json")
	outbox, err := newReportOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.SetUsageReportLimits(usageReportLimits{MaxItems: 1, MaxEncodedBytes: maxUsageReportEncodedBytes}); err != nil {
		t.Fatal(err)
	}
	captureReportTestUsage(t, outbox, reportTestDeltas(4))
	wantIDs := make([]string, len(outbox.state.UsageReports))
	for index, report := range outbox.state.UsageReports {
		wantIDs[index] = report.ReportID
	}
	client := &reportClientStub{usageErrorAt: func(call int, _ flyskyapi.UsageReport) error {
		switch call {
		case 0:
			return &flyskyapi.APIError{StatusCode: http.StatusConflict, Code: "REPORT_ID_CONFLICT", RequestID: "req-409"}
		case 1:
			return &flyskyapi.APIError{StatusCode: http.StatusUnprocessableEntity, Code: "USAGE_ITEM_UNKNOWN", RequestID: "req-unknown"}
		case 2:
			return &flyskyapi.APIError{StatusCode: http.StatusUnprocessableEntity, Code: "VALIDATION_FAILED", RequestID: "req-validation"}
		default:
			return nil
		}
	}}
	err = outbox.Flush(context.Background(), client, "token")
	var reconciliationErr *reportReconciliationError
	if !errors.As(err, &reconciliationErr) || reconciliationErr.Usage != 3 || reconciliationErr.Alive != 0 {
		t.Fatalf("Flush() error = %T %v", err, err)
	}
	usage, alive := outbox.Pending()
	reconciledUsage, reconciledAlive := outbox.Reconciliation()
	if usage != 0 || alive != 0 || reconciledUsage != 3 || reconciledAlive != 0 || len(client.usage) != 4 {
		t.Fatalf("pending=%d/%d reconciliation=%d/%d calls=%d", usage, alive, reconciledUsage, reconciledAlive, len(client.usage))
	}
	for index, item := range outbox.state.UsageReconciliation {
		if item.Report.ReportID != wantIDs[index] || item.Attempts != 1 || item.FirstFailedAt.IsZero() || item.LastFailedAt.IsZero() {
			t.Fatalf("reconciliation %d lost audit state: %+v", index, item)
		}
	}
	reloaded, err := newReportOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.ValidateNode(reportTestNodeID); err != nil {
		t.Fatal(err)
	}
	reconciledUsage, reconciledAlive = reloaded.Reconciliation()
	if reconciledUsage != 3 || reconciledAlive != 0 {
		t.Fatalf("reloaded reconciliation=%d/%d", reconciledUsage, reconciledAlive)
	}
}

func TestReportOutboxReconcilesAliveFailureAndContinues(t *testing.T) {
	t.Parallel()
	outbox, err := newReportOutbox(filepath.Join(t.TempDir(), "reports.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 1, 1, 2, 3, 0, time.UTC)
	for index := 0; index < 2; index++ {
		if err := outbox.CaptureAliveIP(flyskyapi.AliveIPReport{
			NodeID: reportTestNodeID, ObservedAt: now.Add(time.Duration(index) * time.Minute), WindowSeconds: 60,
		}); err != nil {
			t.Fatal(err)
		}
	}
	client := &reportClientStub{aliveErrorAt: func(call int, _ flyskyapi.AliveIPReport) error {
		if call == 0 {
			return &flyskyapi.APIError{StatusCode: http.StatusUnprocessableEntity, Code: "VALIDATION_FAILED"}
		}
		return nil
	}}
	err = outbox.Flush(context.Background(), client, "token")
	var reconciliationErr *reportReconciliationError
	if !errors.As(err, &reconciliationErr) || reconciliationErr.Alive != 1 || len(client.alive) != 2 {
		t.Fatalf("Flush() error=%v calls=%d", err, len(client.alive))
	}
	usage, alive := outbox.Pending()
	reconciledUsage, reconciledAlive := outbox.Reconciliation()
	if usage != 0 || alive != 0 || reconciledUsage != 0 || reconciledAlive != 1 {
		t.Fatalf("pending=%d/%d reconciliation=%d/%d", usage, alive, reconciledUsage, reconciledAlive)
	}
}

func TestReportOutboxPersistsAndObeysRetryAfterAcrossReload(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "reports.json")
	outbox, err := newReportOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	captureReportTestUsage(t, outbox, reportTestDeltas(1))
	reportID := outbox.state.UsageReports[0].ReportID
	now := time.Date(2026, time.August, 1, 1, 2, 3, 0, time.UTC)
	outbox.now = func() time.Time { return now }
	rateLimited := &reportClientStub{usageErr: &flyskyapi.APIError{
		StatusCode: http.StatusTooManyRequests, Code: "RATE_LIMITED", Retryable: true, RetryAfter: "120",
	}}
	if err := outbox.Flush(context.Background(), rateLimited, "token"); err == nil {
		t.Fatal("rate limited report unexpectedly flushed")
	}
	wantRetryAt := now.Add(2 * time.Minute)
	if !outbox.state.UsageRetryNotBefore.Equal(wantRetryAt) {
		t.Fatalf("retry not before = %s, want %s", outbox.state.UsageRetryNotBefore, wantRetryAt)
	}

	reloaded, err := newReportOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	reloaded.now = func() time.Time { return now.Add(time.Minute) }
	client := &reportClientStub{}
	err = reloaded.Flush(context.Background(), client, "token")
	var deferredErr *reportRetryDeferredError
	if !errors.As(err, &deferredErr) || len(client.usage) != 0 {
		t.Fatalf("deferred Flush() error=%T %v calls=%d", err, err, len(client.usage))
	}
	reloaded.now = func() time.Time { return now.Add(121 * time.Second) }
	if err := reloaded.Flush(context.Background(), client, "token"); err != nil {
		t.Fatal(err)
	}
	if len(client.usage) != 1 || client.usage[0].ReportID != reportID {
		t.Fatalf("retry changed report identity: %+v", client.usage)
	}
}

func TestReportOutboxPersistsRetryAfterForRetryableStatuses(t *testing.T) {
	tests := []int{http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests, http.StatusServiceUnavailable}
	for _, statusCode := range tests {
		statusCode := statusCode
		t.Run(fmt.Sprintf("status_%d", statusCode), func(t *testing.T) {
			outbox, err := newReportOutbox(filepath.Join(t.TempDir(), "reports.json"))
			if err != nil {
				t.Fatal(err)
			}
			captureReportTestUsage(t, outbox, reportTestDeltas(1))
			now := time.Date(2026, time.August, 1, 1, 2, 3, 0, time.UTC)
			outbox.now = func() time.Time { return now }
			client := &reportClientStub{usageErr: &flyskyapi.APIError{StatusCode: statusCode, Code: "RETRY", RetryAfter: "17"}}
			if err := outbox.Flush(context.Background(), client, "token"); err == nil {
				t.Fatal("retryable report unexpectedly flushed")
			}
			if !outbox.state.UsageRetryNotBefore.Equal(now.Add(17 * time.Second)) {
				t.Fatalf("retry deadline = %s", outbox.state.UsageRetryNotBefore)
			}
		})
	}

	t.Run("429 without header uses bounded default", func(t *testing.T) {
		outbox, err := newReportOutbox(filepath.Join(t.TempDir(), "reports.json"))
		if err != nil {
			t.Fatal(err)
		}
		captureReportTestUsage(t, outbox, reportTestDeltas(1))
		now := time.Date(2026, time.August, 1, 1, 2, 3, 0, time.UTC)
		outbox.now = func() time.Time { return now }
		client := &reportClientStub{usageErr: &flyskyapi.APIError{StatusCode: http.StatusTooManyRequests, Code: "RATE_LIMITED"}}
		if err := outbox.Flush(context.Background(), client, "token"); err == nil {
			t.Fatal("rate limited report unexpectedly flushed")
		}
		if !outbox.state.UsageRetryNotBefore.Equal(now.Add(defaultRateLimitRetryDelay)) {
			t.Fatalf("default retry deadline = %s", outbox.state.UsageRetryNotBefore)
		}
	})
}

func TestRetryNotBeforeClampsDeltaAndDateHeaders(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 1, 1, 2, 3, 0, time.UTC)
	tests := []struct {
		name       string
		retryAfter string
	}{
		{name: "delta seconds", retryAfter: "172800"},
		{name: "HTTP date", retryAfter: now.Add(72 * time.Hour).Format(http.TimeFormat)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			retryAt, ok := retryNotBefore(&flyskyapi.APIError{
				StatusCode: http.StatusServiceUnavailable,
				RetryAfter: test.retryAfter,
			}, now)
			if !ok || !retryAt.Equal(now.Add(maxReportRetryDelay)) {
				t.Fatalf("retryNotBefore() = %s, %v; want %s", retryAt, ok, now.Add(maxReportRetryDelay))
			}
		})
	}
}

func TestReportOutboxRetainsAndStopsOnAuthenticationAndUnknown4xx(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "401", err: &flyskyapi.APIError{StatusCode: http.StatusUnauthorized, Code: "UNAUTHORIZED", Retryable: true}},
		{name: "403", err: &flyskyapi.APIError{StatusCode: http.StatusForbidden, Code: "NODE_FORBIDDEN", Retryable: true}},
		{name: "unknown 400", err: &flyskyapi.APIError{StatusCode: http.StatusBadRequest, Code: "UNKNOWN"}},
		{name: "unknown retryable 409", err: &flyskyapi.APIError{StatusCode: http.StatusConflict, Code: "TEMPORARY_CONFLICT", Retryable: true}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			outbox, err := newReportOutbox(filepath.Join(t.TempDir(), "reports.json"))
			if err != nil {
				t.Fatal(err)
			}
			captureReportTestUsage(t, outbox, reportTestDeltas(1))
			client := &reportClientStub{usageErr: test.err}
			if err := outbox.Flush(context.Background(), client, "token"); err == nil {
				t.Fatal("permanent error unexpectedly flushed")
			}
			usage, _ := outbox.Pending()
			reconciled, _ := outbox.Reconciliation()
			if usage != 1 || reconciled != 0 || len(client.usage) != 1 || !outbox.state.UsageRetryNotBefore.IsZero() {
				t.Fatalf("pending=%d reconciliation=%d calls=%d retryAt=%s", usage, reconciled, len(client.usage), outbox.state.UsageRetryNotBefore)
			}
		})
	}
}

func TestReportOutboxRetainsRetryableAndTransportFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "transport", err: errors.New("connection reset")},
		{name: "408", err: &flyskyapi.APIError{StatusCode: http.StatusRequestTimeout, Code: "TIMEOUT"}},
		{name: "425", err: &flyskyapi.APIError{StatusCode: http.StatusTooEarly, Code: "TOO_EARLY"}},
		{name: "500", err: &flyskyapi.APIError{StatusCode: http.StatusInternalServerError, Code: "INTERNAL"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			outbox, err := newReportOutbox(filepath.Join(t.TempDir(), "reports.json"))
			if err != nil {
				t.Fatal(err)
			}
			captureReportTestUsage(t, outbox, reportTestDeltas(1))
			client := &reportClientStub{usageErr: test.err}
			if err := outbox.Flush(context.Background(), client, "token"); err == nil {
				t.Fatal("retryable error unexpectedly flushed")
			}
			usage, _ := outbox.Pending()
			if usage != 1 || len(client.usage) != 1 {
				t.Fatalf("pending=%d calls=%d", usage, len(client.usage))
			}
			client.usageErr = nil
			if err := outbox.Flush(context.Background(), client, "token"); err != nil {
				t.Fatal(err)
			}
			if len(client.usage) != 2 || client.usage[0].ReportID != client.usage[1].ReportID {
				t.Fatalf("retry changed identity: %+v", client.usage)
			}
		})
	}
}

func TestReportOutboxRetainsAcceptedReportWhenAckPersistenceFails(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "reports.json")
	outbox, err := newReportOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	captureReportTestUsage(t, outbox, reportTestDeltas(1))
	reportID := outbox.state.UsageReports[0].ReportID
	outbox.write = func(string, []byte) error { return errors.New("disk full") }
	client := &reportClientStub{}
	if err := outbox.Flush(context.Background(), client, "token"); err == nil || !strings.Contains(err.Error(), "acknowledgement") {
		t.Fatalf("Flush() error = %v", err)
	}
	usage, _ := outbox.Pending()
	if usage != 1 || len(client.usage) != 1 {
		t.Fatalf("pending=%d calls=%d", usage, len(client.usage))
	}
	reloaded, err := newReportOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.state.UsageReports) != 1 || reloaded.state.UsageReports[0].ReportID != reportID {
		t.Fatalf("accepted report was lost after persist failure: %+v", reloaded.state.UsageReports)
	}
}

func TestEncodeReportOutboxCountsTrailingNewlineInSafetyLimit(t *testing.T) {
	t.Parallel()
	state := persistedReportOutbox{Version: reportOutboxVersion, NextSequence: 1}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encodeReportOutbox(state, len(raw)); err == nil {
		t.Fatal("safety limit ignored the persisted trailing newline")
	}
	encoded, err := encodeReportOutbox(state, len(raw)+1)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != len(raw)+1 || encoded[len(encoded)-1] != '\n' {
		t.Fatalf("encoded length=%d last=%q", len(encoded), encoded[len(encoded)-1])
	}
}

func TestReportOutboxRejectsPublicPermissionsAndCorruption(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "reports.json")
	if err := os.WriteFile(path, []byte("not-json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := newReportOutbox(path); err == nil {
		t.Fatal("public outbox permissions were accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newReportOutbox(path); err == nil {
		t.Fatal("corrupt outbox was accepted")
	}
}
