package flyskynode

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/internal/flyskyapi"
)

type reportClientStub struct {
	usageErr   error
	aliveErr   error
	badReceipt bool
	usage      []flyskyapi.UsageReport
	alive      []flyskyapi.AliveIPReport
}

func (client *reportClientStub) SubmitUsage(_ context.Context, _ string, report flyskyapi.UsageReport) (flyskyapi.ReportReceipt, error) {
	client.usage = append(client.usage, report)
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
	if client.aliveErr != nil {
		return flyskyapi.ReportReceipt{}, client.aliveErr
	}
	return flyskyapi.ReportReceipt{ReceiptID: report.ReportID, ReportID: report.ReportID, State: "accepted"}, nil
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
