package flyskynode

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go/internal/flyskyapi"
)

const (
	reportOutboxVersion  = 1
	maxReportOutboxBytes = 64 << 20
)

type persistedReportOutbox struct {
	Version        int                       `json:"version"`
	NextSequence   int64                     `json:"next_sequence"`
	UsageReports   []flyskyapi.UsageReport   `json:"usage_reports"`
	AliveIPReports []flyskyapi.AliveIPReport `json:"alive_ip_reports"`
}

type reportOutbox struct {
	mu    sync.Mutex
	path  string
	state persistedReportOutbox
}

type reportClient interface {
	SubmitUsage(context.Context, string, flyskyapi.UsageReport) (flyskyapi.ReportReceipt, error)
	SubmitAliveIPs(context.Context, string, flyskyapi.AliveIPReport) (flyskyapi.ReportReceipt, error)
}

func newReportOutbox(path string) (*reportOutbox, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return nil, errors.New("Flysky report outbox path must be absolute")
	}
	outbox := &reportOutbox{path: path, state: persistedReportOutbox{Version: reportOutboxVersion, NextSequence: 1}}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, fmt.Errorf("create Flysky report outbox directory: %w", err)
		}
		return outbox, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect Flysky report outbox: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Flysky report outbox must be a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Flysky report outbox: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxReportOutboxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Flysky report outbox: %w", err)
	}
	if len(data) > maxReportOutboxBytes {
		return nil, errors.New("Flysky report outbox exceeds its safety limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&outbox.state); err != nil {
		return nil, fmt.Errorf("decode Flysky report outbox: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("Flysky report outbox must contain exactly one JSON value")
	}
	if err := validateReportOutbox(outbox.state); err != nil {
		return nil, err
	}
	return outbox, nil
}

func (outbox *reportOutbox) CaptureUsage(
	nodeID, configVersion string,
	windowStart, windowEnd time.Time,
	deltas []TrafficDelta,
) error {
	if len(deltas) == 0 {
		return nil
	}
	items := make([]flyskyapi.UsageItem, len(deltas))
	for index, delta := range deltas {
		if !validUUID(delta.UserID) || delta.CredentialVersion < 1 || delta.UploadBytes < 0 || delta.DownloadBytes < 0 ||
			delta.UploadBytes == 0 && delta.DownloadBytes == 0 {
			return errors.New("invalid Flysky traffic delta")
		}
		items[index] = flyskyapi.UsageItem{
			UserID: delta.UserID, CredentialVersion: delta.CredentialVersion,
			UploadBytes: delta.UploadBytes, DownloadBytes: delta.DownloadBytes,
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].UserID < items[j].UserID })
	for index := range items {
		items[index].ItemIndex = index
		if index > 0 && items[index-1].UserID == items[index].UserID {
			return errors.New("duplicate Flysky traffic delta user")
		}
	}
	reportID, err := newReportID()
	if err != nil {
		return err
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	report := flyskyapi.UsageReport{
		SchemaVersion: 1, ReportID: reportID, Sequence: outbox.state.NextSequence,
		NodeID: nodeID, ConfigVersion: strings.TrimSpace(configVersion),
		WindowStart: windowStart.UTC(), WindowEnd: windowEnd.UTC(), Items: items,
	}
	next := cloneReportOutbox(outbox.state)
	next.NextSequence++
	next.UsageReports = append(next.UsageReports, report)
	if err := validateReportOutbox(next); err != nil {
		return err
	}
	if err := outbox.persist(next); err != nil {
		return err
	}
	outbox.state = next
	return nil
}

func (outbox *reportOutbox) CaptureAliveIP(report flyskyapi.AliveIPReport) error {
	reportID, err := newReportID()
	if err != nil {
		return err
	}
	report.SchemaVersion = 1
	report.ReportID = reportID
	report.ObservedAt = report.ObservedAt.UTC()
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	next := cloneReportOutbox(outbox.state)
	next.AliveIPReports = append(next.AliveIPReports, report)
	if err := validateReportOutbox(next); err != nil {
		return err
	}
	if err := outbox.persist(next); err != nil {
		return err
	}
	outbox.state = next
	return nil
}

func (outbox *reportOutbox) Flush(ctx context.Context, client reportClient, accessToken string) error {
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	for len(outbox.state.UsageReports) > 0 {
		report := outbox.state.UsageReports[0]
		receipt, err := client.SubmitUsage(ctx, accessToken, report)
		if err != nil {
			return err
		}
		if receipt.ReportID != report.ReportID || receipt.ReceiptID != report.ReportID || receipt.State != "accepted" {
			return errors.New("Flysky usage report acknowledgement does not match the pending report")
		}
		next := cloneReportOutbox(outbox.state)
		next.UsageReports = next.UsageReports[1:]
		if err := outbox.persist(next); err != nil {
			return fmt.Errorf("usage report was accepted but outbox acknowledgement could not be persisted: %w", err)
		}
		outbox.state = next
	}
	for len(outbox.state.AliveIPReports) > 0 {
		report := outbox.state.AliveIPReports[0]
		receipt, err := client.SubmitAliveIPs(ctx, accessToken, report)
		if err != nil {
			return err
		}
		if receipt.ReportID != report.ReportID || receipt.ReceiptID != report.ReportID || receipt.State != "accepted" {
			return errors.New("Flysky online IP report acknowledgement does not match the pending report")
		}
		next := cloneReportOutbox(outbox.state)
		next.AliveIPReports = next.AliveIPReports[1:]
		if err := outbox.persist(next); err != nil {
			return fmt.Errorf("online IP report was accepted but outbox acknowledgement could not be persisted: %w", err)
		}
		outbox.state = next
	}
	return nil
}

func (outbox *reportOutbox) Pending() (usage, alive int) {
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	return len(outbox.state.UsageReports), len(outbox.state.AliveIPReports)
}

func (outbox *reportOutbox) ValidateNode(nodeID string) error {
	if !validUUID(nodeID) {
		return errors.New("invalid Flysky report outbox node identity")
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	for _, report := range outbox.state.UsageReports {
		if report.NodeID != nodeID {
			return errors.New("Flysky report outbox belongs to a different node")
		}
	}
	for _, report := range outbox.state.AliveIPReports {
		if report.NodeID != nodeID {
			return errors.New("Flysky report outbox belongs to a different node")
		}
	}
	return nil
}

func (outbox *reportOutbox) persist(state persistedReportOutbox) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode Flysky report outbox: %w", err)
	}
	if len(data) > maxReportOutboxBytes {
		return errors.New("Flysky report outbox exceeds its safety limit")
	}
	data = append(data, '\n')
	return writeReportOutbox(outbox.path, data)
}

func validateReportOutbox(state persistedReportOutbox) error {
	if state.Version != reportOutboxVersion || state.NextSequence < 1 {
		return errors.New("invalid Flysky report outbox header")
	}
	seenReports := make(map[string]struct{}, len(state.UsageReports)+len(state.AliveIPReports))
	var previousSequence int64
	for index, report := range state.UsageReports {
		if !validUUID(report.ReportID) || !validUUID(report.NodeID) || strings.TrimSpace(report.ConfigVersion) == "" ||
			report.SchemaVersion != 1 || report.Sequence < 1 || index > 0 && report.Sequence <= previousSequence ||
			report.WindowStart.IsZero() || !report.WindowEnd.After(report.WindowStart) || len(report.Items) == 0 || len(report.Items) > 10000 {
			return fmt.Errorf("invalid Flysky usage report at outbox index %d", index)
		}
		previousSequence = report.Sequence
		if _, exists := seenReports[report.ReportID]; exists {
			return errors.New("duplicate Flysky outbox report ID")
		}
		seenReports[report.ReportID] = struct{}{}
		for itemIndex, item := range report.Items {
			if item.ItemIndex != itemIndex || !validUUID(item.UserID) || item.CredentialVersion < 1 ||
				item.UploadBytes < 0 || item.DownloadBytes < 0 || item.UploadBytes == 0 && item.DownloadBytes == 0 {
				return fmt.Errorf("invalid Flysky usage item at outbox index %d", index)
			}
		}
	}
	if len(state.UsageReports) > 0 && state.NextSequence <= previousSequence {
		return errors.New("Flysky report outbox sequence did not advance")
	}
	for index, report := range state.AliveIPReports {
		if !validUUID(report.ReportID) || !validUUID(report.NodeID) || report.SchemaVersion != 1 || report.ObservedAt.IsZero() ||
			report.WindowSeconds < 1 || report.WindowSeconds > 3600 || report.OnlineIPCount < 0 ||
			report.ActiveUsers < 0 || report.Connections < 0 {
			return fmt.Errorf("invalid Flysky online IP report at outbox index %d", index)
		}
		if _, exists := seenReports[report.ReportID]; exists {
			return errors.New("duplicate Flysky outbox report ID")
		}
		seenReports[report.ReportID] = struct{}{}
	}
	return nil
}

func cloneReportOutbox(state persistedReportOutbox) persistedReportOutbox {
	clone := state
	clone.UsageReports = append([]flyskyapi.UsageReport(nil), state.UsageReports...)
	clone.AliveIPReports = append([]flyskyapi.AliveIPReport(nil), state.AliveIPReports...)
	return clone
}

func newReportID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate Flysky report ID: %w", err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

func writeReportOutbox(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".flysky-report-outbox-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
