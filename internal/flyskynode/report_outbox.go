package flyskynode

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go/internal/flyskyapi"
)

const (
	legacyReportOutboxVersion        = 1
	reportOutboxVersion              = 2
	maxReportOutboxBytes             = 64 << 20
	maxUsageReportItems              = 10000
	maxUsageReportEncodedBytes int64 = 4 << 20
	defaultRateLimitRetryDelay       = 5 * time.Second
	maxReportRetryDelay              = 24 * time.Hour
)

type usageReportLimits struct {
	MaxItems        int
	MaxEncodedBytes int64
}

var defaultUsageReportLimits = usageReportLimits{
	MaxItems:        maxUsageReportItems,
	MaxEncodedBytes: maxUsageReportEncodedBytes,
}

func normalizeUsageReportLimits(limits usageReportLimits) (usageReportLimits, error) {
	if limits.MaxItems < 1 || limits.MaxEncodedBytes < 1 {
		return usageReportLimits{}, errors.New("Flysky usage report limits must be positive")
	}
	limits.MaxItems = min(limits.MaxItems, maxUsageReportItems)
	limits.MaxEncodedBytes = min(limits.MaxEncodedBytes, maxUsageReportEncodedBytes)
	return limits, nil
}

type usageReportReconciliation struct {
	Report        flyskyapi.UsageReport `json:"report"`
	StatusCode    int                   `json:"status_code"`
	Code          string                `json:"code"`
	RequestID     string                `json:"request_id,omitzero"`
	Attempts      int                   `json:"attempts"`
	FirstFailedAt time.Time             `json:"first_failed_at"`
	LastFailedAt  time.Time             `json:"last_failed_at"`
}

type aliveIPReportReconciliation struct {
	Report        flyskyapi.AliveIPReport `json:"report"`
	StatusCode    int                     `json:"status_code"`
	Code          string                  `json:"code"`
	RequestID     string                  `json:"request_id,omitzero"`
	Attempts      int                     `json:"attempts"`
	FirstFailedAt time.Time               `json:"first_failed_at"`
	LastFailedAt  time.Time               `json:"last_failed_at"`
}

type persistedReportOutbox struct {
	Version               int                           `json:"version"`
	NextSequence          int64                         `json:"next_sequence"`
	UsageReports          []flyskyapi.UsageReport       `json:"usage_reports"`
	AliveIPReports        []flyskyapi.AliveIPReport     `json:"alive_ip_reports"`
	UsageRetryNotBefore   time.Time                     `json:"usage_retry_not_before,omitzero"`
	AliveIPRetryNotBefore time.Time                     `json:"alive_ip_retry_not_before,omitzero"`
	UsageReconciliation   []usageReportReconciliation   `json:"usage_reconciliation,omitzero"`
	AliveIPReconciliation []aliveIPReportReconciliation `json:"alive_ip_reconciliation,omitzero"`
}

type reportOutbox struct {
	mu     sync.Mutex
	path   string
	state  persistedReportOutbox
	limits usageReportLimits
	now    func() time.Time
	write  func(string, []byte) error
}

type reportClient interface {
	SubmitUsage(context.Context, string, flyskyapi.UsageReport) (flyskyapi.ReportReceipt, error)
	SubmitAliveIPs(context.Context, string, flyskyapi.AliveIPReport) (flyskyapi.ReportReceipt, error)
}

type reportRetryDeferredError struct {
	Queue   string
	RetryAt time.Time
}

func (err *reportRetryDeferredError) Error() string {
	return fmt.Sprintf("Flysky %s report delivery is deferred until %s", err.Queue, err.RetryAt.UTC().Format(time.RFC3339))
}

type reportReconciliationError struct {
	Usage int
	Alive int
}

func (err *reportReconciliationError) Error() string {
	return fmt.Sprintf("Flysky moved permanent report failures to reconciliation (usage=%d alive=%d)", err.Usage, err.Alive)
}

func newReportOutbox(path string) (*reportOutbox, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return nil, errors.New("Flysky report outbox path must be absolute")
	}
	outbox := &reportOutbox{
		path: path,
		state: persistedReportOutbox{
			Version: reportOutboxVersion, NextSequence: 1,
		},
		limits: defaultUsageReportLimits,
		now:    time.Now,
		write:  writeReportOutbox,
	}
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
	if err := migrateReportOutbox(&outbox.state); err != nil {
		return nil, err
	}
	if err := validateReportOutbox(outbox.state); err != nil {
		return nil, err
	}
	return outbox, nil
}

// SetUsageReportLimits applies negotiated limits to reports captured after the
// call. Already-persisted reports keep their stable identity and boundaries.
func (outbox *reportOutbox) SetUsageReportLimits(limits usageReportLimits) error {
	normalized, err := normalizeUsageReportLimits(limits)
	if err != nil {
		return err
	}
	outbox.mu.Lock()
	outbox.limits = normalized
	outbox.mu.Unlock()
	return nil
}

func (outbox *reportOutbox) CaptureUsage(
	nodeID, configVersion string,
	windowStart, windowEnd time.Time,
	deltas []TrafficDelta,
) error {
	if len(deltas) == 0 {
		return nil
	}
	configVersion = strings.TrimSpace(configVersion)
	if !validUUID(nodeID) || configVersion == "" || windowStart.IsZero() || !windowEnd.After(windowStart) {
		return errors.New("invalid Flysky usage report metadata")
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
	sort.Slice(items, func(i, j int) bool {
		if items[i].UserID == items[j].UserID {
			return items[i].CredentialVersion < items[j].CredentialVersion
		}
		return items[i].UserID < items[j].UserID
	})
	for index := 1; index < len(items); index++ {
		if items[index-1].UserID == items[index].UserID &&
			items[index-1].CredentialVersion == items[index].CredentialVersion {
			return errors.New("duplicate Flysky traffic delta identity")
		}
	}

	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	reports, nextSequence, err := splitUsageReports(
		nodeID, configVersion, windowStart.UTC(), windowEnd.UTC(), items,
		outbox.state.NextSequence, outbox.limits,
	)
	if err != nil {
		return err
	}
	next := cloneReportOutbox(outbox.state)
	next.NextSequence = nextSequence
	next.UsageReports = append(next.UsageReports, reports...)
	if err := validateReportOutbox(next); err != nil {
		return err
	}
	if err := outbox.persist(next); err != nil {
		return err
	}
	outbox.state = next
	return nil
}

func splitUsageReports(
	nodeID, configVersion string,
	windowStart, windowEnd time.Time,
	items []flyskyapi.UsageItem,
	firstSequence int64,
	limits usageReportLimits,
) ([]flyskyapi.UsageReport, int64, error) {
	limits, err := normalizeUsageReportLimits(limits)
	if err != nil {
		return nil, firstSequence, err
	}
	if firstSequence < 1 {
		return nil, firstSequence, errors.New("invalid Flysky usage report sequence")
	}
	reports := make([]flyskyapi.UsageReport, 0, (len(items)+limits.MaxItems-1)/limits.MaxItems)
	sequence := firstSequence
	for offset := 0; offset < len(items); {
		reportID, err := newReportID()
		if err != nil {
			return nil, firstSequence, err
		}
		report := flyskyapi.UsageReport{
			SchemaVersion: 1, ReportID: reportID, Sequence: sequence,
			NodeID: nodeID, ConfigVersion: configVersion,
			WindowStart: windowStart, WindowEnd: windowEnd,
			Items: make([]flyskyapi.UsageItem, 0, min(limits.MaxItems, len(items)-offset)),
		}
		emptyJSON, err := json.Marshal(report)
		if err != nil {
			return nil, firstSequence, fmt.Errorf("encode empty Flysky usage report: %w", err)
		}
		encodedSize := int64(len(emptyJSON))
		for offset < len(items) && len(report.Items) < limits.MaxItems {
			item := items[offset]
			item.ItemIndex = len(report.Items)
			itemJSON, err := json.Marshal(item)
			if err != nil {
				return nil, firstSequence, fmt.Errorf("encode Flysky usage item: %w", err)
			}
			additional := int64(len(itemJSON))
			if len(report.Items) > 0 {
				additional++ // comma between adjacent JSON array elements
			}
			if encodedSize+additional > limits.MaxEncodedBytes {
				break
			}
			report.Items = append(report.Items, item)
			encodedSize += additional
			offset++
		}
		if len(report.Items) == 0 {
			return nil, firstSequence, fmt.Errorf("Flysky usage item exceeds negotiated encoded byte limit %d", limits.MaxEncodedBytes)
		}
		encoded, err := json.Marshal(report)
		if err != nil {
			return nil, firstSequence, fmt.Errorf("encode Flysky usage report: %w", err)
		}
		if int64(len(encoded)) != encodedSize || int64(len(encoded)) > limits.MaxEncodedBytes {
			return nil, firstSequence, errors.New("Flysky usage report encoded size accounting mismatch")
		}
		reports = append(reports, report)
		sequence++
	}
	return reports, sequence, nil
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
	var reconciledUsage, reconciledAlive int

	for len(outbox.state.UsageReports) > 0 {
		now := outbox.now().UTC()
		if retryAt := outbox.state.UsageRetryNotBefore; !retryAt.IsZero() && now.Before(retryAt) {
			return joinReconciliationError(reconciledUsage, reconciledAlive, &reportRetryDeferredError{Queue: "usage", RetryAt: retryAt})
		}
		report := outbox.state.UsageReports[0]
		receipt, err := client.SubmitUsage(ctx, accessToken, report)
		if err != nil {
			classification, apiErr := classifyReportError(err)
			switch classification {
			case reportErrorReconcile:
				next := cloneReportOutbox(outbox.state)
				next.UsageReports = next.UsageReports[1:]
				next.UsageRetryNotBefore = time.Time{}
				next.UsageReconciliation = append(next.UsageReconciliation, usageReportReconciliation{
					Report: report, StatusCode: apiErr.StatusCode, Code: apiErr.Code, RequestID: apiErr.RequestID,
					Attempts: 1, FirstFailedAt: now, LastFailedAt: now,
				})
				if err := outbox.commitState(next); err != nil {
					return joinReconciliationError(reconciledUsage, reconciledAlive, fmt.Errorf("persist Flysky usage reconciliation: %w", err))
				}
				reconciledUsage++
				continue
			case reportErrorRetry:
				if retryAt, ok := retryNotBefore(apiErr, now); ok {
					next := cloneReportOutbox(outbox.state)
					if next.UsageRetryNotBefore.Before(retryAt) {
						next.UsageRetryNotBefore = retryAt
					}
					if persistErr := outbox.commitState(next); persistErr != nil {
						return joinReconciliationError(reconciledUsage, reconciledAlive, errors.Join(err, fmt.Errorf("persist Flysky usage retry deadline: %w", persistErr)))
					}
				}
				return joinReconciliationError(reconciledUsage, reconciledAlive, err)
			default:
				return joinReconciliationError(reconciledUsage, reconciledAlive, err)
			}
		}
		if receipt.ReportID != report.ReportID || receipt.ReceiptID != report.ReportID || receipt.State != "accepted" {
			return joinReconciliationError(reconciledUsage, reconciledAlive, errors.New("Flysky usage report acknowledgement does not match the pending report"))
		}
		next := cloneReportOutbox(outbox.state)
		next.UsageReports = next.UsageReports[1:]
		next.UsageRetryNotBefore = time.Time{}
		if err := outbox.commitState(next); err != nil {
			return joinReconciliationError(reconciledUsage, reconciledAlive, fmt.Errorf("usage report was accepted but outbox acknowledgement could not be persisted: %w", err))
		}
	}

	for len(outbox.state.AliveIPReports) > 0 {
		now := outbox.now().UTC()
		if retryAt := outbox.state.AliveIPRetryNotBefore; !retryAt.IsZero() && now.Before(retryAt) {
			return joinReconciliationError(reconciledUsage, reconciledAlive, &reportRetryDeferredError{Queue: "alive IP", RetryAt: retryAt})
		}
		report := outbox.state.AliveIPReports[0]
		receipt, err := client.SubmitAliveIPs(ctx, accessToken, report)
		if err != nil {
			classification, apiErr := classifyReportError(err)
			switch classification {
			case reportErrorReconcile:
				next := cloneReportOutbox(outbox.state)
				next.AliveIPReports = next.AliveIPReports[1:]
				next.AliveIPRetryNotBefore = time.Time{}
				next.AliveIPReconciliation = append(next.AliveIPReconciliation, aliveIPReportReconciliation{
					Report: report, StatusCode: apiErr.StatusCode, Code: apiErr.Code, RequestID: apiErr.RequestID,
					Attempts: 1, FirstFailedAt: now, LastFailedAt: now,
				})
				if err := outbox.commitState(next); err != nil {
					return joinReconciliationError(reconciledUsage, reconciledAlive, fmt.Errorf("persist Flysky online IP reconciliation: %w", err))
				}
				reconciledAlive++
				continue
			case reportErrorRetry:
				if retryAt, ok := retryNotBefore(apiErr, now); ok {
					next := cloneReportOutbox(outbox.state)
					if next.AliveIPRetryNotBefore.Before(retryAt) {
						next.AliveIPRetryNotBefore = retryAt
					}
					if persistErr := outbox.commitState(next); persistErr != nil {
						return joinReconciliationError(reconciledUsage, reconciledAlive, errors.Join(err, fmt.Errorf("persist Flysky online IP retry deadline: %w", persistErr)))
					}
				}
				return joinReconciliationError(reconciledUsage, reconciledAlive, err)
			default:
				return joinReconciliationError(reconciledUsage, reconciledAlive, err)
			}
		}
		if receipt.ReportID != report.ReportID || receipt.ReceiptID != report.ReportID || receipt.State != "accepted" {
			return joinReconciliationError(reconciledUsage, reconciledAlive, errors.New("Flysky online IP report acknowledgement does not match the pending report"))
		}
		next := cloneReportOutbox(outbox.state)
		next.AliveIPReports = next.AliveIPReports[1:]
		next.AliveIPRetryNotBefore = time.Time{}
		if err := outbox.commitState(next); err != nil {
			return joinReconciliationError(reconciledUsage, reconciledAlive, fmt.Errorf("online IP report was accepted but outbox acknowledgement could not be persisted: %w", err))
		}
	}

	return joinReconciliationError(reconciledUsage, reconciledAlive, nil)
}

type reportErrorClassification uint8

const (
	reportErrorHalt reportErrorClassification = iota
	reportErrorRetry
	reportErrorReconcile
)

func classifyReportError(err error) (reportErrorClassification, *flyskyapi.APIError) {
	var apiErr *flyskyapi.APIError
	if !errors.As(err, &apiErr) {
		return reportErrorRetry, nil
	}
	code := strings.TrimSpace(apiErr.Code)
	if apiErr.StatusCode == http.StatusConflict && code == "REPORT_ID_CONFLICT" ||
		apiErr.StatusCode == http.StatusUnprocessableEntity && (code == "USAGE_ITEM_UNKNOWN" || code == "VALIDATION_FAILED") {
		return reportErrorReconcile, apiErr
	}
	if apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden {
		return reportErrorHalt, apiErr
	}
	if retryableReportStatus(apiErr.StatusCode) {
		return reportErrorRetry, apiErr
	}
	if apiErr.StatusCode >= 400 && apiErr.StatusCode <= 499 {
		return reportErrorHalt, apiErr
	}
	if apiErr.Retryable {
		return reportErrorRetry, apiErr
	}
	return reportErrorHalt, apiErr
}

func retryableReportStatus(statusCode int) bool {
	return statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooEarly ||
		statusCode == http.StatusTooManyRequests || statusCode >= 500 && statusCode <= 599
}

func retryNotBefore(apiErr *flyskyapi.APIError, now time.Time) (time.Time, bool) {
	if apiErr == nil {
		return time.Time{}, false
	}
	delay, ok := apiErr.RetryDelay(now)
	if !ok && apiErr.StatusCode == http.StatusTooManyRequests {
		delay = defaultRateLimitRetryDelay
		ok = true
	}
	if !ok {
		return time.Time{}, false
	}
	if delay > maxReportRetryDelay {
		delay = maxReportRetryDelay
	}
	return now.Add(delay).UTC(), true
}

func joinReconciliationError(usage, alive int, err error) error {
	if usage == 0 && alive == 0 {
		return err
	}
	return errors.Join(&reportReconciliationError{Usage: usage, Alive: alive}, err)
}

func (outbox *reportOutbox) Pending() (usage, alive int) {
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	return len(outbox.state.UsageReports), len(outbox.state.AliveIPReports)
}

func (outbox *reportOutbox) Reconciliation() (usage, alive int) {
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	return len(outbox.state.UsageReconciliation), len(outbox.state.AliveIPReconciliation)
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
	for _, item := range outbox.state.UsageReconciliation {
		if item.Report.NodeID != nodeID {
			return errors.New("Flysky report outbox reconciliation belongs to a different node")
		}
	}
	for _, item := range outbox.state.AliveIPReconciliation {
		if item.Report.NodeID != nodeID {
			return errors.New("Flysky report outbox reconciliation belongs to a different node")
		}
	}
	return nil
}

func (outbox *reportOutbox) commitState(next persistedReportOutbox) error {
	if err := validateReportOutbox(next); err != nil {
		return err
	}
	if err := outbox.persist(next); err != nil {
		return err
	}
	outbox.state = next
	return nil
}

func (outbox *reportOutbox) persist(state persistedReportOutbox) error {
	data, err := encodeReportOutbox(state, maxReportOutboxBytes)
	if err != nil {
		return err
	}
	write := outbox.write
	if write == nil {
		write = writeReportOutbox
	}
	return write(outbox.path, data)
}

func encodeReportOutbox(state persistedReportOutbox, maxBytes int) ([]byte, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("encode Flysky report outbox: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxBytes {
		return nil, errors.New("Flysky report outbox exceeds its safety limit")
	}
	return data, nil
}

func migrateReportOutbox(state *persistedReportOutbox) error {
	if state == nil {
		return errors.New("Flysky report outbox state is nil")
	}
	switch state.Version {
	case legacyReportOutboxVersion:
		if !state.UsageRetryNotBefore.IsZero() || !state.AliveIPRetryNotBefore.IsZero() ||
			len(state.UsageReconciliation) != 0 || len(state.AliveIPReconciliation) != 0 {
			return errors.New("legacy Flysky report outbox contains v2 fields")
		}
		state.Version = reportOutboxVersion
	case reportOutboxVersion:
	default:
		return errors.New("invalid Flysky report outbox version")
	}
	return nil
}

func validateReportOutbox(state persistedReportOutbox) error {
	if state.Version != reportOutboxVersion || state.NextSequence < 1 {
		return errors.New("invalid Flysky report outbox header")
	}
	seenReports := make(map[string]struct{}, len(state.UsageReports)+len(state.AliveIPReports)+len(state.UsageReconciliation)+len(state.AliveIPReconciliation))
	var previousSequence, maxSequence int64
	for index, report := range state.UsageReports {
		if err := validateUsageReport(report); err != nil || index > 0 && report.Sequence <= previousSequence {
			return fmt.Errorf("invalid Flysky usage report at outbox index %d", index)
		}
		previousSequence = report.Sequence
		maxSequence = max(maxSequence, report.Sequence)
		if err := rememberReportID(seenReports, report.ReportID); err != nil {
			return err
		}
	}
	for index, report := range state.AliveIPReports {
		if err := validateAliveIPReport(report); err != nil {
			return fmt.Errorf("invalid Flysky online IP report at outbox index %d", index)
		}
		if err := rememberReportID(seenReports, report.ReportID); err != nil {
			return err
		}
	}
	for index, item := range state.UsageReconciliation {
		if err := validateUsageReport(item.Report); err != nil || !validReconciliationFailure(item.StatusCode, item.Code, item.Attempts, item.FirstFailedAt, item.LastFailedAt) {
			return fmt.Errorf("invalid Flysky usage reconciliation at index %d", index)
		}
		maxSequence = max(maxSequence, item.Report.Sequence)
		if err := rememberReportID(seenReports, item.Report.ReportID); err != nil {
			return err
		}
	}
	for index, item := range state.AliveIPReconciliation {
		if err := validateAliveIPReport(item.Report); err != nil || !validReconciliationFailure(item.StatusCode, item.Code, item.Attempts, item.FirstFailedAt, item.LastFailedAt) {
			return fmt.Errorf("invalid Flysky online IP reconciliation at index %d", index)
		}
		if err := rememberReportID(seenReports, item.Report.ReportID); err != nil {
			return err
		}
	}
	if state.NextSequence <= maxSequence {
		return errors.New("Flysky report outbox sequence did not advance")
	}
	return nil
}

func validateUsageReport(report flyskyapi.UsageReport) error {
	if !validUUID(report.ReportID) || !validUUID(report.NodeID) || strings.TrimSpace(report.ConfigVersion) == "" ||
		report.SchemaVersion != 1 || report.Sequence < 1 || report.WindowStart.IsZero() || !report.WindowEnd.After(report.WindowStart) ||
		len(report.Items) == 0 || len(report.Items) > maxUsageReportItems {
		return errors.New("invalid Flysky usage report")
	}
	type itemIdentity struct {
		userID            string
		credentialVersion int64
	}
	seen := make(map[itemIdentity]struct{}, len(report.Items))
	for itemIndex, item := range report.Items {
		if item.ItemIndex != itemIndex || !validUUID(item.UserID) || item.CredentialVersion < 1 ||
			item.UploadBytes < 0 || item.DownloadBytes < 0 || item.UploadBytes == 0 && item.DownloadBytes == 0 {
			return errors.New("invalid Flysky usage item")
		}
		identity := itemIdentity{userID: item.UserID, credentialVersion: item.CredentialVersion}
		if _, exists := seen[identity]; exists {
			return errors.New("duplicate Flysky usage item identity")
		}
		seen[identity] = struct{}{}
	}
	return nil
}

func validateAliveIPReport(report flyskyapi.AliveIPReport) error {
	if !validUUID(report.ReportID) || !validUUID(report.NodeID) || report.SchemaVersion != 1 || report.ObservedAt.IsZero() ||
		report.WindowSeconds < 1 || report.WindowSeconds > 3600 || report.OnlineIPCount < 0 ||
		report.ActiveUsers < 0 || report.Connections < 0 {
		return errors.New("invalid Flysky online IP report")
	}
	return nil
}

func validReconciliationFailure(statusCode int, code string, attempts int, firstFailedAt, lastFailedAt time.Time) bool {
	if attempts < 1 || firstFailedAt.IsZero() || lastFailedAt.Before(firstFailedAt) {
		return false
	}
	code = strings.TrimSpace(code)
	return statusCode == http.StatusConflict && code == "REPORT_ID_CONFLICT" ||
		statusCode == http.StatusUnprocessableEntity && (code == "USAGE_ITEM_UNKNOWN" || code == "VALIDATION_FAILED")
}

func rememberReportID(seen map[string]struct{}, reportID string) error {
	if _, exists := seen[reportID]; exists {
		return errors.New("duplicate Flysky outbox report ID")
	}
	seen[reportID] = struct{}{}
	return nil
}

func cloneReportOutbox(state persistedReportOutbox) persistedReportOutbox {
	clone := state
	clone.UsageReports = make([]flyskyapi.UsageReport, len(state.UsageReports))
	for index, report := range state.UsageReports {
		clone.UsageReports[index] = cloneUsageReport(report)
	}
	clone.AliveIPReports = append([]flyskyapi.AliveIPReport(nil), state.AliveIPReports...)
	clone.UsageReconciliation = make([]usageReportReconciliation, len(state.UsageReconciliation))
	for index, item := range state.UsageReconciliation {
		clone.UsageReconciliation[index] = item
		clone.UsageReconciliation[index].Report = cloneUsageReport(item.Report)
	}
	clone.AliveIPReconciliation = append([]aliveIPReportReconciliation(nil), state.AliveIPReconciliation...)
	return clone
}

func cloneUsageReport(report flyskyapi.UsageReport) flyskyapi.UsageReport {
	report.Items = append([]flyskyapi.UsageItem(nil), report.Items...)
	return report
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
