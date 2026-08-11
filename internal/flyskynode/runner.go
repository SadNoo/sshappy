package flyskynode

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/internal/flyskyapi"
	"github.com/database64128/shadowsocks-go/jsoncfg"
	"github.com/database64128/shadowsocks-go/service"
	"github.com/database64128/shadowsocks-go/ss2022"
	"go.uber.org/zap"
)

const serverName = "flysky-ss2022"

var ErrRuntimeDrainTimeout = errors.New("Flysky runtime shutdown drain timed out")

type enrollmentClient interface {
	Enroll(context.Context, string, flyskyapi.CapabilityReport) (flyskyapi.MachineCredential, error)
}

func Run(ctx context.Context, config Config, logger *zap.Logger) error {
	if err := config.Validate(); err != nil {
		return err
	}
	client, err := flyskyapi.NewClient(flyskyapi.Config{
		BaseURL: config.ControlPlaneURL, AllowInsecureHTTP: config.AllowInsecureHTTP,
		ClientVersion: runtimeVersion(),
	})
	if err != nil {
		return err
	}
	report := capabilityReport(config)
	credential, err := loadOrEnroll(ctx, client, config, report, logger)
	if err != nil {
		return err
	}
	credential = rotateCredentialIfNeeded(ctx, client, config, credential, logger)

	var negotiatedUsageLimits *usageReportLimits
	if capabilities, capabilityErr := client.Capabilities(ctx); capabilityErr != nil {
		logger.Warn("Flysky capability negotiation failed; cached bootstrap remains available", zap.Error(capabilityErr))
	} else if err := validateCapabilities(capabilities, config); err != nil {
		return err
	} else {
		limits, err := usageLimitsFromCapabilities(capabilities)
		if err != nil {
			return err
		}
		negotiatedUsageLimits = &limits
	}

	state := NewState()
	reportOutbox, err := newReportOutbox(config.ReportOutboxPath)
	if err != nil {
		return fmt.Errorf("open Flysky durable report outbox: %w", err)
	}
	if negotiatedUsageLimits != nil {
		if err := reportOutbox.SetUsageReportLimits(*negotiatedUsageLimits); err != nil {
			return fmt.Errorf("apply negotiated Flysky usage report limits: %w", err)
		}
	}
	if err := reportOutbox.ValidateNode(credential.NodeID); err != nil {
		return err
	}
	runtimeHooks := NewRuntime(state)
	syncer := NewSynchronizer(client, runtimeHooks, config.CredentialPath, config.SnapshotPath, config.SyncStatePath)
	var applied AppliedSnapshot
	stopState, stopExists, err := syncer.LoadStopServingState(credential.NodeID)
	if err != nil {
		return err
	}
	if stopExists {
		if durable, exists, stateErr := syncer.loadSynchronizationState(credential.NodeID); stateErr != nil {
			return stateErr
		} else if exists && durable.AppliedServingGeneration != "" && durable.AppliedServingGeneration != stopState.ServingGeneration {
			// A newer generation was fully installed before a crash that preceded
			// removal of the old stop barrier. Its durable ACK proves reactivation.
			if err := syncer.ClearStopServingState(); err != nil {
				return err
			}
			stopExists = false
		}
	}
	if stopExists {
		// A newly enrolled/reactivated node receives a different generation.
		// It may replace the barrier only by fully installing that new snapshot.
		candidate, snapshotErr := client.Snapshot(ctx, credential.AccessToken)
		if snapshotErr == nil && validUUID(candidate.ServingGeneration) && candidate.ServingGeneration != stopState.ServingGeneration {
			applied, err = syncer.InstallSnapshot(candidate, credential.NodeID)
			if err != nil {
				return err
			}
			stopExists = false
		}
	}
	if stopExists {
		if err := syncer.CompleteStopServing(credential.NodeID, stopState.ServingGeneration); err != nil {
			return fmt.Errorf("resume Flysky stop-serving transition: %w", err)
		}
		return awaitStoppedServingAcknowledgement(ctx, client, config, credential.AccessToken, stopState.ServingGeneration, logger)
	}
	if applied.Wire.Node.NodeID == "" {
		applied, err = loadStartupSnapshot(ctx, syncer, credential.AccessToken, credential.NodeID, logger)
		if err != nil {
			var stopRequest *StopServingRequestError
			if errors.As(err, &stopRequest) {
				if completeErr := syncer.CompleteStopServing(credential.NodeID, stopRequest.ServingGeneration); completeErr != nil {
					return errors.Join(ErrSynchronizationUnsafe, fmt.Errorf("complete startup Flysky stop-serving transition: %w", completeErr))
				}
				return awaitStoppedServingAcknowledgement(ctx, client, config, credential.AccessToken, stopRequest.ServingGeneration, logger)
			}
			return err
		}
	}
	if err := reportOutbox.Flush(ctx, client, credential.AccessToken); err != nil {
		logReportFlushFailure(logger, "Flysky retained report delivery state requires attention", reportOutbox, err)
	}

	manager, managedServer, err := newManager(config, applied, runtimeHooks, logger)
	if err != nil {
		return err
	}
	syncer.SetCredentialReloader(managedServer)

	runCtx, cancel := context.WithCancel(ctx)
	runResult := make(chan bool, 1)
	go func() {
		runResult <- manager.Run(runCtx)
	}()

	logger.Info("Flysky integration runtime started with durable usage and online IP reporting",
		zap.String("nodeID", applied.Wire.Node.NodeID),
		zap.Int("port", applied.Wire.Node.ListenPort),
		zap.Int("users", len(applied.Users)),
		zap.Time("snapshotValidUntil", applied.Wire.ValidUntil),
	)

	changeTicker := time.NewTicker(config.ChangePollInterval)
	defer changeTicker.Stop()
	refreshTicker := time.NewTicker(time.Minute)
	defer refreshTicker.Stop()
	heartbeatTimer := time.NewTimer(config.HeartbeatInterval)
	defer heartbeatTimer.Stop()
	usageTicker := time.NewTicker(config.UsageReportInterval)
	defer usageTicker.Stop()
	aliveIPTicker := time.NewTicker(config.AliveIPReportInterval)
	defer aliveIPTicker.Stop()
	usageWindowStart := time.Now().UTC()
	finish := func(baseErr error, managerResult *bool) error {
		drain := func() (bool, error) {
			if managerResult != nil {
				return *managerResult, nil
			}
			return waitForManagerDrain(runResult, config.ShutdownDrainTimeout)
		}
		result := shutdownRuntime(
			cancel,
			drain,
			manager.Close,
			func() error {
				return errors.Join(
					captureUsageReport(state, reportOutbox, applied, &usageWindowStart, logger),
					captureAliveIPReport(state, reportOutbox, applied, config.AliveIPReportInterval, logger),
				)
			},
			func() error {
				flushContext, cancelFlush := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancelFlush()
				return reportOutbox.Flush(flushContext, client, credential.AccessToken)
			},
		)
		if result.drainErr != nil {
			baseErr = errors.Join(baseErr, result.drainErr)
			logger.Error("Flysky manager drain exceeded its safety deadline; final capture may omit writes still inside the stuck relay",
				zap.Duration("timeout", config.ShutdownDrainTimeout), zap.Error(result.drainErr))
		}
		if !result.managerOK && result.drainErr == nil {
			baseErr = errors.Join(baseErr, errors.New("SS2022 service manager stopped with an error"))
		}
		if result.flushErr != nil {
			logReportFlushFailure(logger, "Flysky shutdown report delivery state requires attention", reportOutbox, result.flushErr)
		}
		return errors.Join(baseErr, result.captureErr)
	}
	retire := func(generation string) error {
		// Stop acceptance and close listeners before clearing durable
		// credentials. A drain failure intentionally withholds the ACK.
		cancel()
		managerOK, drainErr := waitForManagerDrain(runResult, config.ShutdownDrainTimeout)
		manager.Close()
		captureErr := errors.Join(
			captureUsageReport(state, reportOutbox, applied, &usageWindowStart, logger),
			captureAliveIPReport(state, reportOutbox, applied, config.AliveIPReportInterval, logger),
		)
		flushContext, cancelFlush := context.WithTimeout(context.Background(), 5*time.Second)
		flushErr := reportOutbox.Flush(flushContext, client, credential.AccessToken)
		cancelFlush()
		if drainErr != nil || !managerOK {
			return errors.Join(ErrSynchronizationUnsafe, drainErr, captureErr, flushErr,
				errors.New("Flysky listener did not confirm a clean stop; retirement ACK withheld"))
		}
		// The listener and all managed sessions are now gone. Detach the closed
		// credential manager before deleting its backing file; runtime policy and
		// durable cache cleanup below remain the authoritative stop barrier.
		syncer.SetCredentialReloader(nil)
		if err := syncer.CompleteStopServing(credential.NodeID, generation); err != nil {
			return errors.Join(ErrSynchronizationUnsafe, captureErr, flushErr,
				fmt.Errorf("complete Flysky stop-serving transition: %w", err))
		}
		if captureErr != nil {
			logger.Warn("Flysky retirement accounting capture was incomplete", zap.Error(captureErr))
		}
		if flushErr != nil {
			logReportFlushFailure(logger, "Flysky retirement report delivery remains pending", reportOutbox, flushErr)
		}
		return awaitStoppedServingAcknowledgement(ctx, client, config, credential.AccessToken, generation, logger)
	}

	for {
		select {
		case <-ctx.Done():
			return finish(nil, nil)
		case ok := <-runResult:
			if !ok {
				return finish(nil, &ok)
			}
			return finish(errors.New("SS2022 service manager stopped unexpectedly"), &ok)
		case <-changeTicker.C:
			updated, changeErr := syncer.PollChanges(ctx, credential.AccessToken)
			switch {
			case changeErr == nil:
				applied = updated
			case errors.Is(changeErr, ErrStopServingRequested):
				var stopRequest *StopServingRequestError
				if !errors.As(changeErr, &stopRequest) {
					return finish(changeErr, nil)
				}
				return retire(stopRequest.ServingGeneration)
			case errors.Is(changeErr, ErrServingGenerationChanged):
				updated, snapshotErr := syncer.FetchAndInstallSnapshot(ctx, credential.AccessToken, credential.NodeID)
				var stopRequest *StopServingRequestError
				if errors.As(snapshotErr, &stopRequest) {
					return retire(stopRequest.ServingGeneration)
				}
				if snapshotErr != nil {
					// A generation change is a control-plane trust epoch change. Once
					// observed, continuing to serve the historical generation is not a
					// safe cache fallback, even when the full refetch fails transiently.
					return finish(errors.Join(changeErr, snapshotErr), nil)
				}
				applied = updated
				logger.Info("Flysky serving generation advanced from a full snapshot",
					zap.String("servingGeneration", applied.Wire.ServingGeneration),
					zap.String("configVersion", applied.Wire.ConfigVersion))
			case errors.Is(changeErr, flyskyapi.ErrCursorExpired):
				updated, snapshotErr := syncer.FetchAndInstallSnapshot(ctx, credential.AccessToken, credential.NodeID)
				var stopRequest *StopServingRequestError
				if errors.As(snapshotErr, &stopRequest) {
					return retire(stopRequest.ServingGeneration)
				}
				if errors.Is(snapshotErr, ErrRestartRequired) || errors.Is(snapshotErr, ErrSynchronizationUnsafe) {
					return finish(snapshotErr, nil)
				}
				if snapshotErr != nil {
					logger.Warn("Flysky cursor recovery snapshot failed", zap.Error(snapshotErr))
					continue
				}
				applied = updated
				logger.Info("Flysky cursor recovered from a full snapshot", zap.String("configVersion", applied.Wire.ConfigVersion))
			case errors.Is(changeErr, ErrRestartRequired), errors.Is(changeErr, ErrSynchronizationUnsafe):
				return finish(changeErr, nil)
			default:
				logger.Warn("Flysky incremental synchronization failed", zap.Error(changeErr))
			}
		case <-refreshTicker.C:
			if time.Until(applied.Wire.ValidUntil) > config.SnapshotRefreshBefore {
				continue
			}
			updated, snapshotErr := syncer.FetchAndInstallSnapshot(ctx, credential.AccessToken, credential.NodeID)
			var stopRequest *StopServingRequestError
			if errors.As(snapshotErr, &stopRequest) {
				return retire(stopRequest.ServingGeneration)
			}
			if errors.Is(snapshotErr, ErrRestartRequired) || errors.Is(snapshotErr, ErrSynchronizationUnsafe) {
				return finish(snapshotErr, nil)
			}
			if snapshotErr != nil {
				logger.Warn("Flysky snapshot refresh failed; new sessions will fail closed at expiry",
					zap.Time("validUntil", applied.Wire.ValidUntil), zap.Error(snapshotErr))
				continue
			}
			applied = updated
			logger.Info("Flysky snapshot refreshed", zap.Time("validUntil", applied.Wire.ValidUntil))
		case <-heartbeatTimer.C:
			credential = rotateCredentialIfNeeded(ctx, client, config, credential, logger)
			nextInterval := reportStatus(ctx, client, config, credential.AccessToken, applied, logger)
			heartbeatTimer.Reset(nextInterval)
		case <-usageTicker.C:
			if err := captureUsageReport(state, reportOutbox, applied, &usageWindowStart, logger); err != nil {
				logger.Error("Flysky usage report could not be persisted; traffic remains in memory", zap.Error(err))
			}
			flushReports(ctx, reportOutbox, client, credential.AccessToken, logger)
		case <-aliveIPTicker.C:
			if err := captureAliveIPReport(state, reportOutbox, applied, config.AliveIPReportInterval, logger); err != nil {
				logger.Error("Flysky online IP aggregate could not be persisted", zap.Error(err))
			}
			flushReports(ctx, reportOutbox, client, credential.AccessToken, logger)
		}
	}
}

type startupSnapshotSource interface {
	FetchAndInstallSnapshot(context.Context, string, string) (AppliedSnapshot, error)
	LoadCachedSnapshot(string) (AppliedSnapshot, error)
}

func loadStartupSnapshot(
	ctx context.Context,
	source startupSnapshotSource,
	accessToken, nodeID string,
	logger *zap.Logger,
) (AppliedSnapshot, error) {
	applied, err := source.FetchAndInstallSnapshot(ctx, accessToken, nodeID)
	if err == nil {
		return applied, nil
	}
	if errors.Is(err, ErrSynchronizationUnsafe) || errors.Is(err, ErrRestartRequired) || errors.Is(err, ErrStopServingRequested) {
		return AppliedSnapshot{}, err
	}
	logger.Warn("Flysky snapshot fetch failed; attempting the last valid local snapshot", zap.Error(err))
	applied, err = source.LoadCachedSnapshot(nodeID)
	if err != nil {
		return AppliedSnapshot{}, fmt.Errorf("load Flysky startup snapshot: %w", err)
	}
	logger.Warn("Flysky runtime started from a cached snapshot",
		zap.String("nodeID", applied.Wire.Node.NodeID),
		zap.Time("validUntil", applied.Wire.ValidUntil),
	)
	return applied, nil
}

type runtimeShutdownResult struct {
	managerOK  bool
	drainErr   error
	captureErr error
	flushErr   error
}

func shutdownRuntime(
	cancel func(),
	drain func() (bool, error),
	closeManager func(),
	capture func() error,
	flush func() error,
) runtimeShutdownResult {
	// Stop acceptance first. Manager.Run then drains every relay and its final
	// accounting. Only after that barrier (or its bounded timeout) may durable
	// capture and the best-effort network flush run.
	cancel()
	managerOK, drainErr := drain()
	closeManager()
	captureErr := capture()
	flushErr := flush()
	return runtimeShutdownResult{
		managerOK: managerOK, drainErr: drainErr, captureErr: captureErr, flushErr: flushErr,
	}
}

func waitForManagerDrain(runResult <-chan bool, timeout time.Duration) (bool, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case ok := <-runResult:
		return ok, nil
	case <-timer.C:
		return false, ErrRuntimeDrainTimeout
	}
}

func captureUsageReport(
	state *State,
	outbox *reportOutbox,
	applied AppliedSnapshot,
	windowStart *time.Time,
	logger *zap.Logger,
) error {
	now := time.Now().UTC()
	deltas := state.SnapshotTraffic()
	if len(deltas) == 0 {
		*windowStart = now
		return nil
	}
	if err := outbox.CaptureUsage(applied.Wire.Node.NodeID, applied.Wire.ConfigVersion, *windowStart, now, deltas); err != nil {
		state.MergeTraffic(deltas)
		return fmt.Errorf("persist Flysky usage report: %w", err)
	}
	*windowStart = now
	return nil
}

func captureAliveIPReport(
	state *State,
	outbox *reportOutbox,
	applied AppliedSnapshot,
	window time.Duration,
	logger *zap.Logger,
) error {
	now := time.Now().UTC()
	onlineIPs, activeUsers := state.AliveSummary(window, now)
	if err := outbox.CaptureAliveIP(flyskyapi.AliveIPReport{
		NodeID: applied.Wire.Node.NodeID, ObservedAt: now, WindowSeconds: int(window / time.Second),
		OnlineIPCount: int64(onlineIPs), ActiveUsers: int64(activeUsers), Connections: 0,
	}); err != nil {
		return fmt.Errorf("persist Flysky online IP aggregate: %w", err)
	}
	return nil
}

func flushReports(
	ctx context.Context,
	outbox *reportOutbox,
	client reportClient,
	accessToken string,
	logger *zap.Logger,
) {
	if err := outbox.Flush(ctx, client, accessToken); err != nil {
		logReportFlushFailure(logger, "Flysky report delivery state requires attention", outbox, err)
	}
}

func logReportFlushFailure(logger *zap.Logger, message string, outbox *reportOutbox, err error) {
	usagePending, alivePending := outbox.Pending()
	usageReconciliation, aliveReconciliation := outbox.Reconciliation()
	logger.Warn(message,
		zap.Int("usagePending", usagePending),
		zap.Int("aliveIPPending", alivePending),
		zap.Int("usageReconciliation", usageReconciliation),
		zap.Int("aliveIPReconciliation", aliveReconciliation),
		zap.Error(err),
	)
}

func loadOrEnroll(
	ctx context.Context,
	client enrollmentClient,
	config Config,
	report flyskyapi.CapabilityReport,
	logger *zap.Logger,
) (flyskyapi.MachineCredential, error) {
	token, err := readEnrollmentToken(config.EnrollmentTokenPath)
	if err == nil {
		credential, enrollErr := client.Enroll(ctx, token, report)
		if enrollErr != nil {
			return flyskyapi.MachineCredential{}, enrollErr
		}
		if err := flyskyapi.SaveMachineCredential(config.MachineCredentialPath, credential); err != nil {
			return flyskyapi.MachineCredential{}, fmt.Errorf("persist Flysky machine credential: %w", err)
		}
		if err := os.Remove(config.EnrollmentTokenPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			logger.Warn("Consumed Flysky enrollment token file could not be removed", zap.Error(err))
		}
		return credential, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return flyskyapi.MachineCredential{}, fmt.Errorf("read Flysky enrollment token: %w", err)
	}
	return flyskyapi.LoadMachineCredential(config.MachineCredentialPath)
}

func rotateCredentialIfNeeded(
	ctx context.Context,
	client *flyskyapi.Client,
	config Config,
	credential flyskyapi.MachineCredential,
	logger *zap.Logger,
) flyskyapi.MachineCredential {
	if time.Until(credential.ExpiresAt) > config.CredentialRotateBefore {
		return credential
	}
	rotated, err := client.RotateCredential(ctx, credential.AccessToken)
	if err != nil {
		logger.Warn("Flysky machine credential rotation failed", zap.Time("expiresAt", credential.ExpiresAt), zap.Error(err))
		return credential
	}
	if err := flyskyapi.SaveMachineCredential(config.MachineCredentialPath, rotated); err != nil {
		logger.Error("Rotated Flysky machine credential is active but could not be persisted; keep this process running",
			zap.Time("expiresAt", rotated.ExpiresAt), zap.Error(err))
		return rotated
	}
	logger.Info("Flysky machine credential rotated", zap.Time("expiresAt", rotated.ExpiresAt))
	return rotated
}

func readEnrollmentToken(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("enrollment token must be a regular file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return "", errors.New("enrollment token file must not grant group or other access")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return "", err
	}
	if len(data) > 256 {
		return "", errors.New("enrollment token file is too large")
	}
	token := strings.TrimSpace(string(data))
	if len(token) != 48 || !strings.HasPrefix(token, "fenr_") || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("enrollment token file has an invalid value")
	}
	return token, nil
}

func capabilityReport(config Config) flyskyapi.CapabilityReport {
	return flyskyapi.CapabilityReport{
		Runtime: "ssbad", Version: runtimeVersion(), SchemaVersions: []int{1},
		Protocols: map[string]flyskyapi.ProtocolCapability{
			"ss2022": {
				Methods: []string{method}, TCP: config.EnableTCP, UDP: config.EnableUDP,
				SinglePortMultiUser: true,
			},
		},
		Features: []string{
			"snapshot_v1", "cursor_changes_v1", "status_report_v1", "credential_rotation_v1",
			"usage_batch_v1", "alive_ip_aggregate_v1", "node_dns_v1", "fake_ip_domain_v1",
			"resource_version_fence_v1", "serving_generation_ack_v1", "stop_serving_ack_v1",
		},
	}
}

func validateCapabilities(capabilities flyskyapi.Capabilities, config Config) error {
	if capabilities.APIVersion != "v1" || !containsInt(capabilities.SchemaVersions, 1) {
		return errors.New("Flysky control plane does not support Node API schema v1")
	}
	protocol, exists := capabilities.Protocols["ss2022"]
	if !exists || !protocol.SinglePortMultiUser || !containsString(protocol.Methods, method) ||
		config.EnableTCP && !protocol.TCP || config.EnableUDP && !protocol.UDP {
		return errors.New("Flysky control plane does not support the configured SS2022 runtime capabilities")
	}
	for _, feature := range []string{
		"snapshot_v1", "cursor_changes_v1", "status_report_v1", "usage_batch_v1", "alive_ip_aggregate_v1",
		"resource_version_fence_v1", "serving_generation_ack_v1", "stop_serving_ack_v1",
	} {
		if !containsString(capabilities.Features, feature) {
			return fmt.Errorf("Flysky control plane is missing required feature %s", feature)
		}
	}
	if _, err := usageLimitsFromCapabilities(capabilities); err != nil {
		return err
	}
	return nil
}

func usageLimitsFromCapabilities(capabilities flyskyapi.Capabilities) (usageReportLimits, error) {
	limits, err := normalizeUsageReportLimits(usageReportLimits{
		MaxItems:        capabilities.Limits.UsageReportMaxItems,
		MaxEncodedBytes: capabilities.Limits.UsageReportMaxBytes,
	})
	if err != nil {
		return usageReportLimits{}, fmt.Errorf("invalid Flysky usage report capability limits: %w", err)
	}
	return limits, nil
}

func reportStatus(
	ctx context.Context,
	client *flyskyapi.Client,
	config Config,
	accessToken string,
	applied AppliedSnapshot,
	logger *zap.Logger,
) time.Duration {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	health := "healthy"
	if time.Until(applied.Wire.ValidUntil) <= config.SnapshotRefreshBefore {
		health = "degraded"
	}
	state, err := client.ReportStatus(ctx, accessToken, flyskyapi.StatusRequest{
		CapabilityReport:         capabilityReport(config),
		AppliedServingGeneration: applied.Wire.ServingGeneration,
		AppliedCursor:            applied.Wire.Cursor,
		Health: flyskyapi.HealthReport{
			Status: health, ActiveConnections: 0, Load1: 0, MemoryUsedBytes: int64(memory.Alloc),
		},
	})
	if err != nil {
		logger.Warn("Flysky status heartbeat failed", zap.Error(err))
		return config.HeartbeatInterval
	}
	next := time.Duration(state.NextHeartbeatSeconds) * time.Second
	if next < 10*time.Second || next > 5*time.Minute {
		next = config.HeartbeatInterval
	}
	return next
}

func awaitStoppedServingAcknowledgement(
	ctx context.Context,
	client *flyskyapi.Client,
	config Config,
	accessToken, generation string,
	logger *zap.Logger,
) error {
	interval := config.HeartbeatInterval
	for {
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		state, err := client.ReportStatus(ctx, accessToken, flyskyapi.StatusRequest{
			CapabilityReport:         capabilityReport(config),
			StoppedServingGeneration: generation,
			Health: flyskyapi.HealthReport{
				Status: "degraded", ActiveConnections: 0, Load1: 0, MemoryUsedBytes: int64(memory.Alloc),
			},
		})
		if err == nil {
			if state.StoppedServingAccepted {
				return nil
			}
			next := time.Duration(state.NextHeartbeatSeconds) * time.Second
			if next >= 10*time.Second && next <= 5*time.Minute {
				interval = next
			}
		} else {
			var apiErr *flyskyapi.APIError
			if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized && apiErr.Code == "NODE_STOP_SERVING_FINALIZED" {
				// The exact ACK was committed but its 200 response was lost. Panel
				// recognizes the revoked credential + finalized exact-generation
				// fence and returns this dedicated terminal code.
				return nil
			}
			logger.Warn("Flysky stopped-serving acknowledgement failed; listener remains stopped",
				zap.String("servingGeneration", generation), zap.Error(err))
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

var buildVersion string

func runtimeVersion() string {
	if version := strings.TrimSpace(buildVersion); version != "" {
		return strings.TrimPrefix(version, "v")
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return "development"
}

func containsInt(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func newManager(
	config Config,
	applied AppliedSnapshot,
	runtimeHooks *Runtime,
	logger *zap.Logger,
) (*service.Manager, *cred.ManagedServer, error) {
	paddingPolicy, err := ss2022.NewPaddingPolicyField("NoPadding")
	if err != nil {
		return nil, nil, err
	}
	address := serverListenAddress(config.ListenHost, applied.Wire.Node.ListenPort)
	udpPathMTUDiscovery := outerUDPPathMTUDiscovery(config.UDPOuterFragmentation)
	server := service.ServerConfig{
		Name: serverName, Protocol: method, MTU: config.UDPMTU, PSK: applied.ServerKey,
		UPSKStorePath: config.CredentialPath, PaddingPolicy: paddingPolicy,
	}
	if config.EnableTCP {
		server.TCPListeners = []service.TCPListenerConfig{{
			ListenerConfig: service.ListenerConfig{Network: "tcp", Address: address},
			FastOpen:       true, FastOpenFallback: true,
			MaxConcurrentHandshakes:   config.TCPMaxHandshakes,
			MaxConnectionsPerUser:     config.TCPMaxConnectionsPerUser,
			MaxEstablishedConnections: config.TCPMaxEstablishedTotal,
			TrafficFlushInterval:      jsoncfg.Duration(config.TCPTrafficFlushInterval),
		}}
	}
	if config.EnableUDP {
		server.UDPListeners = []service.UDPListenerConfig{{
			ListenerConfig: service.ListenerConfig{
				Network: "udp", Address: address,
				PathMTUDiscovery: udpPathMTUDiscovery,
			},
			UDPPerfConfig: service.UDPPerfConfig{
				RelayBatchSize: config.UDPRelayBatchSize, ServerRecvBatchSize: config.UDPServerBatchSize,
				SendChannelCapacity: config.UDPSendQueueSize,
			},
			NATTimeout: jsoncfg.Duration(config.UDPNATTimeout), MaxSessions: config.UDPMaxSessions,
			MaxSessionsPerUser: config.UDPMaxSessionsPerUser,
		}}
	}
	server.SetRuntimeHooks(runtimeHooks, runtimeHooks)
	outboundPolicy, err := newOutboundACL(config.ControlPlaneURL, config.ProtectedEgressPrefixes)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize node outbound ACL: %w", err)
	}
	directClient := service.ClientConfig{
		Name: "direct", Protocol: "direct", EnableTCP: config.EnableTCP,
		DialerTFO: true, TCPFastOpenFallback: true, EnableUDP: config.EnableUDP, MTU: config.UDPMTU,
	}
	directClient.SetOutboundTargetPolicy(outboundPolicy)
	serviceConfig := service.Config{
		Servers:       []service.ServerConfig{server},
		Clients:       []service.ClientConfig{directClient},
		RuntimeAccess: true,
	}
	manager, err := serviceConfig.Manager(logger)
	if err != nil {
		return nil, nil, err
	}
	runtimeServer, ok := manager.RuntimeServer(serverName)
	if !ok || runtimeServer.CredentialManager == nil {
		manager.Close()
		return nil, nil, errors.New("SS2022 credential manager is unavailable")
	}
	return manager, runtimeServer.CredentialManager, nil
}

func outerUDPPathMTUDiscovery(allowFragmentation bool) service.PMTUDMode {
	if allowFragmentation {
		return service.PMTUDModeDont
	}
	return service.PMTUDModeAppDefault
}

func serverListenAddress(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
