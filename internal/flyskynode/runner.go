package flyskynode

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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

	if capabilities, capabilityErr := client.Capabilities(ctx); capabilityErr != nil {
		logger.Warn("Flysky capability negotiation failed; cached bootstrap remains available", zap.Error(capabilityErr))
	} else if err := validateCapabilities(capabilities, config); err != nil {
		return err
	}

	state := NewState()
	reportOutbox, err := newReportOutbox(config.ReportOutboxPath)
	if err != nil {
		return fmt.Errorf("open Flysky durable report outbox: %w", err)
	}
	if err := reportOutbox.ValidateNode(credential.NodeID); err != nil {
		return err
	}
	runtimeHooks := NewRuntime(state)
	syncer := NewSynchronizer(client, runtimeHooks, config.CredentialPath, config.SnapshotPath, config.SyncStatePath)
	applied, err := syncer.FetchAndInstallSnapshot(ctx, credential.AccessToken, credential.NodeID)
	if err != nil {
		logger.Warn("Flysky snapshot fetch failed; attempting the last valid local snapshot", zap.Error(err))
		applied, err = syncer.LoadCachedSnapshot(credential.NodeID)
		if err != nil {
			return fmt.Errorf("load Flysky startup snapshot: %w", err)
		}
		logger.Warn("Flysky runtime started from a cached snapshot",
			zap.String("nodeID", applied.Wire.Node.NodeID),
			zap.Time("validUntil", applied.Wire.ValidUntil),
		)
	}
	if err := reportOutbox.Flush(ctx, client, credential.AccessToken); err != nil {
		usagePending, alivePending := reportOutbox.Pending()
		logger.Warn("Flysky pending reports will be retried", zap.Int("usagePending", usagePending),
			zap.Int("aliveIPPending", alivePending), zap.Error(err))
	}

	manager, managedServer, err := newManager(config, applied, runtimeHooks, logger)
	if err != nil {
		return err
	}
	defer manager.Close()
	syncer.SetCredentialReloader(managedServer)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
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
	defer func() {
		captureUsageReport(state, reportOutbox, applied, &usageWindowStart, logger)
		captureAliveIPReport(state, reportOutbox, applied, config.AliveIPReportInterval, logger)
		flushContext, cancelFlush := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelFlush()
		if err := reportOutbox.Flush(flushContext, client, credential.AccessToken); err != nil {
			usagePending, alivePending := reportOutbox.Pending()
			logger.Warn("Flysky shutdown retained pending reports on disk", zap.Int("usagePending", usagePending),
				zap.Int("aliveIPPending", alivePending), zap.Error(err))
		}
	}()

	for {
		select {
		case <-ctx.Done():
			cancel()
			if ok := <-runResult; !ok {
				return errors.New("SS2022 service manager stopped with an error")
			}
			return nil
		case ok := <-runResult:
			if !ok {
				return errors.New("SS2022 service manager stopped with an error")
			}
			return errors.New("SS2022 service manager stopped unexpectedly")
		case <-changeTicker.C:
			updated, changeErr := syncer.PollChanges(ctx, credential.AccessToken)
			switch {
			case changeErr == nil:
				applied = updated
			case errors.Is(changeErr, flyskyapi.ErrCursorExpired):
				updated, snapshotErr := syncer.FetchAndInstallSnapshot(ctx, credential.AccessToken, credential.NodeID)
				if snapshotErr != nil {
					logger.Warn("Flysky cursor recovery snapshot failed", zap.Error(snapshotErr))
					continue
				}
				applied = updated
				logger.Info("Flysky cursor recovered from a full snapshot", zap.String("configVersion", applied.Wire.ConfigVersion))
			case errors.Is(changeErr, ErrRestartRequired):
				return changeErr
			default:
				logger.Warn("Flysky incremental synchronization failed", zap.Error(changeErr))
			}
		case <-refreshTicker.C:
			if time.Until(applied.Wire.ValidUntil) > config.SnapshotRefreshBefore {
				continue
			}
			updated, snapshotErr := syncer.FetchAndInstallSnapshot(ctx, credential.AccessToken, credential.NodeID)
			if errors.Is(snapshotErr, ErrRestartRequired) {
				return snapshotErr
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
			captureUsageReport(state, reportOutbox, applied, &usageWindowStart, logger)
			flushReports(ctx, reportOutbox, client, credential.AccessToken, logger)
		case <-aliveIPTicker.C:
			captureAliveIPReport(state, reportOutbox, applied, config.AliveIPReportInterval, logger)
			flushReports(ctx, reportOutbox, client, credential.AccessToken, logger)
		}
	}
}

func captureUsageReport(
	state *State,
	outbox *reportOutbox,
	applied AppliedSnapshot,
	windowStart *time.Time,
	logger *zap.Logger,
) {
	now := time.Now().UTC()
	deltas := state.SnapshotTraffic()
	if len(deltas) == 0 {
		*windowStart = now
		return
	}
	if err := outbox.CaptureUsage(applied.Wire.Node.NodeID, applied.Wire.ConfigVersion, *windowStart, now, deltas); err != nil {
		state.MergeTraffic(deltas)
		logger.Error("Flysky usage report could not be persisted; traffic remains in memory", zap.Error(err))
		return
	}
	*windowStart = now
}

func captureAliveIPReport(
	state *State,
	outbox *reportOutbox,
	applied AppliedSnapshot,
	window time.Duration,
	logger *zap.Logger,
) {
	now := time.Now().UTC()
	onlineIPs, activeUsers := state.AliveSummary(window, now)
	if err := outbox.CaptureAliveIP(flyskyapi.AliveIPReport{
		NodeID: applied.Wire.Node.NodeID, ObservedAt: now, WindowSeconds: int(window / time.Second),
		OnlineIPCount: int64(onlineIPs), ActiveUsers: int64(activeUsers), Connections: 0,
	}); err != nil {
		logger.Error("Flysky online IP aggregate could not be persisted", zap.Error(err))
	}
}

func flushReports(
	ctx context.Context,
	outbox *reportOutbox,
	client reportClient,
	accessToken string,
	logger *zap.Logger,
) {
	if err := outbox.Flush(ctx, client, accessToken); err != nil {
		usagePending, alivePending := outbox.Pending()
		logger.Warn("Flysky report delivery failed; durable retry is pending", zap.Int("usagePending", usagePending),
			zap.Int("aliveIPPending", alivePending), zap.Error(err))
	}
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
			"usage_batch_v1", "alive_ip_aggregate_v1",
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
	} {
		if !containsString(capabilities.Features, feature) {
			return fmt.Errorf("Flysky control plane is missing required feature %s", feature)
		}
	}
	return nil
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
		CapabilityReport: capabilityReport(config),
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

func runtimeVersion() string {
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
	// Local interfaces and the exact control-plane target are protected by
	// default. NAT-only public addresses are supplied explicitly until the Panel
	// installer can populate this strict configuration field automatically.
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
