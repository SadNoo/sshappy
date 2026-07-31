package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/jsoncfg"
	"github.com/database64128/shadowsocks-go/service"
	"github.com/database64128/shadowsocks-go/ss2022"
	"go.uber.org/zap"
)

const serverName = "sshappy"

func Run(ctx context.Context, config Config, logger *zap.Logger) error {
	if err := config.Validate(); err != nil {
		return err
	}
	dbHealth := &databaseHealth{}
	dbStartedAt := time.Now()
	db, err := OpenDatabase(config)
	if err != nil {
		return err
	}
	dbHealth.Record("open", dbStartedAt, nil)
	defer db.Close()

	startedAt := time.Now()
	node, err := db.LoadNode()
	dbHealth.Record("loadNode", startedAt, err)
	if err != nil {
		return err
	}
	trafficReporter, err := newTrafficReporter(config.TrafficOutboxPath)
	if err != nil {
		return err
	}
	if outbox := trafficReporter.Metrics(time.Now()); outbox.Batches > 0 {
		logger.Warn("Recovered pending traffic outbox",
			zap.Int("batches", outbox.Batches),
			zap.Int("users", outbox.Users),
			zap.Int64("fileBytes", outbox.FileBytes),
			zap.Duration("oldestAge", outbox.OldestAge),
		)
	}
	startedAt = time.Now()
	if trafficReporter.PendingBatches() > 0 {
		logger.Warn("Skipped traffic marker cleanup while outbox has pending batches",
			zap.Int("pendingBatches", trafficReporter.PendingBatches()),
		)
	} else {
		deleted, cleanupErr := db.CleanupTrafficBatches(node.ID, config.TrafficBatchRetentionDays)
		dbHealth.Record("cleanupTrafficBatches", startedAt, cleanupErr)
		if cleanupErr != nil {
			logger.Warn("Failed to clean traffic batch markers", zap.Error(cleanupErr))
		} else if deleted > 0 {
			logger.Info("Traffic batch markers cleaned", zap.Int64("deleted", deleted))
		}
	}
	startedAt = time.Now()
	users, err := db.LoadUsers(node)
	dbHealth.Record("loadUsers", startedAt, err)
	if err != nil {
		return err
	}
	if err := writeCredentialFile(config.CredentialPath, users); err != nil {
		return err
	}

	state := NewState()
	runtime := NewRuntime(state)
	runtime.ReplaceUsers(users)
	manager, managedServer, err := newManager(config, node, runtime, logger)
	if err != nil {
		return err
	}
	defer manager.Close()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	failures := newFailClosedWindow(time.Duration(config.AuthorizationStaleSeconds)*time.Second, cancel)
	defer failures.Close()
	runResult := make(chan bool, 1)
	go func() {
		runResult <- manager.Run(runCtx)
	}()

	startupFields := []zap.Field{
		zap.Int("node", node.ID),
		zap.Int("port", node.ListenPort),
		zap.Int("users", len(users)),
		zap.Bool("tcpEnabled", config.EnableTCP),
		zap.Bool("udpEnabled", config.EnableUDP),
		zap.Int("trafficBatchRetentionDays", config.TrafficBatchRetentionDays),
		zap.Int("authorizationStaleGraceSeconds", config.AuthorizationStaleSeconds),
		zap.Int("trafficSQLBatchSize", trafficSQLBatchSize),
		zap.Int("resourceReportSeconds", config.ResourceReportSeconds),
		zap.Int64("outboxMinFreeBytes", config.OutboxMinFreeBytes),
	}
	if config.EnableTCP {
		startupFields = append(startupFields,
			zap.Int("tcpMaxConcurrentHandshakes", config.TCPMaxHandshakes),
			zap.Int("tcpMaxConnectionsPerUser", config.TCPMaxConnectionsPerUser),
			zap.Int("tcpMaxEstablishedTotal", config.TCPMaxEstablishedTotal),
			zap.Int("tcpTrafficFlushSeconds", config.TCPTrafficFlushSeconds),
		)
	}
	if config.EnableUDP {
		startupFields = append(startupFields,
			zap.Int("mtu", config.UDPMTU),
			zap.Int("udpRelayBatchSize", config.UDPRelayBatchSize),
			zap.Int("udpServerRecvBatchSize", config.UDPServerBatchSize),
			zap.Int("udpSendChannelCapacity", config.UDPSendQueueSize),
			zap.Int("udpNATTimeoutSeconds", config.UDPNATTimeoutSeconds),
			zap.Int("udpMaxSessions", config.UDPMaxSessions),
			zap.Int("udpMaxSessionsPerUser", config.UDPMaxSessionsPerUser),
		)
	}
	logger.Info("sshappy upstream runtime started", startupFields...)

	syncTicker := time.NewTicker(time.Duration(config.SyncIntervalSeconds) * time.Second)
	trafficTicker := time.NewTicker(time.Duration(config.TrafficReportSeconds) * time.Second)
	nodeTicker := time.NewTicker(time.Duration(config.NodeReportSeconds) * time.Second)
	aliveTicker := time.NewTicker(time.Duration(config.AliveIPReportSeconds) * time.Second)
	resourceTicker := time.NewTicker(time.Duration(config.ResourceReportSeconds) * time.Second)
	monitor := &operationalMonitor{outboxMinFreeBytes: config.OutboxMinFreeBytes}
	var cleanupTicker *time.Ticker
	var cleanupC <-chan time.Time
	if config.TrafficBatchRetentionDays > 0 {
		cleanupTicker = time.NewTicker(24 * time.Hour)
		cleanupC = cleanupTicker.C
	}
	defer syncTicker.Stop()
	defer trafficTicker.Stop()
	defer nodeTicker.Stop()
	defer aliveTicker.Stop()
	defer resourceTicker.Stop()
	if cleanupTicker != nil {
		defer cleanupTicker.Stop()
	}

	var stopErr error
	var managerStopped, managerOK bool

runLoop:
	for {
		select {
		case <-ctx.Done():
			break runLoop
		case ok := <-runResult:
			managerStopped = true
			managerOK = ok
			if failureErr := failures.Err(time.Now()); failureErr != nil {
				stopErr = failureErr
			} else if ctx.Err() == nil {
				if ok {
					stopErr = errors.New("upstream service manager stopped unexpectedly")
				} else {
					stopErr = errors.New("upstream service manager stopped with an error")
				}
			}
			break runLoop
		case <-failures.Expired():
			stopErr = failures.Err(time.Now())
			break runLoop
		case <-syncTicker.C:
			startedAt := time.Now()
			loadedNode, err := db.LoadNode()
			dbHealth.Record("loadNode", startedAt, err)
			if err != nil {
				if errors.Is(err, ErrNodeNotAuthorized) {
					stopErr = err
					break runLoop
				}
				age, remaining, expired := failures.RecordFailure("node authorization refresh", err, time.Now())
				logger.Error("Failed to load node",
					zap.Duration("staleAge", age),
					zap.Duration("staleGraceRemaining", remaining),
					zap.Error(err),
				)
				if expired {
					stopErr = failures.Err(time.Now())
					break runLoop
				}
				continue
			}
			failures.RecordSuccess("node authorization refresh", time.Now())
			if loadedNode.ListenPort != node.ListenPort ||
				!bytes.Equal(loadedNode.ServerKey, node.ServerKey) {
				stopErr = errors.New("node port or server key changed; restart is required")
				break runLoop
			}
			startedAt = time.Now()
			loadedUsers, err := db.LoadUsers(loadedNode)
			dbHealth.Record("loadUsers", startedAt, err)
			if err != nil {
				age, remaining, expired := failures.RecordFailure("user authorization refresh", err, time.Now())
				logger.Error("Failed to load users",
					zap.Duration("staleAge", age),
					zap.Duration("staleGraceRemaining", remaining),
					zap.Error(err),
				)
				if expired {
					stopErr = failures.Err(time.Now())
					break runLoop
				}
				continue
			}
			failures.RecordSuccess("user authorization refresh", time.Now())
			if err := syncCredentials(managedServer, loadedUsers); err != nil {
				age, remaining, expired := failures.RecordFailure("credential refresh", err, time.Now())
				logger.Error("Failed to synchronize credentials",
					zap.Duration("staleAge", age),
					zap.Duration("staleGraceRemaining", remaining),
					zap.Error(err),
				)
				if expired {
					stopErr = failures.Err(time.Now())
					break runLoop
				}
				continue
			}
			failures.RecordSuccess("credential refresh", time.Now())
			runtime.ReplaceUsers(loadedUsers)
			node = loadedNode
			logger.Info("Runtime users synchronized", zap.Int("users", len(loadedUsers)))
		case <-trafficTicker.C:
			startedAt := time.Now()
			flushed, err := reportTraffic(db, node, state, trafficReporter, dbHealth)
			if flushed {
				// A successful durable flush starts a fresh failure window even if a
				// later flush in this reporting cycle fails again.
				failures.RecordSuccess("traffic accounting", time.Now())
			}
			if err != nil {
				outbox := trafficReporter.Metrics(time.Now())
				if errors.Is(err, errTrafficOutboxPersistence) {
					logger.Error("Traffic outbox persistence failed; stopping immediately",
						zap.Duration("duration", time.Since(startedAt)),
						zap.Int("outboxBatches", outbox.Batches),
						zap.Int64("outboxFileBytes", outbox.FileBytes),
						zap.Error(err),
					)
					stopErr = err
					break runLoop
				}
				age, remaining, expired := failures.RecordFailure("traffic accounting", err, time.Now())
				logger.Error("Failed to report traffic",
					zap.Duration("duration", time.Since(startedAt)),
					zap.Duration("staleAge", age),
					zap.Duration("staleGraceRemaining", remaining),
					zap.Int("outboxBatches", outbox.Batches),
					zap.Int64("outboxFileBytes", outbox.FileBytes),
					zap.Duration("outboxOldestAge", outbox.OldestAge),
					zap.Error(err),
				)
				if expired {
					stopErr = failures.Err(time.Now())
					break runLoop
				}
			} else {
				logger.Info("Traffic reported",
					zap.Duration("duration", time.Since(startedAt)),
					zap.Int("outboxBatches", trafficReporter.Metrics(time.Now()).Batches),
				)
			}
		case <-nodeTicker.C:
			online := state.OnlineUserCount(onlineCountWindow(config))
			startedAt := time.Now()
			err := db.ReportNodeStatus(node, online)
			dbHealth.Record("reportNodeStatus", startedAt, err)
			if err != nil {
				logger.Error("Failed to report node status", zap.Error(err))
			} else {
				logger.Info("Node status reported", zap.Int("online", online))
			}
		case <-aliveTicker.C:
			alive := state.SnapshotAliveIPs()
			startedAt := time.Now()
			err := db.ReportAliveIPs(node, alive)
			dbHealth.Record("reportAliveIPs", startedAt, err)
			if err != nil {
				state.MergeAliveIPs(alive)
				logger.Error("Failed to report alive IPs", zap.Error(err))
			} else {
				logger.Info("Alive IPs reported", zap.Int("users", len(alive)))
			}
		case <-resourceTicker.C:
			monitor.Log(
				logger,
				db.Stats(),
				dbHealth.Snapshot(),
				trafficReporter.Metrics(time.Now()),
				state.PendingMetrics(),
				state.OnlineUserCount(onlineCountWindow(config)),
			)
		case <-cleanupC:
			if trafficReporter.PendingBatches() > 0 {
				logger.Warn("Skipped traffic marker cleanup while outbox has pending batches",
					zap.Int("pendingBatches", trafficReporter.PendingBatches()),
				)
			} else {
				startedAt := time.Now()
				deleted, err := db.CleanupTrafficBatches(node.ID, config.TrafficBatchRetentionDays)
				dbHealth.Record("cleanupTrafficBatches", startedAt, err)
				if err != nil {
					logger.Warn("Failed to clean traffic batch markers", zap.Error(err))
				} else {
					logger.Info("Traffic batch markers cleaned", zap.Int64("deleted", deleted))
				}
			}
		}
	}

	failures.Close()
	cancel()
	if !managerStopped {
		managerOK = <-runResult
	}
	if err := reportFinalTraffic(db, node, state, trafficReporter, dbHealth, logger); err != nil {
		return err
	}
	if stopErr != nil {
		return stopErr
	}
	if !managerOK {
		return errors.New("upstream service manager stopped with an error")
	}
	return nil
}

func reportTraffic(db trafficDatabase, node Node, state *State, reporter *trafficReporter, health *databaseHealth) (flushed bool, err error) {
	// Drain durable backlog before taking traffic out of memory. This allows a
	// recovered database to shrink/remove a large outbox before the next append.
	if len(reporter.pending) > 0 {
		startedAt := time.Now()
		flushErr := reporter.Flush(db, node)
		health.Record("reportTraffic", startedAt, flushErr)
		if flushErr != nil {
			return false, flushErr
		}
		flushed = true
	}

	traffic := state.SnapshotTraffic()
	if err := reporter.Capture(traffic); err != nil {
		state.MergeTraffic(traffic)
		return flushed, fmt.Errorf("%w: %v", errTrafficOutboxPersistence, err)
	}
	if len(reporter.pending) == 0 {
		return flushed, nil
	}
	startedAt := time.Now()
	flushErr := reporter.Flush(db, node)
	health.Record("reportTraffic", startedAt, flushErr)
	if flushErr == nil {
		flushed = true
	}
	return flushed, flushErr
}

func reportFinalTraffic(db trafficDatabase, node Node, state *State, reporter *trafficReporter, health *databaseHealth, logger *zap.Logger) error {
	var flushErr error
	if len(reporter.pending) > 0 {
		startedAt := time.Now()
		flushErr = reporter.Flush(db, node)
		health.Record("reportFinalTraffic", startedAt, flushErr)
	}

	traffic := state.SnapshotTraffic()
	if err := reporter.Capture(traffic); err != nil {
		state.MergeTraffic(traffic)
		return fmt.Errorf("%w while persisting final traffic: %v", errTrafficOutboxPersistence, err)
	}
	if len(reporter.pending) == 0 {
		logger.Info("Final traffic reported", zap.Int("pendingUsers", 0))
		return nil
	}
	if flushErr == nil {
		startedAt := time.Now()
		flushErr = reporter.Flush(db, node)
		health.Record("reportFinalTraffic", startedAt, flushErr)
	}
	if errors.Is(flushErr, errTrafficOutboxPersistence) {
		return fmt.Errorf("final traffic outbox update failed: %w", flushErr)
	}
	if flushErr != nil {
		outbox := reporter.Metrics(time.Now())
		logger.Warn("Final traffic persisted for retry",
			zap.Int("pendingBatches", outbox.Batches),
			zap.Int("pendingUsers", outbox.Users),
			zap.Int64("outboxFileBytes", outbox.FileBytes),
			zap.Duration("oldestAge", outbox.OldestAge),
			zap.Error(flushErr),
		)
		return nil
	}
	logger.Info("Final traffic reported", zap.Int("pendingUsers", reporter.PendingUsers()))
	return nil
}

func newManager(config Config, node Node, runtime *Runtime, logger *zap.Logger) (*service.Manager, *cred.ManagedServer, error) {
	if !config.EnableTCP && !config.EnableUDP {
		return nil, nil, errors.New("TCP and UDP cannot both be disabled")
	}
	paddingPolicy, err := ss2022.NewPaddingPolicyField("NoPadding")
	if err != nil {
		return nil, nil, err
	}
	address := net.JoinHostPort(config.ListenHost, strconv.Itoa(node.ListenPort))
	server := service.ServerConfig{
		Name:          serverName,
		Protocol:      Method,
		MTU:           config.UDPMTU,
		PSK:           node.ServerKey,
		UPSKStorePath: config.CredentialPath,
		PaddingPolicy: paddingPolicy,
	}
	if config.EnableTCP {
		server.TCPListeners = []service.TCPListenerConfig{{
			ListenerConfig: service.ListenerConfig{
				Network: "tcp",
				Address: address,
			},
			FastOpen:                  true,
			FastOpenFallback:          true,
			MaxConcurrentHandshakes:   config.TCPMaxHandshakes,
			MaxConnectionsPerUser:     config.TCPMaxConnectionsPerUser,
			MaxEstablishedConnections: config.TCPMaxEstablishedTotal,
			TrafficFlushInterval:      jsoncfg.Duration(time.Duration(config.TCPTrafficFlushSeconds) * time.Second),
		}}
	}
	if config.EnableUDP {
		server.UDPListeners = []service.UDPListenerConfig{{
			ListenerConfig: service.ListenerConfig{
				Network: "udp",
				Address: address,
			},
			UDPPerfConfig: service.UDPPerfConfig{
				RelayBatchSize:      config.UDPRelayBatchSize,
				ServerRecvBatchSize: config.UDPServerBatchSize,
				SendChannelCapacity: config.UDPSendQueueSize,
			},
			NATTimeout:         jsoncfg.Duration(time.Duration(config.UDPNATTimeoutSeconds) * time.Second),
			MaxSessions:        config.UDPMaxSessions,
			MaxSessionsPerUser: config.UDPMaxSessionsPerUser,
		}}
	}
	server.SetRuntimeHooks(runtime, runtime)

	serviceConfig := service.Config{
		Servers: []service.ServerConfig{server},
		Clients: []service.ClientConfig{{
			Name:                "direct",
			Protocol:            "direct",
			EnableTCP:           config.EnableTCP,
			DialerTFO:           true,
			TCPFastOpenFallback: true,
			EnableUDP:           config.EnableUDP,
			MTU:                 config.UDPMTU,
		}},
		RuntimeAccess: true,
	}
	manager, err := serviceConfig.Manager(logger)
	if err != nil {
		return nil, nil, err
	}
	runtimeServer, ok := manager.RuntimeServer(serverName)
	if !ok || runtimeServer.CredentialManager == nil {
		manager.Close()
		return nil, nil, errors.New("upstream credential manager is unavailable")
	}
	return manager, runtimeServer.CredentialManager, nil
}

func writeCredentialFile(path string, users []User) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	credentials := make(map[string][]byte, len(users))
	for _, user := range users {
		credentials[strconv.Itoa(user.ID)] = user.UserKey
	}
	data, err := json.Marshal(credentials)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0600)
}

func syncCredentials(server *cred.ManagedServer, users []User) error {
	current := make(map[string]cred.UserCredential)
	for _, credential := range server.Credentials() {
		current[credential.Name] = credential
	}
	next := make(map[string]struct{}, len(users))
	for _, user := range users {
		username := strconv.Itoa(user.ID)
		next[username] = struct{}{}
		credential, ok := current[username]
		switch {
		case !ok:
			if err := server.AddCredential(username, user.UserKey); err != nil {
				return err
			}
		case !bytes.Equal(credential.UPSK, user.UserKey):
			if err := server.UpdateCredential(username, user.UserKey); err != nil {
				return err
			}
		}
	}
	for username := range current {
		if _, ok := next[username]; !ok {
			if err := server.DeleteCredential(username); err != nil {
				return err
			}
		}
	}
	return nil
}

func onlineCountWindow(config Config) time.Duration {
	seconds := max(config.NodeReportSeconds, config.AliveIPReportSeconds, config.SyncIntervalSeconds)
	return time.Duration(seconds*2+30) * time.Second
}
