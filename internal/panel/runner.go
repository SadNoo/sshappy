package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	db, err := OpenDatabase(config)
	if err != nil {
		return err
	}
	defer db.Close()

	node, err := db.LoadNode()
	if err != nil {
		return err
	}
	if deleted, err := db.CleanupTrafficBatches(node.ID, config.TrafficBatchRetentionDays); err != nil {
		logger.Warn("Failed to clean traffic batch markers", zap.Error(err))
	} else if deleted > 0 {
		logger.Info("Traffic batch markers cleaned", zap.Int64("deleted", deleted))
	}
	users, err := db.LoadUsers(node)
	if err != nil {
		return err
	}
	if err := writeCredentialFile(config.CredentialPath, users); err != nil {
		return err
	}
	trafficReporter, err := newTrafficReporter(config.TrafficOutboxPath)
	if err != nil {
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
		zap.Int("trafficSQLBatchSize", trafficSQLBatchSize),
	}
	if config.EnableTCP {
		startupFields = append(startupFields,
			zap.Int("tcpMaxConcurrentHandshakes", config.TCPMaxHandshakes),
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
	resourceTicker := time.NewTicker(time.Minute)
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

	for {
		select {
		case <-ctx.Done():
			cancel()
			ok := <-runResult
			if err := reportFinalTraffic(db, node, state, trafficReporter, logger); err != nil {
				return err
			}
			if !ok {
				return errors.New("upstream service manager stopped with an error")
			}
			return nil
		case ok := <-runResult:
			if err := reportFinalTraffic(db, node, state, trafficReporter, logger); err != nil {
				return err
			}
			if !ok {
				return errors.New("upstream service manager stopped with an error")
			}
			return errors.New("upstream service manager stopped unexpectedly")
		case <-syncTicker.C:
			loadedNode, err := db.LoadNode()
			if err != nil {
				logger.Error("Failed to load node", zap.Error(err))
				continue
			}
			if loadedNode.ListenPort != node.ListenPort ||
				!bytes.Equal(loadedNode.ServerKey, node.ServerKey) {
				return errors.New("node port or server key changed; restart is required")
			}
			loadedUsers, err := db.LoadUsers(loadedNode)
			if err != nil {
				logger.Error("Failed to load users", zap.Error(err))
				continue
			}
			if err := syncCredentials(managedServer, loadedUsers); err != nil {
				logger.Error("Failed to synchronize credentials", zap.Error(err))
				continue
			}
			runtime.ReplaceUsers(loadedUsers)
			node = loadedNode
			logger.Info("Runtime users synchronized", zap.Int("users", len(loadedUsers)))
		case <-trafficTicker.C:
			startedAt := time.Now()
			if err := reportTraffic(db, node, state, trafficReporter); err != nil {
				logger.Error("Failed to report traffic", zap.Duration("duration", time.Since(startedAt)), zap.Error(err))
			} else {
				logger.Info("Traffic reported", zap.Duration("duration", time.Since(startedAt)))
			}
		case <-nodeTicker.C:
			online := state.OnlineUserCount(onlineCountWindow(config))
			if err := db.ReportNodeStatus(node, online); err != nil {
				logger.Error("Failed to report node status", zap.Error(err))
			} else {
				logger.Info("Node status reported", zap.Int("online", online))
			}
		case <-aliveTicker.C:
			alive := state.SnapshotAliveIPs()
			if err := db.ReportAliveIPs(node, alive); err != nil {
				state.MergeAliveIPs(alive)
				logger.Error("Failed to report alive IPs", zap.Error(err))
			} else {
				logger.Info("Alive IPs reported", zap.Int("users", len(alive)))
			}
		case <-resourceTicker.C:
			logRuntimeMetrics(logger)
		case <-cleanupC:
			deleted, err := db.CleanupTrafficBatches(node.ID, config.TrafficBatchRetentionDays)
			if err != nil {
				logger.Warn("Failed to clean traffic batch markers", zap.Error(err))
			} else {
				logger.Info("Traffic batch markers cleaned", zap.Int64("deleted", deleted))
			}
		}
	}
}

func reportTraffic(db *Database, node Node, state *State, reporter *trafficReporter) error {
	// Flush a recovered or previously failed batch before assigning new traffic
	// to a batch ID. This prevents newly captured traffic from being merged into
	// a batch that MySQL has already committed.
	if reporter.pending != nil {
		if err := reporter.Flush(db, node); err != nil {
			return err
		}
	}
	traffic := state.SnapshotTraffic()
	if err := reporter.Capture(traffic); err != nil {
		state.MergeTraffic(traffic)
		return err
	}
	return reporter.Flush(db, node)
}

func reportFinalTraffic(db *Database, node Node, state *State, reporter *trafficReporter, logger *zap.Logger) error {
	if err := reportTraffic(db, node, state, reporter); err != nil {
		return fmt.Errorf("failed to report final traffic: %w", err)
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
	address := fmt.Sprintf("%s:%d", config.ListenHost, node.ListenPort)
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
			FastOpen:                true,
			FastOpenFallback:        true,
			MaxConcurrentHandshakes: config.TCPMaxHandshakes,
			TrafficFlushInterval:    jsoncfg.Duration(time.Duration(config.TCPTrafficFlushSeconds) * time.Second),
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

type runtimeMetrics struct {
	memoryHeapBytes      uint64
	memoryHeapInuseBytes uint64
	memorySysBytes       uint64
	heapObjects          uint64
	gcCycles             uint32
	goroutines           int
}

func readRuntimeMetrics() runtimeMetrics {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return runtimeMetrics{
		memoryHeapBytes:      stats.HeapAlloc,
		memoryHeapInuseBytes: stats.HeapInuse,
		memorySysBytes:       stats.Sys,
		heapObjects:          stats.HeapObjects,
		gcCycles:             stats.NumGC,
		goroutines:           runtime.NumGoroutine(),
	}
}

func logRuntimeMetrics(logger *zap.Logger) {
	metrics := readRuntimeMetrics()
	logger.Info("Runtime resource metrics",
		zap.Uint64("memoryHeapBytes", metrics.memoryHeapBytes),
		zap.Uint64("memoryHeapInuseBytes", metrics.memoryHeapInuseBytes),
		zap.Uint64("memorySysBytes", metrics.memorySysBytes),
		zap.Uint64("heapObjects", metrics.heapObjects),
		zap.Uint32("gcCycles", metrics.gcCycles),
		zap.Int("goroutines", metrics.goroutines),
	)
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
