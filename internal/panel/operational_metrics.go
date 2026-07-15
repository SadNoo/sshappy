package panel

import (
	"database/sql"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

const operationalWarningInterval = 5 * time.Minute

type databaseHealth struct {
	successes           uint64
	failures            uint64
	consecutiveFailures uint64
	lastSuccess         time.Time
	lastFailure         time.Time
	lastOperation       string
	lastDuration        time.Duration
	operations          map[string]*databaseOperationHealth
}

type databaseOperationHealth struct {
	successes           uint64
	failures            uint64
	consecutiveFailures uint64
	lastSuccess         time.Time
	lastFailure         time.Time
	lastDuration        time.Duration
}

type databaseHealthSnapshot struct {
	Successes           uint64
	Failures            uint64
	ConsecutiveFailures uint64
	LastSuccess         time.Time
	LastFailure         time.Time
	LastOperation       string
	LastDuration        time.Duration
	Operations          map[string]databaseOperationHealth
}

func (h *databaseHealth) Record(operation string, startedAt time.Time, err error) {
	now := time.Now()
	if h.operations == nil {
		h.operations = make(map[string]*databaseOperationHealth)
	}
	operationHealth := h.operations[operation]
	if operationHealth == nil {
		operationHealth = &databaseOperationHealth{}
		h.operations[operation] = operationHealth
	}
	h.lastOperation = operation
	h.lastDuration = now.Sub(startedAt)
	operationHealth.lastDuration = h.lastDuration
	if err != nil {
		h.failures++
		h.consecutiveFailures++
		h.lastFailure = now
		operationHealth.failures++
		operationHealth.consecutiveFailures++
		operationHealth.lastFailure = now
		return
	}
	h.successes++
	h.consecutiveFailures = 0
	h.lastSuccess = now
	operationHealth.successes++
	operationHealth.consecutiveFailures = 0
	operationHealth.lastSuccess = now
}

func (h *databaseHealth) Snapshot() databaseHealthSnapshot {
	operations := make(map[string]databaseOperationHealth, len(h.operations))
	for name, health := range h.operations {
		operations[name] = *health
	}
	return databaseHealthSnapshot{
		Successes:           h.successes,
		Failures:            h.failures,
		ConsecutiveFailures: h.consecutiveFailures,
		LastSuccess:         h.lastSuccess,
		LastFailure:         h.lastFailure,
		LastOperation:       h.lastOperation,
		LastDuration:        h.lastDuration,
		Operations:          operations,
	}
}

type operationalMonitor struct {
	lastDatabaseWarnings map[string]time.Time
	lastOutboxWarning    time.Time
	lastDiskWarning      time.Time
	lastOutboxSample     time.Time
	lastOutboxFileBytes  int64
	outboxMinFreeBytes   int64
}

func (m *operationalMonitor) Log(
	logger *zap.Logger,
	dbStats sql.DBStats,
	health databaseHealthSnapshot,
	outbox trafficOutboxMetrics,
	state pendingStateMetrics,
	onlineUsers int,
) {
	now := time.Now()
	runtimeMetrics := readRuntimeMetrics()
	var outboxGrowthBytes int64
	var outboxGrowthBytesPerSecond float64
	if !m.lastOutboxSample.IsZero() {
		outboxGrowthBytes = outbox.FileBytes - m.lastOutboxFileBytes
		seconds := now.Sub(m.lastOutboxSample).Seconds()
		if seconds > 0 {
			outboxGrowthBytesPerSecond = float64(outboxGrowthBytes) / seconds
		}
	}
	m.lastOutboxSample = now
	m.lastOutboxFileBytes = outbox.FileBytes
	fields := []zap.Field{
		zap.Uint64("memoryHeapBytes", runtimeMetrics.memoryHeapBytes),
		zap.Uint64("memoryHeapInuseBytes", runtimeMetrics.memoryHeapInuseBytes),
		zap.Uint64("memorySysBytes", runtimeMetrics.memorySysBytes),
		zap.Int64("processRSSBytes", runtimeMetrics.processRSSBytes),
		zap.Int("openFileDescriptors", runtimeMetrics.openFileDescriptors),
		zap.Uint64("heapObjects", runtimeMetrics.heapObjects),
		zap.Uint32("gcCycles", runtimeMetrics.gcCycles),
		zap.Int("goroutines", runtimeMetrics.goroutines),
		zap.Int("onlineUsers", onlineUsers),
		zap.Int("pendingTrafficUsers", state.TrafficUsers),
		zap.Int64("pendingTrafficUploadBytes", state.TrafficUploadBytes),
		zap.Int64("pendingTrafficDownloadBytes", state.TrafficDownloadBytes),
		zap.Int("pendingAliveIPUsers", state.AliveUsers),
		zap.Int("pendingAliveIPRecords", state.AliveRecords),
		zap.Int("outboxBatches", outbox.Batches),
		zap.Int("outboxUsers", outbox.Users),
		zap.Int("outboxRecords", outbox.Records),
		zap.Int64("outboxUploadBytes", outbox.UploadBytes),
		zap.Int64("outboxDownloadBytes", outbox.DownloadBytes),
		zap.Int64("outboxFileBytes", outbox.FileBytes),
		zap.Duration("outboxOldestAge", outbox.OldestAge),
		zap.Int64("outboxGrowthBytes", outboxGrowthBytes),
		zap.Float64("outboxGrowthBytesPerSecond", outboxGrowthBytesPerSecond),
		zap.Bool("outboxDiskAvailable", outbox.DiskAvailable),
		zap.Uint64("outboxDiskFreeBytes", outbox.DiskFreeBytes),
		zap.Uint64("outboxDiskTotalBytes", outbox.DiskTotalBytes),
		zap.Int64("outboxMinFreeBytes", m.outboxMinFreeBytes),
		zap.Uint64("databaseSuccesses", health.Successes),
		zap.Uint64("databaseFailures", health.Failures),
		zap.Uint64("databaseConsecutiveFailures", health.ConsecutiveFailures),
		zap.String("databaseLastOperation", health.LastOperation),
		zap.Duration("databaseLastDuration", health.LastDuration),
		zap.Duration("databaseLastSuccessAge", ageSince(now, health.LastSuccess)),
		zap.Duration("databaseLastFailureAge", ageSince(now, health.LastFailure)),
		zap.Int("databaseOpenConnections", dbStats.OpenConnections),
		zap.Int("databaseInUseConnections", dbStats.InUse),
		zap.Int("databaseIdleConnections", dbStats.Idle),
		zap.Int64("databaseWaitCount", dbStats.WaitCount),
		zap.Duration("databaseWaitDuration", dbStats.WaitDuration),
		zap.Int64("databaseMaxIdleClosed", dbStats.MaxIdleClosed),
		zap.Int64("databaseMaxLifetimeClosed", dbStats.MaxLifetimeClosed),
		databaseOperationsField(now, health.Operations),
	}
	logger.Info("Operational metrics", fields...)

	if m.lastDatabaseWarnings == nil {
		m.lastDatabaseWarnings = make(map[string]time.Time)
	}
	operationNames := sortedDatabaseOperationNames(health.Operations)
	for _, operation := range operationNames {
		operationHealth := health.Operations[operation]
		if operationHealth.consecutiveFailures < 3 || now.Sub(m.lastDatabaseWarnings[operation]) < operationalWarningInterval {
			continue
		}
		logger.Warn("Database operation is repeatedly failing",
			zap.String("operation", operation),
			zap.Uint64("consecutiveFailures", operationHealth.consecutiveFailures),
			zap.Uint64("failuresTotal", operationHealth.failures),
			zap.Duration("lastSuccessAge", ageSince(now, operationHealth.lastSuccess)),
		)
		m.lastDatabaseWarnings[operation] = now
	}
	if (outbox.Batches >= 5 || outbox.OldestAge >= 5*time.Minute) && now.Sub(m.lastOutboxWarning) >= operationalWarningInterval {
		logger.Warn("Traffic outbox is accumulating",
			zap.Int("batches", outbox.Batches),
			zap.Int("users", outbox.Users),
			zap.Int64("fileBytes", outbox.FileBytes),
			zap.Duration("oldestAge", outbox.OldestAge),
		)
		m.lastOutboxWarning = now
	}
	if outbox.DiskAvailable && m.outboxMinFreeBytes > 0 && outbox.DiskFreeBytes < uint64(m.outboxMinFreeBytes) && now.Sub(m.lastDiskWarning) >= operationalWarningInterval {
		logger.Warn("Traffic outbox disk space is low",
			zap.Uint64("freeBytes", outbox.DiskFreeBytes),
			zap.Uint64("totalBytes", outbox.DiskTotalBytes),
			zap.Int64("minimumFreeBytes", m.outboxMinFreeBytes),
			zap.Int64("outboxFileBytes", outbox.FileBytes),
			zap.Int64("outboxGrowthBytes", outboxGrowthBytes),
		)
		m.lastDiskWarning = now
	}
}

func databaseOperationsField(now time.Time, operations map[string]databaseOperationHealth) zap.Field {
	fields := make([]zap.Field, 0, len(operations))
	for _, name := range sortedDatabaseOperationNames(operations) {
		health := operations[name]
		fields = append(fields, zap.Dict(name,
			zap.Uint64("successes", health.successes),
			zap.Uint64("failures", health.failures),
			zap.Uint64("consecutiveFailures", health.consecutiveFailures),
			zap.Duration("lastSuccessAge", ageSince(now, health.lastSuccess)),
			zap.Duration("lastFailureAge", ageSince(now, health.lastFailure)),
			zap.Duration("lastDuration", health.lastDuration),
		))
	}
	return zap.Dict("databaseOperations", fields...)
}

func sortedDatabaseOperationNames(operations map[string]databaseOperationHealth) []string {
	names := make([]string, 0, len(operations))
	for name := range operations {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func ageSince(now, value time.Time) time.Duration {
	if value.IsZero() || value.After(now) {
		return 0
	}
	return now.Sub(value)
}

type runtimeMetrics struct {
	memoryHeapBytes      uint64
	memoryHeapInuseBytes uint64
	memorySysBytes       uint64
	processRSSBytes      int64
	openFileDescriptors  int
	heapObjects          uint64
	gcCycles             uint32
	goroutines           int
}

func readRuntimeMetrics() runtimeMetrics {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	rssBytes, openFDs := readProcessMetrics()
	return runtimeMetrics{
		memoryHeapBytes:      stats.HeapAlloc,
		memoryHeapInuseBytes: stats.HeapInuse,
		memorySysBytes:       stats.Sys,
		processRSSBytes:      rssBytes,
		openFileDescriptors:  openFDs,
		heapObjects:          stats.HeapObjects,
		gcCycles:             stats.NumGC,
		goroutines:           runtime.NumGoroutine(),
	}
}

func readProcessMetrics() (rssBytes int64, openFDs int) {
	rssBytes = -1
	openFDs = -1
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "VmRSS:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kibibytes, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					rssBytes = kibibytes * 1024
				}
			}
			break
		}
	}
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		openFDs = len(entries)
	}
	return rssBytes, openFDs
}
