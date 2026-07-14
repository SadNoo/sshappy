package panel

import (
	"database/sql"
	"os"
	"runtime"
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
}

type databaseHealthSnapshot struct {
	Successes           uint64
	Failures            uint64
	ConsecutiveFailures uint64
	LastSuccess         time.Time
	LastFailure         time.Time
	LastOperation       string
	LastDuration        time.Duration
}

func (h *databaseHealth) Record(operation string, startedAt time.Time, err error) {
	now := time.Now()
	h.lastOperation = operation
	h.lastDuration = now.Sub(startedAt)
	if err != nil {
		h.failures++
		h.consecutiveFailures++
		h.lastFailure = now
		return
	}
	h.successes++
	h.consecutiveFailures = 0
	h.lastSuccess = now
}

func (h *databaseHealth) Snapshot() databaseHealthSnapshot {
	return databaseHealthSnapshot{
		Successes:           h.successes,
		Failures:            h.failures,
		ConsecutiveFailures: h.consecutiveFailures,
		LastSuccess:         h.lastSuccess,
		LastFailure:         h.lastFailure,
		LastOperation:       h.lastOperation,
		LastDuration:        h.lastDuration,
	}
}

type operationalMonitor struct {
	lastDatabaseWarning time.Time
	lastOutboxWarning   time.Time
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
	}
	logger.Info("Operational metrics", fields...)

	if health.ConsecutiveFailures >= 3 && now.Sub(m.lastDatabaseWarning) >= operationalWarningInterval {
		logger.Warn("Database operations are repeatedly failing",
			zap.Uint64("consecutiveFailures", health.ConsecutiveFailures),
			zap.Uint64("failuresTotal", health.Failures),
			zap.String("lastOperation", health.LastOperation),
			zap.Duration("lastSuccessAge", ageSince(now, health.LastSuccess)),
		)
		m.lastDatabaseWarning = now
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
