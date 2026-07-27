package flyskynode

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ControlPlaneURL          string
	AllowInsecureHTTP        bool
	EnrollmentTokenPath      string
	MachineCredentialPath    string
	SnapshotPath             string
	SyncStatePath            string
	ReportOutboxPath         string
	CredentialPath           string
	ListenHost               string
	EnableTCP                bool
	EnableUDP                bool
	ChangePollInterval       time.Duration
	HeartbeatInterval        time.Duration
	UsageReportInterval      time.Duration
	AliveIPReportInterval    time.Duration
	SnapshotRefreshBefore    time.Duration
	CredentialRotateBefore   time.Duration
	UDPMTU                   int
	UDPOuterFragmentation    bool
	UDPRelayBatchSize        int
	UDPServerBatchSize       int
	UDPSendQueueSize         int
	UDPNATTimeout            time.Duration
	UDPMaxSessions           int
	UDPMaxSessionsPerUser    int
	TCPMaxHandshakes         int
	TCPMaxConnectionsPerUser int
	TCPMaxEstablishedTotal   int
	TCPTrafficFlushInterval  time.Duration
	loadError                error
}

func LoadConfig() Config {
	enableTCP, tcpErr := envBool("ENABLE_TCP", true)
	enableUDP, udpErr := envBool("ENABLE_UDP", true)
	udpOuterFragmentation, udpOuterFragmentationErr := envBool("UDP_OUTER_FRAGMENTATION", true)
	allowHTTP, httpErr := envBool("FLYSKY_ALLOW_INSECURE_HTTP", false)
	return Config{
		ControlPlaneURL:          strings.TrimSpace(os.Getenv("FLYSKY_CONTROL_PLANE_URL")),
		AllowInsecureHTTP:        allowHTTP,
		EnrollmentTokenPath:      env("FLYSKY_ENROLLMENT_TOKEN_PATH", "/run/secrets/flysky-enrollment-token"),
		MachineCredentialPath:    env("FLYSKY_MACHINE_CREDENTIAL_PATH", "/var/lib/sshappy/flysky-machine.json"),
		SnapshotPath:             env("FLYSKY_SNAPSHOT_PATH", "/var/lib/sshappy/flysky-snapshot.json"),
		SyncStatePath:            env("FLYSKY_SYNC_STATE_PATH", "/var/lib/sshappy/flysky-sync.json"),
		ReportOutboxPath:         env("FLYSKY_REPORT_OUTBOX_PATH", "/var/lib/sshappy/flysky-reports.json"),
		CredentialPath:           env("UPSK_STORE_PATH", "/var/lib/sshappy/users.json"),
		ListenHost:               env("LISTEN_HOST", "0.0.0.0"),
		EnableTCP:                enableTCP,
		EnableUDP:                enableUDP,
		ChangePollInterval:       envDurationSeconds("FLYSKY_CHANGE_POLL_SECONDS", 15),
		HeartbeatInterval:        envDurationSeconds("FLYSKY_HEARTBEAT_SECONDS", 30),
		UsageReportInterval:      envDurationSeconds("FLYSKY_USAGE_REPORT_SECONDS", 30),
		AliveIPReportInterval:    envDurationSeconds("FLYSKY_ALIVE_IP_REPORT_SECONDS", 60),
		SnapshotRefreshBefore:    envDurationSeconds("FLYSKY_SNAPSHOT_REFRESH_BEFORE_SECONDS", 600),
		CredentialRotateBefore:   envDurationSeconds("FLYSKY_CREDENTIAL_ROTATE_BEFORE_SECONDS", 7200),
		UDPMTU:                   envInt("UDP_MTU", 1496),
		UDPOuterFragmentation:    udpOuterFragmentation,
		UDPRelayBatchSize:        envInt("UDP_RELAY_BATCH_SIZE", 8),
		UDPServerBatchSize:       envInt("UDP_SERVER_RECV_BATCH_SIZE", 64),
		UDPSendQueueSize:         envInt("UDP_SEND_CHANNEL_CAPACITY", 1024),
		UDPNATTimeout:            envDurationSeconds("UDP_NAT_TIMEOUT_SECONDS", 60),
		UDPMaxSessions:           envInt("UDP_MAX_SESSIONS", 2048),
		UDPMaxSessionsPerUser:    envInt("UDP_MAX_SESSIONS_PER_USER", 128),
		TCPMaxHandshakes:         envInt("TCP_MAX_CONCURRENT_HANDSHAKES", 1024),
		TCPMaxConnectionsPerUser: envInt("TCP_MAX_CONNECTIONS_PER_USER", 800),
		TCPMaxEstablishedTotal:   envInt("TCP_MAX_ESTABLISHED_TOTAL", 0),
		TCPTrafficFlushInterval:  envDurationSeconds("TCP_TRAFFIC_FLUSH_SECONDS", 30),
		loadError:                errors.Join(tcpErr, udpErr, udpOuterFragmentationErr, httpErr),
	}
}

func (config Config) Validate() error {
	if config.loadError != nil {
		return config.loadError
	}
	switch {
	case config.ControlPlaneURL == "":
		return errors.New("FLYSKY_CONTROL_PLANE_URL must be set")
	case !config.EnableTCP && !config.EnableUDP:
		return errors.New("ENABLE_TCP and ENABLE_UDP cannot both be false")
	case config.ChangePollInterval < time.Second:
		return errors.New("FLYSKY_CHANGE_POLL_SECONDS must be at least 1")
	case config.HeartbeatInterval < 10*time.Second || config.HeartbeatInterval > 5*time.Minute:
		return errors.New("FLYSKY_HEARTBEAT_SECONDS must be between 10 and 300")
	case config.UsageReportInterval < time.Second || config.UsageReportInterval > 10*time.Minute:
		return errors.New("FLYSKY_USAGE_REPORT_SECONDS must be between 1 and 600")
	case config.AliveIPReportInterval < 10*time.Second || config.AliveIPReportInterval > time.Hour:
		return errors.New("FLYSKY_ALIVE_IP_REPORT_SECONDS must be between 10 and 3600")
	case config.SnapshotRefreshBefore < time.Minute:
		return errors.New("FLYSKY_SNAPSHOT_REFRESH_BEFORE_SECONDS must be at least 60")
	case config.CredentialRotateBefore < time.Minute:
		return errors.New("FLYSKY_CREDENTIAL_ROTATE_BEFORE_SECONDS must be at least 60")
	case config.EnableUDP && (config.UDPMTU < 1280 || config.UDPMTU > 65535):
		return errors.New("UDP_MTU must be between 1280 and 65535")
	case config.EnableUDP && (config.UDPRelayBatchSize < 1 || config.UDPRelayBatchSize > 1024):
		return errors.New("UDP_RELAY_BATCH_SIZE must be between 1 and 1024")
	case config.EnableUDP && (config.UDPServerBatchSize < 1 || config.UDPServerBatchSize > 1024):
		return errors.New("UDP_SERVER_RECV_BATCH_SIZE must be between 1 and 1024")
	case config.EnableUDP && config.UDPSendQueueSize < 64:
		return errors.New("UDP_SEND_CHANNEL_CAPACITY must be at least 64")
	case config.EnableUDP && config.UDPNATTimeout < time.Minute:
		return errors.New("UDP_NAT_TIMEOUT_SECONDS must be at least 60 for Shadowsocks 2022")
	case config.EnableUDP && config.UDPMaxSessions < 1:
		return errors.New("UDP_MAX_SESSIONS must be positive")
	case config.EnableUDP && (config.UDPMaxSessionsPerUser < 1 || config.UDPMaxSessionsPerUser > config.UDPMaxSessions):
		return errors.New("UDP_MAX_SESSIONS_PER_USER must be positive and no greater than UDP_MAX_SESSIONS")
	case config.EnableTCP && config.TCPMaxHandshakes < 1:
		return errors.New("TCP_MAX_CONCURRENT_HANDSHAKES must be positive")
	case config.EnableTCP && config.TCPMaxConnectionsPerUser < 0:
		return errors.New("TCP_MAX_CONNECTIONS_PER_USER must not be negative")
	case config.EnableTCP && config.TCPMaxEstablishedTotal < 0:
		return errors.New("TCP_MAX_ESTABLISHED_TOTAL must not be negative")
	case config.EnableTCP && config.TCPTrafficFlushInterval < time.Second:
		return errors.New("TCP_TRAFFIC_FLUSH_SECONDS must be positive")
	}

	paths := []string{
		config.EnrollmentTokenPath, config.MachineCredentialPath, config.SnapshotPath,
		config.SyncStatePath, config.ReportOutboxPath, config.CredentialPath,
	}
	seen := make(map[string]struct{}, len(paths))
	for _, value := range paths {
		if !filepath.IsAbs(value) {
			return fmt.Errorf("Flysky secret and state paths must be absolute: %q", value)
		}
		cleaned := filepath.Clean(value)
		if _, exists := seen[cleaned]; exists {
			return errors.New("Flysky secret and state paths must be distinct")
		}
		seen[cleaned] = struct{}{}
	}
	return nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDurationSeconds(name string, fallback int) time.Duration {
	return time.Duration(envInt(name, fallback)) * time.Second
}

func envBool(name string, fallback bool) (bool, error) {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if value == "" {
		return fallback, nil
	}
	switch value {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return fallback, fmt.Errorf("%s must be a boolean (true or false)", name)
	}
}
