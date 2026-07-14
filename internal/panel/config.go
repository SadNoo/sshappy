package panel

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	MySQLHost                  string
	MySQLPort                  int
	MySQLDB                    string
	MySQLUser                  string
	MySQLPassword              string
	MySQLTLSMode               string
	MySQLTLSCA                 string
	MySQLConnectTimeoutSeconds int
	MySQLIOTimeoutSeconds      int
	NodeID                     int
	ListenHost                 string
	EnableTCP                  bool
	EnableUDP                  bool
	SyncIntervalSeconds        int
	TrafficReportSeconds       int
	NodeReportSeconds          int
	AliveIPReportSeconds       int
	UDPMTU                     int
	UDPRelayBatchSize          int
	UDPServerBatchSize         int
	UDPSendQueueSize           int
	UDPNATTimeoutSeconds       int
	UDPMaxSessions             int
	UDPMaxSessionsPerUser      int
	CredentialPath             string
	TrafficOutboxPath          string
	TCPMaxHandshakes           int
	TCPMaxConnectionsPerUser   int
	TCPTrafficFlushSeconds     int
	TrafficBatchRetentionDays  int
	ResourceReportSeconds      int
	loadError                  error
}

func LoadConfig() Config {
	enableTCP, tcpErr := getenvBool("ENABLE_TCP", true)
	enableUDP, udpErr := getenvBool("ENABLE_UDP", true)
	return Config{
		MySQLHost:                  getenv("MYSQLHOST", getenv("MYSQL_HOST", "127.0.0.1")),
		MySQLPort:                  getenvInt("MYSQLPORT", getenvInt("MYSQL_PORT", 3306)),
		MySQLDB:                    getenv("MYSQLDBNAME", getenv("MYSQL_DB", "sspanel")),
		MySQLUser:                  getenv("MYSQLUSR", getenv("MYSQL_USER", "root")),
		MySQLPassword:              getenv("MYSQLPASSWD", getenv("MYSQL_PASS", "")),
		MySQLTLSMode:               getenv("MYSQL_TLS_MODE", getenv("MYSQL_TLS", "disabled")),
		MySQLTLSCA:                 getenv("MYSQL_TLS_CA", ""),
		MySQLConnectTimeoutSeconds: getenvInt("MYSQL_CONNECT_TIMEOUT_SECONDS", 10),
		MySQLIOTimeoutSeconds:      getenvInt("MYSQL_IO_TIMEOUT_SECONDS", 30),
		NodeID:                     getenvInt("node_id", getenvInt("NODE_ID", 0)),
		ListenHost:                 getenv("LISTEN_HOST", "0.0.0.0"),
		EnableTCP:                  enableTCP,
		EnableUDP:                  enableUDP,
		SyncIntervalSeconds:        getenvInt("SYNC_INTERVAL_SECONDS", 60),
		TrafficReportSeconds:       getenvInt("TRAFFIC_REPORT_SECONDS", 60),
		NodeReportSeconds:          getenvInt("NODE_REPORT_SECONDS", 60),
		AliveIPReportSeconds:       getenvInt("ALIVE_IP_REPORT_SECONDS", 60),
		UDPMTU:                     getenvInt("UDP_MTU", 1496),
		UDPRelayBatchSize:          getenvInt("UDP_RELAY_BATCH_SIZE", 8),
		UDPServerBatchSize:         getenvInt("UDP_SERVER_RECV_BATCH_SIZE", 64),
		UDPSendQueueSize:           getenvInt("UDP_SEND_CHANNEL_CAPACITY", 1024),
		UDPNATTimeoutSeconds:       getenvInt("UDP_NAT_TIMEOUT_SECONDS", 60),
		UDPMaxSessions:             getenvInt("UDP_MAX_SESSIONS", 2048),
		UDPMaxSessionsPerUser:      getenvInt("UDP_MAX_SESSIONS_PER_USER", 128),
		CredentialPath:             getenv("UPSK_STORE_PATH", "/var/lib/sshappy/users.json"),
		TrafficOutboxPath:          getenv("TRAFFIC_OUTBOX_PATH", "/var/lib/sshappy/traffic-outbox.json"),
		TCPMaxHandshakes:           getenvInt("TCP_MAX_CONCURRENT_HANDSHAKES", 1024),
		TCPMaxConnectionsPerUser:   getenvInt("TCP_MAX_CONNECTIONS_PER_USER", 800),
		TCPTrafficFlushSeconds:     getenvInt("TCP_TRAFFIC_FLUSH_SECONDS", 30),
		TrafficBatchRetentionDays:  getenvInt("TRAFFIC_BATCH_RETENTION_DAYS", 30),
		ResourceReportSeconds:      getenvInt("RESOURCE_REPORT_SECONDS", 60),
		loadError:                  errors.Join(tcpErr, udpErr),
	}
}

func (c Config) Validate() error {
	switch {
	case c.loadError != nil:
		return c.loadError
	case c.NodeID <= 0:
		return fmt.Errorf("node_id/NODE_ID must be set")
	case !c.EnableTCP && !c.EnableUDP:
		return fmt.Errorf("ENABLE_TCP and ENABLE_UDP cannot both be false")
	case c.SyncIntervalSeconds <= 0 ||
		c.TrafficReportSeconds <= 0 ||
		c.NodeReportSeconds <= 0 ||
		c.AliveIPReportSeconds <= 0:
		return fmt.Errorf("report and sync intervals must be positive")
	case c.EnableUDP && (c.UDPMTU < 1280 || c.UDPMTU > 65535):
		return fmt.Errorf("UDP_MTU must be between 1280 and 65535")
	case c.EnableUDP && (c.UDPRelayBatchSize < 1 || c.UDPRelayBatchSize > 1024):
		return fmt.Errorf("UDP_RELAY_BATCH_SIZE must be between 1 and 1024")
	case c.EnableUDP && (c.UDPServerBatchSize < 1 || c.UDPServerBatchSize > 1024):
		return fmt.Errorf("UDP_SERVER_RECV_BATCH_SIZE must be between 1 and 1024")
	case c.EnableUDP && c.UDPSendQueueSize < 64:
		return fmt.Errorf("UDP_SEND_CHANNEL_CAPACITY must be at least 64")
	case c.EnableUDP && c.UDPNATTimeoutSeconds < 60:
		return fmt.Errorf("UDP_NAT_TIMEOUT_SECONDS must be at least 60 for Shadowsocks 2022")
	case c.EnableUDP && c.UDPMaxSessions < 1:
		return fmt.Errorf("UDP_MAX_SESSIONS must be positive")
	case c.EnableUDP && (c.UDPMaxSessionsPerUser < 1 || c.UDPMaxSessionsPerUser > c.UDPMaxSessions):
		return fmt.Errorf("UDP_MAX_SESSIONS_PER_USER must be positive and no greater than UDP_MAX_SESSIONS")
	case c.EnableTCP && c.TCPMaxHandshakes < 1:
		return fmt.Errorf("TCP_MAX_CONCURRENT_HANDSHAKES must be positive")
	case c.EnableTCP && c.TCPMaxConnectionsPerUser < 0:
		return fmt.Errorf("TCP_MAX_CONNECTIONS_PER_USER must not be negative")
	case c.EnableTCP && c.TCPTrafficFlushSeconds < 1:
		return fmt.Errorf("TCP_TRAFFIC_FLUSH_SECONDS must be positive")
	case c.TrafficBatchRetentionDays < 0:
		return fmt.Errorf("TRAFFIC_BATCH_RETENTION_DAYS must not be negative")
	case c.ResourceReportSeconds < 10:
		return fmt.Errorf("RESOURCE_REPORT_SECONDS must be at least 10")
	case c.MySQLConnectTimeoutSeconds < 1:
		return fmt.Errorf("MYSQL_CONNECT_TIMEOUT_SECONDS must be positive")
	case c.MySQLIOTimeoutSeconds < 1:
		return fmt.Errorf("MYSQL_IO_TIMEOUT_SECONDS must be positive")
	case !validMySQLTLSMode(c.MySQLTLSMode):
		return fmt.Errorf("MYSQL_TLS_MODE must be one of auto, disabled, preferred, required, or verify")
	case strings.EqualFold(c.MySQLTLSMode, "verify") && c.MySQLTLSCA == "":
		return fmt.Errorf("MYSQL_TLS_CA must be set when MYSQL_TLS_MODE=verify")
	}
	return nil
}

func validMySQLTLSMode(mode string) bool {
	switch strings.ToLower(mode) {
	case "", "auto", "disabled", "preferred", "required", "verify":
		return true
	default:
		return false
	}
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func getenvInt(name string, fallback int) int {
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

func getenvBool(name string, fallback bool) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return fallback, fmt.Errorf("%s must be a boolean (true or false), got %q", name, value)
	}
}
