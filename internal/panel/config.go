package panel

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	MySQLHost            string
	MySQLPort            int
	MySQLDB              string
	MySQLUser            string
	MySQLPassword        string
	NodeID               int
	ListenHost           string
	SyncIntervalSeconds  int
	TrafficReportSeconds int
	NodeReportSeconds    int
	AliveIPReportSeconds int
	UDPMTU               int
	UDPRelayBatchSize    int
	UDPServerBatchSize   int
	UDPSendQueueSize     int
	CredentialPath       string
}

func LoadConfig() Config {
	return Config{
		MySQLHost:            getenv("MYSQLHOST", getenv("MYSQL_HOST", "127.0.0.1")),
		MySQLPort:            getenvInt("MYSQLPORT", getenvInt("MYSQL_PORT", 3306)),
		MySQLDB:              getenv("MYSQLDBNAME", getenv("MYSQL_DB", "sspanel")),
		MySQLUser:            getenv("MYSQLUSR", getenv("MYSQL_USER", "root")),
		MySQLPassword:        getenv("MYSQLPASSWD", getenv("MYSQL_PASS", "")),
		NodeID:               getenvInt("node_id", getenvInt("NODE_ID", 0)),
		ListenHost:           getenv("LISTEN_HOST", "0.0.0.0"),
		SyncIntervalSeconds:  getenvInt("SYNC_INTERVAL_SECONDS", 60),
		TrafficReportSeconds: getenvInt("TRAFFIC_REPORT_SECONDS", 60),
		NodeReportSeconds:    getenvInt("NODE_REPORT_SECONDS", 60),
		AliveIPReportSeconds: getenvInt("ALIVE_IP_REPORT_SECONDS", 60),
		UDPMTU:               getenvInt("UDP_MTU", 1496),
		UDPRelayBatchSize:    getenvInt("UDP_RELAY_BATCH_SIZE", 256),
		UDPServerBatchSize:   getenvInt("UDP_SERVER_RECV_BATCH_SIZE", 64),
		UDPSendQueueSize:     getenvInt("UDP_SEND_CHANNEL_CAPACITY", 1024),
		CredentialPath:       getenv("UPSK_STORE_PATH", "/var/lib/sshappy/users.json"),
	}
}

func (c Config) Validate() error {
	switch {
	case c.NodeID <= 0:
		return fmt.Errorf("node_id/NODE_ID must be set")
	case c.SyncIntervalSeconds <= 0 ||
		c.TrafficReportSeconds <= 0 ||
		c.NodeReportSeconds <= 0 ||
		c.AliveIPReportSeconds <= 0:
		return fmt.Errorf("report and sync intervals must be positive")
	case c.UDPMTU < 1280 || c.UDPMTU > 65535:
		return fmt.Errorf("UDP_MTU must be between 1280 and 65535")
	case c.UDPRelayBatchSize < 1 || c.UDPRelayBatchSize > 1024:
		return fmt.Errorf("UDP_RELAY_BATCH_SIZE must be between 1 and 1024")
	case c.UDPServerBatchSize < 1 || c.UDPServerBatchSize > 1024:
		return fmt.Errorf("UDP_SERVER_RECV_BATCH_SIZE must be between 1 and 1024")
	case c.UDPSendQueueSize < 64:
		return fmt.Errorf("UDP_SEND_CHANNEL_CAPACITY must be at least 64")
	}
	return nil
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
