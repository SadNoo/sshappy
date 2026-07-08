package sstest

import (
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
	TCPConnectTimeout    int
	TCPIdleTimeout       int
	UDPIdleTimeout       int
	TrafficFlushBytes    int64
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
		TCPConnectTimeout:    getenvInt("TCP_CONNECT_TIMEOUT", 10),
		TCPIdleTimeout:       getenvInt("TCP_IDLE_TIMEOUT", 300),
		UDPIdleTimeout:       getenvInt("UDP_IDLE_TIMEOUT", 300),
		TrafficFlushBytes:    int64(getenvInt("TRAFFIC_FLUSH_BYTES", 1<<20)),
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
