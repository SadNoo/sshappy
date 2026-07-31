package panel

import (
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func TestMySQLTLSMode(t *testing.T) {
	tests := []struct {
		name string
		host string
		mode string
		want string
	}{
		{name: "local auto", host: "127.0.0.1", mode: "auto", want: "false"},
		{name: "localhost auto case insensitive", host: "LOCALHOST", mode: "auto", want: "false"},
		{name: "remote auto", host: "db.example", mode: "auto", want: "true"},
		{name: "disabled", host: "db.example", mode: "disabled", want: "false"},
		{name: "preferred", host: "db.example", mode: "preferred", want: "preferred"},
		{name: "required", host: "db.example", mode: "required", want: "true"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := mysqlTLSMode(Config{MySQLHost: test.host, MySQLTLSMode: test.mode})
			if err != nil {
				t.Fatalf("mysqlTLSMode returned error: %v", err)
			}
			if got != test.want {
				t.Fatalf("mysqlTLSMode = %q, want %q", got, test.want)
			}
		})
	}
}

func TestDefaultMySQLTLSModeIsAuto(t *testing.T) {
	t.Setenv("MYSQL_TLS_MODE", "")
	t.Setenv("MYSQL_TLS", "")
	if got := LoadConfig().MySQLTLSMode; got != "auto" {
		t.Fatalf("default MySQL TLS mode = %q, want auto", got)
	}
}

func TestInvalidIntegerEnvironmentIsRejected(t *testing.T) {
	t.Setenv("NODE_ID", "1")
	t.Setenv("SYNC_INTERVAL_SECONDS", "sixty")
	if err := LoadConfig().Validate(); err == nil {
		t.Fatal("invalid integer environment variable was silently accepted")
	}
}

func TestMySQLDriverConfigPreservesCredentialsAndTimeouts(t *testing.T) {
	config := Config{
		MySQLHost:                  "db.example",
		MySQLPort:                  3307,
		MySQLDB:                    "panel_db",
		MySQLUser:                  "panel-user",
		MySQLPassword:              "p@ss:w/ord(1)",
		MySQLConnectTimeoutSeconds: 7,
		MySQLIOTimeoutSeconds:      19,
	}
	parsed, err := mysql.ParseDSN(mysqlDriverConfig(config, "false").FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.User != config.MySQLUser || parsed.Passwd != config.MySQLPassword ||
		parsed.Addr != "db.example:3307" || parsed.DBName != config.MySQLDB {
		t.Fatalf("parsed DSN does not preserve config: %+v", parsed)
	}
	if parsed.Timeout != 7*time.Second || parsed.ReadTimeout != 19*time.Second || parsed.WriteTimeout != 19*time.Second {
		t.Fatalf("unexpected DSN timeouts: %+v", parsed)
	}
}
