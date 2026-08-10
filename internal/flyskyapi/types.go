package flyskyapi

import (
	"encoding/json"
	"time"
)

const (
	MaxSnapshotUsers         = 50000
	MaxResourceVersionFences = 150000
	MaxIncrementalChanges    = 1000
)

type ProtocolCapability struct {
	Methods             []string `json:"methods"`
	TCP                 bool     `json:"tcp"`
	UDP                 bool     `json:"udp"`
	SinglePortMultiUser bool     `json:"single_port_multi_user"`
}

type CapabilityReport struct {
	Runtime        string                        `json:"runtime"`
	Version        string                        `json:"version"`
	SchemaVersions []int                         `json:"schema_versions"`
	Protocols      map[string]ProtocolCapability `json:"protocols"`
	Features       []string                      `json:"features"`
}

type Capabilities struct {
	APIVersion     string                        `json:"api_version"`
	SchemaVersions []int                         `json:"schema_versions"`
	Features       []string                      `json:"features"`
	Protocols      map[string]ProtocolCapability `json:"protocols"`
	Limits         CapabilitiesLimits            `json:"limits"`
}

type CapabilitiesLimits struct {
	UsageReportMaxBytes int64 `json:"usage_report_max_bytes"`
	UsageReportMaxItems int   `json:"usage_report_max_items"`
}

type EnrollmentRequest struct {
	CapabilityReport
	EnrollmentToken string `json:"enrollment_token"`
}

type MachineCredential struct {
	NodeID      string    `json:"node_id"`
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type HealthReport struct {
	Status            string  `json:"status"`
	ActiveConnections int64   `json:"active_connections"`
	Load1             float64 `json:"load_1"`
	MemoryUsedBytes   int64   `json:"memory_used_bytes"`
}

type StatusRequest struct {
	CapabilityReport
	Health                   HealthReport `json:"health"`
	AppliedServingGeneration string       `json:"applied_serving_generation,omitempty"`
	AppliedCursor            string       `json:"applied_cursor,omitempty"`
	StoppedServingGeneration string       `json:"stopped_serving_generation,omitempty"`
}

type RuntimeState struct {
	State                  string    `json:"state"`
	StateVersion           int64     `json:"state_version"`
	LastSeenAt             time.Time `json:"last_seen_at"`
	NextHeartbeatSeconds   int       `json:"next_heartbeat_seconds"`
	StoppedServingAccepted bool      `json:"stopped_serving_accepted,omitempty"`
}

type Snapshot struct {
	SchemaVersion         int              `json:"schema_version"`
	ServingGeneration     string           `json:"serving_generation"`
	StopServingGeneration string           `json:"stop_serving_generation,omitempty"`
	ConfigVersion         string           `json:"config_version"`
	Cursor                string           `json:"cursor"`
	GeneratedAt           time.Time        `json:"generated_at"`
	ValidUntil            time.Time        `json:"valid_until"`
	Node                  SnapshotNode     `json:"node"`
	Users                 []SnapshotUser   `json:"users"`
	ResourceVersions      map[string]int64 `json:"resource_versions"`
}

type SnapshotNode struct {
	NodeID              string `json:"node_id"`
	Protocol            string `json:"protocol"`
	Method              string `json:"method"`
	ListenPort          int    `json:"listen_port"`
	ServerSecretVersion int64  `json:"server_secret_version"`
	ServerKey           string `json:"server_key"`
}

type SnapshotUser struct {
	UserID              string    `json:"user_id"`
	CredentialVersion   int64     `json:"credential_version"`
	UserKey             string    `json:"user_key"`
	ValidUntil          time.Time `json:"valid_until"`
	Unlimited           bool      `json:"unlimited"`
	QuotaRemainingBytes int64     `json:"quota_remaining_bytes"`
	PolicyVersion       int64     `json:"policy_version"`
}

type Change struct {
	Sequence        int64           `json:"sequence"`
	Operation       string          `json:"operation"`
	ResourceID      string          `json:"resource_id"`
	ResourceVersion int64           `json:"resource_version"`
	Payload         json.RawMessage `json:"payload"`
}

type Changes struct {
	ServingGeneration string   `json:"serving_generation"`
	Changes           []Change `json:"changes"`
	NextCursor        string   `json:"next_cursor"`
}

type UsageItem struct {
	ItemIndex         int    `json:"item_index"`
	UserID            string `json:"user_id"`
	CredentialVersion int64  `json:"credential_version"`
	UploadBytes       int64  `json:"upload_bytes"`
	DownloadBytes     int64  `json:"download_bytes"`
}

type UsageReport struct {
	SchemaVersion int         `json:"schema_version"`
	ReportID      string      `json:"report_id"`
	Sequence      int64       `json:"sequence"`
	NodeID        string      `json:"node_id"`
	ConfigVersion string      `json:"config_version"`
	WindowStart   time.Time   `json:"window_start"`
	WindowEnd     time.Time   `json:"window_end"`
	Items         []UsageItem `json:"items"`
}

type ReportReceipt struct {
	ReceiptID string `json:"receipt_id"`
	ReportID  string `json:"report_id"`
	State     string `json:"state"`
}

type AliveIPReport struct {
	SchemaVersion int       `json:"schema_version"`
	ReportID      string    `json:"report_id"`
	NodeID        string    `json:"node_id"`
	ObservedAt    time.Time `json:"observed_at"`
	WindowSeconds int       `json:"window_seconds"`
	OnlineIPCount int64     `json:"online_ip_count"`
	ActiveUsers   int64     `json:"active_users"`
	Connections   int64     `json:"connections"`
}
