package sstest

const (
	method            = "2022-blake3-aes-256-gcm"
	keyLen            = 32
	saltLen           = 32
	tagLen            = 16
	identityHeaderLen = 16
	tcpMaxPayloadSize = 0xffff
	udpMaxPacketSize  = 65536
	udpHeaderLen      = 16
	udpClientType     = 0
	udpServerType     = 1
)

type NodeInfo struct {
	ID           int
	Group        int
	Class        int
	SpeedLimit   float64
	TrafficRate  float64
	Sort         int
	Server       string
	ListenPort   int
	ServerKeyB64 string
	ServerKey    []byte
}

type User struct {
	ID             int
	Email          string
	Passwd         string
	ForbiddenIP    string
	ForbiddenPort  string
	DisconnectIP   string
	NodeSpeedLimit float64
	UserKeyB64     string
	UserKey        []byte
	IdentityHash   [16]byte
}

type TargetAddress struct {
	Host string
	Port int
}

type TrafficDelta struct {
	UserID   int
	Upload   int64
	Download int64
}
