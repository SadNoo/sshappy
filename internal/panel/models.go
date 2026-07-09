package panel

const (
	Method = "2022-blake3-aes-256-gcm"
	KeyLen = 32
)

type Node struct {
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
}

type TrafficDelta struct {
	UserID   int
	Upload   int64
	Download int64
}
