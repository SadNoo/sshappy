package sstest

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	ssconn "github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/ss2022"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

type tcpRuntime struct {
	mu            sync.RWMutex
	protocol      *ss2022.TCPServer
	serverKeyHash [sha256.Size]byte
	users         map[string]*User
	metrics       tcpRuntimeMetrics
}

type tcpRuntimeMetrics struct {
	accepted      atomic.Uint64
	active        atomic.Int64
	dialCount     atomic.Uint64
	dialErrors    atomic.Uint64
	dialNanos     atomic.Uint64
	relayErrors   atomic.Uint64
	uploadBytes   atomic.Uint64
	downloadBytes atomic.Uint64
}

func newTCPRuntime() *tcpRuntime {
	return &tcpRuntime{users: make(map[string]*User)}
}

func (r *tcpRuntime) configure(node NodeInfo, users []User) error {
	userLookup := make(ss2022.UserLookupMap, len(users))
	usersByName := make(map[string]*User, len(users))
	for i := range users {
		name := fmt.Sprint(users[i].ID)
		cipherConfig, err := ss2022.NewServerUserCipherConfig(name, users[i].UserKey, false)
		if err != nil {
			return err
		}
		userLookup[ss2022.PSKHash(users[i].UserKey)] = cipherConfig
		usersByName[name] = &users[i]
	}

	keyHash := sha256.Sum256(node.ServerKey)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.protocol == nil || r.serverKeyHash != keyHash {
		identityConfig, err := ss2022.NewServerIdentityCipherConfig(node.ServerKey, false)
		if err != nil {
			return err
		}
		r.protocol = ss2022.NewTCPServer(
			true,
			ss2022.UserCipherConfig{},
			identityConfig,
			nil,
			nil,
		)
		r.serverKeyHash = keyHash
	}
	r.protocol.ReplaceUserLookupMap(userLookup)
	r.users = usersByName
	return nil
}

func (r *tcpRuntime) accept(raw zerocopy.DirectReadWriteCloser) (
	zerocopy.ReadWriter,
	ssconn.Addr,
	[]byte,
	*User,
	error,
) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	protocol := r.protocol
	users := r.users
	if protocol == nil {
		return nil, ssconn.Addr{}, nil, nil, fmt.Errorf("TCP protocol is not configured")
	}
	rw, target, payload, username, err := protocol.Accept(raw)
	if err != nil {
		return nil, ssconn.Addr{}, nil, nil, err
	}
	user := users[username]
	if user == nil {
		return nil, ssconn.Addr{}, nil, nil, fmt.Errorf("unknown TCP user")
	}
	return rw, target, payload, user, nil
}

type trafficWriter struct {
	writer    zerocopy.Writer
	state     *RuntimeState
	userID    int
	upload    bool
	threshold int64
	pending   int64
	counter   *atomic.Uint64
}

func (w *trafficWriter) WriterInfo() zerocopy.WriterInfo {
	return w.writer.WriterInfo()
}

func (w *trafficWriter) WriteZeroCopy(buf []byte, payloadStart, payloadLen int) (int, error) {
	n, err := w.writer.WriteZeroCopy(buf, payloadStart, payloadLen)
	w.pending += int64(n)
	if w.counter != nil {
		w.counter.Add(uint64(n))
	}
	if w.pending >= w.threshold {
		w.flush()
	}
	return n, err
}

func (w *trafficWriter) flush() {
	if w.pending == 0 {
		return
	}
	if w.upload {
		w.state.AddTraffic(w.userID, w.pending, 0)
	} else {
		w.state.AddTraffic(w.userID, 0, w.pending)
	}
	w.pending = 0
}

func (r *tcpRuntime) reportMetrics(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dialCount := r.metrics.dialCount.Load()
			var averageDialMillis uint64
			if dialCount > 0 {
				averageDialMillis = r.metrics.dialNanos.Load() / dialCount / uint64(time.Millisecond)
			}
			log.Printf(
				"tcp metrics: accepted=%d active=%d dial_errors=%d relay_errors=%d upload_bytes=%d download_bytes=%d average_dial_ms=%d",
				r.metrics.accepted.Load(),
				r.metrics.active.Load(),
				r.metrics.dialErrors.Load(),
				r.metrics.relayErrors.Load(),
				r.metrics.uploadBytes.Load(),
				r.metrics.downloadBytes.Load(),
				averageDialMillis,
			)
		}
	}
}
