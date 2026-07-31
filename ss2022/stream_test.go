package ss2022

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/netiotest"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

type gatedReader struct {
	r       io.Reader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *gatedReader) Read(b []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return r.r.Read(b)
}

func TestShadowStreamConnConcurrentReadsAndWrites(t *testing.T) {
	psk := make([]byte, 32)
	salt := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	config, err := NewUserCipherConfig(psk, false)
	if err != nil {
		t.Fatal(err)
	}
	writeCipher, err := config.ShadowStreamCipher(salt)
	if err != nil {
		t.Fatal(err)
	}
	readCipher, err := config.ShadowStreamCipher(salt)
	if err != nil {
		t.Fatal(err)
	}
	rawWriter, rawReader := netio.NewPipe()
	defer rawWriter.Close()
	defer rawReader.Close()
	writer := &ShadowStreamConn{Conn: rawWriter, writeBuf: getWriteBuf(), writeCipher: writeCipher}
	reader := &ShadowStreamConn{Conn: rawReader, readCipher: readCipher}

	const count = 32
	results := make(chan string, count)
	errs := make(chan error, count*2)
	var readers, writers sync.WaitGroup
	for range count {
		readers.Go(func() {
			buf := make([]byte, streamReadMinBufferSize)
			n, err := reader.Read(buf)
			if err != nil {
				errs <- err
				return
			}
			results <- string(buf[:n])
		})
	}
	for i := range count {
		writers.Go(func() {
			message := fmt.Sprintf("message-%02d", i)
			if _, err := writer.Write([]byte(message)); err != nil {
				errs <- err
			}
		})
	}
	writers.Wait()
	readers.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	close(results)
	seen := make(map[string]bool, count)
	for result := range results {
		if seen[result] {
			t.Errorf("received duplicate %q", result)
		}
		seen[result] = true
	}
	if len(seen) != count {
		t.Fatalf("received %d messages, want %d", len(seen), count)
	}
}

func TestShadowStreamBulkCopyWrappedReaderDoesNotDeadlock(t *testing.T) {
	rawWriter, rawReader := netio.NewPipe()
	defer rawWriter.Close()
	defer rawReader.Close()

	// A non-nil read cipher takes the client directly into the regular stream
	// read path. The pipe remains empty until the test closes rawWriter.
	source := &ShadowStreamClientConn{ShadowStreamConn: ShadowStreamConn{
		Conn:       rawReader,
		readCipher: new(ShadowStreamCipher),
	}}
	destination := &ShadowStreamServerConn{ShadowStreamConn: ShadowStreamConn{
		writeBuf: getWriteBuf(),
	}}
	wrapper := &gatedReader{
		r:       source,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}

	readFromResult := make(chan error, 1)
	go func() {
		_, err := destination.ReadFrom(wrapper)
		readFromResult <- err
	}()

	select {
	case <-wrapper.entered:
	case <-time.After(time.Second):
		t.Fatal("wrapped Reader was not called")
	}

	writeToResult := make(chan error, 1)
	go func() {
		_, err := source.WriteTo(destination)
		writeToResult <- err
	}()

	// Before releasing the wrapper, only WriteTo can hold source.readMu.
	// Waiting for that lock makes the old writeMu -> external Read / readMu ->
	// writeMu inversion deterministic instead of relying on a scheduler delay.
	deadline := time.Now().Add(time.Second)
	for {
		if !source.ShadowStreamConn.readMu.TryLock() {
			break
		}
		source.ShadowStreamConn.readMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("WriteTo did not acquire the source read lock")
		}
		runtime.Gosched()
	}

	close(wrapper.release)
	if err := rawWriter.Close(); err != nil {
		t.Fatal(err)
	}

	for name, result := range map[string]<-chan error{
		"ReadFrom": readFromResult,
		"WriteTo":  writeToResult,
	} {
		select {
		case err := <-result:
			if err != nil {
				t.Errorf("%s failed: %v", name, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s deadlocked", name)
		}
	}
}

func testStreamClientServer(
	t *testing.T,
	allowSegmentedFixedLengthHeader bool,
	clientCipherConfig *ClientCipherConfig,
	userCipherConfig UserCipherConfig,
	identityCipherConfig ServerIdentityCipherConfig,
	userLookupMap UserLookupMap,
	unsafeRequestStreamPrefix, unsafeResponseStreamPrefix []byte,
	username string,
) {
	addr := conn.AddrFromIPAndPort(netip.IPv6Loopback(), 20220)

	newClient := func(psc *netiotest.PipeStreamClient) netio.StreamClient {
		clientConfig := StreamClientConfig{
			Name:                            "test",
			InnerClient:                     psc,
			Addr:                            addr,
			AllowSegmentedFixedLengthHeader: allowSegmentedFixedLengthHeader,
			CipherConfig:                    clientCipherConfig,
			UnsafeRequestStreamPrefix:       unsafeRequestStreamPrefix,
			UnsafeResponseStreamPrefix:      unsafeResponseStreamPrefix,
		}
		return clientConfig.NewStreamClient()
	}

	serverConfig := StreamServerConfig{
		AllowSegmentedFixedLengthHeader: allowSegmentedFixedLengthHeader,
		UserCipherConfig:                userCipherConfig,
		IdentityCipherConfig:            identityCipherConfig,
		UnsafeRequestStreamPrefix:       unsafeRequestStreamPrefix,
		UnsafeResponseStreamPrefix:      unsafeResponseStreamPrefix,
	}
	server := serverConfig.NewStreamServer()
	server.ReplaceUserLookupMap(userLookupMap)

	netiotest.TestWrapConnStreamClientServerProceed(
		t,
		newClient,
		server,
		addr,
		username,
	)
}

func testStreamClientServerReplay(
	t *testing.T,
	allowSegmentedFixedLengthHeader bool,
	clientCipherConfig *ClientCipherConfig,
	userCipherConfig UserCipherConfig,
	identityCipherConfig ServerIdentityCipherConfig,
	userLookupMap UserLookupMap,
	unsafeRequestStreamPrefix, unsafeResponseStreamPrefix []byte,
) {
	ctx := t.Context()
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	psc, ch := netiotest.NewPipeStreamClient(netio.StreamDialerInfo{
		Name:                 "test",
		NativeInitialPayload: true,
	})

	reqCh := make(chan []byte)

	serverConfig := StreamServerConfig{
		AllowSegmentedFixedLengthHeader: allowSegmentedFixedLengthHeader,
		UserCipherConfig:                userCipherConfig,
		IdentityCipherConfig:            identityCipherConfig,
		UnsafeRequestStreamPrefix:       unsafeRequestStreamPrefix,
		UnsafeResponseStreamPrefix:      unsafeResponseStreamPrefix,
	}
	server := serverConfig.NewStreamServer()
	server.ReplaceUserLookupMap(userLookupMap)

	go func() {
		defer psc.Close()

		// 1. Hijack client request and send it to reqCh.
		select {
		case <-ctx.Done():
			t.Error("DialStream not called")
			return

		case pc := <-ch:
			req, err := io.ReadAll(pc)
			if err != nil {
				t.Errorf("io.ReadAll failed: %v", err)
			}
			_ = pc.Close()
			reqCh <- req
		}

		// 2. Server sees it for the first time.
		select {
		case <-ctx.Done():
			t.Error("DialStream not called")
			return

		case pc := <-ch:
			if _, err := server.HandleStream(pc, logger); err != nil {
				t.Errorf("server.HandleStream failed: %v", err)
			}
			_ = pc.Close()
		}

		// 3. Server sees it again.
		select {
		case <-ctx.Done():
			t.Error("DialStream not called")
			return

		case pc := <-ch:
			if _, err := server.HandleStream(pc, logger); err != ErrRepeatedSalt {
				t.Errorf("server.HandleStream = %v, want %v", err, ErrRepeatedSalt)
			}
			_ = pc.Close()
		}
	}()

	serverAddr := conn.AddrFromIPAndPort(netip.IPv6Unspecified(), 20220)
	clientTargetAddr := conn.AddrFromIPAndPort(netip.IPv6Unspecified(), 53)

	clientConfig := StreamClientConfig{
		Name:                            "test",
		InnerClient:                     psc,
		Addr:                            serverAddr,
		AllowSegmentedFixedLengthHeader: allowSegmentedFixedLengthHeader,
		CipherConfig:                    clientCipherConfig,
		UnsafeRequestStreamPrefix:       unsafeRequestStreamPrefix,
		UnsafeResponseStreamPrefix:      unsafeResponseStreamPrefix,
	}
	client := clientConfig.NewStreamClient()

	// Let the client send the request.
	clientConn, err := client.DialStream(ctx, clientTargetAddr, nil)
	if err != nil {
		t.Fatalf("client.DialStream failed: %v", err)
	}
	if err = clientConn.CloseWrite(); err != nil {
		t.Fatalf("clientConn.CloseWrite failed: %v", err)
	}

	// Receive the hijacked request.
	req := <-reqCh

	// Send it twice.
	for range 2 {
		clientConn, err := psc.DialStream(ctx, clientTargetAddr, req)
		if err == nil {
			_ = clientConn.Close()
		}
	}

	// This also synchronizes the exit of the server goroutine.
	if _, ok := <-ch; ok {
		t.Error("DialStream called more than expected")
	}
}

func TestStreamClientServer(t *testing.T) {
	t.Parallel()
	for _, method := range methodCases {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			for _, udpCase := range [...]struct {
				name      string
				enableUDP bool
			}{
				{"EnableUDP", true},
				{"DisableUDP", false},
			} {
				t.Run(udpCase.name, func(t *testing.T) {
					t.Parallel()
					for _, cipherCase := range cipherCases {
						t.Run(cipherCase.name, func(t *testing.T) {
							t.Parallel()

							clientCipherConfig,
								userCipherConfig,
								identityCipherConfig,
								userLookupMap,
								username,
								err := cipherCase.newCipherConfig(method, udpCase.enableUDP)
							if err != nil {
								t.Fatal(err)
							}

							for _, readOnceOrFullCase := range [...]struct {
								name                            string
								allowSegmentedFixedLengthHeader bool
							}{
								{"ReadOnceExpectFull", false},
								{"ReadFull", true},
							} {
								t.Run(readOnceOrFullCase.name, func(t *testing.T) {
									t.Parallel()
									for _, unsafeStreamPrefixCase := range [...]struct {
										name     string
										generate func() (request, response []byte)
									}{
										{
											name: "NoPrefix",
											generate: func() (request, response []byte) {
												return nil, nil
											},
										},
										{
											name: "ShortPrefix",
											generate: func() (request, response []byte) {
												return []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
													[]byte("HTTP/1.1 200 OK\r\n\r\n")
											},
										},
										{
											name: "GiganticPrefix",
											generate: func() (request, response []byte) {
												b := make([]byte, 1<<21)
												rand.Read(b)
												return b[:1<<20], b[1<<20:]
											},
										},
									} {
										t.Run(unsafeStreamPrefixCase.name, func(t *testing.T) {
											t.Parallel()
											unsafeRequestStreamPrefix, unsafeResponseStreamPrefix := unsafeStreamPrefixCase.generate()
											t.Run("Proceed", func(t *testing.T) {
												t.Parallel()
												testStreamClientServer(
													t,
													readOnceOrFullCase.allowSegmentedFixedLengthHeader,
													clientCipherConfig,
													userCipherConfig,
													identityCipherConfig,
													userLookupMap,
													unsafeRequestStreamPrefix,
													unsafeResponseStreamPrefix,
													username,
												)
											})
											t.Run("Replay", func(t *testing.T) {
												t.Parallel()
												testStreamClientServerReplay(
													t,
													readOnceOrFullCase.allowSegmentedFixedLengthHeader,
													clientCipherConfig,
													userCipherConfig,
													identityCipherConfig,
													userLookupMap,
													unsafeRequestStreamPrefix,
													unsafeResponseStreamPrefix,
												)
											})
										})
									}
								})
							}
						})
					}
				})
			}
		})
	}
}

func BenchmarkStreamClientServer(b *testing.B) {
	for _, method := range methodCases {
		b.Run(method, func(b *testing.B) {
			clientCipherConfig,
				userCipherConfig,
				identityCipherConfig,
				userLookupMap,
				_,
				err := cipherCases[0].newCipherConfig(method, false)
			if err != nil {
				b.Fatal(err)
			}

			addr := conn.AddrFromIPAndPort(netip.IPv6Loopback(), 20220)

			newClient := func(psc *netiotest.PipeStreamClient) netio.StreamClient {
				clientConfig := StreamClientConfig{
					Name:         "test",
					InnerClient:  psc,
					Addr:         addr,
					CipherConfig: clientCipherConfig,
				}
				return clientConfig.NewStreamClient()
			}

			serverConfig := StreamServerConfig{
				UserCipherConfig:     userCipherConfig,
				IdentityCipherConfig: identityCipherConfig,
			}
			server := serverConfig.NewStreamServer()
			server.ReplaceUserLookupMap(userLookupMap)

			netiotest.BenchmarkStreamClientServer(b, newClient, server, streamMaxPayloadSize)
		})
	}
}

func BenchmarkStreamClientDialServerHandleStream(b *testing.B) {
	for _, method := range methodCases {
		b.Run(method, func(b *testing.B) {
			for _, cipherCase := range cipherCases {
				b.Run(cipherCase.name, func(b *testing.B) {
					clientCipherConfig,
						userCipherConfig,
						identityCipherConfig,
						userLookupMap,
						_,
						err := cipherCase.newCipherConfig(method, false)
					if err != nil {
						b.Fatal(err)
					}

					addr := conn.AddrFromIPAndPort(netip.IPv6Loopback(), 20220)

					newClient := func(psc *netiotest.PipeStreamClient) netio.StreamClient {
						clientConfig := StreamClientConfig{
							Name:         "test",
							InnerClient:  psc,
							Addr:         addr,
							CipherConfig: clientCipherConfig,
						}
						return clientConfig.NewStreamClient()
					}

					serverConfig := StreamServerConfig{
						UserCipherConfig:     userCipherConfig,
						IdentityCipherConfig: identityCipherConfig,
					}
					server := serverConfig.NewStreamServer()
					server.ReplaceUserLookupMap(userLookupMap)

					netiotest.BenchmarkStreamClientDialServerHandle(b, newClient, newStreamServerClearSaltPool(server))
				})
			}
		})
	}
}

// streamServerClearSaltPool wraps a [StreamServer] and clears the salt pool after handling a stream connection.
// This is useful in benchmarks where the salt pool significantly affects the results.
type streamServerClearSaltPool struct {
	*StreamServer
}

func newStreamServerClearSaltPool(server *StreamServer) *streamServerClearSaltPool {
	return &streamServerClearSaltPool{
		StreamServer: server,
	}
}

// HandleStream implements [netio.StreamServer.HandleStream].
func (s *streamServerClearSaltPool) HandleStream(rawRW netio.Conn, logger *zap.Logger) (req netio.ConnRequest, err error) {
	req, err = s.StreamServer.HandleStream(rawRW, logger)
	s.saltPool.Clear()
	return req, err
}
