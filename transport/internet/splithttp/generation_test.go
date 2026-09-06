package splithttp

import (
	"context"
	stderrors "errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

func TestManagedClientGenerationRotationsReleaseCache(t *testing.T) {
	resetClientGenerationsForTest(t)
	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	var previous ClientGeneration

	for i := 0; i < 32; i++ {
		token, err := BeginClientGeneration()
		if err != nil {
			t.Fatal(err)
		}
		if token <= previous {
			t.Fatalf("generation token did not increase: previous=%d current=%d", previous, token)
		}
		previous = token

		config := &Config{Host: "example.com", Headers: map[string]string{"User-Agent": "xray-test"}}
		if err := BindClientGeneration(config, token); err != nil {
			t.Fatal(err)
		}
		if _, ok := config.GetRequestHeader()[clientGenerationConfigMarker]; ok {
			t.Fatal("internal generation marker escaped into HTTP headers")
		}

		encoded, err := proto.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		decoded := new(Config)
		if err := proto.Unmarshal(encoded, decoded); err != nil {
			t.Fatal(err)
		}
		decodedToken, managed, err := clientGenerationFromConfig(decoded)
		if err != nil || !managed || decodedToken != token {
			t.Fatalf("generation marker did not survive protobuf round-trip: token=%d managed=%v err=%v", decodedToken, managed, err)
		}

		streamSettings := &internet.MemoryStreamConfig{
			ProtocolName:     protocolName,
			ProtocolSettings: decoded,
		}
		if _, _, err := getHTTPClient(context.Background(), destination, streamSettings); err != nil {
			t.Fatal(err)
		}

		clientGenerations.Lock()
		state := clientGenerations.active
		cacheSize := len(state.cache)
		clientGenerations.Unlock()
		if cacheSize > 1 {
			t.Fatalf("managed cache grew beyond one entry: %d", cacheSize)
		}

		if err := EndClientGeneration(context.Background(), token); err != nil {
			t.Fatal(err)
		}
		if state.cache != nil || state.clients != nil {
			t.Fatal("retired generation retained cache or clients")
		}
	}
}

func TestZeroTokenConfigUsesLegacyCache(t *testing.T) {
	resetClientGenerationsForTest(t)
	globalDialerAccess.Lock()
	previous := globalDialerMap
	globalDialerMap = nil
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = previous
		globalDialerAccess.Unlock()
	})

	config := &Config{Host: "example.com"}
	if _, managed, err := clientGenerationFromConfig(config); err != nil || managed {
		t.Fatalf("unbound config did not select legacy lifecycle: managed=%v err=%v", managed, err)
	}
	if _, _, err := getHTTPClient(context.Background(), xnet.TCPDestination(xnet.DomainAddress("example.com"), 443), &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: config,
	}); err != nil {
		t.Fatal(err)
	}

	globalDialerAccess.Lock()
	cacheSize := len(globalDialerMap)
	globalDialerAccess.Unlock()
	if cacheSize != 1 {
		t.Fatalf("legacy cache size = %d, want 1", cacheSize)
	}
}

func TestStaleGenerationCannotReachSystemDialer(t *testing.T) {
	resetClientGenerationsForTest(t)
	dialer := new(countingSystemDialer)
	internet.UseAlternativeSystemDialer(dialer)
	t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })

	first, err := BeginClientGeneration()
	if err != nil {
		t.Fatal(err)
	}
	staleConfig := &Config{Host: "example.com", Mode: "stream-one"}
	if err := BindClientGeneration(staleConfig, first); err != nil {
		t.Fatal(err)
	}
	if err := EndClientGeneration(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second, err := BeginClientGeneration()
	if err != nil {
		t.Fatal(err)
	}
	currentConfig := &Config{Host: "example.com"}
	if err := BindClientGeneration(currentConfig, second); err != nil {
		t.Fatal(err)
	}

	_, err = Dial(context.Background(), xnet.TCPDestination(xnet.DomainAddress("example.com"), 443), &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: staleConfig,
	})
	if !stderrors.Is(err, ErrClientGenerationUnavailable) {
		t.Fatalf("stale generation returned %v", err)
	}
	if calls := dialer.calls.Load(); calls != 0 {
		t.Fatalf("stale generation reached DialSystem %d times", calls)
	}

	if err := EndClientGeneration(context.Background(), second); err != nil {
		t.Fatal(err)
	}
}

func TestManagedGenerationCleanupTimeoutIsObservable(t *testing.T) {
	resetClientGenerationsForTest(t)
	token, err := BeginClientGeneration()
	if err != nil {
		t.Fatal(err)
	}

	clientGenerations.Lock()
	state := clientGenerations.active
	finish, err := state.beginActivity()
	clientGenerations.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = EndClientGeneration(ctx, token)
	if !stderrors.Is(err, context.Canceled) || !stderrors.Is(err, ErrClientGenerationCleanup) {
		t.Fatalf("cleanup timeout was not observable: %v", err)
	}
	if _, err := BeginClientGeneration(); !stderrors.Is(err, ErrClientGenerationActive) {
		t.Fatalf("new generation started during incomplete cleanup: %v", err)
	}

	finish()
	if err := EndClientGeneration(context.Background(), token); err != nil {
		t.Fatal(err)
	}
}

func TestManagedGenerationCleanupErrorIsObservable(t *testing.T) {
	resetClientGenerationsForTest(t)
	token, err := BeginClientGeneration()
	if err != nil {
		t.Fatal(err)
	}

	closeErr := stderrors.New("close failed")
	clientGenerations.Lock()
	state := clientGenerations.active
	client := newManagedDialerClient(state, &closeErrorDialerClient{err: closeErr})
	state.clients[client] = struct{}{}
	clientGenerations.Unlock()

	err = EndClientGeneration(context.Background(), token)
	if !stderrors.Is(err, ErrClientGenerationCleanup) || !stderrors.Is(err, closeErr) {
		t.Fatalf("cleanup error was not observable: %v", err)
	}
	if _, err := BeginClientGeneration(); !stderrors.Is(err, ErrClientGenerationActive) {
		t.Fatalf("new generation started after failed cleanup: %v", err)
	}
}

func resetClientGenerationsForTest(t *testing.T) {
	t.Helper()
	reset := func() {
		clientGenerations.Lock()
		defer clientGenerations.Unlock()
		if clientGenerations.active != nil {
			clientGenerations.active.cancel()
		}
		if clientGenerations.retiring != nil {
			clientGenerations.retiring.cancel()
		}
		clientGenerations.next = 0
		clientGenerations.active = nil
		clientGenerations.retiring = nil
	}
	reset()
	t.Cleanup(reset)
}

type countingSystemDialer struct {
	calls atomic.Int32
}

func (d *countingSystemDialer) Dial(context.Context, xnet.Address, xnet.Destination, *internet.SocketConfig) (xnet.Conn, error) {
	d.calls.Add(1)
	return nil, stderrors.New("unexpected dial")
}

func (*countingSystemDialer) DestIpAddress() xnet.IP { return nil }

type closeErrorDialerClient struct {
	err error
}

func (*closeErrorDialerClient) IsClosed() bool { return false }

func (*closeErrorDialerClient) OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, xnet.Addr, xnet.Addr, error) {
	return nil, nil, nil, nil
}

func (*closeErrorDialerClient) PostPacket(context.Context, string, string, string, buf.MultiBuffer) error {
	return nil
}

func (c *closeErrorDialerClient) Close() error { return c.err }
