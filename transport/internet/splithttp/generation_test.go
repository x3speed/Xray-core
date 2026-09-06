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

func TestManagedClientGenerationPrimaryRotationsReleaseCache(t *testing.T) {
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
			t.Fatalf("primary-only managed cache grew beyond one entry: %d", cacheSize)
		}

		if err := EndClientGeneration(context.Background(), token); err != nil {
			t.Fatal(err)
		}
		if state.cache != nil || state.clients != nil {
			t.Fatal("retired generation retained cache or clients")
		}
	}
}

func TestManagedCacheAllowsPrimaryAndDownloadOnly(t *testing.T) {
	resetClientGenerationsForTest(t)
	token, err := BeginClientGeneration()
	if err != nil {
		t.Fatal(err)
	}
	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)

	for i := 0; i < maxManagedDialerEntries+1; i++ {
		config := &Config{Host: "example.com"}
		if err := BindClientGeneration(config, token); err != nil {
			t.Fatal(err)
		}
		_, _, err := getHTTPClient(context.Background(), destination, &internet.MemoryStreamConfig{
			ProtocolName:     protocolName,
			ProtocolSettings: config,
		})
		if i < maxManagedDialerEntries && err != nil {
			t.Fatalf("managed cache entry %d was rejected: %v", i+1, err)
		}
		if i == maxManagedDialerEntries && !stderrors.Is(err, ErrClientGenerationCacheFull) {
			t.Fatalf("third managed cache entry returned %v", err)
		}
	}

	clientGenerations.Lock()
	cacheSize := len(clientGenerations.active.cache)
	clientGenerations.Unlock()
	if cacheSize != maxManagedDialerEntries {
		t.Fatalf("managed cache size = %d, want %d", cacheSize, maxManagedDialerEntries)
	}
	if err := EndClientGeneration(context.Background(), token); err != nil {
		t.Fatal(err)
	}
}

func TestManagedDefaultClientPreservesPacketUploadSequencing(t *testing.T) {
	raw := &DefaultDialerClient{}
	managed := &managedDialerClient{inner: raw}
	if !waitsForWroteRequest(raw) {
		t.Fatal("default client lost packet upload sequencing")
	}
	if !waitsForWroteRequest(managed) {
		t.Fatal("managed default client lost packet upload sequencing")
	}
	if waitsForWroteRequest(&closeErrorDialerClient{}) {
		t.Fatal("non-default client unexpectedly enabled packet upload sequencing")
	}
}

func TestManagedXmuxChurnReleasesEvictedClients(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		reuseLimit bool
		markClosed bool
	}{
		{name: "reuse rotation", reuseLimit: true},
		{name: "network error", markClosed: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			resetClientGenerationsForTest(t)
			token, err := BeginClientGeneration()
			if err != nil {
				t.Fatal(err)
			}
			config := &Config{Host: "example.com"}
			if testCase.reuseLimit {
				config.Xmux = &XmuxConfig{CMaxReuseTimes: &RangeConfig{From: 1, To: 1}}
			}
			if err := BindClientGeneration(config, token); err != nil {
				t.Fatal(err)
			}
			settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: config}
			destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
			var first *managedDialerClient

			for i := 0; i < 64; i++ {
				client, _, err := getHTTPClient(context.Background(), destination, settings)
				if err != nil {
					t.Fatal(err)
				}
				managed := client.(*managedDialerClient)
				if first == nil {
					first = managed
				}
				if testCase.markClosed {
					managed.mu.Lock()
					managed.inner.(*DefaultDialerClient).closed.Store(true)
					managed.mu.Unlock()
				}

				clientGenerations.Lock()
				clientCount := len(clientGenerations.active.clients)
				clientGenerations.Unlock()
				if clientCount > 1 {
					t.Fatalf("managed client count grew to %d after %d rotations", clientCount, i+1)
				}
			}

			first.mu.Lock()
			firstReleased := first.inner == nil && first.state == nil
			first.mu.Unlock()
			if !firstReleased {
				t.Fatal("first evicted client retained generation references")
			}
			if err := EndClientGeneration(context.Background(), token); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEvictedManagedClientClosesOnlyAfterOperationDrain(t *testing.T) {
	resetClientGenerationsForTest(t)
	if _, err := BeginClientGeneration(); err != nil {
		t.Fatal(err)
	}
	clientGenerations.Lock()
	state := clientGenerations.active
	inner := &countingDialerClient{}
	client := newManagedDialerClient(state, inner)
	state.clients[client] = struct{}{}
	client.mu.Lock()
	client.operations = 2
	client.mu.Unlock()
	state.retireClientLocked(client)
	_, retainedWhileActive := state.clients[client]
	clientGenerations.Unlock()
	if !retainedWhileActive {
		t.Fatal("active client was released before operation drain")
	}

	client.finishOperation()
	clientGenerations.Lock()
	_, retainedWithBackground := state.clients[client]
	clientGenerations.Unlock()
	if !retainedWithBackground {
		t.Fatal("client was released while a background operation remained")
	}

	client.finishOperation()
	clientGenerations.Lock()
	_, retainedAfterDrain := state.clients[client]
	clientGenerations.Unlock()
	if retainedAfterDrain {
		t.Fatal("drained evicted client remained in generation registry")
	}
	client.mu.Lock()
	released := client.inner == nil && client.state == nil
	client.mu.Unlock()
	if !released || inner.closes.Load() != 1 {
		t.Fatalf("drained eviction release=(%v, closes=%d), want (true, 1)", released, inner.closes.Load())
	}
}

func TestManagedReadCloserDropsReferences(t *testing.T) {
	owner := &managedDialerClient{streams: make(map[*managedReadCloser]struct{})}
	inner := new(countingReadCloser)
	var finished atomic.Int32
	stream := &managedReadCloser{inner: inner, owner: owner, finishOperation: func() { finished.Add(1) }}
	owner.streams[stream] = struct{}{}

	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	stream.mu.Lock()
	released := stream.inner == nil && stream.owner == nil && stream.finishOperation == nil
	stream.mu.Unlock()
	if !released {
		t.Fatal("closed managed stream retained inner, owner, or finish references")
	}
	if inner.closes.Load() != 1 || finished.Load() != 1 {
		t.Fatalf("close lifecycle calls = (%d, %d), want (1, 1)", inner.closes.Load(), finished.Load())
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
	clientGenerations.Lock()
	referenceFree := clientGenerations.retiring == nil && clientGenerations.quarantine != nil
	clientGenerations.Unlock()
	client.mu.Lock()
	clientReleased := client.inner == nil && client.state == nil && client.streams == nil
	client.mu.Unlock()
	if !referenceFree || !clientReleased {
		t.Fatal("cleanup-error quarantine retained generation client references")
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
		clientGenerations.quarantine = nil
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

type countingDialerClient struct {
	closes atomic.Int32
}

func (*countingDialerClient) IsClosed() bool { return false }

func (*countingDialerClient) OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, xnet.Addr, xnet.Addr, error) {
	return nil, nil, nil, nil
}

func (*countingDialerClient) PostPacket(context.Context, string, string, string, buf.MultiBuffer) error {
	return nil
}

func (c *countingDialerClient) Close() error {
	c.closes.Add(1)
	return nil
}

type countingReadCloser struct {
	closes atomic.Int32
}

func (*countingReadCloser) Read([]byte) (int, error) { return 0, io.EOF }

func (c *countingReadCloser) Close() error {
	c.closes.Add(1)
	return nil
}
