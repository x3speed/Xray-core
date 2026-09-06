package splithttp

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"strconv"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// ClientGeneration identifies a process-wide managed SplitHTTP client cache.
// Zero is reserved for the unmodified upstream cache lifecycle.
type ClientGeneration uint64

var (
	ErrClientGenerationActive      = stderrors.New("splithttp: a managed client generation is already active")
	ErrClientGenerationUnavailable = stderrors.New("splithttp: managed client generation is unavailable")
	ErrClientGenerationCleanup     = stderrors.New("splithttp: managed client generation cleanup failed")
)

// The marker is serialized with Config so it survives Xray's TypedMessage
// round-trip. GetRequestHeader always removes it before constructing HTTP
// requests, so it is internal configuration metadata and never a wire header.
const clientGenerationConfigMarker = "\x00xray.internal.splithttp.client-generation"

type clientGenerationState struct {
	token  ClientGeneration
	ctx    context.Context
	cancel context.CancelFunc

	// cache and clients are protected by clientGenerations.Mutex.
	cache   map[dialerConf]*XmuxManager
	clients map[*managedDialerClient]struct{}

	activityMu sync.Mutex
	accepting  bool
	activities sync.WaitGroup
	drained    chan struct{}
	drainOnce  sync.Once
	cleanupErr error
}

var clientGenerations = struct {
	sync.Mutex
	next     ClientGeneration
	active   *clientGenerationState
	retiring *clientGenerationState
}{}

// BeginClientGeneration creates the sole managed SplitHTTP cache generation.
// Tokens are process-lifetime monotonic and are never reused.
func BeginClientGeneration() (ClientGeneration, error) {
	clientGenerations.Lock()
	defer clientGenerations.Unlock()

	if clientGenerations.active != nil || clientGenerations.retiring != nil {
		return 0, ErrClientGenerationActive
	}
	if clientGenerations.next == ^ClientGeneration(0) {
		return 0, fmt.Errorf("%w: token space exhausted", ErrClientGenerationUnavailable)
	}

	clientGenerations.next++
	ctx, cancel := context.WithCancel(context.Background())
	state := &clientGenerationState{
		token:     clientGenerations.next,
		ctx:       ctx,
		cancel:    cancel,
		cache:     make(map[dialerConf]*XmuxManager),
		clients:   make(map[*managedDialerClient]struct{}),
		accepting: true,
		drained:   make(chan struct{}),
	}
	clientGenerations.active = state
	return state.token, nil
}

// BindClientGeneration marks a SplitHTTP transport config for the active
// managed generation. The marker survives protobuf serialization while the
// generation registry retains no Config pointer.
func BindClientGeneration(config *Config, token ClientGeneration) error {
	if config == nil || token == 0 {
		return ErrClientGenerationUnavailable
	}

	clientGenerations.Lock()
	defer clientGenerations.Unlock()
	if clientGenerations.active == nil || clientGenerations.active.token != token {
		return ErrClientGenerationUnavailable
	}

	bound, managed, err := clientGenerationFromConfig(config)
	if err != nil {
		return err
	}
	if managed {
		if bound != token {
			return ErrClientGenerationUnavailable
		}
		return nil
	}
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}
	config.Headers[clientGenerationConfigMarker] = strconv.FormatUint(uint64(token), 10)
	return nil
}

// EndClientGeneration retires a managed generation. Lookups are blocked before
// clients are canceled and closed. A context timeout is returned to the caller;
// the retiring generation continues to block BeginClientGeneration until a
// later EndClientGeneration call observes a complete drain.
func EndClientGeneration(ctx context.Context, token ClientGeneration) error {
	if ctx == nil || token == 0 {
		return ErrClientGenerationUnavailable
	}

	clientGenerations.Lock()
	state := clientGenerations.retiring
	if state == nil {
		state = clientGenerations.active
		if state == nil || state.token != token {
			clientGenerations.Unlock()
			return ErrClientGenerationUnavailable
		}

		clientGenerations.active = nil
		clientGenerations.retiring = state
		state.startRetireLocked()
	} else if state.token != token {
		clientGenerations.Unlock()
		return ErrClientGenerationUnavailable
	}
	clientGenerations.Unlock()

	select {
	case <-state.drained:
	default:
		select {
		case <-state.drained:
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ErrClientGenerationCleanup, ctx.Err())
		}
	}

	clientGenerations.Lock()
	defer clientGenerations.Unlock()
	if clientGenerations.retiring != state {
		return ErrClientGenerationUnavailable
	}
	if state.cleanupErr != nil {
		return fmt.Errorf("%w: %w", ErrClientGenerationCleanup, state.cleanupErr)
	}

	for client := range state.clients {
		client.release()
	}
	state.clients = nil
	clientGenerations.retiring = nil
	return nil
}

func (s *clientGenerationState) startRetireLocked() {
	s.activityMu.Lock()
	s.accepting = false
	s.cancel()
	s.activityMu.Unlock()

	for _, manager := range s.cache {
		manager.retire()
	}
	s.cache = nil

	var cleanupErrors []error
	for client := range s.clients {
		if err := client.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	s.cleanupErr = stderrors.Join(cleanupErrors...)
	s.drainOnce.Do(func() {
		go func() {
			s.activities.Wait()
			close(s.drained)
		}()
	})
}

func (s *clientGenerationState) beginActivity() (func(), error) {
	s.activityMu.Lock()
	defer s.activityMu.Unlock()
	if !s.accepting {
		return nil, ErrClientGenerationUnavailable
	}
	s.activities.Add(1)
	return s.activities.Done, nil
}

func clientGenerationFromConfig(config *Config) (ClientGeneration, bool, error) {
	if config == nil || config.Headers == nil {
		return 0, false, nil
	}
	raw, managed := config.Headers[clientGenerationConfigMarker]
	if !managed {
		return 0, false, nil
	}
	token, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || token == 0 {
		return 0, true, ErrClientGenerationUnavailable
	}
	return ClientGeneration(token), true, nil
}

func beginDialGeneration(config *Config) (*clientGenerationState, func(), error) {
	token, managed, err := clientGenerationFromConfig(config)
	if err != nil || !managed {
		return nil, func() {}, err
	}

	clientGenerations.Lock()
	defer clientGenerations.Unlock()
	state := clientGenerations.active
	if state == nil || state.token != token {
		return nil, nil, ErrClientGenerationUnavailable
	}
	finish, err := state.beginActivity()
	if err != nil {
		return nil, nil, err
	}
	return state, finish, nil
}

type clientGenerationContextKey struct{}

func managedOperationContext(ctx context.Context, state *clientGenerationState) (context.Context, func(), error) {
	finishActivity, err := state.beginActivity()
	if err != nil {
		return nil, nil, err
	}

	opCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(state.ctx, cancel)
	var once sync.Once
	finish := func() {
		once.Do(func() {
			stop()
			cancel()
			finishActivity()
		})
	}
	return context.WithValue(opCtx, clientGenerationContextKey{}, state), finish, nil
}

func detachedClientContext(ctx context.Context) context.Context {
	if ctx.Value(clientGenerationContextKey{}) != nil {
		return ctx
	}
	return context.WithoutCancel(ctx)
}

func beginManagedBackgroundActivity(ctx context.Context) (func(), error) {
	state, _ := ctx.Value(clientGenerationContextKey{}).(*clientGenerationState)
	if state == nil {
		return func() {}, nil
	}
	return state.beginActivity()
}

type managedDialerClient struct {
	mu      sync.Mutex
	state   *clientGenerationState
	inner   DialerClient
	closed  bool
	streams map[*managedReadCloser]struct{}
}

func newManagedDialerClient(state *clientGenerationState, inner DialerClient) *managedDialerClient {
	if client, ok := inner.(*DefaultDialerClient); ok {
		client.enableManagedLifecycle()
	}
	return &managedDialerClient{
		state:   state,
		inner:   inner,
		streams: make(map[*managedReadCloser]struct{}),
	}
}

func (c *managedDialerClient) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed || c.inner == nil || c.inner.IsClosed()
}

func (c *managedDialerClient) OpenStream(ctx context.Context, url, sessionID string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	c.mu.Lock()
	closed := c.closed
	state := c.state
	inner := c.inner
	c.mu.Unlock()
	if closed || state == nil || inner == nil {
		return nil, nil, nil, ErrClientGenerationUnavailable
	}

	opCtx, finish, err := managedOperationContext(ctx, state)
	if err != nil {
		return nil, nil, nil, err
	}
	reader, remoteAddr, localAddr, err := inner.OpenStream(opCtx, url, sessionID, body, uploadOnly)
	if err != nil || reader == nil {
		finish()
		return reader, remoteAddr, localAddr, err
	}

	tracked := &managedReadCloser{inner: reader, owner: c, finish: finish}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = tracked.Close()
		return nil, nil, nil, ErrClientGenerationUnavailable
	}
	c.streams[tracked] = struct{}{}
	c.mu.Unlock()
	return tracked, remoteAddr, localAddr, nil
}

func (c *managedDialerClient) PostPacket(ctx context.Context, url, sessionID, sequence string, payload buf.MultiBuffer) error {
	c.mu.Lock()
	closed := c.closed
	state := c.state
	inner := c.inner
	c.mu.Unlock()
	if closed || state == nil || inner == nil {
		return ErrClientGenerationUnavailable
	}

	opCtx, finish, err := managedOperationContext(ctx, state)
	if err != nil {
		return err
	}
	defer finish()
	return inner.PostPacket(opCtx, url, sessionID, sequence, payload)
}

func (c *managedDialerClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	streams := make([]*managedReadCloser, 0, len(c.streams))
	for stream := range c.streams {
		streams = append(streams, stream)
	}
	inner := c.inner
	c.mu.Unlock()

	var closeErrors []error
	for _, stream := range streams {
		if err := stream.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	if closer, ok := inner.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	return stderrors.Join(closeErrors...)
}

func (c *managedDialerClient) release() {
	c.mu.Lock()
	inner := c.inner
	c.inner = nil
	c.state = nil
	c.streams = nil
	c.mu.Unlock()
	if releaser, ok := inner.(interface{ releaseManagedLifecycle() }); ok {
		releaser.releaseManagedLifecycle()
	}
}

func (c *managedDialerClient) removeStream(stream *managedReadCloser) {
	c.mu.Lock()
	delete(c.streams, stream)
	c.mu.Unlock()
}

type managedReadCloser struct {
	once     sync.Once
	inner    io.ReadCloser
	owner    *managedDialerClient
	finish   func()
	closeErr error
}

func (r *managedReadCloser) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	if err != nil {
		_ = r.Close()
	}
	return n, err
}

func (r *managedReadCloser) Close() error {
	r.once.Do(func() {
		r.closeErr = r.inner.Close()
		r.owner.removeStream(r)
		r.finish()
	})
	return r.closeErr
}
