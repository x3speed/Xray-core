package inbound

import (
	"context"
	"crypto/rand"
	"io"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// AuthenticatedConnectionObserver accepts one connection identity minted by
// the VLESS inbound after request authentication and before data dispatch.
type AuthenticatedConnectionObserver interface {
	AcceptAuthenticated(context.Context, *AuthenticatedConnection) (AuthenticatedConnectionLease, error)
}

// AuthenticatedConnectionLease binds the accepted identity to its external
// owner. Cancelling Context revokes the exact VLESS connection.
type AuthenticatedConnectionLease interface {
	Context() context.Context
	Close() error
}

type authenticatedConnectionSeal struct{}

var trustedAuthenticatedConnectionSeal = &authenticatedConnectionSeal{}

// AuthenticatedConnection is an opaque, connection-scoped, single-use token.
// Its zero value and values assembled outside this package are invalid.
type AuthenticatedConnection struct {
	state *authenticatedConnectionState
}

// AuthenticatedConnectionIdentity exposes only the immutable authenticated
// tuple. Its private seal prevents callers from manufacturing a valid value.
type AuthenticatedConnectionIdentity struct {
	state *authenticatedConnectionState
	seal  *authenticatedConnectionSeal
}

type authenticatedConnectionState struct {
	seal       *authenticatedConnectionSeal
	email      string
	inboundTag string
	id         [32]byte
	directTCP  bool
	done       chan struct{}
	consumed   atomic.Bool
	terminal   atomic.Bool
	doneOnce   sync.Once
}

// Consume transfers the token exactly once while its Process is live.
func (connection *AuthenticatedConnection) Consume() (AuthenticatedConnectionIdentity, bool) {
	if connection == nil || connection.state == nil || connection.state.seal != trustedAuthenticatedConnectionSeal ||
		connection.state.terminal.Load() || !connection.state.consumed.CompareAndSwap(false, true) {
		return AuthenticatedConnectionIdentity{}, false
	}
	if connection.state.terminal.Load() {
		return AuthenticatedConnectionIdentity{}, false
	}
	return AuthenticatedConnectionIdentity{state: connection.state, seal: trustedAuthenticatedConnectionSeal}, true
}

func (identity AuthenticatedConnectionIdentity) Email() string {
	if state := identity.liveState(); state != nil {
		return state.email
	}
	return ""
}

func (identity AuthenticatedConnectionIdentity) InboundTag() string {
	if state := identity.liveState(); state != nil {
		return state.inboundTag
	}
	return ""
}

func (identity AuthenticatedConnectionIdentity) ConnectionID() [32]byte {
	if state := identity.liveState(); state != nil {
		return state.id
	}
	return [32]byte{}
}

func (identity AuthenticatedConnectionIdentity) DirectTCP() bool {
	state := identity.liveState()
	return state != nil && state.directTCP
}

func (identity AuthenticatedConnectionIdentity) Done() <-chan struct{} {
	if identity.seal == trustedAuthenticatedConnectionSeal && identity.state != nil && identity.state.seal == trustedAuthenticatedConnectionSeal {
		return identity.state.done
	}
	return closedAuthenticatedConnectionDone
}

func (identity AuthenticatedConnectionIdentity) liveState() *authenticatedConnectionState {
	if identity.seal != trustedAuthenticatedConnectionSeal || identity.state == nil ||
		identity.state.seal != trustedAuthenticatedConnectionSeal || !identity.state.consumed.Load() || identity.state.terminal.Load() {
		return nil
	}
	return identity.state
}

var closedAuthenticatedConnectionDone = func() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}()

type authenticatedObserverSlot struct {
	mu       sync.Mutex
	observer AuthenticatedConnectionObserver
	started  bool
	random   io.Reader
}

func (slot *authenticatedObserverSlot) register(observer AuthenticatedConnectionObserver) error {
	if slot == nil || missingAuthenticatedValue(observer) {
		return authenticatedConnectionError()
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.started || !missingAuthenticatedValue(slot.observer) {
		return authenticatedConnectionError()
	}
	slot.observer = observer
	return nil
}

func (slot *authenticatedObserverSlot) begin() AuthenticatedConnectionObserver {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	slot.started = true
	return slot.observer
}

func (slot *authenticatedObserverSlot) mint(email, inboundTag string) (*AuthenticatedConnection, error) {
	slot.mu.Lock()
	random := slot.random
	slot.mu.Unlock()
	if random == nil {
		random = rand.Reader
	}
	state := &authenticatedConnectionState{
		seal: trustedAuthenticatedConnectionSeal, email: email, inboundTag: inboundTag, directTCP: true, done: make(chan struct{}),
	}
	if _, err := io.ReadFull(random, state.id[:]); err != nil || state.id == [32]byte{} {
		state.finish()
		return nil, authenticatedConnectionError()
	}
	return &AuthenticatedConnection{state: state}, nil
}

func (state *authenticatedConnectionState) finish() {
	if state == nil {
		return
	}
	state.terminal.Store(true)
	state.doneOnce.Do(func() { close(state.done) })
}

type authenticatedConnectionLifetime struct {
	state      *authenticatedConnectionState
	lease      AuthenticatedConnectionLease
	leaseDone  <-chan struct{}
	cancel     context.CancelFunc
	stopRevoke func() bool
	once       sync.Once
}

func acceptAuthenticatedConnection(
	ctx context.Context,
	connection stat.Connection,
	observer AuthenticatedConnectionObserver,
	slot *authenticatedObserverSlot,
	email, inboundTag string,
) (*authenticatedConnectionLifetime, context.Context, error) {
	if missingAuthenticatedValue(ctx) || missingAuthenticatedValue(connection) || missingAuthenticatedValue(observer) || slot == nil || email == "" || inboundTag == "" {
		return nil, ctx, authenticatedConnectionError()
	}
	token, err := slot.mint(email, inboundTag)
	if err != nil {
		return nil, ctx, err
	}
	lease, callErr, panicked := callAuthenticatedObserver(observer, ctx, token)
	if panicked || callErr != nil || missingAuthenticatedValue(lease) || !token.state.consumed.Load() || token.state.terminal.Load() {
		token.state.finish()
		closeAuthenticatedLease(lease)
		return nil, ctx, authenticatedConnectionError()
	}
	leaseCtx, leaseDone, contextDone, contextPanicked := authenticatedLeaseContext(lease)
	if contextPanicked || missingAuthenticatedValue(leaseCtx) || contextDone {
		token.state.finish()
		closeAuthenticatedLease(lease)
		return nil, ctx, authenticatedConnectionError()
	}
	connectionCtx, cancel := context.WithCancel(ctx)
	lifetime := &authenticatedConnectionLifetime{state: token.state, lease: lease, leaseDone: leaseDone, cancel: cancel}
	lifetime.stopRevoke, contextPanicked = authenticatedAfterFunc(leaseCtx, func() {
		cancel()
		common.Interrupt(connection)
	})
	if contextPanicked || authenticatedDone(leaseDone) || connectionCtx.Err() != nil {
		lifetime.Close()
		return nil, ctx, authenticatedConnectionError()
	}
	return lifetime, connectionCtx, nil
}

func (lifetime *authenticatedConnectionLifetime) live() bool {
	return lifetime != nil && lifetime.state != nil && !lifetime.state.terminal.Load() && !authenticatedDone(lifetime.leaseDone)
}

func (lifetime *authenticatedConnectionLifetime) Close() {
	if lifetime == nil {
		return
	}
	lifetime.once.Do(func() {
		if lifetime.stopRevoke != nil {
			lifetime.stopRevoke()
		}
		if lifetime.cancel != nil {
			lifetime.cancel()
		}
		lifetime.state.finish()
		closeAuthenticatedLease(lifetime.lease)
	})
}

func callAuthenticatedObserver(observer AuthenticatedConnectionObserver, ctx context.Context, token *AuthenticatedConnection) (lease AuthenticatedConnectionLease, err error, panicked bool) {
	defer func() {
		if recover() != nil {
			lease, err, panicked = nil, authenticatedConnectionError(), true
		}
	}()
	lease, err = observer.AcceptAuthenticated(ctx, token)
	return lease, err, false
}

func authenticatedLeaseContext(lease AuthenticatedConnectionLease) (ctx context.Context, done <-chan struct{}, contextDone bool, panicked bool) {
	defer func() {
		if recover() != nil {
			ctx, done, contextDone, panicked = nil, nil, false, true
		}
	}()
	ctx = lease.Context()
	if missingAuthenticatedValue(ctx) {
		return nil, nil, false, false
	}
	done = ctx.Done()
	return ctx, done, ctx.Err() != nil || authenticatedDone(done), false
}

func authenticatedAfterFunc(ctx context.Context, callback func()) (stop func() bool, panicked bool) {
	defer func() {
		if recover() != nil {
			stop, panicked = nil, true
		}
	}()
	return context.AfterFunc(ctx, callback), false
}

func authenticatedDone(done <-chan struct{}) bool {
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func closeAuthenticatedLease(lease AuthenticatedConnectionLease) {
	if missingAuthenticatedValue(lease) {
		return
	}
	defer func() { _ = recover() }()
	_ = lease.Close()
}

func missingAuthenticatedValue(value any) bool {
	if value == nil {
		return true
	}
	ref := reflect.ValueOf(value)
	switch ref.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return ref.IsNil()
	}
	return false
}

func authenticatedConnectionError() error {
	return errors.New("authenticated connection rejected").AtWarning()
}
