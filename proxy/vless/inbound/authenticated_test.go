package inbound

import (
	"bytes"
	"context"
	"errors"
	"io"
	stdnet "net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport"
)

const (
	authenticatedTestUserID = "00000000-0000-4000-8000-000000000071"
	authenticatedTestEmail  = "rtc-mesh/00000000-0000-4000-8000-000000000071"
	authenticatedTestTag    = "rtc-vless-in"
	authenticatedTestHost   = "private-destination.invalid"
)

type authenticatedObserverFunc func(context.Context, *AuthenticatedConnection) (AuthenticatedConnectionLease, error)

func (observer authenticatedObserverFunc) AcceptAuthenticated(ctx context.Context, token *AuthenticatedConnection) (AuthenticatedConnectionLease, error) {
	return observer(ctx, token)
}

type authenticatedTestLease struct {
	ctx        context.Context
	closeCalls atomic.Int32
	closeErr   error
	closePanic bool
	ctxPanic   bool
}

func (lease *authenticatedTestLease) Context() context.Context {
	if lease.ctxPanic {
		panic("private lease context panic")
	}
	return lease.ctx
}

func (lease *authenticatedTestLease) Close() error {
	lease.closeCalls.Add(1)
	if lease.closePanic {
		panic("private lease close panic")
	}
	return lease.closeErr
}

type authenticatedTestPolicy struct{}

func (*authenticatedTestPolicy) Type() interface{} { return policy.ManagerType() }
func (*authenticatedTestPolicy) Start() error      { return nil }
func (*authenticatedTestPolicy) Close() error      { return nil }
func (*authenticatedTestPolicy) ForSystem() policy.System {
	return policy.System{}
}
func (*authenticatedTestPolicy) ForLevel(uint32) policy.Session {
	return policy.Session{Timeouts: policy.Timeout{
		Handshake: time.Second, ConnectionIdle: time.Second, UplinkOnly: time.Second, DownlinkOnly: time.Second,
	}}
}

type authenticatedTestDispatcher struct {
	calls    atomic.Int32
	entered  chan struct{}
	block    bool
	err      error
	enterOne sync.Once
}

func (*authenticatedTestDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*authenticatedTestDispatcher) Start() error      { return nil }
func (*authenticatedTestDispatcher) Close() error      { return nil }
func (*authenticatedTestDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, errors.New("unexpected Dispatch")
}
func (dispatcher *authenticatedTestDispatcher) DispatchLink(ctx context.Context, _ xnet.Destination, _ *transport.Link) error {
	dispatcher.calls.Add(1)
	if dispatcher.entered != nil {
		dispatcher.enterOne.Do(func() { close(dispatcher.entered) })
	}
	if dispatcher.block {
		<-ctx.Done()
		return ctx.Err()
	}
	return dispatcher.err
}

type authenticatedLogRecorder struct {
	mu       sync.Mutex
	messages []string
}

func (recorder *authenticatedLogRecorder) Handle(message log.Message) {
	recorder.mu.Lock()
	recorder.messages = append(recorder.messages, message.String())
	recorder.mu.Unlock()
}

func (recorder *authenticatedLogRecorder) String() string {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return strings.Join(recorder.messages, "\n")
}

func TestAuthenticatedProcessOrdersObserverBeforeDispatch(t *testing.T) {
	handler, request := newAuthenticatedTestHandler(t, protocol.RequestCommandTCP)
	observerEntered := make(chan struct{})
	releaseObserver := make(chan struct{})
	lease := &authenticatedTestLease{ctx: context.Background()}
	var identity AuthenticatedConnectionIdentity
	if err := handler.SetAuthenticatedConnectionObserver(authenticatedObserverFunc(func(ctx context.Context, token *AuthenticatedConnection) (AuthenticatedConnectionLease, error) {
		var ok bool
		identity, ok = token.Consume()
		if !ok || ctx == nil || identity.Email() != authenticatedTestEmail || identity.InboundTag() != authenticatedTestTag ||
			identity.ConnectionID() == [32]byte{} || !identity.DirectTCP() {
			t.Error("observer did not receive the exact authenticated tuple")
		}
		close(observerEntered)
		<-releaseObserver
		return lease, nil
	})); err != nil {
		t.Fatal(err)
	}
	dispatcher := &authenticatedTestDispatcher{}
	result := runAuthenticatedProcess(handler, request, dispatcher)
	select {
	case <-observerEntered:
	case <-time.After(time.Second):
		t.Fatal("authenticated observer was not called")
	}
	if dispatcher.calls.Load() != 0 {
		t.Fatal("dispatcher ran before observer acceptance")
	}
	close(releaseObserver)
	if err := <-result; err != nil {
		t.Fatal("valid authenticated connection failed", err)
	}
	if dispatcher.calls.Load() != 1 || lease.closeCalls.Load() != 1 {
		t.Fatal("accepted connection did not dispatch and release exactly once", dispatcher.calls.Load(), lease.closeCalls.Load())
	}
	select {
	case <-identity.Done():
	default:
		t.Fatal("Process return did not terminalize the authenticated identity")
	}
}

func TestAuthenticatedProcessFailuresNeverDispatch(t *testing.T) {
	tests := []struct {
		name     string
		observer authenticatedObserverFunc
	}{
		{name: "observer error", observer: func(context.Context, *AuthenticatedConnection) (AuthenticatedConnectionLease, error) {
			return nil, errors.New("private observer error")
		}},
		{name: "observer panic", observer: func(context.Context, *AuthenticatedConnection) (AuthenticatedConnectionLease, error) {
			panic("private observer panic")
		}},
		{name: "nil lease", observer: func(_ context.Context, token *AuthenticatedConnection) (AuthenticatedConnectionLease, error) {
			_, _ = token.Consume()
			return nil, nil
		}},
		{name: "nil lease context", observer: func(_ context.Context, token *AuthenticatedConnection) (AuthenticatedConnectionLease, error) {
			_, _ = token.Consume()
			return &authenticatedTestLease{}, nil
		}},
		{name: "lease context panic", observer: func(_ context.Context, token *AuthenticatedConnection) (AuthenticatedConnectionLease, error) {
			_, _ = token.Consume()
			return &authenticatedTestLease{ctxPanic: true}, nil
		}},
		{name: "unconsumed", observer: func(context.Context, *AuthenticatedConnection) (AuthenticatedConnectionLease, error) {
			return &authenticatedTestLease{ctx: context.Background()}, nil
		}},
		{name: "closed lease", observer: func(_ context.Context, token *AuthenticatedConnection) (AuthenticatedConnectionLease, error) {
			_, _ = token.Consume()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return &authenticatedTestLease{ctx: ctx}, nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, request := newAuthenticatedTestHandler(t, protocol.RequestCommandTCP)
			if err := handler.SetAuthenticatedConnectionObserver(test.observer); err != nil {
				t.Fatal(err)
			}
			dispatcher := &authenticatedTestDispatcher{}
			if err := <-runAuthenticatedProcess(handler, request, dispatcher); err == nil || dispatcher.calls.Load() != 0 ||
				strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), authenticatedTestEmail) || strings.Contains(err.Error(), authenticatedTestHost) {
				t.Fatal("observer failure escaped or dispatched", err, dispatcher.calls.Load())
			}
		})
	}
}

func TestAuthenticatedRegistrationAndTokenAreOneShot(t *testing.T) {
	var callsA, callsB atomic.Int32
	observerA := authenticatedObserverFunc(func(context.Context, *AuthenticatedConnection) (AuthenticatedConnectionLease, error) {
		callsA.Add(1)
		return nil, nil
	})
	observerB := authenticatedObserverFunc(func(context.Context, *AuthenticatedConnection) (AuthenticatedConnectionLease, error) {
		callsB.Add(1)
		return nil, nil
	})
	handlerA, _ := newAuthenticatedTestHandler(t, protocol.RequestCommandTCP)
	handlerB, _ := newAuthenticatedTestHandler(t, protocol.RequestCommandTCP)
	var nilObserver authenticatedObserverFunc
	if handlerA.SetAuthenticatedConnectionObserver(nilObserver) == nil || handlerA.SetAuthenticatedConnectionObserver(observerA) != nil ||
		handlerA.SetAuthenticatedConnectionObserver(observerB) == nil || handlerB.SetAuthenticatedConnectionObserver(observerB) != nil {
		t.Fatal("observer registration was nil, reusable, late, or process-global")
	}
	registeredA, registeredB := handlerA.authenticated.begin(), handlerB.authenticated.begin()
	_, _ = registeredA.AcceptAuthenticated(context.Background(), nil)
	_, _ = registeredB.AcceptAuthenticated(context.Background(), nil)
	if callsA.Load() != 1 || callsB.Load() != 1 || handlerA.SetAuthenticatedConnectionObserver(observerA) == nil {
		t.Fatal("observer registration was late or process-global")
	}
	handlerC, requestC := newAuthenticatedTestHandler(t, protocol.RequestCommandTCP)
	dispatcherC := &authenticatedTestDispatcher{}
	if err := <-runAuthenticatedProcess(handlerC, requestC, dispatcherC); err != nil || dispatcherC.calls.Load() != 1 ||
		handlerC.SetAuthenticatedConnectionObserver(observerA) == nil {
		t.Fatal("no-observer Process changed or accepted late registration", err, dispatcherC.calls.Load())
	}

	slot := authenticatedObserverSlot{random: bytes.NewReader(bytes.Repeat([]byte{7}, 32))}
	token, err := slot.mint(authenticatedTestEmail, authenticatedTestTag)
	if err != nil {
		t.Fatal(err)
	}
	copyToken := *token
	identity, ok := token.Consume()
	if !ok || identity.ConnectionID() == [32]byte{} {
		t.Fatal("valid token did not transfer")
	}
	if replay, ok := copyToken.Consume(); ok || replay != (AuthenticatedConnectionIdentity{}) {
		t.Fatal("copied token replay succeeded")
	}
	if _, ok := (&AuthenticatedConnection{}).Consume(); ok {
		t.Fatal("zero token was forgeable")
	}
	select {
	case <-((AuthenticatedConnectionIdentity{}).Done()):
	default:
		t.Fatal("zero identity was live")
	}
	token.state.finish()
	if identity.Email() != "" || identity.InboundTag() != "" || identity.DirectTCP() {
		t.Fatal("terminal identity remained readable")
	}
}

func TestAuthenticatedHandlerRejectsFailedAuthFallbackTypesAndEntropy(t *testing.T) {
	commands := []protocol.RequestCommand{
		protocol.RequestCommandUDP, protocol.RequestCommandMux, protocol.RequestCommandRvs, protocol.RequestCommand(99),
	}
	for _, command := range commands {
		handler, request := newAuthenticatedTestHandler(t, command)
		var calls atomic.Int32
		_ = handler.SetAuthenticatedConnectionObserver(countingAuthenticatedObserver(&calls))
		dispatcher := &authenticatedTestDispatcher{}
		if err := <-runAuthenticatedProcess(handler, request, dispatcher); err == nil || calls.Load() != 0 || dispatcher.calls.Load() != 0 {
			t.Fatal("non-direct command reached observer or dispatcher", command, err, calls.Load(), dispatcher.calls.Load())
		}
	}
	t.Run("non TCP network", func(t *testing.T) {
		handler, request := newAuthenticatedTestHandler(t, protocol.RequestCommandTCP)
		var calls atomic.Int32
		_ = handler.SetAuthenticatedConnectionObserver(countingAuthenticatedObserver(&calls))
		dispatcher := &authenticatedTestDispatcher{}
		if err := <-runAuthenticatedProcessOnNetwork(handler, request, dispatcher, xnet.Network_UNIX); err == nil || calls.Load() != 0 || dispatcher.calls.Load() != 0 {
			t.Fatal("non-TCP transport reached observer or dispatcher", err, calls.Load(), dispatcher.calls.Load())
		}
	})

	t.Run("failed auth", func(t *testing.T) {
		handler, request := newAuthenticatedTestHandler(t, protocol.RequestCommandTCP)
		request[1] ^= 0xff
		assertNoAuthenticatedCallback(t, handler, request)
	})
	t.Run("fallback", func(t *testing.T) {
		handler, _ := newAuthenticatedTestHandler(t, protocol.RequestCommandTCP)
		handler.fallbacks = map[string]map[string]map[string]*Fallback{}
		assertNoAuthenticatedCallback(t, handler, []byte{0})
	})
	t.Run("entropy", func(t *testing.T) {
		handler, request := newAuthenticatedTestHandler(t, protocol.RequestCommandTCP)
		handler.authenticated.random = authenticatedErrorReader{}
		assertNoAuthenticatedCallback(t, handler, request)
	})
	t.Run("zero entropy", func(t *testing.T) {
		handler, request := newAuthenticatedTestHandler(t, protocol.RequestCommandTCP)
		handler.authenticated.random = bytes.NewReader(make([]byte, 32))
		assertNoAuthenticatedCallback(t, handler, request)
	})
}

func TestAuthenticatedLeaseCancellationInterruptsExactProcess(t *testing.T) {
	handler, request := newAuthenticatedTestHandler(t, protocol.RequestCommandTCP)
	leaseCtx, cancelLease := context.WithCancel(context.Background())
	lease := &authenticatedTestLease{ctx: leaseCtx, closePanic: true}
	var identity AuthenticatedConnectionIdentity
	_ = handler.SetAuthenticatedConnectionObserver(authenticatedObserverFunc(func(_ context.Context, token *AuthenticatedConnection) (AuthenticatedConnectionLease, error) {
		identity, _ = token.Consume()
		return lease, nil
	}))
	dispatcher := &authenticatedTestDispatcher{entered: make(chan struct{}), block: true}
	result := runAuthenticatedProcess(handler, request, dispatcher)
	select {
	case <-dispatcher.entered:
	case <-time.After(time.Second):
		t.Fatal("accepted connection did not reach dispatcher")
	}
	cancelLease()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("revoked connection returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("lease cancellation did not interrupt Process")
	}
	if lease.closeCalls.Load() != 1 {
		t.Fatal("lease Close panic escaped idempotent cleanup", lease.closeCalls.Load())
	}
	select {
	case <-identity.Done():
	default:
		t.Fatal("revoked identity did not become terminal")
	}
}

func TestAuthenticatedFailuresDoNotLogIdentityOrAddress(t *testing.T) {
	recorder := &authenticatedLogRecorder{}
	log.RegisterHandler(recorder)
	t.Cleanup(func() { log.RegisterHandler(&authenticatedLogRecorder{}) })
	var returned []string
	t.Run("failed auth", func(t *testing.T) {
		handler, request := newAuthenticatedTestHandler(t, protocol.RequestCommandTCP)
		request[1] ^= 0xff
		var calls atomic.Int32
		_ = handler.SetAuthenticatedConnectionObserver(countingAuthenticatedObserver(&calls))
		err := <-runAuthenticatedProcess(handler, request, &authenticatedTestDispatcher{})
		if err == nil {
			t.Fatal("failed authentication returned success")
		}
		returned = append(returned, err.Error())
	})
	t.Run("dispatcher error", func(t *testing.T) {
		handler, request := newAuthenticatedTestHandler(t, protocol.RequestCommandTCP)
		_ = handler.SetAuthenticatedConnectionObserver(authenticatedObserverFunc(func(_ context.Context, token *AuthenticatedConnection) (AuthenticatedConnectionLease, error) {
			_, _ = token.Consume()
			return &authenticatedTestLease{ctx: context.Background()}, nil
		}))
		dispatcher := &authenticatedTestDispatcher{err: errors.New("private dispatch " + authenticatedTestEmail + " " + authenticatedTestHost + " pipe")}
		err := <-runAuthenticatedProcess(handler, request, dispatcher)
		if err == nil {
			t.Fatal("dispatcher failure returned success")
		}
		returned = append(returned, err.Error())
	})
	combined := recorder.String() + "\n" + strings.Join(returned, "\n")
	for _, secret := range []string{authenticatedTestUserID, authenticatedTestEmail, authenticatedTestHost, "pipe"} {
		if strings.Contains(combined, secret) {
			t.Fatal("observer-bound failure logged identity or address", secret, combined)
		}
	}
}

func countingAuthenticatedObserver(calls *atomic.Int32) authenticatedObserverFunc {
	return func(context.Context, *AuthenticatedConnection) (AuthenticatedConnectionLease, error) {
		calls.Add(1)
		return nil, errors.New("unexpected observer call")
	}
}

func assertNoAuthenticatedCallback(t *testing.T, handler *Handler, request []byte) {
	t.Helper()
	var calls atomic.Int32
	if err := handler.SetAuthenticatedConnectionObserver(countingAuthenticatedObserver(&calls)); err != nil {
		t.Fatal(err)
	}
	dispatcher := &authenticatedTestDispatcher{}
	if err := <-runAuthenticatedProcess(handler, request, dispatcher); err == nil || calls.Load() != 0 || dispatcher.calls.Load() != 0 {
		t.Fatal("failed pre-auth path reached observer or dispatcher", err, calls.Load(), dispatcher.calls.Load())
	}
}

func newAuthenticatedTestHandler(t *testing.T, command protocol.RequestCommand) (*Handler, []byte) {
	t.Helper()
	id, err := uuid.ParseString(authenticatedTestUserID)
	if err != nil {
		t.Fatal(err)
	}
	account, err := (&vless.Account{Id: id.String()}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	user := &protocol.MemoryUser{Level: 0, Email: authenticatedTestEmail, Account: account}
	validator := new(vless.MemoryValidator)
	if err = validator.Add(user); err != nil {
		t.Fatal(err)
	}
	request := &protocol.RequestHeader{
		Version: encoding.Version, User: user, Command: command,
		Address: xnet.DomainAddress(authenticatedTestHost), Port: xnet.Port(443),
	}
	if command == protocol.RequestCommandMux {
		request.Address, request.Port = xnet.DomainAddress("v1.mux.cool"), 0
	}
	var encoded bytes.Buffer
	if err = encoding.EncodeRequestHeader(&encoded, request, &encoding.Addons{}); err != nil {
		t.Fatal(err)
	}
	return &Handler{policyManager: &authenticatedTestPolicy{}, validator: validator}, encoded.Bytes()
}

func runAuthenticatedProcess(handler *Handler, request []byte, dispatcher *authenticatedTestDispatcher) <-chan error {
	return runAuthenticatedProcessOnNetwork(handler, request, dispatcher, xnet.Network_TCP)
}

func runAuthenticatedProcessOnNetwork(handler *Handler, request []byte, dispatcher *authenticatedTestDispatcher, network xnet.Network) <-chan error {
	result := make(chan error, 1)
	client, server := stdnet.Pipe()
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: authenticatedTestTag})
	go func() {
		defer server.Close()
		result <- handler.Process(ctx, network, server, dispatcher)
	}()
	go func() {
		_, _ = client.Write(request)
		_ = client.Close()
	}()
	return result
}

type authenticatedErrorReader struct{}

func (authenticatedErrorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
