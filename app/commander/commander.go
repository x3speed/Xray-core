package commander

import (
	"context"
	"net"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal/done"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"google.golang.org/grpc"
)

// Commander is a Xray feature that provides gRPC methods to external clients.
type Commander struct {
	sync.Mutex
	server   *grpc.Server
	listener net.Listener
	serveWG  sync.WaitGroup
	services []Service
	ohm      outbound.Manager
	tag      string
	listen   string
}

// NewCommander creates a new Commander based on the given config.
func NewCommander(ctx context.Context, config *Config) (*Commander, error) {
	c := &Commander{
		tag:    config.Tag,
		listen: config.Listen,
	}

	common.Must(core.RequireFeatures(ctx, func(om outbound.Manager) {
		c.ohm = om
	}))

	for _, rawConfig := range config.Service {
		config, err := rawConfig.GetInstance()
		if err != nil {
			return nil, err
		}
		rawService, err := common.CreateObject(ctx, config)
		if err != nil {
			return nil, err
		}
		service, ok := rawService.(Service)
		if !ok {
			return nil, errors.New("not a Service.")
		}
		c.services = append(c.services, service)
	}

	return c, nil
}

// Type implements common.HasType.
func (c *Commander) Type() interface{} {
	return (*Commander)(nil)
}

// Start implements common.Runnable.
func (c *Commander) Start() error {
	c.Lock()
	defer c.Unlock()
	if c.server != nil {
		return errors.New("API server already started")
	}
	server := grpc.NewServer()
	for _, service := range c.services {
		service.Register(server)
	}
	var listener net.Listener
	if len(c.listen) > 0 {
		l, err := net.Listen("tcp", c.listen)
		if err != nil {
			server.Stop()
			errors.LogErrorInner(context.Background(), err, "API server failed to listen on ", c.listen)
			return err
		}
		listener = l
		errors.LogInfo(context.Background(), "API server listening on ", l.Addr())
	} else {
		l := &OutboundListener{buffer: make(chan net.Conn, 4), done: done.New()}
		if err := c.ohm.RemoveHandler(context.Background(), c.tag); err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to remove existing handler")
		}
		if err := c.ohm.AddHandler(context.Background(), &Outbound{tag: c.tag, listener: l}); err != nil {
			l.Close()
			server.Stop()
			return err
		}
		listener = l
	}
	c.server = server
	c.listener = listener
	c.serveWG.Add(1)
	go func() {
		defer c.serveWG.Done()
		if err := server.Serve(listener); err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to start grpc server")
		}
	}()
	return nil
}

// Close implements common.Closable.
func (c *Commander) Close() error {
	c.Lock()
	defer c.Unlock()
	if c.server != nil {
		c.server.Stop()
		// Serve may not have registered the listener before Stop completed.
		c.listener.Close()
		c.serveWG.Wait()
		c.listener = nil
		c.server = nil
	}
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return NewCommander(ctx, cfg.(*Config))
	}))
}
