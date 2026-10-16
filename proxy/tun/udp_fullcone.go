package tun

import (
	"io"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// Destination is part of the association: packets sharing a source port must
// never inherit the routing decision made for another destination.
type udpAssociationKey struct { source, destination string }

const maxUDPAssociations = 1024

type udpConnectionHandler struct {
	sync.Mutex
	udpConns map[udpAssociationKey]*udpConn
	handleConnection func(net.Conn, net.Destination)
	writePacket func([]byte, net.Destination, net.Destination) error
}

func newUdpConnectionHandler(handle func(net.Conn, net.Destination), write func([]byte, net.Destination, net.Destination) error) *udpConnectionHandler {
	return &udpConnectionHandler{udpConns: make(map[udpAssociationKey]*udpConn), handleConnection: handle, writePacket: write}
}

func (u *udpConnectionHandler) HandlePacket(src, dst net.Destination, data []byte) bool {
	if src.Network != net.Network_UDP || dst.Network != net.Network_UDP || !src.IsValid() || !dst.IsValid() || len(data) > 65507 {
		return false
	}
	key := udpAssociationKey{src.String(), dst.String()}
	u.Lock()
	defer u.Unlock()
	conn := u.udpConns[key]
	if conn == nil {
		if len(u.udpConns) >= maxUDPAssociations { return false }
		conn = &udpConn{handler: u, key: key, egress: make(chan []byte, 16), src: src, dst: dst}
		u.udpConns[key] = conn
		go u.handleConnection(conn, dst)
	}
	// The stack may reuse its input storage. Own the queued datagram, and keep
	// enqueue under the same mutex as close to prevent send-on-closed-channel.
	select {
	case conn.egress <- append([]byte(nil), data...):
		return true
	default:
		return false
	}
}

func (u *udpConnectionHandler) connectionFinished(conn *udpConn) {
	u.Lock()
	if u.udpConns[conn.key] == conn {
		delete(u.udpConns, conn.key)
		conn.closing = true
		close(conn.egress)
	}
	u.Unlock()
	conn.writers.Wait()
}

type udpConn struct {
	net.Conn
	handler *udpConnectionHandler
	key udpAssociationKey
	egress chan []byte
	src, dst net.Destination
	closing bool // handler mutex
	closeOnce sync.Once
	writers sync.WaitGroup
}

func (c *udpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	data, ok := <-c.egress
	if !ok { return nil, io.EOF }
	return buf.MultiBuffer{buf.FromBytes(data)}, nil
}

func (c *udpConn) Read(p []byte) (int, error) {
	data, ok := <-c.egress
	if !ok { return 0, io.EOF }
	if len(data) > len(p) { return 0, io.ErrShortBuffer }
	return copy(p, data), nil
}

func (c *udpConn) beginWrite() bool {
	c.handler.Lock()
	defer c.handler.Unlock()
	if c.closing || c.handler.udpConns[c.key] != c { return false }
	c.writers.Add(1)
	return true
}

func (c *udpConn) Write(p []byte) (int, error) {
	if !c.beginWrite() { return 0, io.ErrClosedPipe }
	defer c.writers.Done()
	if err := c.handler.writePacket(p, c.dst, c.src); err != nil { return 0, err }
	return len(p), nil
}

func (c *udpConn) Close() error {
	c.closeOnce.Do(func() { c.handler.connectionFinished(c) })
	return nil
}

func (c *udpConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: c.dst.Address.IP(), Port: int(c.dst.Port.Value())} }
func (c *udpConn) RemoteAddr() net.Addr { return &net.UDPAddr{IP: c.src.Address.IP(), Port: int(c.src.Port.Value())} }

func (c *udpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if !c.beginWrite() { return io.ErrClosedPipe }
	defer c.writers.Done()
	for _, b := range mb {
		if b.UDP != nil && b.UDP.String() != c.dst.String() { return io.ErrUnexpectedEOF }
		if err := c.handler.writePacket(b.Bytes(), c.dst, c.src); err != nil { return err }
	}
	return nil
}
