package tun

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

func TestUDPAssociationOwnsDestinationAndPacket(t *testing.T) {
	created := make(chan *udpConn, 3)
	h := newUdpConnectionHandler(func(c net.Conn, _ net.Destination) { created <- c.(*udpConn) }, func([]byte, net.Destination, net.Destination) error { return nil })
	src := net.UDPDestination(net.ParseAddress("10.0.0.2"), 4000)
	one := net.UDPDestination(net.ParseAddress("192.0.2.1"), 443)
	two := net.UDPDestination(net.ParseAddress("192.0.2.2"), 53)
	payload := bytes.Repeat([]byte{7}, 9000)
	if !h.HandlePacket(src, one, payload) { t.Fatal("first packet denied") }
	a := <-created
	payload[0] = 9
	if !h.HandlePacket(src, two, []byte{2}) { t.Fatal("second destination denied") }
	b := <-created
	defer a.Close()
	defer b.Close()
	if a == b || a.dst.String() != one.String() || b.dst.String() != two.String() { t.Fatal("destination association lost") }
	mb, err := a.ReadMultiBuffer()
	if err != nil || len(mb) != 1 || len(mb[0].Bytes()) != 9000 || mb[0].Bytes()[0] != 7 { t.Fatal("packet ownership/length lost") }
	buf.ReleaseMulti(mb)
	if err := a.Close(); err != nil { t.Fatal(err) }
	if !h.HandlePacket(src, one, []byte{3}) { t.Fatal("new exact association denied") }
	c := <-created
	defer c.Close()
	h.connectionFinished(a) // stale identity cannot remove its replacement.
	if h.udpConns[c.key] != c { t.Fatal("stale close removed replacement") }
	bad := buf.FromBytes([]byte{1})
	bad.UDP = &two
	if err := c.WriteMultiBuffer(buf.MultiBuffer{bad}); err == nil { t.Fatal("foreign response destination accepted") }
}
