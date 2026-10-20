package inbound

import (
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

// A production observer supplies one shared session meter through its lease.
// The optional extension keeps unrelated observers source compatible; the RTC
// supervisor bridge implements it unconditionally and denies a missing meter.
type authenticatedTrafficMeter interface { ConsumeTraffic(uint64) bool }

type authenticatedReader struct { source buf.Reader; owner *authenticatedConnectionLifetime; destination xnet.Destination }
type authenticatedWriter struct { target buf.Writer; owner *authenticatedConnectionLifetime; destination xnet.Destination }

func (owner *authenticatedConnectionLifetime) acceptTraffic(mb buf.MultiBuffer, destination xnet.Destination) bool {
	if !owner.live() { return false }
	var total uint64
	for _, packet:=range mb {
		if packet==nil { return false }
		if destination.Network==xnet.Network_UDP && packet.UDP!=nil && (packet.UDP.Network!=xnet.Network_UDP || packet.UDP.NetAddr()!=destination.NetAddr()) { return false }
		next:=total+uint64(packet.Len());if next<total{return false};total=next
	}
	if meter,ok:=owner.lease.(authenticatedTrafficMeter);ok {return meter.ConsumeTraffic(total) && owner.live()}
	return owner.live()
}
func (r *authenticatedReader) ReadMultiBuffer()(buf.MultiBuffer,error){
	mb,err:=r.source.ReadMultiBuffer()
	if !r.owner.acceptTraffic(mb,r.destination){buf.ReleaseMulti(mb);r.owner.Close();return nil,authenticatedConnectionError()}
	return mb,err
}
func (w *authenticatedWriter) WriteMultiBuffer(mb buf.MultiBuffer)error{
	if !w.owner.acceptTraffic(mb,w.destination){buf.ReleaseMulti(mb);w.owner.Close();return authenticatedConnectionError()}
	return w.target.WriteMultiBuffer(mb)
}
