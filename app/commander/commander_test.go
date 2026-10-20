package commander

import (
	"net"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
)

func lifecycleInstance(t *testing.T, address string) *core.Instance {
	t.Helper()
	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(&Config{Tag: "lifecycle-handler", Listen: address}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return instance
}

func TestCommanderImmediateCloseRetiresOwnedListener(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	for _, directTCP := range []bool{false, true} {
		name := "tagged"
		address := ""
		if directTCP {
			name = "tcp"
			probe, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address = probe.Addr().String()
			if err = probe.Close(); err != nil {
				t.Fatal(err)
			}
		}
		t.Run(name, func(t *testing.T) {
			instance := lifecycleInstance(t, address)
			defer instance.Close()
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}
			var tagged *OutboundListener
			if !directTCP {
				manager := instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
				handler, ok := manager.GetHandler("lifecycle-handler").(*Outbound)
				if !ok {
					t.Fatal("real commander handler not installed")
				}
				tagged = handler.listener
			}
			// No yield/sleep: Close must also retire a Serve goroutine not scheduled yet.
			if err := instance.Close(); err != nil {
				t.Fatal(err)
			}
			if tagged != nil {
				select {
				case <-tagged.done.Wait():
				default:
					t.Fatal("owned tagged listener still open")
				}
			} else {
				probe, err := net.Listen("tcp4", address)
				if err != nil {
					t.Fatal("owned TCP listener survived Close", err)
				}
				if err = probe.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestCommanderFailedListenReleasesServer(t *testing.T) {
	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	instance := lifecycleInstance(t, held.Addr().String())
	defer instance.Close()
	if err = instance.Start(); err == nil {
		t.Fatal("occupied TCP listener accepted")
	}
	commander := instance.GetFeature((*Commander)(nil)).(*Commander)
	commander.Lock()
	retained := commander.server != nil
	commander.Unlock()
	if retained {
		t.Fatal("failed Start retained its gRPC server")
	}
	if err = instance.Close(); err != nil {
		t.Fatal(err)
	}
}
