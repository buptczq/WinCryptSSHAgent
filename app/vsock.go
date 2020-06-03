package app

import (
	"context"
	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"io"
	"sync"
)

const servicePort = 0x22223333

var (
	vmWildCard, _ = guid.FromString("00000000-0000-0000-0000-000000000000")
)

// https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service
//$friendlyName = "WinCryptSSHAgent"
//$service = New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices" -Name "22223333-facb-11e6-bd58-64006a7986d3"
//$service.SetValue("ElementName", $friendlyName)

type VSock struct {
	running bool
}

func (s *VSock) Run(ctx context.Context, handler func(conn io.ReadWriteCloser)) error {
	agentSrvGUID := winio.VsockServiceID(servicePort)
	pipe, err := winio.ListenHvsock(&winio.HvsockAddr{
		VMID:      vmWildCard,
		ServiceID: agentSrvGUID,
	})
	if err != nil {
		return err
	}

	s.running = true
	defer pipe.Close()

	wg := new(sync.WaitGroup)
	// context cancelled
	go func() {
		<-ctx.Done()
		wg.Wait()
	}()
	// loop
	for {
		conn, err := pipe.Accept()
		if err != nil {
			return nil
		}
		wg.Add(1)
		go func() {
			handler(conn)
			wg.Done()
		}()
	}
}

func (*VSock) AppId() AppId {
	return APP_HYPERV
}

func (s *VSock) Menu(register func(id AppId, name string, handler func())) {
}
