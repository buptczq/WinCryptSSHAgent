package app

import (
	"context"
	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"io"
	"net"
	"sync"
	"time"
)

var (
	vmWildCard, _ = guid.FromString("00000000-0000-0000-0000-000000000000")
)

// TODO: check and install service
// https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service
//$friendlyName = "WinCryptSSHAgent"
//$service = New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices" -Name "22223333-facb-11e6-bd58-64006a7986d3"
//$service.SetValue("ElementName", $friendlyName)

type VSock struct {
	running bool
}

type vSockWorker struct {
	l       net.Listener
	handler func(conn io.ReadWriteCloser)
}

func newVSockWorker(vmid string, handler func(conn io.ReadWriteCloser)) (*vSockWorker, error) {
	vmidGUID, err := guid.FromString(vmid)
	if err != nil {
		return nil, err
	}
	agentSrvGUID := winio.VsockServiceID(utils.ServicePort)
	pipe, err := winio.ListenHvsock(&winio.HvsockAddr{
		VMID:      vmidGUID,
		ServiceID: agentSrvGUID,
	})
	if err != nil {
		return nil, err
	}
	return &vSockWorker{
		l:       pipe,
		handler: handler,
	}, nil
}

func (s *vSockWorker) Run() {
	for {
		conn, err := s.l.Accept()
		if err != nil {
			return
		}
		go func() {
			s.handler(conn)
		}()
	}
}

func (s *vSockWorker) Close() {
	s.l.Close()
}

func vmidDiff(old, new []string) (add, del []string) {
	add = make([]string, 0)
	del = make([]string, 0)
	oldIDS := make(map[string]interface{})
	newIDS := make(map[string]interface{})
	for _, v := range old {
		oldIDS[v] = 0
	}
	for _, v := range new {
		newIDS[v] = 0
	}
	for _, v := range new {
		if _, ok := oldIDS[v]; !ok {
			add = append(add, v)
		}
	}
	for _, v := range old {
		if _, ok := newIDS[v]; !ok {
			del = append(del, v)
		}
	}
	return
}

func (s *VSock) wsl2Watcher(ctx context.Context, handler func(conn io.ReadWriteCloser)) {
	lastVMID := make([]string, 0)
	workers := make(map[string]*vSockWorker)
	for {
		vmids := utils.GetVMID()
		add, del := vmidDiff(lastVMID, vmids)
		for _, v := range add {
			w, err := newVSockWorker(v, handler)
			if err != nil {
				continue
			}
			workers[v] = w
			go w.Run()
		}
		for _, v := range del {
			w := workers[v]
			if w != nil {
				w.Close()
				delete(workers, v)
			}
		}
		lastVMID = vmids
		// TODO: wait process creating event
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second * 15):
		}
	}
}

func (s *VSock) Run(ctx context.Context, handler func(conn io.ReadWriteCloser)) error {
	isHV := ctx.Value("hv").(bool)
	if isHV {
		return nil
	}
	agentSrvGUID := winio.VsockServiceID(utils.ServicePort)
	pipe, err := winio.ListenHvsock(&winio.HvsockAddr{
		VMID:      vmWildCard,
		ServiceID: agentSrvGUID,
	})
	if err != nil {
		return err
	}

	s.running = true
	defer pipe.Close()

	// TODO: check if WSL2 is enabled
	go s.wsl2Watcher(ctx, handler)

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
	register(s.AppId(), "Show WSL2 Settings", s.onClick)
}

func (s *VSock) onClick() {
	if s.running {
		help := "socat UNIX-LISTEN:/tmp/wincrypt-hv.sock,fork,mode=777 SOCKET-CONNECT:40:0:x0000x33332222x02000000x00000000,forever,interval=5 &\n"
		help += "export SSH_AUTH_SOCK=/tmp/wincrypt-hv.sock\n"
		if utils.MessageBox(s.AppId().FullName()+" (OK to copy):", help, utils.MB_OKCANCEL) == utils.IDOK {
			utils.SetClipBoard(help)
		}
	} else {
		utils.MessageBox("Error:", s.AppId().String()+" agent doesn't work!", utils.MB_ICONWARNING)
	}
}
