package app

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/buptczq/WinCryptSSHAgent/utils"
)

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

type vSockWorker struct {
	l       net.Listener
	handler func(conn io.ReadWriteCloser)
}

func newVSockWorker(vmid string, handler func(conn io.ReadWriteCloser)) (*vSockWorker, error) {
	vmidGUID, err := guid.FromString(vmid)
	if err != nil {
		return nil, err
	}
	pipe, err := winio.ListenHvsock(&winio.HvsockAddr{
		VMID:      vmidGUID,
		ServiceID: utils.HyperVServiceGUID,
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
	timeout := time.Second * 60
	ch := make(chan *utils.ProcessEvent, 1)
	pn, err := utils.NewProcessNotify("wslhost.exe", ch)
	if err != nil {
		// fallback to polling mode
		timeout = time.Second * 15
		println("ProcessNotify error:", err.Error())
	} else {
		pn.Start()
		defer pn.Stop()
	}
	lastVMIDs := make([]string, 0)
	workers := make(map[string]*vSockWorker)
	for {
		vmids := utils.GetVMIDs()
		add, del := vmidDiff(lastVMIDs, vmids)
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
		lastVMIDs = vmids
		select {
		case <-ctx.Done():
			return
		case <-ch:
		case <-time.After(timeout):
		}
	}
}

func (s *VSock) Run(ctx context.Context, handler func(conn io.ReadWriteCloser)) error {
	isHV := ctx.Value("hv").(bool)
	if isHV {
		return nil
	}

	if !utils.CheckHvSocket() {
		return nil
	}

	if !utils.CheckHVService() {
		return nil
	}

	pipe, err := winio.ListenHvsock(&winio.HvsockAddr{
		VMID:      vmWildCard,
		ServiceID: utils.HyperVServiceGUID,
	})
	if err != nil {
		return err
	}

	s.running = true
	defer pipe.Close()

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
	if !utils.CheckHvSocket() {
		return
	}
	wsl2 := AppId(APP_WSL2)
	register(wsl2, "Show WSL2 / Linux On Hyper-V Settings", s.onClick)
	register(s.AppId(), "Check Hyper-V Agent Status", s.onCheckClick)
}

func (s *VSock) onClick() {
	if !s.running {
		s.checkHvService()
		return
	}

	// socat 1.7.4 support vsock,
	// `SOCKET-CONNECT` can be replaced with `VSOCK-CONNECT:2:0x22223333`
	help := `export SSH_AUTH_SOCK=/tmp/wincrypt-hv.sock
ss -lnx | grep -q $SSH_AUTH_SOCK
if [ $? -ne 0 ]; then
	rm -f $SSH_AUTH_SOCK
  (setsid nohup socat UNIX-LISTEN:$SSH_AUTH_SOCK,fork SOCKET-CONNECT:40:0:x0000x33332222x02000000x00000000 >/dev/null 2>&1)
fi`
	if utils.MessageBox(s.AppId().FullName()+" (OK to copy):", help, utils.MB_OKCANCEL) == utils.IDOK {
		utils.SetClipBoard(help)
	}
}

func (s *VSock) onCheckClick() {
	if !s.running {
		s.checkHvService()
		return
	}

	utils.MessageBox(s.AppId().FullName()+":", s.AppId().String()+" agent is working!", 0)
}

func (s *VSock) checkHvService() {
	if utils.CheckHVService() {
		utils.MessageBox("Error:", s.AppId().String()+" agent doesn't work!", utils.MB_ICONWARNING)
		return
	}

	if utils.MessageBox(s.AppId().FullName()+":", s.AppId().String()+" agent is not working! Do you want to enable it?", utils.MB_OKCANCEL) == utils.IDOK {
		if err := utils.RunMeElevatedWithArgs("-i"); err != nil {
			utils.MessageBox("Install Service Error:", err.Error(), utils.MB_ICONERROR)
		}
	}
}
