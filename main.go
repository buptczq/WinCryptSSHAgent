package main

//go:generate goversioninfo -icon=assets/icon.ico

import (
	"context"
	"github.com/hattya/go.notify"
	notification "github.com/hattya/go.notify/windows"
	"os"
	"os/signal"
	"github.com/buptczq/WinCryptSSHAgent/common"
	"github.com/buptczq/WinCryptSSHAgent/sshagent"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"sync"
	"time"
)

func initSystray() (notify.Notifier, error) {
	icon, err := notification.LoadIcon(1)
	if err != nil {
		return nil, err
	}
	n, err := notification.NewNotifier("WinCrypt SSH Agent", icon)
	if err != nil {
		return nil, err
	}
	n.Register("info", notification.IconInfo, nil)
	utils.RegisterNotifier(n)
	return n, nil
}

func createMenu(sysTray *notification.NotifyIcon) {
	menu := sysTray.CreateMenu()
	menu.Item("Cygwin Help", common.APP_CYGWIN)
	menu.Item("WSL Help", common.APP_WSL)
	menu.Item("WinSSH Help", common.APP_WINSSH)
	menu.Item("SecureCRT Help", common.APP_SECURECRT)
	menu.Sep()
	menu.Item("Quit", common.MENU_QUIT)
	sysTray.Add()
}

func main() {
	notifier, err := initSystray()
	if err != nil {
		utils.MessageBox("Error:", err.Error(), utils.MB_ICONERROR)
		return
	}
	sysTray := notifier.Sys().(*notification.NotifyIcon)
	createMenu(sysTray)
	backCtx := context.WithValue(context.Background(), "status", &common.Services{
		Service: make(map[common.AppId]*common.ServiceStatus),
	})
	ctx, cancel := context.WithCancel(backCtx)

	ag := new(sshagent.CAPIAgent)
	defer ag.Free()
	server := &sshagent.Server{ag}
	wg := new(sync.WaitGroup)
	wg.Add(4)
	// services
	go func() {
		err := wslServer(ctx, server.SSHAgentHandler)
		if err != nil {
			utils.MessageBox("WSL Agent Error:", err.Error(), utils.MB_ICONWARNING)
		}
		wg.Done()
	}()
	go func() {
		err := cygwinSocketServer(ctx, server.SSHAgentHandler)
		if err != nil {
			utils.MessageBox("Cygwin Agent Error:", err.Error(), utils.MB_ICONWARNING)
		}
		wg.Done()
	}()
	go func() {
		err := namedPipeServer(ctx, server.SSHAgentHandler)
		if err != nil {
			utils.MessageBox("Windows OpenSSH Agent Error:", err.Error(), utils.MB_ICONWARNING)
		}
		wg.Done()
	}()
	go func() {
		err := pageantServer(ctx, server.SSHAgentHandler)
		if err != nil {
			utils.MessageBox("Pageant Agent Error:", err.Error(), utils.MB_ICONWARNING)
		}
		wg.Done()
	}()

	// interrupt signal
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)

	// systray
	handler := menuHandler(ctx)
	for {
		select {
		case clicked := <-sysTray.Menu:
			if clicked.ID == common.MENU_QUIT {
				goto cleanup
			}
			handler(common.AppId(clicked.ID))
		case <-sysTray.Balloon:
			continue
		case <-quit:
			goto cleanup
		}
	}
cleanup:
	sysTray.Close()
	cancel()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		done <- struct{}{}
	}()
	select {
	case <-time.NewTimer(time.Second * 10).C:
	case <-done:
	}
}

func menuHandler(ctx context.Context) func(id common.AppId) {
	serviceStatus := ctx.Value("status").(*common.Services)
	return func(id common.AppId) {
		serviceStatus.RLock()
		info := serviceStatus.Service[id]
		serviceStatus.RUnlock()
		if info != nil && info.Running {
			if utils.MessageBox(id.FullName()+" (OK to copy):", info.Help, utils.MB_OKCANCEL) == utils.IDOK {
				utils.SetClipBoard(info.Help)
			}
		} else {
			utils.MessageBox("Error:", id.String()+" agent doesn't work!", utils.MB_ICONWARNING)
		}
	}
}
