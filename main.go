package main

//go:generate goversioninfo -icon=assets/icon.ico

import (
	"context"
	"flag"
	"github.com/buptczq/WinCryptSSHAgent/capi"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/buptczq/WinCryptSSHAgent/app"
	"github.com/buptczq/WinCryptSSHAgent/sshagent"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	notify "github.com/hattya/go.notify"
	notification "github.com/hattya/go.notify/windows"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const agentTitle = "WinCrypt SSH Agent v1.1.9"

var applications = []app.Application{
	new(app.PubKeyView),
	new(app.WSL),
	new(app.VSock),
	new(app.Cygwin),
	new(app.NamedPipe),
	new(app.Pageant),
	new(app.XShell),
}

var installHVService = flag.Bool("i", false, "Install Hyper-V Guest Communication Services")
var disableCapi = flag.Bool("disable-capi", false, "Disable Windows Crypto API")
var disablePINCache = flag.Bool("disable-pin-cache", false, "Clear the Smart Card PIN Cache after each operation")

func installService() {
	if !utils.IsAdmin() {
		err := utils.RunMeElevated()
		if err != nil {
			utils.MessageBox("Install Service Error:", err.Error(), utils.MB_ICONERROR)
		}
		return
	}

	err := winio.RunWithPrivilege(winio.SeRestorePrivilege, func() error {
		gcs, err := registry.OpenKey(registry.LOCAL_MACHINE, utils.HyperVServiceRegPath, registry.ALL_ACCESS)
		if err != nil {
			return err
		}
		defer gcs.Close()
		agentSrv, _, err := registry.CreateKey(gcs, utils.HyperVServiceGUID.String(), registry.ALL_ACCESS)
		if err != nil {
			return err
		}
		err = agentSrv.SetStringValue("ElementName", "WinCryptSSHAgent")
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		utils.MessageBox("Install Service Error:", err.Error(), utils.MB_ICONERROR)
	} else {
		utils.MessageBox("Install Service Success:", "Please reboot your computer to take effect!", utils.MB_ICONINFORMATION)
	}
	return

}

func initDebugLog() {
	if os.Getenv("WCSA_DEBUG") == "1" {
		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		f, err := os.OpenFile(filepath.Join(home, "WCSA_DEBUG.log"), os.O_WRONLY|os.O_CREATE|os.O_SYNC|os.O_APPEND, 0664)
		if err != nil {
			return
		}
		err = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(f.Fd()))
		if err != nil {
			return
		}
		err = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd()))
		if err != nil {
			return
		}
		os.Stdout = f
		os.Stderr = f
	}
}

func main() {
	flag.Parse()
	utils.SetProcessSystemDpiAware()
	initDebugLog()
	if *installHVService {
		installService()
		return
	}
	// hyper-v
	hvClient := false
	hvConn, err := utils.ConnectHyperV()
	if err == nil {
		hvConn.Close()
		hvClient = true
	}

	// systray
	notifier, err := initSystray(hvClient)
	if err != nil {
		utils.MessageBox("Error:", err.Error(), utils.MB_ICONERROR)
		return
	}
	sysTray := notifier.Sys().(*notification.NotifyIcon)
	menu := NewMenu(sysTray)

	// context
	ctx, cancel := context.WithCancel(context.Background())

	capi.SetDisablePINCache(*disablePINCache)

	// agent
	var ag agent.Agent
	if hvClient {
		ag = sshagent.NewHVAgent()
	} else if *disableCapi {
		ag = sshagent.NewKeyRingAgent()
	} else {
		cag := new(sshagent.CAPIAgent)
		defer cag.Close()
		defaultAgent := sshagent.NewKeyRingAgent()
		ag = sshagent.NewWrappedAgent(defaultAgent, []agent.Agent{agent.Agent(cag)})
	}
	ctx = context.WithValue(ctx, "agent", ag)
	ctx = context.WithValue(ctx, "hv", hvClient)
	server := &sshagent.Server{
		Agent: ag,
	}

	// application
	wg := new(sync.WaitGroup)
	for _, v := range applications {
		v.Menu(menu.Register)
		wg.Add(1)
		go func(application app.Application) {
			err := application.Run(ctx, server.SSHAgentHandler)
			if err != nil {
				utils.MessageBox(application.AppId().String()+" Error:", err.Error(), utils.MB_ICONWARNING)
			}
			wg.Done()
		}(v)
	}

	// interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	// show systray
	menu.menu.Sep()
	menu.menu.Item("Quit", app.MENU_QUIT)
	err = sysTray.Add()
	if err != nil {
		utils.MessageBox("Error:", err.Error(), utils.MB_ICONERROR)
		goto cleanup
	}

	// event
	for {
		select {
		case clicked := <-sysTray.Menu:
			if clicked.ID == app.MENU_QUIT {
				goto cleanup
			}
			menu.Handle(app.AppId(clicked.ID))
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
	case <-time.After(time.Second * 5):
	case <-done:
	}
}

func initSystray(hv bool) (notify.Notifier, error) {
	icon, err := notification.LoadIcon(1)
	if err != nil {
		return nil, err
	}
	title := agentTitle
	if hv {
		title += " (Hyper-V)"
	}
	n, err := notification.NewNotifier(title, icon)
	if err != nil {
		return nil, err
	}
	n.Register("info", notification.IconInfo, map[string]interface{}{
		"windows:sound": false,
	})
	utils.RegisterNotifier(n)
	return n, nil
}
