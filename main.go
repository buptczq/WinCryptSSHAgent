package main

//go:generate goversioninfo -icon=assets/icon.ico

import (
	"context"
	"github.com/buptczq/WinCryptSSHAgent/app"
	"github.com/buptczq/WinCryptSSHAgent/sshagent"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"github.com/hattya/go.notify"
	notification "github.com/hattya/go.notify/windows"
	"golang.org/x/crypto/ssh/agent"
	"os"
	"os/signal"
	"sync"
	"time"
)

var applications = []app.Application{
	new(app.PubKeyView),
	new(app.WSL),
	new(app.Cygwin),
	new(app.NamedPipe),
	new(app.Pageant),
	new(app.VSock),
}

func main() {
	// hyper-v
	hvClient := false
	hvConn, err := utils.ConnectHyperV()
	if err == nil {
		defer hvConn.Close()
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

	// agent
	var ag agent.Agent
	if hvClient {
		ag = sshagent.NewHVAgent(hvConn)
	} else {
		cag := new(sshagent.CAPIAgent)
		defer cag.Close()
		ag = cag
	}
	ctx = context.WithValue(ctx, "agent", ag)
	ctx = context.WithValue(ctx, "hv", hvClient)
	server := &sshagent.Server{ag}

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
	quit := make(chan os.Signal)
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
	case <-time.NewTimer(time.Second * 10).C:
	case <-done:
	}
}

func initSystray(hv bool) (notify.Notifier, error) {
	icon, err := notification.LoadIcon(1)
	if err != nil {
		return nil, err
	}
	title := "WinCrypt SSH Agent"
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
