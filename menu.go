package main

import (
	notification "github.com/hattya/go.notify/windows"
	"github.com/buptczq/WinCryptSSHAgent/app"
)

type Menu struct {
	menu *notification.Menu
	icon *notification.NotifyIcon
	handlers map[app.AppId]func()
}

func NewMenu(icon *notification.NotifyIcon)  *Menu{
	return &Menu{icon.CreateMenu(),icon, make(map[app.AppId]func())}
}

func (m *Menu)Register(id app.AppId, name string, handler func()){
	m.menu.Item(name, uint(id))
	m.handlers[id] = handler
}

func (m *Menu)Handle(id app.AppId){
	if handler, ok := m.handlers[id]; ok {
		handler()
	}
}

