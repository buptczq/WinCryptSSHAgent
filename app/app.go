package app

import (
	"context"
	"io"
)

const (
	WSL_SOCK    = "wincrypt-wsl.sock"
	CYGWIN_SOCK = "wincrypt-cygwin.sock"
	NAMED_PIPE  = "\\\\.\\pipe\\openssh-ssh-agent"
	APP_CYGWIN  = iota
	APP_WSL
	APP_WINSSH
	APP_SECURECRT
	APP_PAGEANT
	APP_PUBKEY
	MENU_QUIT
)

type Application interface {
	AppId() AppId
	Run(ctx context.Context, handler func(conn io.ReadWriteCloser)) error
	Menu(func(id AppId, name string, handler func()))
}

type AppId int

var appIdToName = map[AppId]string{
	APP_CYGWIN:    "Cygwin",
	APP_WSL:       "WSL",
	APP_WINSSH:    "WinSSH",
	APP_SECURECRT: "SecureCRT",
	APP_PAGEANT:   "Pageant",
}

var appIdToFullName = map[AppId]string{
	APP_CYGWIN:    "Cygwin (MinGW64 & MSYS2)",
	APP_WSL:       "Windows Subsystem for Linux",
	APP_WINSSH:    "Windows OpenSSH",
	APP_SECURECRT: "SecureCRT",
	APP_PAGEANT:   "Pageant",
}

func (id AppId) String() string {
	return appIdToName[id]
}

func (id AppId) FullName() string {
	return appIdToFullName[id]
}
