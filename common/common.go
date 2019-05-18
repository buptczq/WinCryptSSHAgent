package common

import (
	"sync"
)

const (
	WSL_SOCK    = "wincrypt-wsl.sock"
	CYGWIN_SOCK = "wincrypt-cygwin.sock"
	NAMED_PIPE  = "\\\\.\\pipe\\openssh-ssh-agent"
	APP_CYGWIN  = iota
	APP_WSL
	APP_WINSSH
	APP_SECURECRT
	MENU_QUIT
)

type AppId int

var appIdToName = map[AppId]string{
	APP_CYGWIN:    "Cygwin",
	APP_WSL:       "WSL",
	APP_WINSSH:    "WinSSH",
	APP_SECURECRT: "SecureCRT",
}

var appIdToFullName = map[AppId]string{
	APP_CYGWIN:    "Cygwin (MinGW64 & MSYS2)",
	APP_WSL:       "Windows Subsystem for Linux",
	APP_WINSSH:    "Windows OpenSSH",
	APP_SECURECRT: "SecureCRT",
}

func (id AppId) String() string {
	return appIdToName[id]
}

func (id AppId) FullName() string {
	return appIdToFullName[id]
}

type ServiceStatus struct {
	Running bool
	Help    string
}

type Services struct {
	Service map[AppId]*ServiceStatus
	sync.RWMutex
}
