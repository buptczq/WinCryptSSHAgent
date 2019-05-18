package utils

import (
	"github.com/hattya/go.notify"
	"syscall"
	"unsafe"
)

var (
	moduser32      = syscall.NewLazyDLL("user32.dll")
	procMessageBox = moduser32.NewProc("MessageBoxW")
	notifier       notify.Notifier
)

const (
	MB_OK                = 0x00000000
	MB_OKCANCEL          = 0x00000001
	MB_ABORTRETRYIGNORE  = 0x00000002
	MB_YESNOCANCEL       = 0x00000003
	MB_YESNO             = 0x00000004
	MB_RETRYCANCEL       = 0x00000005
	MB_CANCELTRYCONTINUE = 0x00000006
	MB_ICONHAND          = 0x00000010
	MB_ICONQUESTION      = 0x00000020
	MB_ICONEXCLAMATION   = 0x00000030
	MB_ICONASTERISK      = 0x00000040
	MB_USERICON          = 0x00000080
	MB_ICONWARNING       = MB_ICONEXCLAMATION
	MB_ICONERROR         = MB_ICONHAND
	MB_ICONINFORMATION   = MB_ICONASTERISK
	MB_ICONSTOP          = MB_ICONHAND

	MB_DEFBUTTON1 = 0x00000000
	MB_DEFBUTTON2 = 0x00000100
	MB_DEFBUTTON3 = 0x00000200
	MB_DEFBUTTON4 = 0x00000300

	IDOK     = 1
	IDCANCEL = 2
	IDABORT  = 3
	IDRETRY  = 4
	IDIGNORE = 5
	IDYES    = 6
	IDNO     = 7
)

func MessageBox(title, text string, style uintptr) int {
	pText, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return -1
	}
	pTitle, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return -1
	}
	ret, _, _ := syscall.Syscall6(procMessageBox.Addr(),
		4,
		0,
		uintptr(unsafe.Pointer(pText)),
		uintptr(unsafe.Pointer(pTitle)),
		style,
		0,
		0)
	return int(ret)
}

func Notify(title, message string) {
	if notifier == nil {
		return
	}
	notifier.Notify("info", title, message)
}

func RegisterNotifier(n notify.Notifier) {
	notifier = n
}
