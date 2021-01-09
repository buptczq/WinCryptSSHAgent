package utils

import "syscall"

var (
	shcore                 = syscall.NewLazyDLL("Shcore.dll")
	setProcessDpiAwareness = shcore.NewProc("SetProcessDpiAwareness")
)

func SetProcessSystemDpiAware() error {
	if err := setProcessDpiAwareness.Find(); err != nil {
		return err
	}
	_, _, err := setProcessDpiAwareness.Call(uintptr(1))
	return err
}
