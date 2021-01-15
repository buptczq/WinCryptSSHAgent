package utils

import "syscall"

var (
	shcore                 = syscall.NewLazyDLL("Shcore.dll")
	setProcessDpiAwareness = shcore.NewProc("SetProcessDpiAwareness")
)

func SetProcessSystemDpiAware() error {
	if setProcessDpiAwarenessContext, err := user32.FindProc("SetProcessDpiAwarenessContext"); err == nil {
		// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
		var DPI_AWARENESS_CONTEXT uintptr = 0
		r0, _, _ := setProcessDpiAwarenessContext.Call(DPI_AWARENESS_CONTEXT - 4)
		if r0 == 1 {
			return nil
		}
	}
	if err := setProcessDpiAwareness.Find(); err == nil {
		// PROCESS_SYSTEM_DPI_AWARE
		r0, _, err := setProcessDpiAwareness.Call(uintptr(1))
		if r0 == 1 {
			return nil
		}
		return err
	}
	if setProcessDpiAware, err := user32.FindProc("SetProcessDPIAware"); err == nil {
		r0, _, err := setProcessDpiAware.Call()
		if r0 == 1 {
			return nil
		}
		return err
	}
	return nil
}
