package utils

import (
	"golang.org/x/sys/windows"
	"syscall"
)

func GetUserSID() (*windows.SID, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}

func GetHandleSID(h windows.Handle) (*windows.SID, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	sid, _, err := sd.Owner()
	if err != nil {
		return nil, err
	}
	return sid, nil
}

func GetDefaultSID() (*windows.SID, error) {
	proc := windows.CurrentProcess()
	return GetHandleSID(proc)
}

func SetFileAttributes(path string, attr uint32) error {
	cpath, cpathErr := syscall.UTF16PtrFromString(path)
	if cpathErr != nil {
		return cpathErr
	}
	return syscall.SetFileAttributes(cpath, attr)
}
