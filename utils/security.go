package utils

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

var (
	modadvapi32         = windows.NewLazySystemDLL("advapi32.dll")
	procGetSecurityInfo = modadvapi32.NewProc("GetSecurityInfo")
)

const (
	seKernelObject           = 6
	ownerSecurityInformation = 1
)

func getSecurityInfo(
	handle windows.Handle,
	objectType uint32,
	securityInformation uint32,
	ppsidOwner **windows.SID,
	ppsidGroup **windows.SID,
	ppDacl uintptr,
	ppSacl uintptr,
	ppSecurityDescriptor *windows.Handle,
) (err error) {
	r1, _, e1 := syscall.Syscall9(
		procGetSecurityInfo.Addr(),
		8,
		uintptr(handle),
		uintptr(objectType),
		uintptr(securityInformation),
		uintptr(unsafe.Pointer(ppsidOwner)),
		uintptr(unsafe.Pointer(ppsidGroup)),
		uintptr(unsafe.Pointer(ppDacl)),
		uintptr(unsafe.Pointer(ppSacl)),
		uintptr(unsafe.Pointer(ppSecurityDescriptor)),
		0,
	)
	if r1 != 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func GetUserSID() (*windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}

func GetHandleSID(h windows.Handle) (*windows.SID, error) {
	var sid, gid *windows.SID
	var psd windows.Handle
	err := getSecurityInfo(h, seKernelObject, ownerSecurityInformation, &sid, &gid, 0, 0, &psd)
	defer func() {
		if psd != 0 {
			windows.LocalFree(psd)
		}
	}()
	if err != nil {
		return nil, err
	}
	return sid, nil
}

func GetDefaultSID() (*windows.SID, error) {
	proc, err := windows.GetCurrentProcess()
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(proc)
	return GetHandleSID(proc)
}

func SetFileAttributes(path string, attr uint32) error {
	cpath, cpathErr := syscall.UTF16PtrFromString(path)
	if cpathErr != nil {
		return cpathErr
	}
	return syscall.SetFileAttributes(cpath, attr)
}
