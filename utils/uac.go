package utils

import (
	"golang.org/x/sys/windows"
	"os"
	"strings"
	"syscall"
)

func IsAdmin() bool {
	var adminSID *windows.SID

	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&adminSID,
	)

	if err != nil {
		return false
	}

	token := windows.Token(0)
	defer token.Close()

	member, err := token.IsMember(adminSID)
	if err != nil {
		return false
	}
	return member
}

func RunMeElevated() error {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	return windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, 1)
}

func RunMeElevatedWithArgs(args string) error {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	return windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, 1)
}
