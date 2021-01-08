package utils

import (
	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows"
	"os"
	"syscall"
)

func CheckSCardSvrStatus() (bool, error) {
	type Win32_Service struct {
		State string
	}
	var services []Win32_Service
	q := wmi.CreateQuery(&services, "WHERE Name='SCardSvr'")
	err := wmi.Query(q, &services)
	if err != nil {
		return false, err
	}
	if len(services) > 0 && services[0].State == "Running" {
		return true, nil
	}
	return false, nil
}

func StartSCardSvr() error {
	cwd, _ := os.Getwd()
	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString("net")
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString("start scardsvr")

	return windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, 0)
}
