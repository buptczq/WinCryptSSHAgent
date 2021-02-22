package utils

import (
	"strings"
	"syscall"

	"github.com/bi-zone/wmi"
	"golang.org/x/sys/windows/registry"
)

const afHvSock = 34      // AF_HYPERV
const sHvProtocolRaw = 1 // HV_PROTOCOL_RAW

func CheckHVService() bool {
	gcs, err := registry.OpenKey(registry.LOCAL_MACHINE, HyperVServiceRegPath, registry.READ)
	if err != nil {
		return false
	}
	defer gcs.Close()

	agentSrv, err := registry.OpenKey(gcs, HyperVServiceGUID.String(), registry.READ)
	if err != nil {
		return false
	}
	agentSrv.Close()
	return true
}

func GetVMIDs() []string {
	type Win32_Process struct {
		CommandLine string
	}
	var processes []Win32_Process
	q := wmi.CreateQuery(&processes, "WHERE Name='wslhost.exe'")
	err := wmi.Query(q, &processes)
	if err != nil {
		return nil
	}

	guids := make(map[string]interface{})

	for _, v := range processes {
		args := strings.Split(v.CommandLine, " ")
		for i := len(args) - 1; i >= 0; i-- {
			if strings.Contains(args[i], "{") {
				guids[args[i]] = nil
				break
			}
		}
	}

	results := make([]string, 0)
	for k := range guids {
		results = append(results, k[1:len(k)-1])
	}
	return results
}

func CheckHvSocket() bool {
	fd, err := syscall.Socket(afHvSock, syscall.SOCK_STREAM, sHvProtocolRaw)
	if err != nil {
		println(err.Error())
		return false
	}
	syscall.Close(fd)
	return true
}
