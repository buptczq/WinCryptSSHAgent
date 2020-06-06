package utils

import (
	"github.com/StackExchange/wmi"
	"strings"
)

func GetVMID() []string {
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
				guids[args[i]] = 0
				break
			}
		}
	}
	results := make([]string, 0)
	for k, _ := range guids {
		results = append(results, k[1:len(k)-1])
	}
	return results
}
