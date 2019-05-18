package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"github.com/buptczq/WinCryptSSHAgent/common"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"strings"
	"sync"
	"time"
)

func listenUnixSock(filename string) (string, net.Listener, error) {
	path, err := filepath.Abs(filename)
	if err != nil {
		return "", nil, err
	}
	os.Remove(path)
	l, err := net.Listen("unix", path)
	return path, l, err
}

func winPath2Unix(path string) string {
	volumeName := filepath.VolumeName(path)
	vnl := len(volumeName)
	fileName := path[vnl:]
	if vnl == 2 {
		return "/mnt/" + strings.ToLower(string(volumeName[0])) + filepath.ToSlash(fileName)
	} else {
		return filepath.ToSlash(path)
	}
}

func wslServer(ctx context.Context, handler func(conn io.ReadWriteCloser)) error {
	fallback := false
	// try to listen unix sock (Win10 1803)
	path, l, err := listenUnixSock(common.WSL_SOCK)
	if err != nil {
		// fallback to raw tcp
		l, err = net.Listen("tcp", "localhost:0")
		fallback = true
		if err != nil {
			return err
		}
	}
	defer l.Close()
	status := ctx.Value("status").(*common.Services)
	status.Lock()
	s := &common.ServiceStatus{
		Running: true,
	}
	status.Service[common.APP_WSL] = s
	if !fallback {
		s.Help = fmt.Sprintf("export SSH_AUTH_SOCK=" + winPath2Unix(path))
	} else {
		s.Help = fmt.Sprintf("socat -d UNIX-LISTEN:/tmp/ssh-capi-agent.sock,reuseaddr,fork TCP:localhost:%d &\n", l.Addr().(*net.TCPAddr).Port)
		s.Help += "export SSH_AUTH_SOCK=/tmp/ssh-capi-agent.sock"
	}
	status.Unlock()
	// loop
	wg := new(sync.WaitGroup)
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		default:
		}
		utils.SetListenerDeadline(l, time.Now().Add(time.Second))
		conn, err := l.Accept()
		if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
			continue
		}
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			handler(conn)
			wg.Done()
		}()
	}
}
