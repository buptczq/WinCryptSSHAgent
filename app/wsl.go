package app

import (
	"context"
	"fmt"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type WSL struct {
	running bool
	help    string
}

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

func (s *WSL) Run(ctx context.Context, handler func(conn io.ReadWriteCloser)) error {
	fallback := false
	// try to listen unix sock (Win10 1803)
	path, l, err := listenUnixSock(WSL_SOCK)
	if err != nil {
		// fallback to raw tcp
		l, err = net.Listen("tcp", "localhost:0")
		fallback = true
		if err != nil {
			return err
		}
	}
	defer l.Close()

	s.running = true
	if !fallback {
		s.help = fmt.Sprintf("export SSH_AUTH_SOCK=" + winPath2Unix(path))
	} else {
		s.help = fmt.Sprintf("socat -d UNIX-LISTEN:/tmp/ssh-capi-agent.sock,reuseaddr,fork TCP:localhost:%d &\n", l.Addr().(*net.TCPAddr).Port)
		s.help += "export SSH_AUTH_SOCK=/tmp/ssh-capi-agent.sock"
	}
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

func (*WSL) AppId() AppId {
	return APP_WSL
}

func (s *WSL) Menu(register func(id AppId, name string, handler func())) {
	register(s.AppId(), s.AppId().String()+" Help", s.onClick)
}

func (s *WSL) onClick() {
	if s.running {
		if utils.MessageBox(s.AppId().FullName()+" (OK to copy):", s.help, utils.MB_OKCANCEL) == utils.IDOK {
			utils.SetClipBoard(s.help)
		}
	} else {
		utils.MessageBox("Error:", s.AppId().String()+" agent doesn't work!", utils.MB_ICONWARNING)
	}
}
