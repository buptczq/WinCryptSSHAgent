package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"sync"
	"syscall"
	"time"
)

type Cygwin struct {
	running bool
	sockfile string
}

func createCygwinSocket(filename string, port int) ([]byte, error) {
	os.Remove(filename)
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, err
	}
	var uuid [16]byte
	_, err = rand.Read(uuid[:])
	if err != nil {
		return nil, err
	}
	file.WriteString(fmt.Sprintf("!<socket >%d s %s", port, utils.UUIDToString(uuid)))
	file.Close()
	if err := utils.SetFileAttributes(filename, syscall.FILE_ATTRIBUTE_SYSTEM|syscall.FILE_ATTRIBUTE_READONLY); err != nil {
		return nil, err
	}
	return uuid[:], nil
}

func cygwinHandshake(conn net.Conn, uuid []byte) error {
	var cuuid [16]byte
	_, err := conn.Read(cuuid[:])
	if err != nil {
		return err
	}
	if !bytes.Equal(uuid[:], cuuid[:]) {
		return fmt.Errorf("invalid uuid")
	}
	conn.Write(uuid[:])
	pidsUids := make([]byte, 12)
	_, err = conn.Read(pidsUids[:])
	if err != nil {
		return err
	}
	pid := os.Getpid()
	gid := pid // for cygwin's AF_UNIX -> AF_INET, pid = gid
	binary.LittleEndian.PutUint32(pidsUids, uint32(pid))
	binary.LittleEndian.PutUint32(pidsUids[8:], uint32(gid))
	if _, err = conn.Write(pidsUids); err != nil {
		return err
	}
	return nil
}


func (s *Cygwin)Run(ctx context.Context, handler func(conn io.ReadWriteCloser)) error {
	sockfile, err := filepath.Abs(CYGWIN_SOCK)
	if err != nil {
		return err
	}
	s.sockfile = sockfile
	// listen tcp socket
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return err
	}
	defer func() {
		defer l.Close()
		os.Remove(sockfile)
	}()
	// cygwin socket uuid
	port := l.Addr().(*net.TCPAddr).Port
	uuid, err := createCygwinSocket(sockfile, port)
	if err != nil {
		return err
	}
	s.running = true
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
		err = cygwinHandshake(conn, uuid)
		if err != nil {
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			handler(conn)
			wg.Done()
		}()
	}
}

func (*Cygwin)AppId() AppId {
	return APP_CYGWIN
}

func (s *Cygwin)Menu(register func(id AppId, name string, handler func())){
	register(s.AppId(), s.AppId().String() + " Help", s.onClick)
}

func (s *Cygwin)onClick()  {
	if s.running {
		help := fmt.Sprintf(`export SSH_AUTH_SOCK="%s"`, s.sockfile)
		if utils.MessageBox(s.AppId().FullName()+" (OK to copy):", help, utils.MB_OKCANCEL) == utils.IDOK {
			utils.SetClipBoard(help)
		}
	} else {
		utils.MessageBox("Error:", s.AppId().String()+" agent doesn't work!", utils.MB_ICONWARNING)
	}
}
