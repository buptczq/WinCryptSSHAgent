package main

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
	"github.com/buptczq/WinCryptSSHAgent/common"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"sync"
	"syscall"
	"time"
)

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

func cygwinSocketServer(ctx context.Context, handler func(conn io.ReadWriteCloser)) error {
	sockfile, err := filepath.Abs(common.CYGWIN_SOCK)
	if err != nil {
		return err
	}
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
	status := ctx.Value("status").(*common.Services)
	status.Lock()
	status.Service[common.APP_CYGWIN] = &common.ServiceStatus{
		Running: true,
		Help:    fmt.Sprintf(`export SSH_AUTH_SOCK="%s"`, sockfile),
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
