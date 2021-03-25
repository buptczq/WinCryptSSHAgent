package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"sync"
)

const (
	maxAgentResponseBytes = 16 << 20
	agentSignRequest      = 13
)

type XShell struct {
	cookie string
}

func (s *XShell) Run(ctx context.Context, handler func(conn io.ReadWriteCloser)) error {
	s.cookie = utils.RandomString(7)
	win, err := utils.NewXAgent(s.cookie)
	if err != nil {
		return err
	}
	defer win.Close()

	wg := new(sync.WaitGroup)
	l := win.Listener()
	for {
		conn, err := l.Accept()
		if err != nil {
			if err != io.ErrClosedPipe {
				return err
			}
			return nil
		}
		err = xshellHandshake(conn, s.cookie)
		if err != nil {
			println(err.Error())
			conn.Close()
			continue
		}
		wg.Add(1)
		go func(c io.ReadWriteCloser) {
			w := &xshellProxy{conn: c}
			handler(w)
			wg.Done()
		}(conn)
	}
}

func (*XShell) AppId() AppId {
	return APP_XSHELL
}

func (s *XShell) Menu(register func(id AppId, name string, handler func())) {
}

type initAgentMsg struct {
	Flag   uint32 `sshtype:"99"`
	Length uint32
	Cookie []byte `ssh:"rest"`
}

type initAgentRepMsg struct {
	Flag uint32 `sshtype:"99"`
}

func xshellHandshake(conn net.Conn, cookie string) error {
	var length [4]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return err
	}
	l := binary.BigEndian.Uint32(length[:]) + 4
	if l > maxAgentResponseBytes {
		return fmt.Errorf("xagent: request too large: %d", l)
	}

	req := make([]byte, l)
	if _, err := io.ReadFull(conn, req); err != nil {
		return err
	}
	if req[0] != 99 {
		return fmt.Errorf("xagent: unknown opcode: %d", req[0])
	}

	var initMsg initAgentMsg
	if err := ssh.Unmarshal(req, &initMsg); err != nil {
		return err
	}
	if int(initMsg.Length) != len(cookie) {
		return fmt.Errorf("xagent: invalid cookie length")
	}
	if int(initMsg.Length) < len(initMsg.Cookie) {
		return fmt.Errorf("xagent: invalid message length")
	}

	cookieRemain := make([]byte, int(initMsg.Length)-len(initMsg.Cookie))
	if _, err := io.ReadFull(conn, cookieRemain); err != nil {
		return err
	}
	cookieReq := string(initMsg.Cookie) + string(cookieRemain)
	if cookieReq != cookie {
		return fmt.Errorf("xagent: invalid cookie")
	}
	var repMsg initAgentRepMsg
	repMsg.Flag = initMsg.Flag
	rep := ssh.Marshal(&repMsg)
	buf := bytes.NewBuffer(nil)
	err := binary.Write(buf, binary.BigEndian, uint32(len(rep)))
	if err != nil {
		return err
	}
	_, err = buf.Write(rep)
	if err != nil {
		return err
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

type xshellProxy struct {
	conn    io.ReadWriteCloser
	buf     []byte
	wlength int
	wbuf    []byte
}

type signRequestAgentMsg struct {
	KeyBlob []byte `sshtype:"13"`
	Data    []byte
	Flags   uint32
}

func (s *xshellProxy) Read(p []byte) (n int, err error) {
	if len(s.buf) > 0 {
		n := copy(p, s.buf)
		s.buf = s.buf[n:]
		return n, nil
	}
	var length [4]byte
	if _, err := io.ReadFull(s.conn, length[:]); err != nil {
		return 0, err
	}
	l := binary.BigEndian.Uint32(length[:])
	if l == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if l > maxAgentResponseBytes {
		return 0, fmt.Errorf("xagent: request too large: %d", l)
	}

	s.buf = make([]byte, 4+l, 8+l)
	if _, err := io.ReadFull(s.conn, s.buf[4:]); err != nil {
		return 0, err
	}
	// sign
	if s.buf[4] == agentSignRequest {
		var req signRequestAgentMsg
		if err := ssh.Unmarshal(s.buf[4:], &req); err != nil {
			l += 4
			s.buf = append(s.buf, []byte{0, 0, 0, 0}...)
		}
	}
	binary.BigEndian.PutUint32(s.buf, l)
	n = copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

func (s *xshellProxy) Write(p []byte) (n int, err error) {
	// xshell treats TCP as a message-oriented connection
	// this piece of sh*t code is in order to be compatible with xshell
	if s.wlength == 0 {
		if len(p) != 4 {
			return 0, fmt.Errorf("xagent proxy: invalid write status")
		}
		s.wlength = int(binary.BigEndian.Uint32(p)) + 4
		s.wbuf = append(s.wbuf, p...)
	} else {
		s.wbuf = append(s.wbuf, p...)
		if len(s.wbuf) == s.wlength {
			s.wlength = 0
			_, err := s.conn.Write(s.wbuf)
			if err != nil {
				return 0, err
			}
			s.wbuf = nil
		} else if len(s.wbuf) > s.wlength {
			return 0, fmt.Errorf("xagent proxy: invalid write length")
		}
	}
	return len(p), nil
}

func (s *xshellProxy) Close() error {
	return s.conn.Close()
}
