package utils

import (
	"bytes"
	"golang.org/x/sys/windows"
	"io"
	"sync"
)

func OpenFileMapping(dwDesiredAccess uint32, bInheritHandle uintptr, mapNamePtr uintptr) (windows.Handle, error) {
	ptr, _, err := pOpenFileMapping.Call(uintptr(dwDesiredAccess), bInheritHandle, mapNamePtr)
	if err != nil && err.Error() == "The operation completed successfully." {
		err = nil
	}
	return windows.Handle(ptr), err
}

type memoryMapConn struct {
	req    request
	offset int
	w      bytes.Buffer
	closed bool
	sync.Mutex
}

func (m *memoryMapConn) Read(p []byte) (n int, err error) {
	m.Lock()
	defer m.Unlock()
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	if m.offset >= len(m.req.data) {
		return 0, io.EOF
	}
	n = copy(p, m.req.data[m.offset:])
	m.offset += n
	return
}

func (m *memoryMapConn) Write(p []byte) (n int, err error) {
	m.Lock()
	defer m.Unlock()
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	return m.w.Write(p)
}

func (m *memoryMapConn) Close() error {
	m.Lock()
	defer m.Unlock()
	if m.closed {
		return io.ErrClosedPipe
	}
	if !m.closed {
		if m.w.Len() > 0 {
			m.req.response <- response{m.w.Bytes(), nil}
		} else {
			m.req.response <- response{err: io.ErrUnexpectedEOF}
		}
	}
	return nil
}
