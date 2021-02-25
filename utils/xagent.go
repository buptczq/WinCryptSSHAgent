package utils

import (
	"golang.org/x/sys/windows"
	"net"
	"syscall"
	"unsafe"
)

const (
	xAgentClassName        = "NSSSH:AGENTWND"
	xAgentSingleClassName  = "STATIC"
	xAgentSingleWindowName = "_SINGLE_INSTANCE::XAGENT"
)

var (
	pSetWindowLong = u32.NewProc("SetWindowLongW")
)

type XAgent struct {
	socket            net.Listener
	cookieWin         *window
	singleInstanceWin *window
}

type window struct {
	class  *wndClassEx
	window windows.Handle
}

func createDefaultWindow(class, name string) (*window, error) {
	classNamePtr, err := syscall.UTF16PtrFromString(class)
	if err != nil {
		return nil, err
	}

	windowNamePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}

	win := new(window)
	wcex := &wndClassEx{
		WndProc:   pDefWindowProc.Addr(),
		ClassName: classNamePtr,
	}
	err = wcex.register()
	if err != nil {
		return nil, err
	}
	win.class = wcex

	windowHandle, _, err := pCreateWindowEx.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(classNamePtr)),
		uintptr(unsafe.Pointer(windowNamePtr)),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)
	if windowHandle == 0 {
		wcex.unregister()
		return nil, err
	}
	win.window = windows.Handle(windowHandle)
	return win, nil
}

func (s *window) Close() {
	pDestroyWindow.Call(uintptr(s.window))
	s.class.unregister()
}

func NewXAgent(cookie string) (*XAgent, error) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, err
	}

	win := new(XAgent)
	win.socket = l
	cookieWin, err := createDefaultWindow(xAgentClassName, cookie)
	if err != nil {
		return nil, err
	}
	siWin, err := createDefaultWindow(xAgentSingleClassName, xAgentSingleWindowName)
	if err != nil {
		return nil, err
	}
	SetWindowLong(cookieWin.window, 0xFFFFFFEB, uintptr(l.Addr().(*net.TCPAddr).Port))
	win.cookieWin = cookieWin
	win.singleInstanceWin = siWin
	return win, nil
}

func (s *XAgent) Listener() net.Listener {
	return s.socket
}

func (s *XAgent) Close() {
	s.cookieWin.Close()
	s.singleInstanceWin.Close()
}

func SetWindowLong(hWnd windows.Handle, index, value uintptr) int32 {
	ret, _, _ := pSetWindowLong.Call(
		uintptr(hWnd),
		index,
		value,
	)
	return int32(ret)
}
