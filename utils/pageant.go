package utils

import (
	"context"
	"encoding/binary"
	"golang.org/x/sys/windows"
	"io"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	k32               = windows.NewLazySystemDLL("Kernel32.dll")
	u32               = windows.NewLazySystemDLL("User32.dll")
	pCreateWindowEx   = u32.NewProc("CreateWindowExW")
	pDefWindowProc    = u32.NewProc("DefWindowProcW")
	pDestroyWindow    = u32.NewProc("DestroyWindow")
	pRegisterClass    = u32.NewProc("RegisterClassExW")
	pUnregisterClass  = u32.NewProc("UnregisterClassW")
	pOpenFileMapping  = k32.NewProc("OpenFileMappingA")
	pDispatchMessage  = u32.NewProc("DispatchMessageW")
	pTranslateMessage = u32.NewProc("TranslateMessage")
	pGetMessage       = u32.NewProc("GetMessageW")
)

const (
	className        = "Pageant"
	agentCopydataId  = 0x804e50ba
	agentMaxMsglen   = 8192
	fileMapAllAccess = 0xf001f
	fileMapWrite     = 0x2
)

type request struct {
	data     []byte
	response chan response
}

type response struct {
	data []byte
	err  error
}

type createWindow struct {
	handle uintptr
	err    error
}

type pageantWindow struct {
	class     *wndClassEx
	window    windows.Handle
	requestCh chan request
}

func NewPageant() (*pageantWindow, error) {

	classNamePtr, err := syscall.UTF16PtrFromString(className)
	if err != nil {
		return nil, err
	}

	win := new(pageantWindow)

	wcex := &wndClassEx{
		WndProc:   windows.NewCallback(win.wndProc),
		ClassName: classNamePtr,
	}
	err = wcex.register()
	if err != nil {
		return nil, err
	}
	win.class = wcex
	ch := make(chan createWindow)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		windowHandle, _, err := pCreateWindowEx.Call(
			uintptr(0),
			uintptr(unsafe.Pointer(classNamePtr)),
			uintptr(unsafe.Pointer(classNamePtr)),
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
		ch <- createWindow{windowHandle, err}
		if windowHandle != 0 {
			eventLoop(windowHandle)
		}
	}()
	result := <-ch
	if result.handle == 0 {
		wcex.unregister()
		return nil, err
	}
	win.window = windows.Handle(result.handle)
	win.requestCh = make(chan request)
	return win, nil
}

func (s *pageantWindow) AcceptCtx(ctx context.Context) (io.ReadWriteCloser, error) {
	select {
	case req := <-s.requestCh:
		return &memoryMapConn{req: req}, nil
	case <-ctx.Done():
		return nil, io.ErrClosedPipe
	}
}

func (s *pageantWindow) Close() {
	pDestroyWindow.Call(uintptr(s.window))
	s.class.unregister()
}

func eventLoop(window uintptr) {
	m := &struct {
		WindowHandle windows.Handle
		Message      uint32
		Wparam       uintptr
		Lparam       uintptr
		Time         uint32
		Pt           point
	}{}
	for {
		ret, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(m)), window, 0, 0)

		// If the function retrieves a message other than WM_QUIT, the return value is nonzero.
		// If the function retrieves the WM_QUIT message, the return value is zero.
		// If there is an error, the return value is -1
		// https://msdn.microsoft.com/en-us/library/windows/desktop/ms644936(v=vs.85).aspx
		switch int32(ret) {
		case -1:
			return
		case 0:
			return
		default:
			pTranslateMessage.Call(uintptr(unsafe.Pointer(m)))
			pDispatchMessage.Call(uintptr(unsafe.Pointer(m)))
		}
	}
}

// WindowProc callback function that processes messages sent to a window.
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms633573(v=vs.85).aspx
func (s *pageantWindow) wndProc(hWnd windows.Handle, message uint32, wParam, lParam uintptr) (lResult uintptr) {
	const (
		WM_COPYDATA = 0x004A
	)
	if message != WM_COPYDATA {
		lResult, _, _ = pDefWindowProc.Call(
			uintptr(hWnd),
			uintptr(message),
			uintptr(wParam),
			uintptr(lParam),
		)
		return
	}
	copyData := (*copyDataStruct)(unsafe.Pointer(lParam))
	if copyData.dwData != agentCopydataId {
		return 0
	}
	fileMap, err := OpenFileMapping(fileMapAllAccess, 0, copyData.lpData)
	if err != nil {
		return
	}
	defer func() {
		windows.CloseHandle(fileMap)
	}()
	// check security
	ourself, err := GetUserSID()
	if err != nil {
		return
	}
	ourself2, err := GetDefaultSID()
	if err != nil {
		return
	}
	mapOwner, err := GetHandleSID(fileMap)
	if err != nil {
		return
	}
	if !windows.EqualSid(mapOwner, ourself) && !windows.EqualSid(mapOwner, ourself2) {
		return
	}
	// get map view
	sharedMemory, err := windows.MapViewOfFile(fileMap, fileMapWrite, 0, 0, 0)
	if err != nil {
		return
	}
	defer windows.UnmapViewOfFile(sharedMemory)
	sharedMemoryArray := (*[agentMaxMsglen]byte)(unsafe.Pointer(sharedMemory))
	// check buffer size
	size := binary.BigEndian.Uint32(sharedMemoryArray[:4])
	size += 4
	if size > agentMaxMsglen {
		return
	}

	// send data to handler
	data := make([]byte, size)
	copy(data, sharedMemoryArray[:size])
	ch := make(chan response)
	s.requestCh <- request{data, ch}
	// wait for response
	resp := <-ch
	if resp.err == nil {
		copy(sharedMemoryArray[:], resp.data)
		return 1
	}
	return
}
