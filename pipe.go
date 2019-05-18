package main

import (
	"context"
	"fmt"
	"github.com/Microsoft/go-winio"
	"io"
	"github.com/buptczq/WinCryptSSHAgent/common"
	"sync"
)

func namedPipeServer(ctx context.Context, handler func(conn io.ReadWriteCloser)) error {
	var cfg = &winio.PipeConfig{}
	pipe, err := winio.ListenPipe(common.NAMED_PIPE, cfg)
	if err != nil {
		return err
	}

	status := ctx.Value("status").(*common.Services)
	status.Lock()
	status.Service[common.APP_WINSSH] = &common.ServiceStatus{
		Running: true,
		Help:    fmt.Sprintf(`set SSH_AUTH_SOCK=%s`, common.NAMED_PIPE),
	}
	status.Service[common.APP_SECURECRT] = &common.ServiceStatus{
		Running: true,
		Help:    fmt.Sprintf(`setx "VANDYKE_SSH_AUTH_SOCK" "%s"`, common.NAMED_PIPE),
	}
	status.Unlock()
	defer pipe.Close()

	wg := new(sync.WaitGroup)
	// context cancelled
	go func() {
		<-ctx.Done()
		wg.Wait()
		pipe.Close()
	}()
	// loop
	for {
		conn, err := pipe.Accept()
		if err != nil {
			if err != winio.ErrPipeListenerClosed {
				return err
			}
			return nil
		}
		wg.Add(1)
		go func() {
			handler(conn)
			wg.Done()
		}()
	}
}
