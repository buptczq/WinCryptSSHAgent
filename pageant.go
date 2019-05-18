package main

import (
	"context"
	"io"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"sync"
)

func pageantServer(ctx context.Context, handler func(conn io.ReadWriteCloser)) error {
	win, err := utils.NewPageant()
	if err != nil {
		return err
	}
	defer win.Close()

	wg := new(sync.WaitGroup)
	for {
		conn, err := win.AcceptCtx(ctx)
		if err != nil {
			if err != io.ErrClosedPipe {
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
