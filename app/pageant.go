package app

import (
	"context"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"io"
	"sync"
)

type Pageant struct{}

func (*Pageant) Run(ctx context.Context, handler func(conn io.ReadWriteCloser)) error {
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

func (*Pageant) AppId() AppId {
	return APP_PAGEANT
}

func (s *Pageant) Menu(register func(id AppId, name string, handler func())) {
}
