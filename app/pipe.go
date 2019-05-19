package app

import (
	"context"
	"fmt"
	"github.com/Microsoft/go-winio"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"io"
	"sync"
)

type NamedPipe struct {
	running bool
}

func (s *NamedPipe) Run(ctx context.Context, handler func(conn io.ReadWriteCloser)) error {
	var cfg = &winio.PipeConfig{}
	pipe, err := winio.ListenPipe(NAMED_PIPE, cfg)
	if err != nil {
		return err
	}

	s.running = true
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

func (*NamedPipe) AppId() AppId {
	return APP_WINSSH
}

func (s *NamedPipe) Menu(register func(id AppId, name string, handler func())) {
	register(s.AppId(), s.AppId().String()+" Help", s.onClick)
	app := AppId(APP_SECURECRT)
	register(app, app.String()+" Help", s.onClickSC)
}

func (s *NamedPipe) onClick() {
	if s.running {
		help := fmt.Sprintf(`set SSH_AUTH_SOCK=%s`, NAMED_PIPE)
		if utils.MessageBox(s.AppId().FullName()+" (OK to copy):", help, utils.MB_OKCANCEL) == utils.IDOK {
			utils.SetClipBoard(help)
		}
	} else {
		utils.MessageBox("Error:", s.AppId().String()+" agent doesn't work!", utils.MB_ICONWARNING)
	}
}

func (s *NamedPipe) onClickSC() {
	if s.running {
		help := fmt.Sprintf(`setx "VANDYKE_SSH_AUTH_SOCK" "%s"`, NAMED_PIPE)
		if utils.MessageBox(s.AppId().FullName()+" (OK to copy):", help, utils.MB_OKCANCEL) == utils.IDOK {
			utils.SetClipBoard(help)
		}
	} else {
		utils.MessageBox("Error:", s.AppId().String()+" agent doesn't work!", utils.MB_ICONWARNING)
	}
}
