package app

import (
	"context"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"golang.org/x/crypto/ssh/agent"
	"io"
)

type PubKeyView struct {
	ag agent.Agent
}

func (s *PubKeyView) Run(ctx context.Context, handler func(conn io.ReadWriteCloser)) error {
	s.ag = ctx.Value("agent").(agent.Agent)
	return nil
}

func (*PubKeyView) AppId() AppId {
	return APP_PUBKEY
}

func (s *PubKeyView) Menu(register func(id AppId, name string, handler func())) {
	register(s.AppId(), "Show Public Keys", s.onClick)
}

func (s *PubKeyView) onClick() {
	keys, err := s.ag.List()
	if err != nil {
		utils.MessageBox("Error:", err.Error(), utils.MB_ICONWARNING)
		return
	}

	pubkey := ""
	for _, key := range keys {
		pubkey += key.String() + "\n"
	}

	if utils.MessageBox("Public Keys (OK to copy):", pubkey, utils.MB_OKCANCEL) == utils.IDOK {
		utils.SetClipBoard(pubkey)
	}
}
