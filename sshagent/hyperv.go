package sshagent

import (
	"fmt"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type HVAgent struct {
}

func NewHVAgent() *HVAgent {
	return &HVAgent{}
}

func (s *HVAgent) List() ([]*agent.Key, error) {
	conn, err := utils.ConnectHyperV()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	proxy := agent.NewClient(conn)
	return proxy.List()
}

func (s *HVAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	conn, err := utils.ConnectHyperV()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	proxy := agent.NewClient(conn)
	return proxy.Sign(key, data)
}

func (s *HVAgent) Add(key agent.AddedKey) error {
	return fmt.Errorf("implement me")
}

func (s *HVAgent) Remove(key ssh.PublicKey) error {
	return fmt.Errorf("implement me")
}

func (s *HVAgent) RemoveAll() error {
	return fmt.Errorf("implement me")
}

func (s *HVAgent) Lock(passphrase []byte) error {
	return fmt.Errorf("implement me")
}

func (s *HVAgent) Unlock(passphrase []byte) error {
	return fmt.Errorf("implement me")
}

func (s *HVAgent) Signers() ([]ssh.Signer, error) {
	return nil, fmt.Errorf("implement me")
}
