package sshagent

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
	"sync"
)

type HVAgent struct {
	mu    sync.Mutex
	proxy agent.Agent
}

func NewHVAgent(conn net.Conn) *HVAgent {
	return &HVAgent{proxy: agent.NewClient(conn)}
}

func (s *HVAgent) List() ([]*agent.Key, error) {
	return s.proxy.List()
}

func (s *HVAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return s.proxy.Sign(key, data)
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
