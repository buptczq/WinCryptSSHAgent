package sshagent

import (
	"golang.org/x/crypto/ssh/agent"
	"io"
)

type Server struct {
	Agent agent.Agent
}

func (s *Server) SSHAgentHandler(conn io.ReadWriteCloser) {
	defer conn.Close()
	if s.Agent == nil {
		return
	}
	err := agent.ServeAgent(s.Agent, conn)
	if err != nil && err != io.EOF {
		println(err.Error())
	}
}
