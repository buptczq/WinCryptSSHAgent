package sshagent

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"github.com/buptczq/WinCryptSSHAgent/capi"
)

type rsaSigner struct {
	pub  ssh.PublicKey
	cert *capi.Certificate
}

func (s *rsaSigner) PublicKey() ssh.PublicKey {
	return s.pub
}

func (s *rsaSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data, "")
}

func (s *rsaSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	capiAlg := ""
	switch algorithm {
	case "", ssh.SigAlgoRSA:
		algorithm = ssh.SigAlgoRSA
		capiAlg = capi.ALG_RSA_SHA1RSA
	case ssh.SigAlgoRSASHA2256:
		capiAlg = capi.ALG_RSA_SHA256RSA
	case ssh.SigAlgoRSASHA2512:
		capiAlg = capi.ALG_RSA_SHA512RSA
	default:
		return nil, fmt.Errorf("ssh: unsupported signature algorithm %s", algorithm)
	}
	p7, err := capi.Sign(capiAlg, s.cert, data)
	if err != nil || len(p7.Signers) < 1 {
		return nil, err
	}
	return &ssh.Signature{
		Format: algorithm,
		Blob:   p7.Signers[0].EncryptedDigest,
	}, nil
}
