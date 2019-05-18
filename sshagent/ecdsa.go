package sshagent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"golang.org/x/crypto/ssh"
	"io"
	"math/big"
	"github.com/buptczq/WinCryptSSHAgent/capi"
)

type ecdsaSigner struct {
	pub  ssh.PublicKey
	cert *capi.Certificate
}

func (s *ecdsaSigner) PublicKey() ssh.PublicKey {
	return s.pub
}

func (s *ecdsaSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	pubkey := s.cert.PublicKey.(*ecdsa.PublicKey)
	capiAlg := ecAlg(pubkey.Curve)
	p7, err := capi.Sign(capiAlg, s.cert, data)
	if err != nil || len(p7.Signers) < 1 {
		return nil, err
	}

	type asn1Signature struct {
		R, S *big.Int
	}
	asn1Sig := new(asn1Signature)
	_, err = asn1.Unmarshal(p7.Signers[0].EncryptedDigest, asn1Sig)
	if err != nil {
		return nil, err
	}
	return &ssh.Signature{
		Format: s.pub.Type(),
		Blob:   ssh.Marshal(asn1Sig),
	}, nil
}

func ecAlg(curve elliptic.Curve) string {
	bitSize := curve.Params().BitSize
	switch {
	case bitSize <= 256:
		return capi.ALG_ECDSA_SHA256
	case bitSize <= 384:
		return capi.ALG_ECDSA_SHA384
	}
	return capi.ALG_ECDSA_SHA512
}
