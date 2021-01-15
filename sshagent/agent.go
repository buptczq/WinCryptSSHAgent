package sshagent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/buptczq/WinCryptSSHAgent/capi"
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"os"
	"sync"
)

type sshKey struct {
	cert    *capi.Certificate
	signer  ssh.Signer
	comment string
}

type CAPIAgent struct {
	mu   sync.Mutex
	keys []*sshKey
}

func (s *CAPIAgent) close() (err error) {
	for _, key := range s.keys {
		err = key.cert.Free()
	}
	s.keys = nil
	return
}

func (s *CAPIAgent) Close() (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.close()
}

func (s *CAPIAgent) loadCerts() (err error) {
	certs, err := capi.LoadUserCerts()
	if err != nil {
		return
	}
	s.keys = make([]*sshKey, 0, len(certs))

	for _, cert := range certs {
		if !FilterCertificateEKU(cert) {
			cert.Free()
			continue
		}
		pub, err := ssh.NewPublicKey(cert.PublicKey)
		if err != nil {
			cert.Free()
			continue
		}
		key := &sshKey{
			cert:    cert,
			comment: cert.Subject.CommonName,
		}
		switch pub.Type() {
		case ssh.KeyAlgoRSA:
			key.signer = &rsaSigner{
				pub:  pub,
				cert: cert,
			}
		case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
			key.signer = &ecdsaSigner{
				pub:  pub,
				cert: cert,
			}
		default:
			cert.Free()
			continue
		}
		s.keys = append(s.keys, key)
		if keyWithCert, err := loadSSHCertificate(key); err == nil {
			s.keys = append(s.keys, keyWithCert)
		}
	}
	return
}

func (s *CAPIAgent) List() (keys []*agent.Key, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.keys != nil {
		s.close()
	}
	err = s.loadCerts()
	if err != nil {
		return
	}
	var ids []*agent.Key
	for _, k := range s.keys {
		pub := k.signer.PublicKey()
		ids = append(ids, &agent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: k.comment})
	}
	return ids, nil
}

func (s *CAPIAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return s.SignWithFlags(key, data, 0)
}

func (s *CAPIAgent) signed(comment string) {
	utils.Notify(
		"Authenticated",
		"Authentication Success by Certificate <"+comment+">",
	)
}

func (s *CAPIAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if os.Getenv("WCSA_CHECKSVR") == "1" {
		if ok, err := utils.CheckSCardSvrStatus(); err == nil && !ok {
			if utils.MessageBox("Warning:", "Smart Card Service is stopped! Do you want to restart it?", utils.MB_OKCANCEL) == utils.IDOK {
				utils.StartSCardSvr()
			}
		}
	}

	if s.keys == nil {
		if err := s.loadCerts(); err != nil {
			return nil, err
		}
	}

	wanted := key.Marshal()
	for _, k := range s.keys {
		if bytes.Equal(k.signer.PublicKey().Marshal(), wanted) {
			if flags == 0 {
				sign, err := k.signer.Sign(rand.Reader, data)
				if err == nil {
					s.signed(k.comment)
				}
				return sign, err
			} else {
				if algorithmSigner, ok := k.signer.(ssh.AlgorithmSigner); !ok {
					return nil, fmt.Errorf("agent: signature does not support non-default signature algorithm: %T", k.signer)
				} else {
					var algorithm string
					switch flags {
					case agent.SignatureFlagRsaSha256:
						algorithm = ssh.SigAlgoRSASHA2256
					case agent.SignatureFlagRsaSha512:
						algorithm = ssh.SigAlgoRSASHA2512
					default:
						return nil, fmt.Errorf("agent: unsupported signature flags: %d", flags)
					}
					sign, err := algorithmSigner.SignWithAlgorithm(rand.Reader, data, algorithm)
					if err == nil {
						s.signed(k.comment)
					}
					return sign, err
				}
			}
		}
	}
	return nil, errors.New("not found")
}

func (*CAPIAgent) Add(key agent.AddedKey) error {
	return fmt.Errorf("implement me")
}

func (*CAPIAgent) Remove(key ssh.PublicKey) error {
	return fmt.Errorf("implement me")
}

func (*CAPIAgent) RemoveAll() error {
	return fmt.Errorf("implement me")
}

func (*CAPIAgent) Lock(passphrase []byte) error {
	return fmt.Errorf("implement me")
}

func (*CAPIAgent) Unlock(passphrase []byte) error {
	return fmt.Errorf("implement me")
}

func (*CAPIAgent) Signers() ([]ssh.Signer, error) {
	return nil, fmt.Errorf("implement me")
}

func (s *CAPIAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
