package sshagent

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
)

func loadCertFile(filename string) (*ssh.Certificate, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, err
	}
	if cert, ok := pub.(*ssh.Certificate); ok {
		return cert, nil
	}
	return nil, errors.New("invalid openssh certificate")
}

func loadSSHCertificate(key *sshKey) (*sshKey, error) {
	filename := fmt.Sprintf("%s-cert.pub", key.cert.SerialNumber.String())
	cert, err := loadCertFile(filename)
	if err != nil {
		filename = fmt.Sprintf("%s-cert.pub", key.comment)
		cert, err = loadCertFile(filename)
	}
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewCertSigner(cert, key.signer)
	if err != nil {
		return nil, err
	}
	newX509Cert, err := key.cert.Copy()
	if err != nil {
		return nil, err
	}
	return &sshKey{
		cert:    newX509Cert,
		signer:  signer,
		comment: cert.KeyId,
	}, nil
}
