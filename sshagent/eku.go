package sshagent

import (
	"crypto/x509"
	"encoding/asn1"
	"github.com/buptczq/WinCryptSSHAgent/capi"
)

var (
	oidExtKeyUsageSmartCardLogon           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
	oidExtKeyUsageBitLockerDriveEncryption = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 67, 1, 1}
	oidExtKeyUsageEncryptingFileSystem     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 4}
)

func FilterCertificateEKU(cert *capi.Certificate) bool {
	flagAny := false
	flagBitLocker := false
	flagAuth := false
	flagServerAuth := false
	for i := range cert.ExtKeyUsage {
		if cert.ExtKeyUsage[i] == x509.ExtKeyUsageAny {
			flagAny = true
		} else if cert.ExtKeyUsage[i] == x509.ExtKeyUsageClientAuth {
			flagAuth = true
		} else if cert.ExtKeyUsage[i] == x509.ExtKeyUsageServerAuth {
			flagServerAuth = true
		}
	}
	for i := range cert.UnknownExtKeyUsage {
		if cert.UnknownExtKeyUsage[i].Equal(oidExtKeyUsageSmartCardLogon) {
			flagAuth = true
		} else if cert.UnknownExtKeyUsage[i].Equal(oidExtKeyUsageBitLockerDriveEncryption) {
			flagBitLocker = true
		} else if cert.UnknownExtKeyUsage[i].Equal(oidExtKeyUsageEncryptingFileSystem) {
			flagBitLocker = true
		}
	}
	if flagAny || flagAuth {
		return true
	}
	if flagBitLocker || flagServerAuth {
		return false
	}
	return true
}

func FilterCertificateSmartCardLogon(cert *capi.Certificate) bool {
	flagClientAuth := false
	flagSmartCardLogon := false
	for i := range cert.ExtKeyUsage {
		if cert.ExtKeyUsage[i] == x509.ExtKeyUsageClientAuth {
			flagClientAuth = true
		}
	}
	for i := range cert.UnknownExtKeyUsage {
		if cert.UnknownExtKeyUsage[i].Equal(oidExtKeyUsageSmartCardLogon) {
			flagSmartCardLogon = true
		}
	}
	return flagClientAuth && flagSmartCardLogon
}
