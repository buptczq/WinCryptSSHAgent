package capi

import (
	"crypto/x509"
	"fmt"
	"github.com/fullsailor/pkcs7"
	"syscall"
	"unsafe"
)

const (
	ALG_RSA_SHA1RSA     = "1.2.840.113549.1.1.5"
	ALG_RSA_SHA256RSA   = "1.2.840.113549.1.1.11"
	ALG_RSA_SHA384RSA   = "1.2.840.113549.1.1.12"
	ALG_RSA_SHA512RSA   = "1.2.840.113549.1.1.13"
	ALG_ECDSA_SHA1      = "1.2.840.10045.4.1"
	ALG_ECDSA_SPECIFIED = "1.2.840.10045.4.3"
	ALG_ECDSA_SHA256    = "1.2.840.10045.4.3.2"
	ALG_ECDSA_SHA384    = "1.2.840.10045.4.3.3"
	ALG_ECDSA_SHA512    = "1.2.840.10045.4.3.4"
)

var (
	modcrypt32                          = syscall.NewLazyDLL("crypt32.dll")
	procCryptSignMessage                = modcrypt32.NewProc("CryptSignMessage")
	procCertDuplicateCertificateContext = modcrypt32.NewProc("CertDuplicateCertificateContext")
)

type cryptoapiBlob struct {
	DataSize uint32
	Data     uintptr
}

type cryptAlgorithmIdentifier struct {
	ObjId      uintptr
	Parameters cryptoapiBlob
}

type cryptSignMessagePara struct {
	CbSize                  uint32
	MsgEncodingType         uint32
	SigningCert             uintptr
	HashAlgorithm           cryptAlgorithmIdentifier
	HashAuxInfo             uintptr
	MsgCertSize             uint32
	MsgCert                 uintptr
	MsgCrlSize              uint32
	MsgCrl                  uintptr
	AuthAttrSize            uint32
	AuthAttr                uintptr
	UnauthAttrSize          uint32
	UnauthAttr              uintptr
	Flags                   uint32
	InnerContentType        uint32
	HashEncryptionAlgorithm cryptAlgorithmIdentifier
	HashEncryptionAuxInfo   uintptr
}

func cryptSignMessage(para *cryptSignMessagePara, data []byte) (sign []byte, err error) {
	dataPtr := uintptr(unsafe.Pointer(&data[0]))
	dataSize := uint32(len(data))
	dataSizePtr := uintptr(unsafe.Pointer(&dataSize))
	result := make([]byte, 0x2000)
	size := uint32(0x2000)
	sizePtr := uintptr(unsafe.Pointer(&size))
	resultPtr := uintptr(unsafe.Pointer(&result[0]))
	r0, _, e1 := syscall.Syscall9(
		procCryptSignMessage.Addr(),
		7,
		uintptr(unsafe.Pointer(para)),
		1,
		1,
		uintptr(unsafe.Pointer(&dataPtr)),
		dataSizePtr,
		resultPtr,
		sizePtr,
		0,
		0,
	)
	if e1 != syscall.Errno(0) {
		return nil, e1
	}
	if r0 == 0 {
		return nil, fmt.Errorf("failed to sign")
	}
	return result[:size], nil
}

func certDuplicateCertificateContext(context *syscall.CertContext) (uintptr, error) {
	r0, _, e1 := syscall.Syscall(procCertDuplicateCertificateContext.Addr(), 1, uintptr(unsafe.Pointer(context)), 0, 0)
	if e1 != syscall.Errno(0) {
		return 0, e1
	}
	return r0, nil
}

type Certificate struct {
	certContext uintptr
	*x509.Certificate
}

func (s *Certificate) Free() error {
	return syscall.CertFreeCertificateContext((*syscall.CertContext)(unsafe.Pointer(s.certContext)))
}

func (s *Certificate) Copy() (*Certificate, error) {
	context := (*syscall.CertContext)(unsafe.Pointer(s.certContext))
	certContext, err := certDuplicateCertificateContext(context)
	if err != nil {
		return nil, err
	}
	return &Certificate{
		certContext: certContext,
		Certificate: s.Certificate,
	}, nil
}

func LoadUserCerts() ([]*Certificate, error) {
	const (
		CERT_STORE_PROV_SYSTEM_A       = 9
		CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
		CERT_STORE_READONLY_FLAG       = 0x00008000
		CRYPT_E_NOT_FOUND              = 0x80092004
	)
	ptr, _ := syscall.BytePtrFromString("My")
	store, err := syscall.CertOpenStore(
		CERT_STORE_PROV_SYSTEM_A,
		0,
		0,
		CERT_SYSTEM_STORE_CURRENT_USER|CERT_STORE_READONLY_FLAG,
		uintptr(unsafe.Pointer(ptr)),
	)
	if err != nil {
		return nil, err
	}
	defer syscall.CertCloseStore(store, 0)

	certs := make([]*Certificate, 0)
	var cert *syscall.CertContext
	for {
		cert, err = syscall.CertEnumCertificatesInStore(store, cert)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if errno == CRYPT_E_NOT_FOUND {
					break
				}
			}
			return nil, err
		}
		if cert == nil {
			break
		}
		// Copy the buf, since ParseCertificate does not create its own copy.
		buf := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:]
		buf2 := make([]byte, cert.Length)
		copy(buf2, buf)
		if c, err := x509.ParseCertificate(buf2); err == nil {
			cc, err := certDuplicateCertificateContext(cert)
			if err != nil {
				continue
			}
			certs = append(certs, &Certificate{
				cc,
				c,
			})
		}
	}
	return certs, nil
}

func Sign(alg string, cert *Certificate, data []byte) (*pkcs7.PKCS7, error) {
	const (
		X509_ASN_ENCODING   = 0x1
		PKCS_7_ASN_ENCODING = 0x10000
	)
	algptr, err := syscall.BytePtrFromString(alg)
	if err != nil {
		return nil, err
	}
	sign, err := cryptSignMessage(&cryptSignMessagePara{
		CbSize:                  uint32(unsafe.Sizeof(cryptSignMessagePara{})),
		MsgEncodingType:         X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		SigningCert:             cert.certContext,
		HashAlgorithm:           cryptAlgorithmIdentifier{ObjId: uintptr(unsafe.Pointer(algptr))},
		HashEncryptionAlgorithm: cryptAlgorithmIdentifier{ObjId: uintptr(unsafe.Pointer(algptr))},
	}, data)
	if err != nil {
		return nil, err
	}
	return pkcs7.Parse(sign)
}
