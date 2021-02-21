package utils

import (
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/linuxkit/virtsock/pkg/hvsock"
)

const (
	servicePort          = 0x22223333
	HyperVServiceRegPath = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices`
)

var HyperVServiceGUID = winio.VsockServiceID(servicePort)

func ConnectHyperV() (net.Conn, error) {
	svcid, err := hvsock.GUIDFromString(HyperVServiceGUID.String())
	if err != nil {
		return nil, err
	}

	// use go-winio when this issue resolved.
	// see: https://github.com/microsoft/go-winio/issues/198
	conn, err := hvsock.Dial(hvsock.Addr{VMID: hvsock.GUIDParent, ServiceID: svcid})
	if err != nil {
		return nil, err
	}
	return conn, nil
}
