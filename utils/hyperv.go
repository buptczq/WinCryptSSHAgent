package utils

import (
	"github.com/Microsoft/go-winio"
	"github.com/linuxkit/virtsock/pkg/hvsock"
	"github.com/linuxkit/virtsock/pkg/vsock"
	"net"
)

const ServicePort = 0x22223333

func ConnectHyperV() (net.Conn, error) {
	agentSrvGUID := winio.VsockServiceID(ServicePort)
	svcid, err := hvsock.GUIDFromString(agentSrvGUID.String())
	if err != nil {
		return nil, err
	}
	// Check which version of Hyper-V socket bindings to use
	if hvsock.Supported() {
		// Use old interface
		conn, err := hvsock.Dial(hvsock.Addr{VMID: hvsock.GUIDParent, ServiceID: svcid})
		if err != nil {
			return nil, err
		}
		return conn, nil
	} else {
		// Use new interface
		port, err := svcid.Port()
		if err != nil {
			return nil, err
		}
		conn, err := vsock.Dial(vsock.CIDHost, port)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}
