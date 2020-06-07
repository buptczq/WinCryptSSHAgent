set GOARCH=amd64
go generate
go build -ldflags -H=windowsgui
set GOARCH=386
go build -ldflags -H=windowsgui -o WinCryptSSHAgent_32bit.exe

