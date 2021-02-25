package utils

import (
	cryptornd "crypto/rand"
	"encoding/hex"
	"math/rand"
	"time"
)

func UUIDToString(uuid [16]byte) string {
	var buf [35]byte
	dst := buf[:]
	for i := 0; i < 4; i++ {
		b := uuid[i*4 : i*4+4]
		hex.Encode(dst[i*9:i*9+8], []byte{b[3], b[2], b[1], b[0]})
		if i != 3 {
			dst[9*i+8] = '-'
		}
	}
	return string(buf[:])
}

func RandomString(n int) string {
	const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	var randby bool
	if num, err := cryptornd.Read(bytes); num != n || err != nil {
		rand.Seed(time.Now().UnixNano())
		randby = true
	}
	for i, b := range bytes {
		if randby {
			bytes[i] = alphanum[rand.Intn(len(alphanum))]
		} else {
			bytes[i] = alphanum[b%byte(len(alphanum))]
		}
	}
	return string(bytes)
}
