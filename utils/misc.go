package utils

import "encoding/hex"

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
