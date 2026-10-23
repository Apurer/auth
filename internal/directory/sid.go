package directory

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Apurer/auth/internal/config"
)

func DecodeSID(raw []byte) (string, error) {
	if len(raw) < 8 || raw[0] != 1 || raw[1] == 0 || raw[1] > 15 || len(raw) != 8+4*int(raw[1]) {
		return "", errors.New("invalid binary SID")
	}
	var authority uint64
	for _, b := range raw[2:8] {
		authority = authority<<8 | uint64(b)
	}
	s := fmt.Sprintf("S-1-%d", authority)
	for i := 8; i < len(raw); i += 4 {
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(raw[i:i+4]))
	}
	return s, nil
}

func EncodeSID(sid string) ([]byte, error) {
	if !config.ValidSID(sid) {
		return nil, errors.New("invalid SID")
	}
	p := strings.Split(sid, "-")
	b := make([]byte, 8+4*(len(p)-3))
	b[0] = 1
	b[1] = byte(len(p) - 3)
	n, _ := strconv.ParseUint(p[2], 10, 48)
	for i := 7; i >= 2; i-- {
		b[i] = byte(n)
		n >>= 8
	}
	for i, v := range p[3:] {
		n, _ := strconv.ParseUint(v, 10, 32)
		binary.LittleEndian.PutUint32(b[8+4*i:], uint32(n))
	}
	return b, nil
}

func binaryFilter(b []byte) string {
	var out strings.Builder
	for _, v := range b {
		fmt.Fprintf(&out, "\\%02x", v)
	}
	return out.String()
}
