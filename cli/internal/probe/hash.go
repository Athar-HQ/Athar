package probe

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"strings"
)

// MMH3 is 32-bit MurmurHash3 with seed 0, as a signed integer. This matches
// Python's mmh3.hash, which Shodan and FOFA use.
func MMH3(data []byte) int32 {
	var m mmh3Sum
	m.Write(data)
	return m.Sum()
}

// mmh3Sum computes MMH3 over data written in pieces.
type mmh3Sum struct {
	h    uint32
	n    int     // bytes written
	tail [4]byte // the last n%4 bytes, not yet part of h
}

func (m *mmh3Sum) Write(p []byte) (int, error) {
	written := len(p)
	if have := m.n % 4; have > 0 {
		c := copy(m.tail[have:], p)
		m.n += c
		p = p[c:]
		if have+c < 4 {
			return written, nil
		}
		m.block(binary.LittleEndian.Uint32(m.tail[:]))
	}
	m.n += len(p)
	for ; len(p) >= 4; p = p[4:] {
		m.block(binary.LittleEndian.Uint32(p))
	}
	copy(m.tail[:], p)
	return written, nil
}

func (m *mmh3Sum) block(k uint32) {
	k *= 0xcc9e2d51
	k = bits.RotateLeft32(k, 15)
	k *= 0x1b873593
	m.h ^= k
	m.h = bits.RotateLeft32(m.h, 13)
	m.h = m.h*5 + 0xe6546b64
}

// Sum returns the hash of what was written so far.
func (m *mmh3Sum) Sum() int32 {
	h := m.h
	var k uint32
	switch tail := m.tail[:m.n%4]; len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= 0xcc9e2d51
		k = bits.RotateLeft32(k, 15)
		k *= 0x1b873593
		h ^= k
	}
	h ^= uint32(m.n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}

// FaviconMMH3 is the Shodan/FOFA favicon hash: MMH3 over the base64 encoding
// of the icon with a newline after every 76 characters and at the end, as
// Python's base64.encodebytes produces it.
func FaviconMMH3(icon []byte) int32 {
	enc := base64.StdEncoding.EncodeToString(icon)
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteByte('\n')
		enc = enc[76:]
	}
	if enc != "" {
		b.WriteString(enc)
		b.WriteByte('\n')
	}
	return MMH3([]byte(b.String()))
}

func md5Hex(b []byte) string {
	s := md5.Sum(b)
	return hex.EncodeToString(s[:])
}

func sha1Hex(b []byte) string {
	s := sha1.Sum(b)
	return hex.EncodeToString(s[:])
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
