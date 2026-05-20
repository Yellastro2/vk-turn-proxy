package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

const (
	wrapKeyLen    = 32
	wrapHdrLen    = 12
	wrapMaxPad    = 32
	wrapPadLen    = 2
	wrapCoverMark = 0xFFFF
)

var wrapCounter atomic.Uint64
var rtpSSRC uint32

// initSSRC derives a stable RTP-like SSRC value from the active WRAP key.
func initSSRC(key []byte) {
	h := sha256.Sum256(key)
	rtpSSRC = binary.BigEndian.Uint32(h[:4])
}

// putHeader writes the RTP-like header used by the client WRAP layer.
func putHeader(buf []byte, counter uint64, payloadLen int) {
	buf[0] = 0x80
	marker := byte(0)
	if counter == 0 {
		marker = 0x80
	}
	if counter%50 == 0 {
		buf[1] = marker | 0x60
	} else {
		buf[1] = marker | 0x6F
	}
	binary.BigEndian.PutUint16(buf[2:4], uint16(counter&0xFFFF))
	binary.BigEndian.PutUint32(buf[4:8], uint32(counter*960))
	binary.BigEndian.PutUint32(buf[8:12], rtpSSRC)
	_ = payloadLen
}

// readHeader recovers the packet counter encoded in a WRAP RTP-like header.
func readHeader(buf []byte) (counter uint64, payloadLen int) {
	ts := uint64(binary.BigEndian.Uint32(buf[4:8]))
	counter = ts / 960
	payloadLen = 0
	return
}

// xorKeystream expands the WRAP key and packet counter into a per-packet byte stream.
func xorKeystream(key []byte, counter uint64, length int) []byte {
	if length <= 0 {
		return nil
	}
	ks := make([]byte, length)
	var state [32]byte
	h := sha256.New()
	h.Write(key)
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	h.Write(ctr[:])
	h.Sum(state[:0])
	for off := 0; off < length; off += 32 {
		n := length - off
		if n > 32 {
			n = 32
		}
		copy(ks[off:], state[:n])
		if off+32 < length {
			state = sha256.Sum256(state[:])
		}
	}
	return ks
}

// xorInPlace applies the WRAP keystream to a packet body.
func xorInPlace(key []byte, counter uint64, data []byte) {
	ks := xorKeystream(key, uint64(uint32(counter)), len(data))
	for i := range data {
		data[i] ^= ks[i]
	}
}

// decodeWrapKey validates and decodes the optional WRAP key passed from the CLI.
func decodeWrapKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("wrap-key invalid hex: %w", err)
	}
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap-key must decode to %d bytes (got %d)", wrapKeyLen, len(key))
	}
	initSSRC(key)
	return key, nil
}

// randPadLen chooses a small random padding length for one WRAP datagram.
func randPadLen() int {
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		return 0
	}
	return int(b[0]) % (wrapMaxPad + 1)
}

// wrapPacket masks one relay datagram with an RTP-like header, padding and a keyed XOR body.
func wrapPacket(key, payload []byte) ([]byte, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap: key must be %d bytes", wrapKeyLen)
	}
	counter := wrapCounter.Add(1) - 1

	padLen := randPadLen()
	plaintext := make([]byte, len(payload)+padLen+wrapPadLen)
	copy(plaintext, payload)
	if padLen > 0 {
		_, _ = rand.Read(plaintext[len(payload) : len(payload)+padLen])
	}
	binary.BigEndian.PutUint16(plaintext[len(plaintext)-wrapPadLen:], uint16(padLen))

	xorInPlace(key, counter, plaintext)

	out := make([]byte, wrapHdrLen+len(plaintext))
	putHeader(out[:wrapHdrLen], counter, len(plaintext))
	copy(out[wrapHdrLen:], plaintext)
	return out, nil
}

// unwrapPacket restores one WRAP datagram and skips cover packets by returning zero bytes.
func unwrapPacket(key, wire, dst []byte) (int, error) {
	if len(key) != wrapKeyLen {
		return 0, fmt.Errorf("wrap: key must be %d bytes", wrapKeyLen)
	}
	if len(wire) < wrapHdrLen+wrapPadLen {
		return 0, errors.New("wrap: short packet")
	}
	counter, _ := readHeader(wire[:wrapHdrLen])
	ciphertext := wire[wrapHdrLen:]
	if len(ciphertext) < wrapPadLen {
		return 0, errors.New("wrap: encrypted payload too short")
	}
	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ciphertext)
	xorInPlace(key, counter, plaintext)

	padLen := int(binary.BigEndian.Uint16(plaintext[len(plaintext)-wrapPadLen:]))
	if padLen == wrapCoverMark {
		return 0, nil
	}
	if padLen > wrapMaxPad || wrapPadLen+padLen > len(plaintext) {
		return 0, errors.New("wrap: invalid padding")
	}
	n := len(plaintext) - wrapPadLen - padLen
	if n > len(dst) {
		return 0, errors.New("wrap: dst buffer too small")
	}
	copy(dst, plaintext[:n])
	return n, nil
}
