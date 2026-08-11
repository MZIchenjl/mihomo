package x365

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

var magic = [4]byte{'X', '3', '6', '5'}

// BuildFrame builds the connection preamble emitted by efanapp's x365 core.
func BuildFrame(id [16]byte, network string, port uint16, address string) ([]byte, error) {
	if port == 0 {
		return nil, errors.New("x365: target port must be non-zero")
	}
	if address == "" {
		return nil, errors.New("x365: target address is empty")
	}

	kind, err := streamKind(network)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 25)
	copy(frame[0:4], magic[:])
	frame[4] = 1
	frame[5] = kind
	copy(frame[6:22], id[:])
	binary.BigEndian.PutUint16(frame[22:24], port)

	if ip := net.ParseIP(address); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			frame[24] = 1
			return append(frame, v4...), nil
		}
		frame[24] = 3
		return append(frame, ip.To16()...), nil
	}

	if len(address) > 255 {
		return nil, errors.New("x365: domain is longer than 255 bytes")
	}
	frame[24] = 2
	frame = append(frame, byte(len(address)))
	frame = append(frame, address...)
	return frame, nil
}

func streamKind(network string) (byte, error) {
	switch strings.ToLower(network) {
	case "", "tcp":
		return 1, nil
	case "udp":
		return 2, nil
	default:
		return 0, fmt.Errorf("x365: unsupported stream kind %q", network)
	}
}

// ReadResponseHeader consumes the five-byte x365 server response preamble.
func ReadResponseHeader(r io.Reader) error {
	var raw [5]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return fmt.Errorf("x365: response header: %w", err)
	}
	if !bytes.Equal(raw[:4], magic[:]) {
		return fmt.Errorf("x365: unexpected response magic %q", raw[:4])
	}
	if raw[4] != 0 {
		return fmt.Errorf("x365: server status %d", raw[4])
	}
	return nil
}
