package x365

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func testUUID(t *testing.T) [16]byte {
	t.Helper()
	var id [16]byte
	if _, err := hex.Decode(id[:], []byte("00112233445566778899aabbccddeeff")); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestBuildDomainTCPFrame(t *testing.T) {
	frame, err := BuildFrame(testUUID(t), "tcp", 443, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) != 25+1+len("example.test") {
		t.Fatalf("unexpected length %d", len(frame))
	}
	wantPrefix := []byte{'X', '3', '6', '5', 1, 1}
	if !bytes.Equal(frame[:6], wantPrefix) || frame[24] != 2 || frame[25] != byte(len("example.test")) {
		t.Fatalf("unexpected prefix: %x", frame[:26])
	}
}

func TestBuildIPv4Frame(t *testing.T) {
	frame, err := BuildFrame(testUUID(t), "tcp", 80, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) != 29 || frame[24] != 1 {
		t.Fatalf("unexpected IP frame: %x", frame)
	}
	if !bytes.Equal(frame[25:], []byte{192, 0, 2, 1}) {
		t.Fatalf("unexpected IPv4 payload: %x", frame[25:])
	}
}

func TestBuildIPv6AndUDPFrame(t *testing.T) {
	frame, err := BuildFrame(testUUID(t), "udp", 53, "2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) != 41 || frame[5] != 2 || frame[24] != 3 {
		t.Fatalf("unexpected IPv6 UDP frame: %x", frame)
	}
}

func TestResponseHeader(t *testing.T) {
	if err := ReadResponseHeader(strings.NewReader("X365\x00payload")); err != nil {
		t.Fatal(err)
	}
	if err := ReadResponseHeader(strings.NewReader("X365\x03")); err == nil {
		t.Fatal("expected server status error")
	}
	if err := ReadResponseHeader(strings.NewReader("nope\x00")); err == nil {
		t.Fatal("expected magic error")
	}
}

func TestUDPDatagramFraming(t *testing.T) {
	var wire bytes.Buffer
	payload := []byte("dns-packet")
	n, err := writeDatagram(&wire, payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) || !bytes.Equal(wire.Bytes(), append([]byte{0, byte(len(payload))}, payload...)) {
		t.Fatalf("unexpected UDP frame: %x", wire.Bytes())
	}

	decoded := make([]byte, len(payload))
	n, err = readDatagram(&wire, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) || !bytes.Equal(decoded, payload) {
		t.Fatalf("unexpected UDP payload: %q", decoded[:n])
	}
}

func TestUDPReadTruncatesAndDrainsFrame(t *testing.T) {
	var wire bytes.Buffer
	_, _ = writeDatagram(&wire, []byte("first-payload"))
	_, _ = writeDatagram(&wire, []byte("next"))

	short := make([]byte, 5)
	n, err := readDatagram(&wire, short)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(short) || string(short) != "first" {
		t.Fatalf("unexpected truncated datagram: %q", short[:n])
	}
	next := make([]byte, 8)
	n, err = readDatagram(&wire, next)
	if err != nil {
		t.Fatal(err)
	}
	if string(next[:n]) != "next" {
		t.Fatalf("next frame was not aligned: %q", next[:n])
	}
}

func TestUDPWriteRejectsOversizePayload(t *testing.T) {
	if _, err := writeDatagram(&bytes.Buffer{}, make([]byte, 65536)); err == nil {
		t.Fatal("expected oversized datagram error")
	}
}
