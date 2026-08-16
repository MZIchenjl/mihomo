package x365

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newH2TestClient(t *testing.T, handler http.Handler) (*Client, func()) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	client, err := NewClient(Node{
		Server: host,
		Port:   uint16(port),
		Host:   "authority.example",
		Path:   "/x365",
		UUID:   testUUID(t),
	}, func(ctx context.Context) (net.Conn, error) {
		dialer := &tls.Dialer{Config: &tls.Config{
			InsecureSkipVerify: true, // test server certificate
			NextProtos:         []string{"h2"},
		}}
		return dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
	})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, func() {
		_ = client.Close()
		server.Close()
	}
}

func verifyRequest(t *testing.T, request *http.Request, expectedPreamble []byte) bool {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.Path != "/x365" {
		t.Errorf("unexpected request target %s %s", request.Method, request.URL.Path)
		return false
	}
	if request.Host != "authority.example" || request.Header.Get("Content-Type") != "application/grpc" {
		t.Errorf("unexpected authority or content type: %q %q", request.Host, request.Header.Get("Content-Type"))
		return false
	}
	if request.Header.Get("User-Agent") != chromeUserAgent {
		t.Errorf("unexpected user agent %q", request.Header.Get("User-Agent"))
		return false
	}
	referer, err := url.Parse(request.Header.Get("Referer"))
	if err != nil {
		t.Errorf("invalid referer: %v", err)
		return false
	}
	if referer.Scheme != "https" || referer.Host != "authority.example" || referer.Path != request.URL.Path {
		t.Errorf("unexpected referer target %q", referer.String())
		return false
	}
	if len(referer.Query()) != 1 {
		t.Errorf("unexpected referer query keys")
		return false
	}
	padding := referer.Query().Get("x_padding")
	if len(padding) < 100 || len(padding) > 999 || strings.Trim(padding, "X") != "" {
		t.Errorf("unexpected referer padding length %d", len(padding))
		return false
	}
	actual := make([]byte, len(expectedPreamble))
	if _, err = io.ReadFull(request.Body, actual); err != nil {
		t.Errorf("read preamble: %v", err)
		return false
	}
	if !bytes.Equal(actual, expectedPreamble) {
		t.Errorf("unexpected preamble %x", actual)
		return false
	}
	return true
}

func TestH2TCPBidirectionalStream(t *testing.T) {
	expected, err := BuildFrame(testUUID(t), "tcp", 443, "target.example")
	if err != nil {
		t.Fatal(err)
	}
	client, closeClient := newH2TestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !verifyRequest(t, request, expected) {
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("X365\x00"))
		writer.(http.Flusher).Flush()
		payload := make([]byte, 4)
		if _, readErr := io.ReadFull(request.Body, payload); readErr != nil {
			t.Errorf("read TCP payload: %v", readErr)
			return
		}
		_, _ = writer.Write(payload)
		writer.(http.Flusher).Flush()
	}))
	defer closeClient()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "target.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err = io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "ping" {
		t.Fatalf("unexpected response %q", response)
	}
}

func TestH2TCPCloseWriteHalfClosePreservesRead(t *testing.T) {
	expected, err := BuildFrame(testUUID(t), "tcp", 22, "ssh.example")
	if err != nil {
		t.Fatal(err)
	}
	client, closeClient := newH2TestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !verifyRequest(t, request, expected) {
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("X365\x00"))
		writer.(http.Flusher).Flush()
		// Draining until EOF proves the client's END_STREAM arrived; the
		// response must still be writable afterwards.
		if _, readErr := io.Copy(io.Discard, request.Body); readErr != nil {
			t.Errorf("drain request body: %v", readErr)
			return
		}
		_, _ = writer.Write([]byte("after-eof"))
		writer.(http.Flusher).Flush()
	}))
	defer closeClient()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "ssh.example", 22)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	halfCloser, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("x365 stream conn does not implement CloseWrite")
	}
	if err = halfCloser.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("late")); err == nil {
		t.Error("write after CloseWrite unexpectedly succeeded")
	}
	response := make([]byte, len("after-eof"))
	if _, err = io.ReadFull(conn, response); err != nil {
		t.Fatalf("read after CloseWrite: %v", err)
	}
	if string(response) != "after-eof" {
		t.Fatalf("unexpected response after half-close %q", response)
	}
}

func TestH2UDPDatagramStream(t *testing.T) {
	expected, err := BuildFrame(testUUID(t), "udp", 53, "dns.example")
	if err != nil {
		t.Fatal(err)
	}
	client, closeClient := newH2TestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !verifyRequest(t, request, expected) {
			return
		}
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		var header [2]byte
		if _, readErr := io.ReadFull(request.Body, header[:]); readErr != nil {
			t.Errorf("read UDP header: %v", readErr)
			return
		}
		payload := make([]byte, binary.BigEndian.Uint16(header[:]))
		if _, readErr := io.ReadFull(request.Body, payload); readErr != nil {
			t.Errorf("read UDP payload: %v", readErr)
			return
		}
		_, _ = writer.Write([]byte("X365\x00"))
		_, _ = writer.Write(header[:])
		_, _ = writer.Write(payload)
		writer.(http.Flusher).Flush()
	}))
	defer closeClient()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "udp", "dns.example", 53)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 16)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response[:n], payload) {
		t.Fatalf("unexpected UDP response %x", response[:n])
	}
}

func TestH2UDPServerWaitsForFirstDatagram(t *testing.T) {
	expected, err := BuildFrame(testUUID(t), "udp", 53, "dns.example")
	if err != nil {
		t.Fatal(err)
	}
	client, closeClient := newH2TestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !verifyRequest(t, request, expected) {
			return
		}
		var header [2]byte
		if _, readErr := io.ReadFull(request.Body, header[:]); readErr != nil {
			t.Errorf("read UDP header before response: %v", readErr)
			return
		}
		payload := make([]byte, binary.BigEndian.Uint16(header[:]))
		if _, readErr := io.ReadFull(request.Body, payload); readErr != nil {
			t.Errorf("read UDP payload before response: %v", readErr)
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("X365\x00"))
		_, _ = writer.Write(header[:])
		_, _ = writer.Write(payload)
		writer.(http.Flusher).Flush()
	}))
	defer closeClient()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "udp", "dns.example", 53)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte{1, 2, 3, 4}
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 16)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response[:n], payload) {
		t.Fatalf("unexpected UDP response %x", response[:n])
	}
}

func TestH2UDPStreamOutlivesDialContext(t *testing.T) {
	expected, err := BuildFrame(testUUID(t), "udp", 53, "dns.example")
	if err != nil {
		t.Fatal(err)
	}
	client, closeClient := newH2TestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !verifyRequest(t, request, expected) {
			return
		}
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		var header [2]byte
		if _, readErr := io.ReadFull(request.Body, header[:]); readErr != nil {
			t.Errorf("read UDP header: %v", readErr)
			return
		}
		payload := make([]byte, binary.BigEndian.Uint16(header[:]))
		if _, readErr := io.ReadFull(request.Body, payload); readErr != nil {
			t.Errorf("read UDP payload: %v", readErr)
			return
		}
		_, _ = writer.Write([]byte("X365\x00"))
		_, _ = writer.Write(header[:])
		_, _ = writer.Write(payload)
		writer.(http.Flusher).Flush()
	}))
	defer closeClient()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := client.DialContext(ctx, "udp", "dns.example", 53)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	defer conn.Close()
	payload := []byte{5, 6, 7, 8}
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 16)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response[:n], payload) {
		t.Fatalf("unexpected UDP response %x", response[:n])
	}
}

func TestCloseBeforeHTTPResponse(t *testing.T) {
	client, closeClient := newH2TestClient(t, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer closeClient()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "udp", "dns.example", 53)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked waiting for the HTTP response")
	}
}
