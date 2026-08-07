package x365

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const chromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

type Node struct {
	Server string
	Port   uint16
	Host   string
	Path   string
	UUID   [16]byte
}

func (n Node) ServerAddr() string {
	return net.JoinHostPort(n.Server, strconv.Itoa(int(n.Port)))
}

type DialTLSContext func(ctx context.Context) (net.Conn, error)

// Client opens one HTTP/2 request stream for each proxied TCP connection and
// reuses the underlying authenticated connection through http2.Transport.
type Client struct {
	node      Node
	transport *http2.Transport
	http      *http.Client
}

func NewClient(node Node, dialTLS DialTLSContext) (*Client, error) {
	if node.Server == "" || node.Port == 0 {
		return nil, errors.New("x365: missing server or port")
	}
	if node.Host == "" {
		return nil, errors.New("x365: missing HTTP authority host")
	}
	if node.Path == "" {
		node.Path = "/"
	}
	if !strings.HasPrefix(node.Path, "/") {
		node.Path = "/" + node.Path
	}
	if len(node.Path) > 4096 {
		return nil, errors.New("x365: path is too long")
	}
	if dialTLS == nil {
		return nil, errors.New("x365: missing TLS dialer")
	}

	transport := &http2.Transport{
		AllowHTTP:          false,
		DisableCompression: true,
		ReadIdleTimeout:    30 * time.Second,
		PingTimeout:        15 * time.Second,
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			return dialTLS(ctx)
		},
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Client{node: node, transport: transport, http: client}, nil
}

func (c *Client) DialContext(ctx context.Context, network, address string, port uint16) (net.Conn, error) {
	preamble, err := BuildFrame(c.node.UUID, network, port, address)
	if err != nil {
		return nil, err
	}

	requestReader, requestWriter := io.Pipe()
	streamCtx, cancel := context.WithCancel(ctx)
	request, err := http.NewRequestWithContext(streamCtx, http.MethodPost, c.endpointURL(), requestReader)
	if err != nil {
		cancel()
		_ = requestReader.Close()
		_ = requestWriter.Close()
		return nil, err
	}
	request.ContentLength = -1
	request.Host = c.node.Host
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("User-Agent", chromeUserAgent)
	request.Header.Set("Referer", c.referer())

	result := make(chan streamResult, 1)
	go func() {
		response, requestErr := c.http.Do(request)
		if requestErr != nil {
			result <- streamResult{err: requestErr}
			return
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			result <- streamResult{err: fmt.Errorf("x365: HTTP status %s", response.Status)}
			return
		}
		reader := bufio.NewReader(response.Body)
		result <- streamResult{reader: &responseReader{Reader: reader, close: response.Body.Close}}
	}()

	writeResult := make(chan error, 1)
	go func() {
		_, writeErr := requestWriter.Write(preamble)
		writeResult <- writeErr
	}()

	waitResponse := func() (net.Conn, error) {
		outcome := <-result
		if outcome.err != nil {
			cancel()
			_ = requestWriter.CloseWithError(outcome.err)
			return nil, outcome.err
		}
		return &streamConn{reader: outcome.reader, writer: requestWriter, cancel: cancel, datagram: strings.EqualFold(network, "udp")}, nil
	}

	select {
	case outcome := <-result:
		if outcome.err != nil {
			cancel()
			_ = requestWriter.CloseWithError(outcome.err)
			return nil, outcome.err
		}
		return &streamConn{reader: outcome.reader, writer: requestWriter, cancel: cancel, datagram: strings.EqualFold(network, "udp")}, nil
	case writeErr := <-writeResult:
		if writeErr != nil {
			cancel()
			_ = requestWriter.CloseWithError(writeErr)
			return nil, fmt.Errorf("x365: write request preamble: %w", writeErr)
		}
		return waitResponse()
	case <-ctx.Done():
		cancel()
		_ = requestWriter.CloseWithError(ctx.Err())
		return nil, ctx.Err()
	}
}

func (c *Client) endpointURL() string {
	return (&url.URL{Scheme: "https", Host: c.node.ServerAddr(), Path: c.node.Path}).String()
}

func (c *Client) referer() string {
	padding, err := rand.Int(rand.Reader, big.NewInt(900))
	if err != nil {
		padding = big.NewInt(0)
	}
	u := &url.URL{Scheme: "https", Host: c.node.ServerAddr(), Path: c.node.Path}
	query := u.Query()
	query.Set("padding", strings.Repeat("0", 100+int(padding.Int64())))
	u.RawQuery = query.Encode()
	return u.String()
}

func (c *Client) Close() error {
	c.transport.CloseIdleConnections()
	return nil
}

type streamResult struct {
	reader *responseReader
	err    error
}

type responseReader struct {
	*bufio.Reader
	close func() error
}

func (r *responseReader) Close() error { return r.close() }

type streamConn struct {
	reader       *responseReader
	writer       *io.PipeWriter
	cancel       context.CancelFunc
	once         sync.Once
	responseOnce sync.Once
	responseErr  error
	readMu       sync.Mutex
	writeMu      sync.Mutex
	datagram     bool
}

func (c *streamConn) Read(p []byte) (int, error) {
	c.responseOnce.Do(func() {
		c.responseErr = ReadResponseHeader(c.reader)
	})
	if c.responseErr != nil {
		return 0, c.responseErr
	}
	if !c.datagram {
		return c.reader.Read(p)
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return readDatagram(c.reader, p)
}

func (c *streamConn) Write(p []byte) (int, error) {
	if !c.datagram {
		return c.writer.Write(p)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeDatagram(c.writer, p)
}
func (c *streamConn) Close() error {
	var closeErr error
	c.once.Do(func() {
		c.cancel()
		_ = c.writer.Close()
		closeErr = c.reader.Close()
	})
	return closeErr
}

func (c *streamConn) LocalAddr() net.Addr              { return streamAddr("x365-local") }
func (c *streamConn) RemoteAddr() net.Addr             { return streamAddr("x365-remote") }
func (c *streamConn) SetDeadline(time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

type streamAddr string

func (a streamAddr) Network() string { return "x365" }
func (a streamAddr) String() string  { return string(a) }

// readDatagram mirrors efanapp's x365 v1 stream reader. Each UDP payload is
// prefixed by a two-byte big-endian length. When the caller's buffer is too
// small, the official client returns the truncated prefix and drains the rest
// of that datagram so the next read remains frame-aligned.
func readDatagram(reader io.Reader, payload []byte) (int, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	readSize := size
	if len(payload) < readSize {
		readSize = len(payload)
	}
	n, err := io.ReadFull(reader, payload[:readSize])
	if err != nil {
		return n, err
	}
	if remaining := size - readSize; remaining > 0 {
		if _, err = io.CopyN(io.Discard, reader, int64(remaining)); err != nil {
			return n, err
		}
	}
	return n, nil
}

func writeDatagram(writer io.Writer, payload []byte) (int, error) {
	if len(payload) > 0xffff {
		return 0, errors.New("x365: UDP payload exceeds 65535 bytes")
	}
	frame := make([]byte, len(payload)+2)
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	for written := 0; written < len(frame); {
		n, err := writer.Write(frame[written:])
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.ErrShortWrite
		}
		written += n
	}
	return len(payload), nil
}
