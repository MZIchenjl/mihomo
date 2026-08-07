package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/mihomo/transport/x365"

	"github.com/gofrs/uuid/v5"
)

type X365 struct {
	*Base
	client *x365.Client
	option *X365Option
}

type X365Option struct {
	BasicOption
	Name              string         `proxy:"name"`
	Server            string         `proxy:"server"`
	Port              int            `proxy:"port"`
	UUID              string         `proxy:"uuid"`
	Host              string         `proxy:"host"`
	Path              string         `proxy:"path,omitempty"`
	SNI               string         `proxy:"sni,omitempty"`
	ServerName        string         `proxy:"servername,omitempty"`
	Transport         string         `proxy:"transport,omitempty"`
	ClientFingerprint string         `proxy:"client-fingerprint,omitempty"`
	RealityOpts       RealityOptions `proxy:"reality-opts"`
	UDP               bool           `proxy:"udp,omitempty"`
}

// DialContext implements C.ProxyAdapter.
func (x *X365) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	address := metadata.Host
	if address == "" && metadata.DstIP.IsValid() {
		address = metadata.DstIP.String()
	}
	conn, err := x.client.DialContext(ctx, "tcp", address, metadata.DstPort)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", x.addr, err)
	}
	return NewConn(conn, x), nil
}

// ListenPacketContext implements C.ProxyAdapter. x365 v1 binds each UDP
// stream to the destination encoded in its request preamble, so packets sent
// through the returned PacketConn must keep that destination.
func (x *X365) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if !x.option.UDP {
		return nil, errors.New("x365: UDP is disabled")
	}
	if err = x.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	address := metadata.Host
	if address == "" && metadata.DstIP.IsValid() {
		address = metadata.DstIP.String()
	}
	conn, err := x.client.DialContext(ctx, "udp", address, metadata.DstPort)
	if err != nil {
		return nil, fmt.Errorf("%s UDP connect error: %w", x.addr, err)
	}
	return NewPacketConn(&x365PacketConn{Conn: conn, rAddr: metadata.UDPAddr()}, x), nil
}

// ProxyInfo implements C.ProxyAdapter.
func (x *X365) ProxyInfo() C.ProxyInfo {
	info := x.Base.ProxyInfo()
	info.DialerProxy = x.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter.
func (x *X365) Close() error {
	return x.client.Close()
}

func NewX365(option X365Option) (*X365, error) {
	if strings.TrimSpace(option.Name) == "" {
		return nil, errors.New("x365: missing name")
	}
	if strings.TrimSpace(option.Server) == "" {
		return nil, errors.New("x365: missing server")
	}
	if option.Port <= 0 || option.Port > 65535 {
		return nil, errors.New("x365: invalid port")
	}
	if strings.TrimSpace(option.Host) == "" {
		return nil, errors.New("x365: missing host")
	}
	if option.SNI != "" && option.ServerName != "" && option.SNI != option.ServerName {
		return nil, errors.New("x365: sni and servername disagree")
	}
	serverName := option.SNI
	if serverName == "" {
		serverName = option.ServerName
	}
	if serverName == "" {
		return nil, errors.New("x365: missing sni")
	}
	if option.Transport == "" {
		option.Transport = "h2"
	}
	if option.Transport != "h2" {
		return nil, fmt.Errorf("x365: unsupported transport %q", option.Transport)
	}
	parsedUUID, err := uuid.FromString(option.UUID)
	if err != nil {
		return nil, fmt.Errorf("x365: invalid UUID: %w", err)
	}
	realityConfig, err := option.RealityOpts.Parse()
	if err != nil {
		return nil, fmt.Errorf("x365: %w", err)
	}
	if realityConfig == nil {
		return nil, errors.New("x365: reality-opts.public-key is required")
	}
	// The inspected efanapp core writes REALITY client version 1.8.1.
	realityConfig.ClientVersion = [3]byte{1, 8, 1}

	if option.ClientFingerprint == "" {
		option.ClientFingerprint = "chrome"
	}
	if _, ok := tlsC.GetFingerprint(option.ClientFingerprint); !ok {
		return nil, fmt.Errorf("x365: unsupported client fingerprint %q", option.ClientFingerprint)
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &X365{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.X365,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	dialTLS := func(ctx context.Context) (net.Conn, error) {
		raw, dialErr := outbound.dialer.DialContext(ctx, "tcp", addr)
		if dialErr != nil {
			return nil, dialErr
		}
		conn, tlsErr := vmess.StreamTLSConn(ctx, raw, &vmess.TLSConfig{
			Host:              serverName,
			NextProtos:        []string{"h2"},
			ClientFingerprint: option.ClientFingerprint,
			Reality:           realityConfig,
		})
		if tlsErr != nil {
			_ = raw.Close()
			return nil, tlsErr
		}
		return conn, nil
	}

	client, err := x365.NewClient(x365.Node{
		Server: option.Server,
		Port:   uint16(option.Port),
		Host:   option.Host,
		Path:   option.Path,
		UUID:   [16]byte(parsedUUID),
	}, dialTLS)
	if err != nil {
		return nil, err
	}
	outbound.client = client
	return outbound, nil
}

type x365PacketConn struct {
	net.Conn
	rAddr net.Addr
	write sync.Mutex
}

func (c *x365PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	if c.rAddr == nil || addr == nil || c.rAddr.String() != addr.String() {
		return 0, ErrUDPRemoteAddrMismatch
	}
	c.write.Lock()
	defer c.write.Unlock()
	return c.Conn.Write(payload)
}

func (c *x365PacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(payload)
	return n, c.rAddr, err
}
