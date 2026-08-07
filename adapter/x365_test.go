package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseX365Proxy(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":               "x365-test",
		"type":               "x365",
		"server":             "edge.example",
		"port":               443,
		"uuid":               "00112233-4455-6677-8899-aabbccddeeff",
		"host":               "authority.example",
		"path":               "/tunnel",
		"sni":                "reality.example",
		"transport":          "h2",
		"client-fingerprint": "chrome",
		"reality-opts": map[string]any{
			"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"short-id":   "0123456789abcdef",
		},
		"udp": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if proxy.Type() != C.X365 || !proxy.SupportUDP() {
		t.Fatalf("unexpected parsed adapter: type=%s udp=%t", proxy.Type(), proxy.SupportUDP())
	}
}
