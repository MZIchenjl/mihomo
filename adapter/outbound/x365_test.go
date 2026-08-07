package outbound

import "testing"

func validX365Option() X365Option {
	return X365Option{
		Name:              "x365-test",
		Server:            "edge.example",
		Port:              443,
		UUID:              "00112233-4455-6677-8899-aabbccddeeff",
		Host:              "authority.example",
		Path:              "/tunnel",
		SNI:               "reality.example",
		ClientFingerprint: "chrome",
		RealityOpts: RealityOptions{
			PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			ShortID:   "0123456789abcdef",
		},
		UDP: true,
	}
}

func TestNewX365SupportsConfirmedH2AndUDP(t *testing.T) {
	adapter, err := NewX365(validX365Option())
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if !adapter.SupportUDP() {
		t.Fatal("x365 adapter should advertise UDP when enabled")
	}
	if adapter.Type().String() != "X365" {
		t.Fatalf("unexpected adapter type %s", adapter.Type())
	}
}

func TestNewX365RejectsUnknownTransport(t *testing.T) {
	option := validX365Option()
	option.Transport = "h3"
	if _, err := NewX365(option); err == nil {
		t.Fatal("expected unsupported transport error")
	}
}

func TestNewX365RejectsConflictingServerNames(t *testing.T) {
	option := validX365Option()
	option.ServerName = "other.example"
	if _, err := NewX365(option); err == nil {
		t.Fatal("expected conflicting SNI error")
	}
}
