package tls

import "testing"

func TestRealityClientVersionDefaultAndOverride(t *testing.T) {
	if got := realityClientVersion(&RealityConfig{}); got != [3]byte{1, 8, 2} {
		t.Fatalf("unexpected default REALITY version %v", got)
	}
	config := &RealityConfig{ClientVersion: [3]byte{1, 8, 1}}
	if got := realityClientVersion(config); got != config.ClientVersion {
		t.Fatalf("unexpected overridden REALITY version %v", got)
	}
}
