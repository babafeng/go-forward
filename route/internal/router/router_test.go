package router_test

import (
	"testing"

	"go-forward/route/internal/router"
)

func TestEngineDecide(t *testing.T) {
	specs := []router.RuleSpec{
		{Type: "DOMAIN", Value: "example.com", Action: "DIRECT"},
		{Type: "DOMAIN-SUFFIX", Value: "google.com", Action: "PROXY", Proxy: "g-proxy"},
		{Type: "CIDR", Value: "10.0.0.0/24", Action: "REJECT"},
		{Action: "FINAL", Fallback: "DIRECT"},
	}

	eng, err := router.NewEngine(specs, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("exact match", func(t *testing.T) {
		dec := eng.Decide("example.com")
		if dec.Action != router.ActionDirect {
			t.Fatalf("expected direct, got %v", dec.Action)
		}
		if !dec.Matched {
			t.Fatal("expected match")
		}
	})

	t.Run("suffix match", func(t *testing.T) {
		dec := eng.Decide("mail.google.com")
		if dec.Action != router.ActionProxy {
			t.Fatalf("expected proxy, got %v", dec.Action)
		}
		if dec.Proxy != "g-proxy" {
			t.Fatalf("expected proxy name g-proxy, got %s", dec.Proxy)
		}
	})

	t.Run("cidr match", func(t *testing.T) {
		dec := eng.Decide("10.0.0.2")
		if dec.Action != router.ActionReject {
			t.Fatalf("expected reject, got %v", dec.Action)
		}
	})

	t.Run("default", func(t *testing.T) {
		dec := eng.Decide("unknown.com")
		if dec.Action != router.ActionDirect {
			t.Fatalf("expected direct fallback, got %v", dec.Action)
		}
		if dec.Matched {
			t.Fatalf("should not be matched rule")
		}
	})
}

func TestEngineFinalProxy(t *testing.T) {
	specs := []router.RuleSpec{
		{Type: "DOMAIN", Value: "block.me", Action: "REJECT"},
		{Action: "FINAL", Fallback: "PROXY", Proxy: "fallback"},
	}
	eng, err := router.NewEngine(specs, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dec := eng.Decide("another.com")
	if dec.Action != router.ActionProxy {
		t.Fatalf("expected proxy fallback, got %v", dec.Action)
	}
	if dec.Proxy != "fallback" {
		t.Fatalf("expected fallback proxy, got %s", dec.Proxy)
	}
}

func TestEngineRequiresFinal(t *testing.T) {
	specs := []router.RuleSpec{{Type: "DOMAIN", Value: "example.com", Action: "DIRECT"}}
	if _, err := router.NewEngine(specs, nil); err == nil {
		t.Fatal("expected error for missing final rule")
	}
}

func TestEngineKeywordPriority(t *testing.T) {
	specs := []router.RuleSpec{
		{Type: "DOMAIN", Value: "special.site", Action: "DIRECT"},
		{Type: "DOMAIN-KEYWORD", Value: "special", Action: "REJECT"},
		{Action: "FINAL", Fallback: "DIRECT"},
	}
	eng, err := router.NewEngine(specs, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dec := eng.Decide("special.site")
	if dec.Action != router.ActionDirect {
		t.Fatalf("exact match should win, got %v", dec.Action)
	}
}
