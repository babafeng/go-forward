package config_test

import (
	"testing"
	"testing/fstest"

	"go-forward/route/internal/config"
)

const sampleConfig = `[General]
http-listen = 0.0.0.0:1080
socks5-listen = 0.0.0.0:1081
log-level = debug
log-format = json
prefer-ipv6 = true
ipv6 = false
bypass-system = false
skip-proxy = 10.0.0.0/8, 192.168.0.0/16
default-proxy = PROXY

[Proxy]
PROXY = socks5, proxy.example.com:1080, user, pass, 5s
BACKUP = http, 203.0.113.10:3128

[Rule]
DOMAIN-SUFFIX,google.com,DIRECT
IP-CIDR,10.0.0.0/8,PROXY
FINAL,DIRECT
`

func TestParseINIConfig(t *testing.T) {
	fs := fstest.MapFS{
		"conf.ini": {Data: []byte(sampleConfig)},
	}
	cfg, err := config.ReadFS(fs, "conf.ini")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Listen.HTTP != "0.0.0.0:1080" {
		t.Fatalf("unexpected http listen: %s", cfg.Listen.HTTP)
	}
	if cfg.Log.Level != "debug" || cfg.Log.Format != "json" {
		t.Fatalf("unexpected log config: %+v", cfg.Log)
	}
	if !cfg.General.PreferIPv6 {
		t.Fatalf("prefer ipv6 should be true")
	}
	if len(cfg.General.SkipProxy) != 2 {
		t.Fatalf("expected 2 skip proxy entries, got %d", len(cfg.General.SkipProxy))
	}
	if len(cfg.Servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(cfg.Servers))
	}
	if cfg.Servers[0].Name != "PROXY" {
		t.Fatalf("unexpected first server name: %s", cfg.Servers[0].Name)
	}
	if len(cfg.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(cfg.Rules))
	}
	if cfg.Rules[1].Action != "PROXY" || cfg.Rules[1].Proxy != "PROXY" {
		t.Fatalf("rule should reference PROXY: %+v", cfg.Rules[1])
	}
	if cfg.Rules[2].Type != "FINAL" || cfg.Rules[2].Fallback != "DIRECT" {
		t.Fatalf("unexpected final rule: %+v", cfg.Rules[2])
	}
}
