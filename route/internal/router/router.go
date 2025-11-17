package router

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Action represents the routing outcome for a connection.
type Action int

const (
	ActionDirect Action = iota
	ActionProxy
	ActionReject
)

func (a Action) String() string {
	switch a {
	case ActionDirect:
		return "DIRECT"
	case ActionProxy:
		return "PROXY"
	case ActionReject:
		return "REJECT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(a))
	}
}

// MatchType describes how to match a rule to an incoming hostname.
type MatchType int

const (
	matchDomain MatchType = iota
	matchSuffix
	matchKeyword
	matchCIDR
)

// RuleSpec is an intermediate description used to build an Engine.
type RuleSpec struct {
	Type     string
	Value    string
	Action   string
	Proxy    string
	Fallback string
}

// Rule represents a compiled routing rule.
type Rule struct {
	Type   MatchType
	Value  string
	Action Action
	Proxy  string
	IPNet  *net.IPNet
	Index  int
}

// MatchTypeString returns textual representation of the rule match type.
func (r *Rule) MatchTypeString() string {
	switch r.Type {
	case matchDomain:
		return "DOMAIN"
	case matchSuffix:
		return "DOMAIN-SUFFIX"
	case matchKeyword:
		return "DOMAIN-KEYWORD"
	case matchCIDR:
		return "CIDR"
	default:
		return "UNKNOWN"
	}
}

// Decision captures the result of routing.
type Decision struct {
	Action  Action
	Proxy   string
	Rule    *Rule
	Matched bool
}

// Engine evaluates routing decisions based on compiled rules.
type Engine struct {
	exactRules   []*Rule
	suffixRules  []*Rule
	keywordRules []*Rule
	cidrRules    []*Rule
	defaultDec   Decision
}

// NewEngine builds a routing engine from rule specifications.
func NewEngine(specs []RuleSpec) (*Engine, error) {
	engine := &Engine{}
	var seenFinal bool

	for i, spec := range specs {
		actionName := strings.ToUpper(strings.TrimSpace(spec.Action))
		typeName := strings.ToUpper(strings.TrimSpace(spec.Type))
		value := strings.TrimSpace(spec.Value)
		proxy := strings.TrimSpace(spec.Proxy)
		fallback := strings.ToUpper(strings.TrimSpace(spec.Fallback))

		if actionName == "FINAL" || typeName == "FINAL" {
			if seenFinal {
				return nil, fmt.Errorf("multiple FINAL rules defined")
			}
			seenFinal = true
			if fallback == "" {
				fallback = "DIRECT"
			}
			finalAction, err := parseAction(fallback)
			if err != nil {
				return nil, fmt.Errorf("final rule: %w", err)
			}
			if finalAction == ActionProxy && proxy == "" {
				return nil, fmt.Errorf("final rule requires proxy name")
			}
			engine.defaultDec = Decision{Action: finalAction, Proxy: proxy, Matched: false, Rule: nil}
			continue
		}

		action, err := parseAction(actionName)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		if action == ActionProxy && proxy == "" {
			return nil, fmt.Errorf("rule %d requires proxy name", i)
		}

		rule, err := compileRule(typeName, value, action, proxy, i)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		switch rule.Type {
		case matchDomain:
			engine.exactRules = append(engine.exactRules, rule)
		case matchSuffix:
			engine.suffixRules = append(engine.suffixRules, rule)
		case matchKeyword:
			engine.keywordRules = append(engine.keywordRules, rule)
		case matchCIDR:
			engine.cidrRules = append(engine.cidrRules, rule)
		default:
			return nil, fmt.Errorf("rule %d has unsupported match type", i)
		}
	}

	if !seenFinal {
		return nil, fmt.Errorf("missing FINAL rule for default policy")
	}

	return engine, nil
}

func parseAction(a string) (Action, error) {
	switch a {
	case "DIRECT":
		return ActionDirect, nil
	case "PROXY":
		return ActionProxy, nil
	case "REJECT":
		return ActionReject, nil
	default:
		return ActionReject, fmt.Errorf("unsupported action %s", a)
	}
}

func compileRule(t, v string, action Action, proxy string, idx int) (*Rule, error) {
	switch t {
	case "DOMAIN":
		if v == "" {
			return nil, fmt.Errorf("DOMAIN rule requires value")
		}
		return &Rule{Type: matchDomain, Value: strings.ToLower(v), Action: action, Proxy: proxy, Index: idx}, nil
	case "DOMAIN-SUFFIX":
		if v == "" {
			return nil, fmt.Errorf("DOMAIN-SUFFIX rule requires value")
		}
		return &Rule{Type: matchSuffix, Value: strings.ToLower(v), Action: action, Proxy: proxy, Index: idx}, nil
	case "DOMAIN-KEYWORD":
		if v == "" {
			return nil, fmt.Errorf("DOMAIN-KEYWORD rule requires value")
		}
		return &Rule{Type: matchKeyword, Value: strings.ToLower(v), Action: action, Proxy: proxy, Index: idx}, nil
	case "CIDR", "IP-CIDR":
		_, ipnet, err := net.ParseCIDR(v)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR value %s", v)
		}
		return &Rule{Type: matchCIDR, IPNet: ipnet, Action: action, Proxy: proxy, Index: idx}, nil
	default:
		return nil, fmt.Errorf("unsupported match type %s", t)
	}
}

// Decide selects the routing decision for a given destination host.
func (e *Engine) Decide(host string) Decision {
	if host == "" {
		return e.defaultDec
	}

	hostLower := strings.ToLower(host)

	// Exact domain matches.
	for _, rule := range e.exactRules {
		if hostLower == rule.Value {
			return Decision{Action: rule.Action, Proxy: rule.Proxy, Rule: rule, Matched: true}
		}
	}

	// Attempt IP parsing for CIDR rules.
	if ip, err := netip.ParseAddr(hostLower); err == nil {
		if ipDecision, ok := e.matchCIDR(ip); ok {
			return ipDecision
		}
	}

	// Suffix matches.
	for _, rule := range e.suffixRules {
		if strings.HasSuffix(hostLower, rule.Value) {
			if len(hostLower) == len(rule.Value) || hostLower[len(hostLower)-len(rule.Value)-1] == '.' {
				return Decision{Action: rule.Action, Proxy: rule.Proxy, Rule: rule, Matched: true}
			}
		}
	}

	// Keyword matches.
	for _, rule := range e.keywordRules {
		if strings.Contains(hostLower, rule.Value) {
			return Decision{Action: rule.Action, Proxy: rule.Proxy, Rule: rule, Matched: true}
		}
	}

	// Finally, check CIDR rules for textual IPs that didn't parse earlier.
	if ip := net.ParseIP(hostLower); ip != nil {
		if ipDecision, ok := e.matchLegacyCIDR(ip); ok {
			return ipDecision
		}
	}

	return e.defaultDec
}

func (e *Engine) matchCIDR(ip netip.Addr) (Decision, bool) {
	for _, rule := range e.cidrRules {
		if rule.IPNet == nil {
			continue
		}
		if containsIP(rule.IPNet, ip) {
			return Decision{Action: rule.Action, Proxy: rule.Proxy, Rule: rule, Matched: true}, true
		}
	}
	return Decision{}, false
}

func (e *Engine) matchLegacyCIDR(ip net.IP) (Decision, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return Decision{}, false
	}
	return e.matchCIDR(addr)
}

func containsIP(n *net.IPNet, addr netip.Addr) bool {
	if addr.Is4() != (n.IP.To4() != nil) {
		return false
	}
	return n.Contains(net.IP(addr.AsSlice()))
}
