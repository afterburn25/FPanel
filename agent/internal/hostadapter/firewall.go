package hostadapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type FirewallRule struct {
	Direction string `json:"direction"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
	Source    string `json:"source"`
	Action    string `json:"action"`
}

type FirewallApplyResult struct {
	RuleCount int    `json:"rule_count"`
	Table     string `json:"table"`
	Validated bool   `json:"validated"`
	Applied   bool   `json:"applied"`
}

func RenderPrivoraNftBatch(rules []FirewallRule) (string, error) {
	var b strings.Builder
	b.WriteString("flush chain inet privora input\n")
	b.WriteString("flush chain inet privora output\n")
	for _, r := range rules {
		direction := strings.ToLower(strings.TrimSpace(r.Direction))
		protocol := strings.ToLower(strings.TrimSpace(r.Protocol))
		action := strings.ToLower(strings.TrimSpace(r.Action))
		if direction != "inbound" && direction != "outbound" {
			return "", errors.New("invalid firewall direction")
		}
		if protocol != "tcp" && protocol != "udp" {
			return "", errors.New("invalid firewall protocol")
		}
		if action != "allow" && action != "deny" {
			return "", errors.New("invalid firewall action")
		}
		if r.Port < 1 || r.Port > 65535 {
			return "", errors.New("invalid firewall port")
		}
		if action == "deny" && direction == "inbound" && r.Port == 22 {
			return "", errors.New("refusing to deny inbound SSH without break-glass workflow")
		}
		source := strings.TrimSpace(r.Source)
		if source == "" {
			source = "0.0.0.0/0"
		}
		ip, network, err := net.ParseCIDR(source)
		if err != nil {
			return "", errors.New("firewall source must be a CIDR")
		}
		family := "ip"
		if ip.To4() == nil {
			family = "ip6"
		}
		verb := "accept"
		if action == "deny" {
			verb = "drop"
		}
		chain := "input"
		if direction == "outbound" {
			chain = "output"
		}
		fmt.Fprintf(&b, "add rule inet privora %s %s saddr %s %s dport %d counter %s\n", chain, family, network.String(), protocol, r.Port, verb)
	}
	return b.String(), nil
}

func (a *Adapter) ApplyNftablesRules(ctx context.Context, rules []FirewallRule) (FirewallApplyResult, error) {
	if !a.cfg.AllowMutations {
		return FirewallApplyResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("nftables"); err != nil {
		return FirewallApplyResult{}, err
	}
	if _, ok := commandExists("nft"); !ok {
		return FirewallApplyResult{}, errors.New("nft not installed")
	}
	batch, err := RenderPrivoraNftBatch(rules)
	if err != nil {
		return FirewallApplyResult{}, err
	}

	// Privora owns only its dedicated table/chains. Bootstrap is idempotent and
	// never flushes the host's other firewall tables.
	if _, err := a.run(ctx, "nft", "list", "table", "inet", "privora"); err != nil {
		if _, err := a.run(ctx, "nft", "add", "table", "inet", "privora"); err != nil {
			return FirewallApplyResult{}, fmt.Errorf("create Privora nftables table: %w", err)
		}
		if _, err := a.run(ctx, "nft", "add", "chain", "inet", "privora", "input", "{", "type", "filter", "hook", "input", "priority", "10", ";", "policy", "accept", ";", "}"); err != nil {
			return FirewallApplyResult{}, fmt.Errorf("create input chain: %w", err)
		}
		if _, err := a.run(ctx, "nft", "add", "chain", "inet", "privora", "output", "{", "type", "filter", "hook", "output", "priority", "10", ";", "policy", "accept", ";", "}"); err != nil {
			return FirewallApplyResult{}, fmt.Errorf("create output chain: %w", err)
		}
	}
	path := a.cfg.NftablesPath
	if path == "" {
		path = "/etc/nftables.d/privora.nft"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return FirewallApplyResult{}, err
	}
	tmp := path + ".candidate"
	if err := os.WriteFile(tmp, []byte(batch), 0600); err != nil {
		return FirewallApplyResult{}, err
	}
	defer os.Remove(tmp)
	if _, err := a.run(ctx, "nft", "-c", "-f", tmp); err != nil {
		return FirewallApplyResult{}, fmt.Errorf("nftables validation failed: %w", err)
	}
	if _, err := a.run(ctx, "nft", "-f", tmp); err != nil {
		return FirewallApplyResult{}, fmt.Errorf("nftables apply failed: %w", err)
	}
	if err := AtomicWrite(path, []byte(batch), 0640); err != nil {
		return FirewallApplyResult{}, fmt.Errorf("firewall applied but managed file write failed: %w", err)
	}
	return FirewallApplyResult{RuleCount: len(rules), Table: "inet privora", Validated: true, Applied: true}, nil
}
