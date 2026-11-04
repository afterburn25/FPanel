package hostops

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Step describes one privileged operation without invoking a shell. Program and
// Args are kept separate so an eventual executor can use execve-style calls.
type Step struct {
	Operation    string   `json:"operation"`
	Program      string   `json:"program,omitempty"`
	Args         []string `json:"args,omitempty"`
	Target       string   `json:"target,omitempty"`
	RequiresRoot bool     `json:"requires_root"`
}

type Plan struct {
	Kind       string `json:"kind"`
	Resource   string `json:"resource"`
	Steps      []Step `json:"steps"`
	Validation []Step `json:"validation"`
	Rollback   []Step `json:"rollback"`
	Executable bool   `json:"executable"`
	Gate       string `json:"gate"`
}

type Request struct {
	Kind       string `json:"kind"`
	Username   string `json:"username,omitempty"`
	Domain     string `json:"domain,omitempty"`
	PHPVersion string `json:"php_version,omitempty"`
	Database   string `json:"database,omitempty"`
	DBUser     string `json:"db_user,omitempty"`
	Port       int    `json:"port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	CIDR       string `json:"cidr,omitempty"`
}

var (
	userRE  = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,31}$`)
	labelRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	dbRE    = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	phpRE   = regexp.MustCompile(`^8\.[2-5]$`)
)

func validDomain(v string) bool {
	v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
	if len(v) < 3 || len(v) > 253 || !strings.Contains(v, ".") {
		return false
	}
	for _, p := range strings.Split(v, ".") {
		if !labelRE.MatchString(p) {
			return false
		}
	}
	return true
}

func rejectMeta(v string) error {
	if strings.ContainsAny(v, "\x00\n\r;&|`$<>") || strings.Contains(v, "..") || strings.Contains(v, "/") || strings.Contains(v, "\\") {
		return errors.New("unsafe input")
	}
	return nil
}

func Build(in Request) (Plan, error) {
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	switch kind {
	case "account-create":
		if !userRE.MatchString(in.Username) || rejectMeta(in.Username) != nil {
			return Plan{}, errors.New("invalid username")
		}
		home := "/home/" + in.Username
		return gated(kind, in.Username,
			[]Step{{Operation: "linux-user-create", Program: "/usr/sbin/useradd", Args: []string{"--create-home", "--home-dir", home, "--shell", "/usr/sbin/nologin", in.Username}, RequiresRoot: true}},
			[]Step{{Operation: "user-exists", Program: "/usr/bin/id", Args: []string{in.Username}}},
			[]Step{{Operation: "linux-user-remove", Program: "/usr/sbin/userdel", Args: []string{"--remove", in.Username}, RequiresRoot: true}}), nil
	case "site-config":
		if !validDomain(in.Domain) || rejectMeta(in.Domain) != nil {
			return Plan{}, errors.New("invalid domain")
		}
		if !userRE.MatchString(in.Username) {
			return Plan{}, errors.New("invalid username")
		}
		if !phpRE.MatchString(in.PHPVersion) {
			return Plan{}, errors.New("unsupported PHP version")
		}
		target := "/etc/nginx/sites-available/privora-" + strings.ToLower(in.Domain) + ".conf"
		socket := "/run/php/php" + in.PHPVersion + "-fpm-" + in.Username + ".sock"
		return gated(kind, in.Domain,
			[]Step{{Operation: "write-generated-config", Target: target, Args: []string{"owner=root:root", "mode=0644", "php_socket=" + socket}, RequiresRoot: true}, {Operation: "enable-site", Target: "/etc/nginx/sites-enabled/privora-" + strings.ToLower(in.Domain) + ".conf", RequiresRoot: true}, {Operation: "reload-nginx", Program: "/usr/bin/systemctl", Args: []string{"reload", "nginx"}, RequiresRoot: true}},
			[]Step{{Operation: "nginx-config-test", Program: "/usr/sbin/nginx", Args: []string{"-t"}}, {Operation: "site-health-check", Target: "https://" + strings.ToLower(in.Domain)}},
			[]Step{{Operation: "restore-previous-config", Target: target, RequiresRoot: true}, {Operation: "reload-nginx", Program: "/usr/bin/systemctl", Args: []string{"reload", "nginx"}, RequiresRoot: true}}), nil
	case "database-create":
		if !dbRE.MatchString(in.Database) || !dbRE.MatchString(in.DBUser) || rejectMeta(in.Database) != nil || rejectMeta(in.DBUser) != nil {
			return Plan{}, errors.New("invalid database or user")
		}
		return gated(kind, in.Database,
			[]Step{{Operation: "database-create-via-driver", Target: in.Database, Args: []string{"user=" + in.DBUser}, RequiresRoot: true}},
			[]Step{{Operation: "database-connect-test", Target: in.Database}},
			[]Step{{Operation: "database-drop-via-driver", Target: in.Database, RequiresRoot: true}}), nil
	case "firewall-allow":
		if in.Port < 1 || in.Port > 65535 {
			return Plan{}, errors.New("invalid port")
		}
		proto := strings.ToLower(in.Protocol)
		if proto != "tcp" && proto != "udp" {
			return Plan{}, errors.New("invalid protocol")
		}
		if in.CIDR == "" {
			in.CIDR = "0.0.0.0/0"
		}
		if rejectMeta(in.CIDR) != nil || len(in.CIDR) > 64 {
			return Plan{}, errors.New("invalid CIDR")
		}
		spec := proto + "/" + strconv.Itoa(in.Port) + " from " + in.CIDR
		return gated(kind, spec,
			[]Step{{Operation: "nftables-add-rule", Target: spec, RequiresRoot: true}},
			[]Step{{Operation: "nftables-ruleset-check", Program: "/usr/sbin/nft", Args: []string{"--check", "--file", "/etc/nftables.conf"}}},
			[]Step{{Operation: "nftables-remove-rule", Target: spec, RequiresRoot: true}}), nil
	case "ssl-issue":
		if !validDomain(in.Domain) || rejectMeta(in.Domain) != nil {
			return Plan{}, errors.New("invalid domain")
		}
		return gated(kind, in.Domain,
			[]Step{{Operation: "acme-order", Target: in.Domain}, {Operation: "install-certificate", Target: "/etc/privora/tls/" + strings.ToLower(in.Domain), RequiresRoot: true}, {Operation: "reload-nginx", Program: "/usr/bin/systemctl", Args: []string{"reload", "nginx"}, RequiresRoot: true}},
			[]Step{{Operation: "certificate-chain-check", Target: in.Domain}, {Operation: "nginx-config-test", Program: "/usr/sbin/nginx", Args: []string{"-t"}}},
			[]Step{{Operation: "restore-previous-certificate", Target: in.Domain, RequiresRoot: true}}), nil
	default:
		return Plan{}, fmt.Errorf("unsupported host operation kind %q", kind)
	}
}

func gated(kind, resource string, steps, validation, rollback []Step) Plan {
	return Plan{Kind: kind, Resource: resource, Steps: steps, Validation: validation, Rollback: rollback, Executable: false, Gate: "production-host-adapter-certification-required"}
}
