package config

import "strings"

type Config struct {
	SocketPath            string
	AuditPath             string
	StatePath             string
	MockRoot              string
	AgentToken            string
	Mock                  bool
	HostMutations         bool
	HostCertificationPath string
	BackupRoot            string
	MigrationInbox        string
	MigrationRoot         string
	RegistrarProvider     string
	RegistrarAdapterURL   string
	RegistrarToken        string
	AllowedServices       map[string]bool
}

func DefaultAllowedServices() map[string]bool {
	items := []string{
		"nginx", "apache2", "httpd", "php8.5-fpm", "php8.4-fpm", "php8.3-fpm", "php8.2-fpm",
		"mariadb", "mysql", "postgresql", "redis-server", "postfix", "dovecot", "rspamd", "ssh", "sshd", "cron", "bind9", "privora-panel-fpm",
	}
	out := make(map[string]bool, len(items))
	for _, item := range items {
		out[item] = true
	}
	return out
}

func ParseAllowedServices(raw string) map[string]bool {
	if strings.TrimSpace(raw) == "" {
		return DefaultAllowedServices()
	}
	out := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out[item] = true
		}
	}
	return out
}
