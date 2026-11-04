package hostadapter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeExecutable(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLFamilyCapabilityDoesNotDoubleAdvertiseMariaDB(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "mysql", `echo "mysql  Ver 15.1 Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)"`)
	writeExecutable(t, dir, "mariadb", `echo "mariadb  Ver 15.1 Distrib 10.11.6-MariaDB"`)
	old := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+old)
	if ok, _ := mysqlFamilyAvailable("mysql"); ok {
		t.Fatal("MariaDB compatibility mysql client must not advertise Oracle/MySQL")
	}
	if ok, _ := mysqlFamilyAvailable("mariadb"); !ok {
		t.Fatal("MariaDB should be available")
	}
}

func TestMySQLFamilyCapabilityRecognizesOracleMySQL(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "mysql", `echo "mysql  Ver 8.0.40 for Linux on x86_64 (MySQL Community Server - GPL)"`)
	old := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+old)
	if ok, detail := mysqlFamilyAvailable("mysql"); !ok {
		t.Fatalf("MySQL should be available: %s", detail)
	}
	if ok, _ := mysqlFamilyAvailable("mariadb"); ok {
		t.Fatal("MariaDB should not be advertised when only Oracle/MySQL is installed")
	}
}

func TestDiscoverInventoryUsesLiveAccountSiteAndDatabaseState(t *testing.T) {
	root := t.TempDir()
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(filepath.Join(homes, "acmeweb", "domains", "example.test", "public"), 0755); err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(root, "passwd")
	shadow := filepath.Join(root, "shadow")
	if err := os.WriteFile(passwd, []byte("acmeweb:x:2001:2001::"+filepath.Join(homes, "acmeweb")+":/usr/sbin/nologin\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadow, []byte("acmeweb:*:20000:0:99999:7:::\n"), 0600); err != nil {
		t.Fatal(err)
	}
	avail := filepath.Join(root, "nginx", "sites-available")
	enabled := filepath.Join(root, "nginx", "sites-enabled")
	if err := os.MkdirAll(avail, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(enabled, 0755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(avail, "privora-example.test.conf")
	cfg := "server {\n server_name example.test www.example.test;\n root " + filepath.Join(homes, "acmeweb", "domains", "example.test", "public") + ";\n fastcgi_pass unix:/run/php/php8.4-fpm-acmeweb.sock;\n}\n"
	if err := os.WriteFile(conf, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(conf, filepath.Join(enabled, filepath.Base(conf))); err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, bin, "mariadb", `case "$*" in *"SELECT CONCAT"*) echo "10.11.6-MariaDB Debian";; *"INFORMATION_SCHEMA.SCHEMATA"*) echo "acmeweb_app";; esac`)
	old := os.Getenv("PATH")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+old)

	a := New(Config{PasswdPath: passwd, ShadowPath: shadow, AccountHomeBase: homes, NginxSitesAvailable: avail, NginxSitesEnabled: enabled, PHPFPMPoolDir: filepath.Join(root, "php"), CommandTimeout: 2 * time.Second})
	inv := a.DiscoverInventory(context.Background())
	if len(inv.Accounts) != 1 || inv.Accounts[0].Username != "acmeweb" {
		t.Fatalf("accounts=%+v", inv.Accounts)
	}
	if len(inv.Sites) != 1 {
		t.Fatalf("expected www alias to collapse into one live website, got %+v", inv.Sites)
	}
	if inv.Sites[0].Username != "acmeweb" || !inv.Sites[0].Enabled {
		t.Fatalf("site=%+v", inv.Sites[0])
	}
	if len(inv.Databases) != 1 || inv.Databases[0].Engine != "mariadb" || inv.Databases[0].Owner != "acmeweb" {
		t.Fatalf("databases=%+v", inv.Databases)
	}
	if !strings.Contains(inv.Databases[0].Source, "system catalog") {
		t.Fatalf("source=%s", inv.Databases[0].Source)
	}
}

func TestDiscoverNginxSitesScansExtensionlessAndConfD(t *testing.T) {
	root := t.TempDir()
	avail := filepath.Join(root, "nginx", "sites-available")
	enabled := filepath.Join(root, "nginx", "sites-enabled")
	confD := filepath.Join(root, "nginx", "conf.d")
	for _, d := range []string{avail, enabled, confD, filepath.Join(root, "www", "alpha"), filepath.Join(root, "www", "beta")} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	defaultPath := filepath.Join(avail, "default")
	if err := os.WriteFile(defaultPath, []byte("server {\n server_name alpha.test;\n root "+filepath.Join(root, "www", "alpha")+";\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(defaultPath, filepath.Join(enabled, "default")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confD, "beta.conf"), []byte("server {\n server_name beta.test;\n root "+filepath.Join(root, "www", "beta")+";\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	a := New(Config{NginxSitesAvailable: avail, NginxSitesEnabled: enabled, AccountHomeBase: filepath.Join(root, "home"), CommandTimeout: time.Second})
	inv := HostInventory{Warnings: []string{}}
	sites := a.discoverNginxSites(context.Background(), nil, &inv)
	if len(sites) != 2 {
		t.Fatalf("sites=%+v warnings=%v", sites, inv.Warnings)
	}
	got := map[string]LiveSite{}
	for _, s := range sites {
		got[s.Domain] = s
	}
	if !got["alpha.test"].Enabled {
		t.Fatalf("extensionless enabled site not detected: %+v", got["alpha.test"])
	}
	if !got["beta.test"].Enabled {
		t.Fatalf("conf.d site not treated as enabled: %+v", got["beta.test"])
	}
}

func TestDiscoverNginxSitesUsesEffectiveConfigFromNginxT(t *testing.T) {
	root := t.TempDir()
	avail := filepath.Join(root, "nginx", "sites-available")
	enabled := filepath.Join(root, "nginx", "sites-enabled")
	for _, d := range []string{avail, enabled, filepath.Join(root, "custom"), filepath.Join(root, "www", "gamma"), filepath.Join(root, "bin")} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	custom := filepath.Join(root, "custom", "generated-hosting.conf")
	nginxScript := "cat <<'OUT'\n# configuration file /etc/nginx/nginx.conf:\nhttp {\n# configuration file " + custom + ":\nserver {\n listen 80;\n server_name gamma.test www.gamma.test;\n root " + filepath.Join(root, "www", "gamma") + ";\n}\n}\nOUT"
	writeExecutable(t, filepath.Join(root, "bin"), "nginx", nginxScript)
	t.Setenv("PATH", filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	a := New(Config{NginxSitesAvailable: avail, NginxSitesEnabled: enabled, PasswdPath: filepath.Join(root, "passwd"), CommandTimeout: time.Second})
	inv := HostInventory{Warnings: []string{}, Diagnostics: map[string]any{}}
	sites := a.discoverNginxSites(context.Background(), nil, &inv)
	if len(sites) != 1 {
		t.Fatalf("expected www alias to collapse into one effective website, sites=%+v warnings=%v", sites, inv.Warnings)
	}
	if inv.Diagnostics["nginx_effective_config"] != true {
		t.Fatalf("effective config diagnostic=%v", inv.Diagnostics)
	}
	for _, site := range sites {
		if !site.Enabled || site.Source != "nginx-effective" || site.NginxConfig != custom {
			t.Fatalf("site=%+v", site)
		}
	}
}

func TestDiscoverAccountsAdoptsExistingHomeWithoutPrivoraDomainsLayout(t *testing.T) {
	root := t.TempDir()
	homes := filepath.Join(root, "home")
	home := filepath.Join(homes, "providerusr")
	if err := os.MkdirAll(filepath.Join(home, "public_html"), 0755); err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(root, "passwd")
	shadow := filepath.Join(root, "shadow")
	if err := os.WriteFile(passwd, []byte("providerusr:x:2002:2002::"+home+":/bin/bash\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadow, []byte("providerusr:*:20000:0:99999:7:::\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Config{PasswdPath: passwd, ShadowPath: shadow, AccountHomeBase: homes, NginxSitesAvailable: filepath.Join(root, "nginx", "sites-available"), NginxSitesEnabled: filepath.Join(root, "nginx", "sites-enabled"), PHPFPMPoolDir: filepath.Join(root, "php"), CommandTimeout: time.Second})
	inv := a.DiscoverInventory(context.Background())
	if len(inv.Accounts) != 1 || inv.Accounts[0].Username != "providerusr" {
		t.Fatalf("accounts=%+v", inv.Accounts)
	}
	if inv.Accounts[0].Managed {
		t.Fatalf("existing provider account should be discovered but not falsely marked Privora-managed: %+v", inv.Accounts[0])
	}
	if !strings.Contains(inv.Accounts[0].Source, "public_html") {
		t.Fatalf("source=%q", inv.Accounts[0].Source)
	}
}

func TestSiteFromBlockCollapsesWWWAliasAndMarksPrivoraVhostManaged(t *testing.T) {
	block := nginxServerBlock{Source: "/etc/nginx/sites-enabled/privora-example.test.conf", Active: true, Text: "server {\n server_name example.test www.example.test;\n root /home/exampleweb/domains/example.test/public;\n}\n"}
	ids := map[string]passwdIdentity{"exampleweb": {Username: "exampleweb", UID: 1001, GID: 1001, Home: "/home/exampleweb", Shell: "/bin/bash"}}
	rows := siteFromBlock(block, ids, map[int]string{1001: "exampleweb"}, map[string]bool{})
	if len(rows) != 1 || rows[0].Domain != "example.test" || !rows[0].Managed {
		t.Fatalf("unexpected site inventory: %+v", rows)
	}
}

func TestInspectManagedSiteReconcilesCustomFilenameAndInlineDirectives(t *testing.T) {
	root := t.TempDir()
	avail := filepath.Join(root, "nginx", "sites-available")
	enabled := filepath.Join(root, "nginx", "sites-enabled")
	bin := filepath.Join(root, "bin")
	for _, d := range []string{avail, enabled, bin, filepath.Join(root, "home", "siteowner", "public_html")} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	custom := filepath.Join(avail, "legacy-customer-site")
	cfg := "server { listen 80; server_name privoralabs.com www.privoralabs.com; root " + filepath.Join(root, "home", "siteowner", "public_html") + "; }\n"
	if err := os.WriteFile(custom, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(custom, filepath.Join(enabled, "legacy-customer-site")); err != nil {
		t.Fatal(err)
	}
	// Force the fallback directory scan so this test proves reconciliation does
	// not depend on the current privora-<domain>.conf filename convention.
	writeExecutable(t, bin, "nginx", "echo unavailable >&2; exit 1")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	a := New(Config{NginxSitesAvailable: avail, NginxSitesEnabled: enabled, AccountHomeBase: filepath.Join(root, "home"), PasswdPath: filepath.Join(root, "passwd"), CommandTimeout: time.Second})
	site, ok := a.InspectManagedSite("privoralabs.com")
	if !ok || !site.Enabled || site.Domain != "privoralabs.com" {
		t.Fatalf("custom enabled vhost not reconciled: ok=%v site=%+v", ok, site)
	}
	if site.NginxConfig != filepath.Join(enabled, "legacy-customer-site") {
		t.Fatalf("nginx config=%q", site.NginxConfig)
	}
}

func TestEffectiveBINDZonesDiscoversLegacyZoneOutsidePrivoraDirectory(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "privora-zones")
	legacy := filepath.Join(root, "legacy", "db.privoralabs.com")
	cfg := `options { directory "` + root + `"; };
zone "privoralabs.com" {
    type master;
    file "legacy/db.privoralabs.com";
};
zone "10.in-addr.arpa" { type master; file "legacy/db.10"; };
`
	zones := effectiveBINDZones(cfg, managed)
	if len(zones) != 1 {
		t.Fatalf("zones=%+v", zones)
	}
	if zones[0].Domain != "privoralabs.com" || zones[0].ZoneFile != legacy || zones[0].Managed {
		t.Fatalf("legacy zone not reconciled correctly: %+v", zones[0])
	}
	if zones[0].Source != "bind effective config" {
		t.Fatalf("source=%q", zones[0].Source)
	}
}

func TestDiscoverInventoryIncludesEffectiveBINDLegacyZone(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	legacyDir := filepath.Join(root, "legacy")
	managedDir := filepath.Join(root, "privora-zones")
	for _, d := range []string{bin, legacyDir, managedDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	legacy := filepath.Join(legacyDir, "db.privoralabs.com")
	if err := os.WriteFile(legacy, []byte("$TTL 3600\nprivoralabs.com. IN SOA ns1.privoralabs.com. hostmaster.privoralabs.com. ( 1 3600 900 1209600 300 )\nprivoralabs.com. IN NS ns1.privoralabs.com.\nprivoralabs.com. IN A 192.0.2.10\n"), 0644); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, bin, "named-checkconf", `cat <<'OUT'
options { directory "`+root+`"; };
zone "privoralabs.com" { type master; file "legacy/db.privoralabs.com"; };
OUT`)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	a := New(Config{DNSZoneDir: managedDir, DNSIndexPath: filepath.Join(root, "privora-zones.conf"), PasswdPath: filepath.Join(root, "passwd"), NginxSitesAvailable: filepath.Join(root, "nginx", "sites-available"), NginxSitesEnabled: filepath.Join(root, "nginx", "sites-enabled"), PHPFPMPoolDir: filepath.Join(root, "php"), CommandTimeout: time.Second})
	inv := a.DiscoverInventory(context.Background())
	if len(inv.DNSZones) != 1 {
		t.Fatalf("dns zones=%+v warnings=%v diagnostics=%v", inv.DNSZones, inv.Warnings, inv.Diagnostics)
	}
	z := inv.DNSZones[0]
	if z.Domain != "privoralabs.com" || z.Managed || z.ZoneFile != legacy {
		t.Fatalf("legacy DNS zone missing from inventory: %+v", z)
	}
	if inv.Diagnostics["bind_effective_config"] != true {
		t.Fatalf("effective BIND diagnostic missing: %v", inv.Diagnostics)
	}
}

func TestReadBINDZoneFileShowsExternalRecordsReadOnly(t *testing.T) {
	root := t.TempDir()
	zonePath := filepath.Join(root, "db.privoralabs.com")
	zone := `$TTL 3600
privoralabs.com. IN SOA ns1.privoralabs.com. hostmaster.privoralabs.com. ( 1 3600 900 1209600 300 )
privoralabs.com. IN NS ns1.privoralabs.com.
                 IN NS ns2.privoralabs.com.
@ 300 IN A 192.0.2.10
www 300 IN CNAME privoralabs.com.
`
	if err := os.WriteFile(zonePath, []byte(zone), 0644); err != nil {
		t.Fatal(err)
	}
	a := New(Config{})
	got, err := a.ReadBINDZoneFile("privoralabs.com", zonePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 4 {
		t.Fatalf("records=%+v", got.Records)
	}
	if got.Records[0].Type != "NS" || got.Records[1].Type != "NS" {
		t.Fatalf("inherited apex NS records not parsed: %+v", got.Records)
	}
}

func TestNginxDumpHasServerNameOddServerFormatting(t *testing.T) {
	dump := "# configuration file /etc/nginx/sites-enabled/legacy.conf:\nserver\n{\n  listen 80;\n  server_name www.privoralabs.com privoralabs.com;\n}\n"
	if !nginxDumpHasServerName(dump, "privoralabs.com") {
		t.Fatal("exact server_name fallback missed legacy formatting")
	}
	if nginxDumpHasServerName(dump, "not-there.example") {
		t.Fatal("server_name fallback produced false positive")
	}
}

func TestDiscoverDNSInventoryDoesNotProbeDatabase(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	managed := filepath.Join(root, "privora-zones")
	avail := filepath.Join(root, "nginx", "sites-available")
	enabled := filepath.Join(root, "nginx", "sites-enabled")
	for _, d := range []string{bin, managed, avail, enabled} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(root, "database-probe-ran")
	writeExecutable(t, bin, "mariadb", `touch "`+marker+`"; exit 1`)
	writeExecutable(t, bin, "named-checkconf", `cat <<'OUT'
options { directory "`+root+`"; };
zone "privoralabs.com" { type master; file "db.privoralabs.com"; };
OUT`)
	if err := os.WriteFile(filepath.Join(root, "passwd"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	a := New(Config{DNSZoneDir: managed, PasswdPath: filepath.Join(root, "passwd"), NginxSitesAvailable: avail, NginxSitesEnabled: enabled, AccountHomeBase: filepath.Join(root, "home"), CommandTimeout: time.Second})
	inv := a.DiscoverDNSInventory(context.Background())
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("DNS-only inventory invoked database probe; err=%v", err)
	}
	if len(inv.DNSZones) != 1 || inv.DNSZones[0].Domain != "privoralabs.com" {
		t.Fatalf("dns-only inventory missed zone: %+v warnings=%v", inv.DNSZones, inv.Warnings)
	}
	if inv.Diagnostics["dns_inventory_scope"] != "dns-only" {
		t.Fatalf("dns-only diagnostic missing: %v", inv.Diagnostics)
	}
}

func TestDiscoverDNSInventoryFallsBackToRNDCForLoadedHostedRootZone(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	managed := filepath.Join(root, "privora-zones")
	avail := filepath.Join(root, "nginx", "sites-available")
	enabled := filepath.Join(root, "nginx", "sites-enabled")
	for _, d := range []string{bin, managed, avail, enabled} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate a degraded legacy BIND include: named-checkconf cannot print the
	// effective config, but the running named process still has privoralabs.com
	// loaded from its last valid configuration.
	writeExecutable(t, bin, "named-checkconf", `echo 'legacy include parse failure' >&2; exit 1`)
	writeExecutable(t, bin, "rndc", `if [ "$1" = zonestatus ] && [ "$2" = privoralabs.com ]; then
cat <<'OUT'
name: privoralabs.com
 type: primary
 serial: 2026082101
OUT
exit 0
fi
exit 1`)
	if err := os.WriteFile(filepath.Join(avail, "legacy-root"), []byte("server { listen 80; server_name privoralabs.com www.privoralabs.com; root "+filepath.Join(root, "home", "owner", "domains", "privoralabs.com", "public")+"; }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(avail, "legacy-root"), filepath.Join(enabled, "legacy-root")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "passwd"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	a := New(Config{DNSZoneDir: managed, PasswdPath: filepath.Join(root, "passwd"), NginxSitesAvailable: avail, NginxSitesEnabled: enabled, AccountHomeBase: filepath.Join(root, "home"), CommandTimeout: time.Second})
	inv := a.DiscoverDNSInventory(context.Background())
	found := false
	for _, z := range inv.DNSZones {
		if z.Domain == "privoralabs.com" {
			found = true
			if z.Managed {
				t.Fatalf("rndc fallback must remain read-only without a managed zone file: %+v", z)
			}
			if !strings.Contains(z.Source, "rndc-zonestatus") {
				t.Fatalf("source=%q", z.Source)
			}
		}
	}
	if !found {
		t.Fatalf("loaded root zone disappeared: zones=%+v warnings=%v diagnostics=%v", inv.DNSZones, inv.Warnings, inv.Diagnostics)
	}
	if inv.Diagnostics["bind_rndc_fallback"] != true {
		t.Fatalf("rndc fallback diagnostic missing: %v", inv.Diagnostics)
	}
}
