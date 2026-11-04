package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// AccountTerminationPlan is a read-only, live-authoritative preview of an
// account termination. Known resources that the current termination transaction
// cannot remove safely become blockers instead of being orphaned silently.
type AccountTerminationPlan struct {
	Username           string    `json:"username"`
	Status             string    `json:"status"`
	PrimaryDomain      string    `json:"primary_domain,omitempty"`
	Package            string    `json:"package,omitempty"`
	HomeDirectory      string    `json:"home_directory,omitempty"`
	Websites           []string  `json:"websites"`
	ExternalWebsites   []string  `json:"external_websites"`
	DNSZones           []string  `json:"dns_zones"`
	Databases          []string  `json:"databases"`
	ManagedDatabases   []string  `json:"managed_databases"`
	UnmanagedDatabases []string  `json:"unmanaged_databases"`
	Mailboxes          []string  `json:"mailboxes"`
	ManagedMailboxes   []string  `json:"managed_mailboxes"`
	UnmanagedMailboxes []string  `json:"unmanaged_mailboxes"`
	Certificates       []string  `json:"certificates"`
	SFTPAccounts       []string  `json:"sftp_accounts"`
	Applications       []string  `json:"applications"`
	AppInstalls        []string  `json:"app_installs"`
	Deployments        []string  `json:"deployments"`
	CronJobs           []string  `json:"cron_jobs"`
	Backups            []string  `json:"backups"`
	CleanupActions     []string  `json:"cleanup_actions"`
	Retained           []string  `json:"retained"`
	CoverageWarnings   []string  `json:"coverage_warnings"`
	Blockers           []string  `json:"blockers"`
	Ready              bool      `json:"ready"`
	Fingerprint        string    `json:"fingerprint"`
	CollectedAt        time.Time `json:"collected_at"`
}

func appendUnique(dst []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return dst
	}
	for _, existing := range dst {
		if existing == value {
			return dst
		}
	}
	return append(dst, value)
}

func sortStrings(v []string) []string { sort.Strings(v); return v }

func (s *Server) buildAccountTerminationPlan(ctx context.Context, username string) (AccountTerminationPlan, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	plan := AccountTerminationPlan{
		Username: username,
		Websites: []string{}, ExternalWebsites: []string{}, DNSZones: []string{}, Databases: []string{}, ManagedDatabases: []string{}, UnmanagedDatabases: []string{},
		Mailboxes: []string{}, ManagedMailboxes: []string{}, UnmanagedMailboxes: []string{}, Certificates: []string{}, SFTPAccounts: []string{}, Applications: []string{},
		AppInstalls: []string{}, Deployments: []string{}, CronJobs: []string{}, Backups: []string{},
		CleanupActions: []string{}, Retained: []string{}, CoverageWarnings: []string{}, Blockers: []string{},
		CollectedAt: time.Now().UTC(),
	}
	if username == "" {
		return plan, fmt.Errorf("hosting username is required")
	}

	accountFound := false
	for _, a := range s.hosting.ListAccounts() {
		if strings.EqualFold(a.Username, username) {
			plan.PrimaryDomain, plan.Package, plan.Status = a.PrimaryDomain, a.Package, a.Status
			accountFound = true
			break
		}
	}

	ownedDomains := map[string]bool{}
	if s.cfg.Mock {
		for _, site := range s.hosting.ListSites() {
			if site.Username != username {
				continue
			}
			plan.Websites = appendUnique(plan.Websites, site.Domain)
			ownedDomains[strings.ToLower(site.Domain)] = true
		}
		if plan.Status == "" && accountFound {
			plan.Status = "active"
		}
		plan.HomeDirectory = "/home/" + username
	} else {
		s.host.InvalidateInventory()
		inv := s.host.DiscoverInventory(ctx)
		for _, a := range inv.Accounts {
			if a.Username != username {
				continue
			}
			accountFound = true
			plan.Status = a.Status
			plan.HomeDirectory = a.Home
			break
		}
		for _, site := range inv.Sites {
			if site.Username != username {
				continue
			}
			ownedDomains[strings.ToLower(site.Domain)] = true
			if site.Managed {
				plan.Websites = appendUnique(plan.Websites, site.Domain)
			} else {
				plan.ExternalWebsites = appendUnique(plan.ExternalWebsites, site.Domain)
			}
		}
		for _, db := range inv.Databases {
			if strings.EqualFold(db.Owner, username) {
				plan.Databases = appendUnique(plan.Databases, db.Engine+":"+db.Name)
			}
		}
		for _, zone := range inv.DNSZones {
			if ownedDomains[strings.ToLower(zone.Domain)] {
				plan.DNSZones = appendUnique(plan.DNSZones, zone.Domain)
			}
		}
		for _, mb := range inv.Mailboxes {
			if ownedDomains[strings.ToLower(mb.Domain)] {
				plan.Mailboxes = appendUnique(plan.Mailboxes, mb.Address)
			}
		}
		for _, cert := range inv.Certificates {
			if ownedDomains[strings.ToLower(cert.Domain)] {
				plan.Certificates = appendUnique(plan.Certificates, cert.Domain)
			}
		}
	}
	if !accountFound {
		return plan, fmt.Errorf("account not found")
	}

	// Privora state supplements live discovery with ownership metadata that is
	// not always discoverable safely from operating-system services.
	managedDB := map[string]bool{}
	for _, db := range s.resources.ListDatabases() {
		if strings.EqualFold(db.Owner, username) {
			key := db.Engine + ":" + db.Name
			managedDB[key] = true
			plan.Databases = appendUnique(plan.Databases, key)
			plan.ManagedDatabases = appendUnique(plan.ManagedDatabases, key)
		}
	}
	for _, sf := range s.resources.ListSFTPAccounts() {
		if strings.EqualFold(sf.Owner, username) {
			plan.SFTPAccounts = appendUnique(plan.SFTPAccounts, sf.Username)
		}
	}
	for _, app := range s.resources.ListApplications() {
		if strings.EqualFold(app.Owner, username) {
			plan.Applications = appendUnique(plan.Applications, app.Type+":"+app.Domain)
		}
	}
	managedMailbox := map[string]bool{}
	for _, mb := range s.resources.ListMailboxes() {
		if ownedDomains[strings.ToLower(mb.Domain)] {
			managedMailbox[strings.ToLower(mb.Address)] = true
			plan.Mailboxes = appendUnique(plan.Mailboxes, mb.Address)
			plan.ManagedMailboxes = appendUnique(plan.ManagedMailboxes, mb.Address)
		}
	}
	for _, cert := range s.resources.ListCertificates() {
		if ownedDomains[strings.ToLower(cert.Domain)] {
			plan.Certificates = appendUnique(plan.Certificates, cert.Domain)
		}
	}
	for _, zone := range s.resources.ListDNSZones() {
		if ownedDomains[strings.ToLower(zone.Domain)] {
			plan.DNSZones = appendUnique(plan.DNSZones, zone.Domain)
		}
	}
	for _, backup := range s.resources.ListBackups() {
		resource := strings.ToLower(strings.TrimSpace(backup.Resource))
		if resource == username || ownedDomains[resource] {
			plan.Backups = appendUnique(plan.Backups, backup.ID+":"+backup.Scope)
		}
	}
	for _, job := range s.platform.ListCronJobs() {
		if strings.EqualFold(job.Owner, username) {
			plan.CronJobs = appendUnique(plan.CronJobs, job.ID)
		}
	}
	for _, app := range s.platform.ListAppInstalls() {
		if strings.EqualFold(app.Owner, username) {
			plan.AppInstalls = appendUnique(plan.AppInstalls, app.ID+":"+app.Domain)
		}
	}
	for _, dep := range s.platform.ListDeployments() {
		if strings.EqualFold(dep.Owner, username) {
			plan.Deployments = appendUnique(plan.Deployments, dep.ID+":"+dep.Domain)
		}
	}

	for _, key := range plan.Databases {
		if !managedDB[key] {
			plan.UnmanagedDatabases = appendUnique(plan.UnmanagedDatabases, key)
		}
	}
	for _, address := range plan.Mailboxes {
		if !managedMailbox[strings.ToLower(address)] {
			plan.UnmanagedMailboxes = appendUnique(plan.UnmanagedMailboxes, address)
		}
	}

	plan.Websites = sortStrings(plan.Websites)
	plan.ExternalWebsites = sortStrings(plan.ExternalWebsites)
	plan.DNSZones = sortStrings(plan.DNSZones)
	plan.Databases = sortStrings(plan.Databases)
	plan.ManagedDatabases = sortStrings(plan.ManagedDatabases)
	plan.UnmanagedDatabases = sortStrings(plan.UnmanagedDatabases)
	plan.Mailboxes = sortStrings(plan.Mailboxes)
	plan.ManagedMailboxes = sortStrings(plan.ManagedMailboxes)
	plan.UnmanagedMailboxes = sortStrings(plan.UnmanagedMailboxes)
	plan.Certificates = sortStrings(plan.Certificates)
	plan.SFTPAccounts = sortStrings(plan.SFTPAccounts)
	plan.Applications = sortStrings(plan.Applications)
	plan.AppInstalls = sortStrings(plan.AppInstalls)
	plan.Deployments = sortStrings(plan.Deployments)
	plan.CronJobs = sortStrings(plan.CronJobs)
	plan.Backups = sortStrings(plan.Backups)

	plan.CleanupActions = append(plan.CleanupActions, "remove Privora-managed website vhosts", "remove account PHP-FPM runtime", "remove Linux hosting identity and home directory")
	if len(plan.DNSZones) > 0 {
		plan.CleanupActions = append(plan.CleanupActions, "optionally remove Privora-managed DNS zones for owned websites")
	}
	if len(plan.ManagedDatabases) > 0 {
		plan.CleanupActions = append(plan.CleanupActions, fmt.Sprintf("remove %d Privora-managed database(s) and paired users", len(plan.ManagedDatabases)))
	}
	if len(plan.ManagedMailboxes) > 0 {
		plan.CleanupActions = append(plan.CleanupActions, fmt.Sprintf("remove %d Privora-managed mailbox(es) and mail storage", len(plan.ManagedMailboxes)))
	}
	if len(plan.SFTPAccounts) > 0 {
		plan.CleanupActions = append(plan.CleanupActions, "remove account SFTP metadata; Linux account deletion removes group membership")
	}
	if len(plan.Applications)+len(plan.Deployments)+len(plan.CronJobs) > 0 {
		plan.CleanupActions = append(plan.CleanupActions, "remove account-owned simulation/lab metadata")
	}
	if len(plan.AppInstalls) > 0 {
		plan.CleanupActions = append(plan.CleanupActions, "remove curated-app records after their owned website data is removed")
	}
	if len(plan.Certificates) > 0 {
		plan.Retained = append(plan.Retained, fmt.Sprintf("%d certificate record(s) are not deleted by the current termination transaction", len(plan.Certificates)))
	}
	if len(plan.Backups) > 0 {
		plan.Retained = append(plan.Retained, fmt.Sprintf("%d backup record(s) are retained for recovery/history", len(plan.Backups)))
	}
	plan.CoverageWarnings = append(plan.CoverageWarnings,
		"FTP account termination is not yet inventory-backed; no FTP resource is claimed absent unless a certified backend reports it.",
		"Platform cron records are simulation/lab state until a certified live cron backend replaces them.")

	if plan.Status != "suspended" {
		plan.Blockers = append(plan.Blockers, "account must be suspended before termination")
	}
	if len(plan.ExternalWebsites) > 0 {
		plan.Blockers = append(plan.Blockers, "externally managed website configuration must be removed or adopted before termination")
	}
	if len(plan.UnmanagedDatabases) > 0 {
		plan.Blockers = append(plan.Blockers, "one or more owned databases are not Privora-managed; adopt, remove, or migrate them before termination")
	}
	if len(plan.UnmanagedMailboxes) > 0 {
		plan.Blockers = append(plan.Blockers, "one or more owned mailboxes are not Privora-managed; adopt, remove, or migrate them before termination")
	}
	plan.Ready = len(plan.Blockers) == 0

	// Fingerprint excludes the volatile collection timestamp and itself. The
	// delete request must echo this digest, forcing a fresh preflight whenever
	// ownership/state changes between preview and confirmation.
	copyPlan := plan
	copyPlan.Fingerprint = ""
	copyPlan.CollectedAt = time.Time{}
	b, _ := json.Marshal(copyPlan)
	sum := sha256.Sum256(b)
	plan.Fingerprint = hex.EncodeToString(sum[:])
	return plan, nil
}

func (s *Server) accountTerminationPlan(w http.ResponseWriter, r *http.Request) {
	plan, err := s.buildAccountTerminationPlan(r.Context(), r.PathValue("user"))
	if err != nil {
		code := 400
		if strings.Contains(err.Error(), "not found") {
			code = 404
		}
		writeJSON(w, code, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "plan": plan})
}
