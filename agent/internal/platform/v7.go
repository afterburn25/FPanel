package platform

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

// 6.91 — mailbox-level message filtering policy. The live Sieve adapter owns
// compilation/application; this state records operator/customer intent.
type MailFilter struct {
	ID          string    `json:"id"`
	Owner       string    `json:"owner"`
	Address     string    `json:"address"`
	Name        string    `json:"name"`
	Field       string    `json:"field"`
	Operator    string    `json:"operator"`
	Value       string    `json:"value"`
	Action      string    `json:"action"`
	Destination string    `json:"destination,omitempty"`
	Enabled     bool      `json:"enabled"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// 6.92 — scheduled/retained backup policy. Execution is deliberately separate
// from storage policy so an unavailable destination cannot masquerade as ready.
type BackupPolicy struct {
	ID          string    `json:"id"`
	Owner       string    `json:"owner,omitempty"`
	Scope       string    `json:"scope"`
	Resource    string    `json:"resource"`
	Destination string    `json:"destination"`
	Schedule    string    `json:"schedule"`
	Retention   int       `json:"retention"`
	Verify      bool      `json:"verify"`
	Enabled     bool      `json:"enabled"`
	Status      string    `json:"status"`
	LastRun     time.Time `json:"last_run,omitempty"`
	LastStatus  string    `json:"last_status,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// 6.96 — advanced per-site behavior kept as explicit intent and reconciled by
// the certified Nginx adapter.
type SitePolicy struct {
	Domain            string    `json:"domain"`
	Owner             string    `json:"owner"`
	ForceHTTPS        bool      `json:"force_https"`
	HSTS              bool      `json:"hsts"`
	HSTSMaxAge        int       `json:"hsts_max_age"`
	RedirectTarget    string    `json:"redirect_target,omitempty"`
	DirectoryIndex    string    `json:"directory_index,omitempty"`
	HotlinkProtection bool      `json:"hotlink_protection"`
	Status            string    `json:"status"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// 6.99 — reusable authoritative DNS record templates.
type DNSTemplate struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	Records   []DNSRecordTemplate `json:"records"`
	CreatedAt time.Time           `json:"created_at"`
	UpdatedAt time.Time           `json:"updated_at"`
}
type DNSRecordTemplate struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

// 7.0 — persistent output of the readiness planner, so remediation is auditable.
type ReadinessItem struct {
	ID           string `json:"id"`
	Area         string `json:"area"`
	Resource     string `json:"resource"`
	Severity     string `json:"severity"`
	Status       string `json:"status"`
	Summary      string `json:"summary"`
	RepairAction string `json:"repair_action,omitempty"`
}
type ReadinessRun struct {
	ID        string          `json:"id"`
	Score     int             `json:"score"`
	Status    string          `json:"status"`
	Items     []ReadinessItem `json:"items"`
	CreatedAt time.Time       `json:"created_at"`
}

func (m *Manager) ListMailFilters() []MailFilter {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]MailFilter, 0, len(m.state.MailFilters))
	for _, v := range m.state.MailFilters {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
func (m *Manager) UpsertMailFilter(v MailFilter) (MailFilter, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v.Address = strings.ToLower(strings.TrimSpace(v.Address))
	v.Owner = strings.ToLower(strings.TrimSpace(v.Owner))
	v.Name = strings.TrimSpace(v.Name)
	if !strings.Contains(v.Address, "@") || !validSafeText(v.Name, 100) || !map[string]bool{"from": true, "to": true, "subject": true, "size": true}[v.Field] || !map[string]bool{"contains": true, "is": true, "matches": true, "over": true, "under": true}[v.Operator] || !map[string]bool{"keep": true, "discard": true, "fileinto": true, "redirect": true}[v.Action] || !validSafeText(v.Value, 240) {
		return v, errors.New("invalid mail filter")
	}
	if v.Action == "redirect" && !strings.Contains(v.Destination, "@") {
		return v, errors.New("redirect destination must be an email address")
	}
	if v.Action == "fileinto" && !regexp.MustCompile(`^[A-Za-z0-9 _.-]{1,80}$`).MatchString(v.Destination) {
		return v, errors.New("invalid mailbox folder")
	}
	now := time.Now().UTC()
	if v.ID == "" {
		v.ID = makeID("filter")
		v.CreatedAt = now
	} else if old, ok := m.state.MailFilters[v.ID]; ok {
		v.CreatedAt = old.CreatedAt
	} else {
		return v, errors.New("mail filter not found")
	}
	v.UpdatedAt = now
	v.Enabled = true
	if v.Status == "" {
		v.Status = "pending-reconcile"
	}
	m.state.MailFilters[v.ID] = v
	return v, m.save()
}
func (m *Manager) DeleteMailFilter(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.state.MailFilters[id]; !ok {
		return errors.New("mail filter not found")
	}
	delete(m.state.MailFilters, id)
	return m.save()
}

func (m *Manager) ListBackupPolicies() []BackupPolicy {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]BackupPolicy, 0, len(m.state.BackupPolicies))
	for _, v := range m.state.BackupPolicies {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
func (m *Manager) UpsertBackupPolicy(v BackupPolicy) (BackupPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !map[string]bool{"site": true, "account": true}[v.Scope] || !validSafeText(v.Resource, 190) || !map[string]bool{"local": true}[v.Destination] || !regexp.MustCompile(`^(hourly|daily|weekly|monthly|[0-9*/?, -]+)$`).MatchString(v.Schedule) || v.Retention < 1 || v.Retention > 365 {
		return v, errors.New("invalid backup policy")
	}
	now := time.Now().UTC()
	if v.ID == "" {
		v.ID = makeID("backup_policy")
		v.CreatedAt = now
	} else if old, ok := m.state.BackupPolicies[v.ID]; ok {
		v.CreatedAt = old.CreatedAt
	} else {
		return v, errors.New("backup policy not found")
	}
	v.UpdatedAt = now
	v.Enabled = true
	if v.Status == "" {
		v.Status = "configured"
	}
	m.state.BackupPolicies[v.ID] = v
	return v, m.save()
}
func (m *Manager) DeleteBackupPolicy(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.state.BackupPolicies[id]; !ok {
		return errors.New("backup policy not found")
	}
	delete(m.state.BackupPolicies, id)
	return m.save()
}

func (m *Manager) GetSitePolicy(domain string) (SitePolicy, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.state.SitePolicies[strings.ToLower(domain)]
	return v, ok
}
func (m *Manager) ListSitePolicies() []SitePolicy {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SitePolicy, 0, len(m.state.SitePolicies))
	for _, v := range m.state.SitePolicies {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}
func (m *Manager) SetSitePolicy(v SitePolicy) (SitePolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v.Domain = strings.ToLower(strings.TrimSpace(v.Domain))
	if !domainRx.MatchString(v.Domain) || !ownerRx.MatchString(v.Owner) {
		return v, errors.New("invalid site policy")
	}
	if v.HSTSMaxAge == 0 {
		v.HSTSMaxAge = 15552000
	}
	if v.HSTSMaxAge < 0 || v.HSTSMaxAge > 63072000 {
		return v, errors.New("invalid HSTS max age")
	}
	if v.RedirectTarget != "" {
		if !strings.HasPrefix(v.RedirectTarget, "https://") || len(v.RedirectTarget) > 240 {
			return v, errors.New("redirect target must be https")
		}
	}
	if v.DirectoryIndex == "" {
		v.DirectoryIndex = "index.php index.html index.htm"
	}
	if !regexp.MustCompile(`^[A-Za-z0-9._ -]{1,120}$`).MatchString(v.DirectoryIndex) {
		return v, errors.New("invalid directory index")
	}
	v.UpdatedAt = time.Now().UTC()
	if v.Status == "" {
		v.Status = "pending-reconcile"
	}
	m.state.SitePolicies[v.Domain] = v
	return v, m.save()
}

func (m *Manager) DeleteSitePolicy(domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	domain = strings.ToLower(strings.TrimSpace(domain))
	if _, ok := m.state.SitePolicies[domain]; !ok {
		return nil
	}
	delete(m.state.SitePolicies, domain)
	return m.save()
}

func (m *Manager) ListDNSTemplates() []DNSTemplate {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]DNSTemplate, 0, len(m.state.DNSTemplates))
	for _, v := range m.state.DNSTemplates {
		v.Records = append([]DNSRecordTemplate(nil), v.Records...)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func (m *Manager) UpsertDNSTemplate(v DNSTemplate) (DNSTemplate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validSafeText(v.Name, 100) || len(v.Records) < 1 || len(v.Records) > 100 {
		return v, errors.New("invalid DNS template")
	}
	for _, r := range v.Records {
		if !map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true, "CAA": true}[strings.ToUpper(r.Type)] || r.TTL < 60 || r.TTL > 86400 || !validSafeText(r.Name, 190) || !validSafeText(r.Value, 4096) {
			return v, errors.New("invalid DNS template record")
		}
	}
	now := time.Now().UTC()
	if v.ID == "" {
		v.ID = makeID("dns_template")
		v.CreatedAt = now
	} else if old, ok := m.state.DNSTemplates[v.ID]; ok {
		v.CreatedAt = old.CreatedAt
	} else {
		return v, errors.New("DNS template not found")
	}
	v.UpdatedAt = now
	m.state.DNSTemplates[v.ID] = v
	return v, m.save()
}
func (m *Manager) DeleteDNSTemplate(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.state.DNSTemplates[id]; !ok {
		return errors.New("DNS template not found")
	}
	delete(m.state.DNSTemplates, id)
	return m.save()
}

func (m *Manager) RecordReadiness(score int, status string, items []ReadinessItem) (ReadinessRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if score < 0 || score > 100 {
		return ReadinessRun{}, errors.New("invalid readiness score")
	}
	v := ReadinessRun{ID: makeID("ready"), Score: score, Status: status, Items: append([]ReadinessItem(nil), items...), CreatedAt: time.Now().UTC()}
	m.state.ReadinessRuns[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListReadinessRuns() []ReadinessRun {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ReadinessRun, 0, len(m.state.ReadinessRuns))
	for _, v := range m.state.ReadinessRuns {
		v.Items = append([]ReadinessItem(nil), v.Items...)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func validateCIDRs(cidrs []string) error {
	for _, v := range cidrs {
		if _, _, err := net.ParseCIDR(v); err != nil {
			return fmt.Errorf("invalid CIDR %q", v)
		}
	}
	return nil
}

// UpdateBackupPolicyRun records scheduler execution without changing policy intent.
func (m *Manager) UpdateBackupPolicyRun(id, status string, at time.Time) (BackupPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.state.BackupPolicies[id]
	if !ok {
		return BackupPolicy{}, errors.New("backup policy not found")
	}
	v.LastRun = at.UTC()
	v.LastStatus = strings.TrimSpace(status)
	v.UpdatedAt = time.Now().UTC()
	m.state.BackupPolicies[id] = v
	return v, m.save()
}

func metricValueV7(v MetricSample, metric string) float64 {
	switch metric {
	case "cpu":
		return v.CPU
	case "memory":
		return v.Memory
	case "disk":
		return v.Disk
	case "load":
		return v.Load
	case "mail_queue":
		return float64(v.MailQueue)
	case "php_busy":
		return float64(v.PHPBusy)
	default:
		return 0
	}
}

func compareAlertV7(value float64, op string, threshold float64) bool {
	switch op {
	case ">":
		return value > threshold
	case ">=":
		return value >= threshold
	case "<":
		return value < threshold
	case "<=":
		return value <= threshold
	default:
		return false
	}
}

// EnsureDefaultAlertRules gives a new server useful operational alerts without
// overwriting operator-created rules. It is idempotent.
func (m *Manager) EnsureDefaultAlertRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.state.AlertRules) != 0 {
		return nil
	}
	now := time.Now().UTC()
	defaults := []AlertRule{
		{Name: "Disk usage above 85%", Metric: "disk", Operator: ">=", Threshold: 85, WindowMin: 5, Severity: "critical", Enabled: true},
		{Name: "Memory usage above 90%", Metric: "memory", Operator: ">=", Threshold: 90, WindowMin: 10, Severity: "warning", Enabled: true},
		{Name: "CPU usage above 90%", Metric: "cpu", Operator: ">=", Threshold: 90, WindowMin: 10, Severity: "warning", Enabled: true},
		{Name: "Mail queue above 100 messages", Metric: "mail_queue", Operator: ">=", Threshold: 100, WindowMin: 5, Severity: "warning", Enabled: true},
	}
	for _, v := range defaults {
		v.ID = makeID("alert")
		v.CreatedAt = now
		m.state.AlertRules[v.ID] = v
	}
	return m.save()
}

// EvaluateAlertRules evaluates each enabled rule over the requested recent
// window. It opens one incident per rule and resolves that incident when the
// condition clears, preventing notification storms from duplicate incidents.
func (m *Manager) EvaluateAlertRules(now time.Time) ([]Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	for _, rule := range m.state.AlertRules {
		if !rule.Enabled {
			continue
		}
		window := time.Duration(rule.WindowMin) * time.Minute
		cutoff := now.Add(-window)
		var total float64
		count := 0
		for _, sample := range m.state.Metrics {
			if sample.CapturedAt.Before(cutoff) {
				continue
			}
			total += metricValueV7(sample, rule.Metric)
			count++
		}
		if count == 0 {
			continue
		}
		value := total / float64(count)
		triggered := compareAlertV7(value, rule.Operator, rule.Threshold)
		openID := ""
		for id, inc := range m.state.Incidents {
			if inc.RuleID == rule.ID && inc.Status == "open" {
				openID = id
				break
			}
		}
		if triggered && openID == "" {
			inc := Incident{ID: makeID("incident"), RuleID: rule.ID, Title: rule.Name, Severity: rule.Severity, Status: "open", Detail: fmt.Sprintf("%s average %.2f %s %.2f over %d minute(s)", rule.Metric, value, rule.Operator, rule.Threshold, rule.WindowMin), CreatedAt: now.UTC()}
			m.state.Incidents[inc.ID] = inc
		} else if !triggered && openID != "" {
			inc := m.state.Incidents[openID]
			inc.Status = "resolved"
			inc.Detail += fmt.Sprintf("; cleared at %s", now.UTC().Format(time.RFC3339))
			m.state.Incidents[openID] = inc
		}
	}
	out := make([]Incident, 0, len(m.state.Incidents))
	for _, v := range m.state.Incidents {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, m.save()
}

func (m *Manager) DeleteAlertRule(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.state.AlertRules[id]; !ok {
		return errors.New("alert rule not found")
	}
	delete(m.state.AlertRules, id)
	for incidentID, inc := range m.state.Incidents {
		if inc.RuleID == id && inc.Status == "open" {
			inc.Status = "resolved"
			inc.Detail += "; rule deleted"
			m.state.Incidents[incidentID] = inc
		}
	}
	return m.save()
}

func (m *Manager) ResolveIncident(id string) (Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.state.Incidents[id]
	if !ok {
		return Incident{}, errors.New("incident not found")
	}
	v.Status = "resolved"
	m.state.Incidents[id] = v
	return v, m.save()
}
