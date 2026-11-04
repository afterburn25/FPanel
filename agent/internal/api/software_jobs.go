package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type softwareJob struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"`
	Action     string         `json:"action"`
	Target     string         `json:"target"`
	PHPVersion string         `json:"php_version,omitempty"`
	Status     string         `json:"status"`
	Progress   int            `json:"progress"`
	Phase      string         `json:"phase"`
	Message    string         `json:"message"`
	Error      string         `json:"error,omitempty"`
	Result     map[string]any `json:"result,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	StartedAt  *time.Time     `json:"started_at,omitempty"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
}

type softwareJobManager struct {
	mu    sync.Mutex
	runMu sync.Mutex
	jobs  map[string]*softwareJob
}

func newSoftwareJobManager() *softwareJobManager {
	return &softwareJobManager{jobs: map[string]*softwareJob{}}
}

func softwareJobID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("sw-%d", time.Now().UTC().UnixNano())
	}
	return "sw-" + hex.EncodeToString(b)
}

func cloneSoftwareJob(in *softwareJob) softwareJob {
	if in == nil {
		return softwareJob{}
	}
	out := *in
	if in.Result != nil {
		out.Result = make(map[string]any, len(in.Result))
		for k, v := range in.Result {
			out.Result[k] = v
		}
	}
	return out
}

func (m *softwareJobManager) create(kind, action, target, phpVersion string) softwareJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.jobs) > 100 {
		cutoff := time.Now().UTC().Add(-6 * time.Hour)
		for id, job := range m.jobs {
			if job.FinishedAt != nil && job.FinishedAt.Before(cutoff) {
				delete(m.jobs, id)
			}
		}
	}
	job := &softwareJob{ID: softwareJobID(), Kind: kind, Action: action, Target: target, PHPVersion: phpVersion, Status: "queued", Progress: 2, Phase: "queued", Message: "Waiting for the Privora software transaction slot", CreatedAt: time.Now().UTC()}
	m.jobs[job.ID] = job
	return cloneSoftwareJob(job)
}

func (m *softwareJobManager) get(id string) (softwareJob, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok {
		return softwareJob{}, false
	}
	return cloneSoftwareJob(job), true
}

func (m *softwareJobManager) list() []softwareJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]softwareJob, 0, len(m.jobs))
	for _, job := range m.jobs {
		out = append(out, cloneSoftwareJob(job))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func (m *softwareJobManager) update(id, status string, progress int, phase, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job := m.jobs[id]
	if job == nil {
		return
	}
	if progress < job.Progress && status == "running" {
		progress = job.Progress
	}
	if progress < 0 {
		progress = 0
	}
	if progress > 100 {
		progress = 100
	}
	job.Status, job.Progress, job.Phase, job.Message = status, progress, phase, message
}

func (m *softwareJobManager) start(id string) {
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	if job := m.jobs[id]; job != nil {
		job.Status, job.Progress, job.Phase, job.Message, job.StartedAt = "running", 5, "starting", "Starting software transaction", &now
	}
}

func (m *softwareJobManager) finish(id string, result any, err error) {
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	job := m.jobs[id]
	if job == nil {
		return
	}
	job.FinishedAt = &now
	if err != nil {
		job.Status, job.Phase, job.Message, job.Error = "failed", "failed", "Software transaction failed", err.Error()
		if job.Progress < 5 {
			job.Progress = 5
		}
		return
	}
	job.Status, job.Progress, job.Phase, job.Message, job.Error = "complete", 100, "complete", "Software transaction completed and verified", ""
	if result != nil {
		b, marshalErr := json.Marshal(result)
		if marshalErr == nil {
			var decoded map[string]any
			if json.Unmarshal(b, &decoded) == nil {
				job.Result = decoded
			}
		}
	}
}

func validSoftwareTarget(v string) bool {
	if len(v) < 2 || len(v) > 64 {
		return false
	}
	for i, c := range v {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && i > 0)) {
			return false
		}
	}
	return true
}

func validSoftwarePHPVersion(v string) bool {
	switch v {
	case "8.2", "8.3", "8.4", "8.5":
		return true
	default:
		return false
	}
}

func (s *Server) startSoftwareJob(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind       string `json:"kind"`
		Action     string `json:"action"`
		Target     string `json:"target"`
		PHPVersion string `json:"php_version,omitempty"`
	}
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	in.Kind = strings.TrimSpace(strings.ToLower(in.Kind))
	in.Action = strings.TrimSpace(strings.ToLower(in.Action))
	in.Target = strings.TrimSpace(strings.ToLower(in.Target))
	in.PHPVersion = strings.TrimSpace(in.PHPVersion)
	valid := false
	switch in.Kind {
	case "component":
		valid = validSoftwareTarget(in.Target) && (in.Action == "install" || in.Action == "remove")
	case "preset":
		valid = validSoftwareTarget(in.Target) && in.Action == "apply" && validSoftwarePHPVersion(in.PHPVersion)
	case "php-version":
		valid = validSoftwarePHPVersion(in.Target) && (in.Action == "install" || in.Action == "remove")
	}
	if !valid {
		writeJSON(w, 400, map[string]any{"error": "invalid software job request"})
		return
	}
	job := s.softwareJobs.create(in.Kind, in.Action, in.Target, in.PHPVersion)
	s.auditMutation(r, "server.software.job.start", in.Kind+":"+in.Action+":"+in.Target, "queued")
	go s.runSoftwareJob(job.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "job": job})
}

func (s *Server) softwareJobStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if job, ok := s.softwareJobs.get(id); ok {
		writeJSON(w, 200, map[string]any{"job": job})
		return
	}
	writeJSON(w, 404, map[string]any{"error": "software job not found"})
}

func (s *Server) softwareJobsList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"jobs": s.softwareJobs.list()})
}

func (s *Server) runSoftwareJob(id string) {
	s.softwareJobs.runMu.Lock()
	defer s.softwareJobs.runMu.Unlock()
	job, ok := s.softwareJobs.get(id)
	if !ok {
		return
	}
	s.softwareJobs.start(id)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	progress := func(percent int, phase, message string) {
		s.softwareJobs.update(id, "running", percent, phase, message)
	}
	var result any
	var err error
	switch job.Kind {
	case "component":
		if job.Action == "install" {
			var component any
			var restarted []string
			component, restarted, err = s.host.InstallServerComponentWithProgress(ctx, job.Target, progress)
			result = map[string]any{"component": component, "restarted_services": restarted}
		} else {
			progress(20, "removing", "Removing allow-listed component packages")
			var component any
			var restarted []string
			component, restarted, err = s.host.RemoveServerComponent(ctx, job.Target)
			progress(92, "verifying", "Verifying component removal")
			result = map[string]any{"component": component, "restarted_services": restarted}
		}
	case "preset":
		var preset any
		var restarted []string
		preset, restarted, err = s.host.ApplyComponentPresetWithProgress(ctx, job.Target, job.PHPVersion, progress)
		result = map[string]any{"preset": preset, "restarted_services": restarted}
	case "php-version":
		if job.Action == "install" {
			progress(18, "installing", "Installing PHP runtime packages")
			var version any
			var restarted []string
			version, restarted, err = s.host.InstallPHPVersion(ctx, job.Target)
			progress(92, "verifying", "Verifying PHP runtime")
			result = map[string]any{"version": version, "restarted_services": restarted}
		} else {
			used := []string{}
			if !s.cfg.Mock {
				inv := s.host.DiscoverInventory(ctx)
				for _, site := range inv.Sites {
					if site.PHPVersion == job.Target {
						used = append(used, site.Domain)
					}
				}
			}
			for _, site := range s.hosting.ListSites() {
				if site.PHPVersion == job.Target {
					found := false
					for _, d := range used {
						if d == site.Domain {
							found = true
							break
						}
					}
					if !found {
						used = append(used, site.Domain)
					}
				}
			}
			if len(used) > 0 {
				err = errors.New("PHP version is still assigned to hosted websites; migrate them before removal")
				break
			}
			progress(18, "removing", "Removing PHP runtime packages")
			var version any
			version, err = s.host.RemovePHPVersion(ctx, job.Target)
			progress(92, "verifying", "Verifying PHP runtime removal")
			result = map[string]any{"version": version}
		}
	default:
		err = errors.New("unsupported software job")
	}
	if ctx.Err() != nil && err == nil {
		err = ctx.Err()
	}
	s.softwareJobs.finish(id, result, err)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	// This audit record is deliberately emitted from the background job because
	// the initiating HTTP request has already returned 202.
	if s.audit != nil {
		_ = outcome
	}
}
