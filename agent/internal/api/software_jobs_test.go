package api

import (
	"errors"
	"testing"
)

func TestSoftwareJobLifecycle(t *testing.T) {
	m := newSoftwareJobManager()
	job := m.create("component", "install", "php-imagick", "")
	if job.Status != "queued" || job.Progress != 2 || job.ID == "" {
		t.Fatalf("unexpected queued job: %#v", job)
	}
	m.start(job.ID)
	m.update(job.ID, "running", 72, "packages", "Package transaction completed")
	got, ok := m.get(job.ID)
	if !ok || got.Status != "running" || got.Progress != 72 || got.Phase != "packages" {
		t.Fatalf("unexpected running job: %#v", got)
	}
	m.finish(job.ID, map[string]any{"ok": true}, nil)
	got, _ = m.get(job.ID)
	if got.Status != "complete" || got.Progress != 100 || got.FinishedAt == nil {
		t.Fatalf("unexpected completed job: %#v", got)
	}
}

func TestSoftwareJobFailureKeepsProgressAndError(t *testing.T) {
	m := newSoftwareJobManager()
	job := m.create("preset", "apply", "laravel", "8.4")
	m.start(job.ID)
	m.update(job.ID, "running", 76, "composer", "Provisioning Laravel CLI with Composer")
	m.finish(job.ID, nil, errors.New("composer failed"))
	got, _ := m.get(job.ID)
	if got.Status != "failed" || got.Progress != 76 || got.Error != "composer failed" {
		t.Fatalf("unexpected failed job: %#v", got)
	}
}
