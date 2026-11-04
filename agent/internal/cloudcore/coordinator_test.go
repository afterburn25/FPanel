package cloudcore

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type countingProvider struct {
	inner   *MemoryProvider
	creates int
	deletes int
}

func (p *countingProvider) Create(ctx context.Context, r CreateRequest) (Instance, error) {
	p.creates++
	return p.inner.Create(ctx, r)
}
func (p *countingProvider) Delete(ctx context.Context, r DeleteRequest) error {
	p.deletes++
	return p.inner.Delete(ctx, r)
}
func (p *countingProvider) Get(ctx context.Context, id string) (Instance, error) {
	return p.inner.Get(ctx, id)
}
func (p *countingProvider) List(ctx context.Context) ([]Instance, error) { return p.inner.List(ctx) }

func TestDurableCoordinatorCreateSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cloud.json")
	p := &countingProvider{inner: NewMemoryProvider()}
	req := CreateRequest{Provider: "test-provider", Region: "us-central", Size: "small-2", Image: "debian-13", Name: "web01", IdempotencyKey: "order-durable-1"}
	c, err := NewCoordinator(p, path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.Create(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := NewCoordinator(p, path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c2.Create(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || p.creates != 1 {
		t.Fatalf("durable idempotency failed: first=%s second=%s creates=%d", first.ID, second.ID, p.creates)
	}
	if err := c2.Delete(context.Background(), DeleteRequest{InstanceID: first.ID, Confirmation: first.ID}); err != nil {
		t.Fatal(err)
	}
	c3, err := NewCoordinator(p, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := c3.Delete(context.Background(), DeleteRequest{InstanceID: first.ID, Confirmation: first.ID}); err != nil {
		t.Fatal(err)
	}
	if p.deletes != 1 {
		t.Fatalf("delete reran after restart: %d", p.deletes)
	}
}

func TestDurableCoordinatorIncompleteIntentFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cloud.json")
	req := CreateRequest{Provider: "test-provider", Region: "us-central", Size: "small-2", Image: "debian-13", Name: "web01", IdempotencyKey: "order-incomplete-1"}
	st := durableState{Records: map[string]durableRecord{req.IdempotencyKey: {IdempotencyKey: req.IdempotencyKey, Status: "creating", Request: req, UpdatedAt: time.Now().UTC()}}}
	b, _ := json.Marshal(st)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	p := &countingProvider{inner: NewMemoryProvider()}
	c, err := NewCoordinator(p, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Create(context.Background(), req); err == nil {
		t.Fatal("incomplete durable create was re-executed")
	}
	if p.creates != 0 {
		t.Fatal("provider was called for incomplete durable state")
	}
}
