package cloudcore

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"sync"
	"time"
)

var safe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$`)

type Instance struct {
	ID, Provider, Region, Size, Image, Status string
	CreatedAt                                 time.Time
}
type CreateRequest struct{ Provider, Region, Size, Image, Name, IdempotencyKey string }
type DeleteRequest struct{ InstanceID, Confirmation string }
type Provider interface {
	Create(context.Context, CreateRequest) (Instance, error)
	Delete(context.Context, DeleteRequest) error
	Get(context.Context, string) (Instance, error)
	List(context.Context) ([]Instance, error)
}
type MemoryProvider struct {
	mu        sync.Mutex
	seq       int
	instances map[string]Instance
	keys      map[string]string
}

func NewMemoryProvider() *MemoryProvider {
	return &MemoryProvider{instances: map[string]Instance{}, keys: map[string]string{}}
}
func validate(r CreateRequest) error {
	if !safe.MatchString(r.Provider) || !safe.MatchString(r.Region) || !safe.MatchString(r.Size) || !safe.MatchString(r.Image) || !safe.MatchString(r.Name) || len(r.IdempotencyKey) < 8 {
		return errors.New("invalid cloud create request")
	}
	return nil
}
func (p *MemoryProvider) Create(_ context.Context, r CreateRequest) (Instance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := validate(r); err != nil {
		return Instance{}, err
	}
	if id, ok := p.keys[r.IdempotencyKey]; ok {
		return p.instances[id], nil
	}
	p.seq++
	id := "inst-" + r.Name + "-" + time.Now().UTC().Format("150405")
	v := Instance{ID: id, Provider: r.Provider, Region: r.Region, Size: r.Size, Image: r.Image, Status: "running", CreatedAt: time.Now().UTC()}
	p.instances[id] = v
	p.keys[r.IdempotencyKey] = id
	return v, nil
}
func (p *MemoryProvider) Delete(_ context.Context, r DeleteRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.instances[r.InstanceID]
	if !ok {
		return errors.New("instance not found")
	}
	if r.Confirmation != v.ID {
		return errors.New("destructive cloud delete confirmation mismatch")
	}
	delete(p.instances, r.InstanceID)
	return nil
}
func (p *MemoryProvider) Get(_ context.Context, id string) (Instance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.instances[id]
	if !ok {
		return Instance{}, errors.New("instance not found")
	}
	return v, nil
}
func (p *MemoryProvider) List(_ context.Context) ([]Instance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Instance, 0, len(p.instances))
	for _, v := range p.instances {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
