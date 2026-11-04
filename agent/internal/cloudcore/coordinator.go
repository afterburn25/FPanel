package cloudcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type durableRecord struct {
	IdempotencyKey string        `json:"idempotency_key"`
	Status         string        `json:"status"`
	Request        CreateRequest `json:"request"`
	Instance       Instance      `json:"instance"`
	Error          string        `json:"error,omitempty"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

type durableState struct {
	Records map[string]durableRecord `json:"records"`
}

// Coordinator makes provider lifecycle idempotency durable across process restarts.
// A crash after an intent is persisted but before its result is durably recorded
// fails closed and requires explicit recovery; it never guesses whether the
// provider side effect happened.
type Coordinator struct {
	mu       sync.Mutex
	provider Provider
	path     string
	state    durableState
}

func NewCoordinator(provider Provider, path string) (*Coordinator, error) {
	if provider == nil {
		return nil, errors.New("cloud provider required")
	}
	c := &Coordinator{provider: provider, path: path, state: durableState{Records: map[string]durableRecord{}}}
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return c, nil
	}
	if err := json.Unmarshal(b, &c.state); err != nil {
		return nil, fmt.Errorf("invalid cloud coordinator state: %w", err)
	}
	if c.state.Records == nil {
		c.state.Records = map[string]durableRecord{}
	}
	return c, nil
}

func (c *Coordinator) persistLocked() error {
	if c.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	writeErr := error(nil)
	if _, err = f.Write(b); err != nil {
		writeErr = err
	} else if err = f.Sync(); err != nil {
		writeErr = err
	}
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(tmp)
		return writeErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Rename(tmp, c.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (c *Coordinator) Create(ctx context.Context, r CreateRequest) (Instance, error) {
	if err := validate(r); err != nil {
		return Instance{}, err
	}
	c.mu.Lock()
	if existing, ok := c.state.Records[r.IdempotencyKey]; ok {
		switch existing.Status {
		case "created":
			c.mu.Unlock()
			return existing.Instance, nil
		case "creating", "deleting":
			c.mu.Unlock()
			return Instance{}, errors.New("cloud lifecycle has incomplete durable state and requires recovery")
		case "deleted":
			c.mu.Unlock()
			return Instance{}, errors.New("idempotency key already completed a deleted lifecycle")
		case "failed":
			c.mu.Unlock()
			if existing.Error == "" {
				return Instance{}, errors.New("cloud lifecycle previously failed")
			}
			return Instance{}, errors.New(existing.Error)
		}
	}
	rec := durableRecord{IdempotencyKey: r.IdempotencyKey, Status: "creating", Request: r, UpdatedAt: time.Now().UTC()}
	c.state.Records[r.IdempotencyKey] = rec
	if err := c.persistLocked(); err != nil {
		delete(c.state.Records, r.IdempotencyKey)
		c.mu.Unlock()
		return Instance{}, fmt.Errorf("persist cloud create intent: %w", err)
	}
	c.mu.Unlock()

	inst, err := c.provider.Create(ctx, r)

	c.mu.Lock()
	defer c.mu.Unlock()
	rec = c.state.Records[r.IdempotencyKey]
	rec.UpdatedAt = time.Now().UTC()
	if err != nil {
		rec.Status = "failed"
		rec.Error = err.Error()
		c.state.Records[r.IdempotencyKey] = rec
		_ = c.persistLocked()
		return Instance{}, err
	}
	rec.Status = "created"
	rec.Instance = inst
	rec.Error = ""
	c.state.Records[r.IdempotencyKey] = rec
	if err := c.persistLocked(); err != nil {
		// We know the provider created the instance but could not durably record
		// it. Attempt exact-ID compensation rather than risk an orphan.
		_ = c.provider.Delete(ctx, DeleteRequest{InstanceID: inst.ID, Confirmation: inst.ID})
		rec.Status = "failed"
		rec.Error = "provider create succeeded but durable result persistence failed"
		c.state.Records[r.IdempotencyKey] = rec
		_ = c.persistLocked()
		return Instance{}, errors.New(rec.Error)
	}
	return inst, nil
}

func (c *Coordinator) Delete(ctx context.Context, r DeleteRequest) error {
	if r.InstanceID == "" || r.Confirmation != r.InstanceID {
		return errors.New("destructive cloud delete confirmation mismatch")
	}
	c.mu.Lock()
	var key string
	var rec durableRecord
	for k, candidate := range c.state.Records {
		if candidate.Instance.ID == r.InstanceID {
			key, rec = k, candidate
			break
		}
	}
	if key == "" {
		c.mu.Unlock()
		return errors.New("instance not tracked by durable coordinator")
	}
	switch rec.Status {
	case "deleted":
		c.mu.Unlock()
		return nil
	case "creating", "deleting":
		c.mu.Unlock()
		return errors.New("cloud lifecycle has incomplete durable state and requires recovery")
	case "created":
	default:
		c.mu.Unlock()
		return errors.New("cloud lifecycle is not deletable")
	}
	rec.Status = "deleting"
	rec.UpdatedAt = time.Now().UTC()
	c.state.Records[key] = rec
	if err := c.persistLocked(); err != nil {
		rec.Status = "created"
		c.state.Records[key] = rec
		c.mu.Unlock()
		return fmt.Errorf("persist cloud delete intent: %w", err)
	}
	c.mu.Unlock()

	if err := c.provider.Delete(ctx, r); err != nil {
		c.mu.Lock()
		rec = c.state.Records[key]
		rec.Status = "failed"
		rec.Error = err.Error()
		rec.UpdatedAt = time.Now().UTC()
		c.state.Records[key] = rec
		_ = c.persistLocked()
		c.mu.Unlock()
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	rec = c.state.Records[key]
	rec.Status = "deleted"
	rec.Error = ""
	rec.UpdatedAt = time.Now().UTC()
	c.state.Records[key] = rec
	if err := c.persistLocked(); err != nil {
		return fmt.Errorf("provider delete succeeded but durable result persistence failed: %w", err)
	}
	return nil
}
