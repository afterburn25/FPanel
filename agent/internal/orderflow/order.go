package orderflow

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Step struct {
	Name       string
	Run        func(context.Context) error
	Compensate func(context.Context) error
}
type Result struct {
	Key         string    `json:"key"`
	Status      string    `json:"status"`
	Completed   []string  `json:"completed"`
	Compensated []string  `json:"compensated"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	Error       string    `json:"error,omitempty"`
}
type Engine struct {
	mu       sync.Mutex
	results  map[string]Result
	inflight map[string]bool
	journal  string
}

func New() *Engine { return &Engine{results: map[string]Result{}, inflight: map[string]bool{}} }

func NewPersistent(journal string) (*Engine, error) {
	e := &Engine{results: map[string]Result{}, inflight: map[string]bool{}, journal: journal}
	f, err := os.Open(journal)
	if errors.Is(err, os.ErrNotExist) {
		return e, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2<<20)
	for scanner.Scan() {
		var r Result
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("invalid order journal: %w", err)
		}
		if r.Key != "" {
			e.results[r.Key] = r
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) append(r Result) error {
	if e.journal == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(e.journal), 0750); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.OpenFile(e.journal, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func cloneResult(r Result) Result {
	r.Completed = append([]string(nil), r.Completed...)
	r.Compensated = append([]string(nil), r.Compensated...)
	return r
}
func (e *Engine) store(r Result) error {
	e.mu.Lock()
	e.results[r.Key] = cloneResult(r)
	e.mu.Unlock()
	return e.append(r)
}

func (e *Engine) Run(ctx context.Context, key string, steps []Step) (Result, error) {
	if len(key) < 8 {
		return Result{}, errors.New("idempotency key required")
	}
	e.mu.Lock()
	if r, ok := e.results[key]; ok {
		e.mu.Unlock()
		if r.Status == "succeeded" {
			return cloneResult(r), nil
		}
		if r.Status == "running" || r.Status == "compensating" {
			return cloneResult(r), errors.New("order has incomplete durable state and requires recovery")
		}
		return cloneResult(r), errors.New(r.Error)
	}
	if e.inflight[key] {
		e.mu.Unlock()
		return Result{}, errors.New("order already in progress")
	}
	e.inflight[key] = true
	e.mu.Unlock()
	r := Result{Key: key, Status: "running", StartedAt: time.Now().UTC()}
	if err := e.store(r); err != nil {
		e.mu.Lock()
		delete(e.inflight, key)
		e.mu.Unlock()
		return r, fmt.Errorf("persist order start: %w", err)
	}
	finish := func() { e.mu.Lock(); delete(e.inflight, key); e.mu.Unlock() }
	defer finish()
	compensate := func(last int) {
		r.Status = "compensating"
		_ = e.store(r)
		for j := last; j >= 0; j-- {
			if steps[j].Compensate != nil {
				if ce := steps[j].Compensate(ctx); ce == nil {
					r.Compensated = append(r.Compensated, steps[j].Name)
					_ = e.store(r)
				}
			}
		}
	}
	for i, s := range steps {
		if s.Name == "" || s.Run == nil {
			r.Status = "failed"
			r.Error = "invalid step"
			r.FinishedAt = time.Now().UTC()
			_ = e.store(r)
			return r, errors.New(r.Error)
		}
		if err := s.Run(ctx); err != nil {
			compensate(i - 1)
			r.Status = "failed"
			r.Error = err.Error()
			r.FinishedAt = time.Now().UTC()
			_ = e.store(r)
			return r, err
		}
		r.Completed = append(r.Completed, s.Name)
		if err := e.store(r); err != nil {
			compensate(i)
			r.Status = "failed"
			r.Error = "persist completed step: " + err.Error()
			r.FinishedAt = time.Now().UTC()
			_ = e.store(r)
			return r, errors.New(r.Error)
		}
	}
	r.Status = "succeeded"
	r.FinishedAt = time.Now().UTC()
	if err := e.store(r); err != nil {
		return r, fmt.Errorf("persist order completion: %w", err)
	}
	return r, nil
}
