package fabriccore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

type controllerState struct {
	Nodes      map[string]Node      `json:"nodes"`
	Workloads  map[string]Workload  `json:"workloads"`
	Placements map[string]Placement `json:"placements"`
}

// Controller persists desired workloads, node health/capacity, and the most
// recent placement decision. It is a control-plane placement controller only;
// it does not claim data replication, consensus, traffic routing, or provider
// orchestration.
type Controller struct {
	mu    sync.Mutex
	path  string
	state controllerState
}

func NewController(path string) (*Controller, error) {
	c := &Controller{path: path, state: controllerState{Nodes: map[string]Node{}, Workloads: map[string]Workload{}, Placements: map[string]Placement{}}}
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
		return nil, fmt.Errorf("invalid fabric controller state: %w", err)
	}
	if c.state.Nodes == nil {
		c.state.Nodes = map[string]Node{}
	}
	if c.state.Workloads == nil {
		c.state.Workloads = map[string]Workload{}
	}
	if c.state.Placements == nil {
		c.state.Placements = map[string]Placement{}
	}
	return c, nil
}

func validNode(n Node) bool {
	return n.ID != "" && n.Region != "" && n.Role != "" && n.Capacity > 0 && n.Used >= 0 && n.Used <= n.Capacity
}

func (c *Controller) persistLocked() error {
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
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return err
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

func (c *Controller) UpsertNode(n Node) error {
	if !validNode(n) {
		return errors.New("invalid fabric node")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.Nodes[n.ID] = n
	return c.persistLocked()
}

func (c *Controller) SetNodeHealth(id string, healthy bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.state.Nodes[id]
	if !ok {
		return errors.New("fabric node not found")
	}
	n.Healthy = healthy
	c.state.Nodes[id] = n
	return c.persistLocked()
}

func (c *Controller) UpsertWorkload(w Workload) error {
	if w.Name == "" || w.Role == "" || w.Replicas < 1 || w.MinRegions < 1 || w.MinRegions > w.Replicas {
		return errors.New("invalid workload")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.Workloads[w.Name] = w
	return c.persistLocked()
}

func (c *Controller) effectiveNodesLocked(excludeWorkload string) []Node {
	usedByPlacement := map[string]int{}
	for name, p := range c.state.Placements {
		if name == excludeWorkload || p.Degraded {
			continue
		}
		for _, id := range p.Nodes {
			usedByPlacement[id]++
		}
	}
	out := make([]Node, 0, len(c.state.Nodes))
	for _, n := range c.state.Nodes {
		n.Used += usedByPlacement[n.ID]
		if n.Used > n.Capacity {
			n.Used = n.Capacity
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (c *Controller) Reconcile(name string) (Placement, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w, ok := c.state.Workloads[name]
	if !ok {
		return Placement{}, errors.New("fabric workload not found")
	}
	nodes := c.effectiveNodesLocked(name)
	p, err := Plan(nodes, w)
	if err != nil {
		p = Placement{Workload: w.Name, Degraded: true}
		c.state.Placements[name] = p
		if persistErr := c.persistLocked(); persistErr != nil {
			return p, persistErr
		}
		return p, err
	}
	p.Degraded = false
	c.state.Placements[name] = p
	if err := c.persistLocked(); err != nil {
		return Placement{}, err
	}
	return p, nil
}

func (c *Controller) Placement(name string) (Placement, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.state.Placements[name]
	if !ok {
		return Placement{}, false
	}
	p.Nodes = append([]string(nil), p.Nodes...)
	p.Regions = append([]string(nil), p.Regions...)
	return p, true
}

func (c *Controller) Nodes() []Node {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Node, 0, len(c.state.Nodes))
	for _, n := range c.state.Nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
