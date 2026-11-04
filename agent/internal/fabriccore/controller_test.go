package fabriccore

import (
	"path/filepath"
	"testing"
)

func TestPersistentControllerReconcilesFailoverAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fabric.json")
	c, err := NewController(path)
	if err != nil {
		t.Fatal(err)
	}
	nodes := []Node{
		{ID: "chi1", Region: "us-central", Role: "web", Healthy: true, Capacity: 10},
		{ID: "nyc1", Region: "us-east", Role: "web", Healthy: true, Capacity: 8},
		{ID: "sjc1", Region: "us-west", Role: "web", Healthy: true, Capacity: 6},
	}
	for _, n := range nodes {
		if err := c.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.UpsertWorkload(Workload{Name: "site-a", Role: "web", Replicas: 2, MinRegions: 2}); err != nil {
		t.Fatal(err)
	}
	first, err := c.Reconcile("site-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Nodes) != 2 || len(first.Regions) != 2 {
		t.Fatalf("unexpected placement: %+v", first)
	}
	dead := first.Nodes[0]
	if err := c.SetNodeHealth(dead, false); err != nil {
		t.Fatal(err)
	}
	second, err := c.Reconcile("site-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range second.Nodes {
		if id == dead {
			t.Fatalf("unhealthy node retained: %+v", second)
		}
	}
	if len(second.Regions) < 2 {
		t.Fatalf("region diversity lost: %+v", second)
	}

	c2, err := NewController(path)
	if err != nil {
		t.Fatal(err)
	}
	restored, ok := c2.Placement("site-a")
	if !ok {
		t.Fatal("placement missing after restart")
	}
	if len(restored.Nodes) != len(second.Nodes) {
		t.Fatalf("placement not persisted: %+v", restored)
	}
	for i := range restored.Nodes {
		if restored.Nodes[i] != second.Nodes[i] {
			t.Fatalf("placement changed after restart: %+v vs %+v", restored, second)
		}
	}
	for _, n := range c2.Nodes() {
		if n.ID == dead && n.Healthy {
			t.Fatal("node health was not durable")
		}
	}
}

func TestControllerPersistsDegradedDecision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fabric.json")
	c, err := NewController(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.UpsertNode(Node{ID: "chi1", Region: "us-central", Role: "web", Healthy: true, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	if err := c.UpsertWorkload(Workload{Name: "site-b", Role: "web", Replicas: 2, MinRegions: 2}); err != nil {
		t.Fatal(err)
	}
	p, err := c.Reconcile("site-b")
	if err == nil || !p.Degraded {
		t.Fatalf("insufficient capacity was not degraded: %+v err=%v", p, err)
	}
	c2, err := NewController(path)
	if err != nil {
		t.Fatal(err)
	}
	restored, ok := c2.Placement("site-b")
	if !ok || !restored.Degraded {
		t.Fatalf("degraded state not durable: %+v", restored)
	}
}
