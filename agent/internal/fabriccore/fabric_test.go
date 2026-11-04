package fabriccore

import (
	"testing"
)

func TestMultiRegionPlacementAndFailover(t *testing.T) {
	nodes := []Node{{ID: "chi1", Region: "us-central", Role: "web", Healthy: true, Capacity: 10}, {ID: "chi2", Region: "us-central", Role: "web", Healthy: true, Capacity: 10}, {ID: "nyc1", Region: "us-east", Role: "web", Healthy: true, Capacity: 8}, {ID: "sjc1", Region: "us-west", Role: "web", Healthy: true, Capacity: 6}}
	w := Workload{Name: "site-a", Role: "web", Replicas: 3, MinRegions: 2}
	p, err := Plan(nodes, w)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != 3 || len(p.Regions) < 2 {
		t.Fatalf("%+v", p)
	}
	for i := range nodes {
		if nodes[i].ID == p.Nodes[0] {
			nodes[i].Healthy = false
		}
	}
	p2, err := Failover(nodes, w, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range p2.Nodes {
		if id == p.Nodes[0] {
			t.Fatal("unhealthy node retained")
		}
	}
}
