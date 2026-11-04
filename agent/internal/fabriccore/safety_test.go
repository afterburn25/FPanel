package fabriccore

import (
	"testing"
	"time"
)

func TestFailureDecisionRequiresFreshPeerQuorum(t *testing.T) {
	members := []string{"chi1", "nyc1", "sjc1"}
	now := time.Now().UTC()
	epoch := uint64(7)
	d, err := DecideFailure(members, "chi1", epoch, []HealthObservation{{Observer: "nyc1", Target: "chi1", Healthy: false, Epoch: epoch, At: now}, {Observer: "sjc1", Target: "chi1", Healthy: false, Epoch: epoch, At: now}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != "fence-and-replace" || d.UnhealthyVotes != 2 || d.NextEpoch != 8 || d.FenceToken != "chi1:8" {
		t.Fatalf("unexpected decision %+v", d)
	}
	d, err = DecideFailure(members, "chi1", epoch, []HealthObservation{{Observer: "nyc1", Target: "chi1", Healthy: false, Epoch: epoch, At: now}, {Observer: "sjc1", Target: "chi1", Healthy: true, Epoch: epoch, At: now}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != "hold" {
		t.Fatalf("conflicting evidence triggered failover %+v", d)
	}
	d, err = DecideFailure(members, "chi1", epoch, []HealthObservation{{Observer: "nyc1", Target: "chi1", Healthy: false, Epoch: epoch, At: now.Add(-2 * time.Minute)}, {Observer: "sjc1", Target: "chi1", Healthy: false, Epoch: epoch, At: now}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != "hold" {
		t.Fatalf("stale minority triggered failover %+v", d)
	}
}

func TestRoutePlanDropsUnhealthyBackends(t *testing.T) {
	nodes := []Node{{ID: "chi1", Healthy: false}, {ID: "nyc1", Healthy: true}, {ID: "sjc1", Healthy: true}}
	p, err := BuildRoutePlan(nodes, Placement{Workload: "site-a", Nodes: []string{"chi1", "nyc1", "sjc1"}}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Degraded || len(p.Backends) != 2 || p.Backends[0] != "nyc1" {
		t.Fatalf("unexpected route plan %+v", p)
	}
}
