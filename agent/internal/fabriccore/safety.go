package fabriccore

import (
	"errors"
	"sort"
	"time"
)

type HealthObservation struct {
	Observer string    `json:"observer"`
	Target   string    `json:"target"`
	Healthy  bool      `json:"healthy"`
	Epoch    uint64    `json:"epoch"`
	At       time.Time `json:"at"`
}

type FailureDecision struct {
	Target         string   `json:"target"`
	Epoch          uint64   `json:"epoch"`
	NextEpoch      uint64   `json:"next_epoch,omitempty"`
	RequiredQuorum int      `json:"required_quorum"`
	UnhealthyVotes int      `json:"unhealthy_votes"`
	HealthyVotes   int      `json:"healthy_votes"`
	Voters         []string `json:"voters"`
	Action         string   `json:"action"`
	FenceToken     string   `json:"fence_token,omitempty"`
}

// DecideFailure is a safety algorithm, not a distributed consensus protocol.
// It requires a fresh majority of distinct peer observations at the exact
// control epoch before emitting a fence-and-replace intent. A minority,
// conflict, stale evidence, or a two-node topology always holds.
func DecideFailure(clusterMembers []string, target string, epoch uint64, observations []HealthObservation, maxAge time.Duration) (FailureDecision, error) {
	if len(clusterMembers) < 3 || target == "" || epoch == 0 {
		return FailureDecision{}, errors.New("failure decision requires at least 3 members, target and epoch")
	}
	if maxAge <= 0 {
		maxAge = 30 * time.Second
	}
	members := map[string]bool{}
	for _, id := range clusterMembers {
		if id == "" {
			return FailureDecision{}, errors.New("invalid cluster member")
		}
		members[id] = true
	}
	if !members[target] {
		return FailureDecision{}, errors.New("target is not a cluster member")
	}
	quorum := len(clusterMembers)/2 + 1
	now := time.Now().UTC()
	latest := map[string]HealthObservation{}
	for _, o := range observations {
		if o.Target != target || o.Observer == target || !members[o.Observer] || o.Epoch != epoch || o.At.IsZero() {
			continue
		}
		if o.At.Before(now.Add(-maxAge)) || o.At.After(now.Add(5*time.Second)) {
			continue
		}
		if prev, ok := latest[o.Observer]; !ok || o.At.After(prev.At) {
			latest[o.Observer] = o
		}
	}
	d := FailureDecision{Target: target, Epoch: epoch, RequiredQuorum: quorum, Action: "hold"}
	for observer, o := range latest {
		d.Voters = append(d.Voters, observer)
		if o.Healthy {
			d.HealthyVotes++
		} else {
			d.UnhealthyVotes++
		}
	}
	sort.Strings(d.Voters)
	if d.UnhealthyVotes >= quorum && d.HealthyVotes == 0 {
		d.Action = "fence-and-replace"
		d.NextEpoch = epoch + 1
		d.FenceToken = target + ":" + formatEpoch(d.NextEpoch)
	}
	return d, nil
}

func formatEpoch(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

type RoutePlan struct {
	Workload string   `json:"workload"`
	Epoch    uint64   `json:"epoch"`
	Backends []string `json:"backends"`
	Degraded bool     `json:"degraded"`
}

func BuildRoutePlan(nodes []Node, placement Placement, epoch uint64) (RoutePlan, error) {
	if placement.Workload == "" || epoch == 0 {
		return RoutePlan{}, errors.New("workload and epoch required")
	}
	byID := map[string]Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	p := RoutePlan{Workload: placement.Workload, Epoch: epoch, Degraded: placement.Degraded}
	for _, id := range placement.Nodes {
		n, ok := byID[id]
		if !ok || !n.Healthy {
			p.Degraded = true
			continue
		}
		p.Backends = append(p.Backends, id)
	}
	sort.Strings(p.Backends)
	if len(p.Backends) == 0 {
		return p, errors.New("no healthy route backends")
	}
	return p, nil
}
