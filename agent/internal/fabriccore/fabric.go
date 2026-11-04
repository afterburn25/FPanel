package fabriccore

import (
	"errors"
	"sort"
)

type Node struct {
	ID, Region, Role string
	Healthy          bool
	Capacity         int
	Used             int
}
type Workload struct {
	Name, Role           string
	Replicas, MinRegions int
}
type Placement struct {
	Workload string   `json:"workload"`
	Nodes    []string `json:"nodes"`
	Regions  []string `json:"regions"`
	Degraded bool     `json:"degraded"`
}

func Plan(nodes []Node, w Workload) (Placement, error) {
	if w.Name == "" || w.Role == "" || w.Replicas < 1 || w.MinRegions < 1 || w.MinRegions > w.Replicas {
		return Placement{}, errors.New("invalid workload")
	}
	eligible := make([]Node, 0)
	for _, n := range nodes {
		if n.Healthy && n.Role == w.Role && n.Capacity > n.Used {
			eligible = append(eligible, n)
		}
	}
	if len(eligible) < w.Replicas {
		return Placement{}, errors.New("insufficient healthy capacity")
	}
	sort.Slice(eligible, func(i, j int) bool {
		ai := eligible[i].Capacity - eligible[i].Used
		aj := eligible[j].Capacity - eligible[j].Used
		if ai == aj {
			return eligible[i].ID < eligible[j].ID
		}
		return ai > aj
	})
	chosen := []Node{}
	regions := map[string]bool{}
	for _, n := range eligible {
		if len(chosen) >= w.Replicas {
			break
		}
		if len(regions) < w.MinRegions && regions[n.Region] {
			continue
		}
		chosen = append(chosen, n)
		regions[n.Region] = true
	}
	for _, n := range eligible {
		if len(chosen) >= w.Replicas {
			break
		}
		found := false
		for _, c := range chosen {
			if c.ID == n.ID {
				found = true
			}
		}
		if !found {
			chosen = append(chosen, n)
			regions[n.Region] = true
		}
	}
	if len(chosen) < w.Replicas || len(regions) < w.MinRegions {
		return Placement{}, errors.New("region diversity requirement cannot be met")
	}
	p := Placement{Workload: w.Name}
	for _, n := range chosen {
		p.Nodes = append(p.Nodes, n.ID)
	}
	for r := range regions {
		p.Regions = append(p.Regions, r)
	}
	sort.Strings(p.Regions)
	return p, nil
}
func Failover(nodes []Node, w Workload, current Placement) (Placement, error) {
	p, err := Plan(nodes, w)
	if err != nil {
		return Placement{Workload: w.Name, Degraded: true}, err
	}
	p.Degraded = false
	return p, nil
}
