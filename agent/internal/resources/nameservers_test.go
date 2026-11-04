package resources

import "testing"

func TestNameserverConfigurationValidation(t *testing.T) {
	m := New(t.TempDir()+"/resources.json", false)
	v, err := m.SetNameservers(NameserverConfig{BaseDomain: "hosting.test", Primary: "ns1.hosting.test", Secondary: "ns2.hosting.test", IPv4: "192.0.2.20"})
	if err != nil {
		t.Fatal(err)
	}
	if v.GlueStatus != "local-glue-ready" || m.Nameservers().Primary != "ns1.hosting.test" {
		t.Fatalf("unexpected nameserver config: %+v", v)
	}
	if _, err := m.SetNameservers(NameserverConfig{BaseDomain: "hosting.test", Primary: "ns1.other.test", Secondary: "ns2.hosting.test"}); err == nil {
		t.Fatal("accepted nameserver outside base domain")
	}
}

func TestNameserverAssignmentsAreExplicit(t *testing.T) {
	m := New(t.TempDir()+"/resources.json", false)
	if _, err := m.SetNameservers(NameserverConfig{BaseDomain: "privoralabs.com", Primary: "ns1.privoralabs.com", Secondary: "ns2.privoralabs.com", IPv4: "192.0.2.10", Default: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetNameservers(NameserverConfig{BaseDomain: "privoralabs.org", Primary: "ns1.privoralabs.org", Secondary: "ns2.privoralabs.org", IPv4: "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	if got := m.Nameservers(); got.BaseDomain != "privoralabs.com" {
		t.Fatalf("unexpected default set: %+v", got)
	}
	if _, ok := m.AssignedNameservers("privoralabs.org"); ok {
		t.Fatal("same-name nameserver set was implicitly assigned to hosted domain")
	}
	set, err := m.SetNameserverAssignment("privoralabs.org", "privoralabs.com")
	if err != nil {
		t.Fatal(err)
	}
	if set.Primary != "ns1.privoralabs.com" {
		t.Fatalf("explicit assignment selected wrong set: %+v", set)
	}
	got, ok := m.AssignedNameservers("privoralabs.org")
	if !ok || got.BaseDomain != "privoralabs.com" {
		t.Fatalf("assignment not persisted: %+v ok=%v", got, ok)
	}
}
