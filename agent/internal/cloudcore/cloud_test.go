package cloudcore

import (
	"context"
	"testing"
)

func TestIdempotentProvisionAndSafeDelete(t *testing.T) {
	p := NewMemoryProvider()
	r := CreateRequest{Provider: "test-provider", Region: "us-central", Size: "small-2", Image: "debian-13", Name: "web01", IdempotencyKey: "order-12345"}
	a, e := p.Create(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	b, e := p.Create(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	if a.ID != b.ID {
		t.Fatal("idempotency failed")
	}
	if e := p.Delete(context.Background(), DeleteRequest{InstanceID: a.ID, Confirmation: "wrong"}); e == nil {
		t.Fatal("unsafe delete accepted")
	}
	if e := p.Delete(context.Background(), DeleteRequest{InstanceID: a.ID, Confirmation: a.ID}); e != nil {
		t.Fatal(e)
	}
}
