package kubestore

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/state"
)

func put(t *testing.T, s *Store, name string) *state.Secret {
	t.Helper()
	now := time.Now().UTC()
	saved, err := s.Update(ctx, name, func(cur *state.Secret) (*state.Secret, error) {
		next := &state.Secret{Type: "s3", Version: 1, CreatedAt: now, UpdatedAt: now, Owner: "subject:iss|admin",
			Params: map[string]json.RawMessage{"secret": json.RawMessage(`"material"`)},
			Grants: []state.Grant{{ID: "g", Principal: "role:analysts", Verbs: []string{"use"}}}}
		if cur != nil {
			next.Version, next.CreatedAt = cur.Version+1, cur.CreatedAt
		}
		return next, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

// edit changes a resource behind the store, as whoever can write the namespace would.
func edit(t *testing.T, ns string, k kind, name string, fn func(u *unstructured.Unstructured)) {
	t.Helper()
	ri := dynamic.NewForConfigOrDie(cfg).Resource(schema.GroupVersionResource{Group: Group, Version: Version,
		Resource: k.resource}).Namespace(ns)
	u, err := ri.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fn(u)
	if _, err := ri.Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func tampered(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrTampered) || !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("%s: %v, want the resource refused", what, err)
	}
}

// a secret changed behind the store - a grant added, a field, a label, a finalizer - is never served nor
// written over; a list leaves it out
func TestSecretChangedBehind(t *testing.T) {
	cases := map[string]func(u *unstructured.Unstructured){
		"a grant added": func(u *unstructured.Unstructured) {
			grants, _, _ := unstructured.NestedSlice(u.Object, "spec", "grants")
			grants = append(grants, map[string]any{"id": "x", "principal": "role:mallory", "verbs": []any{"use"}})
			unstructured.SetNestedSlice(u.Object, grants, "spec", "grants")
		},
		"the owner": func(u *unstructured.Unstructured) {
			unstructured.SetNestedField(u.Object, "subject:iss|mallory", "spec", "owner")
		},
		"the scope emptied": func(u *unstructured.Unstructured) {
			unstructured.SetNestedSlice(u.Object, []any{}, "spec", "scope")
		},
		"a finalizer": func(u *unstructured.Unstructured) { u.SetFinalizers([]string{"example.com/hold"}) },
		"a label of the store's": func(u *unstructured.Unstructured) {
			u.SetLabels(map[string]string{labelGrant: "x"})
		},
	}
	for what, change := range cases {
		t.Run(what, func(t *testing.T) {
			ns := namespace(t)
			s := openIn(t, ns, kek(t, 1), "")
			put(t, s, "lake")
			put(t, s, "other")
			edit(t, ns, kindSecret, secretName("lake"), change)
			_, err := s.Describe(ctx, "lake")
			tampered(t, "describe", err)
			_, err = s.Get(ctx, "lake")
			tampered(t, "get", err)
			ran := false
			_, err = s.Update(ctx, "lake", func(*state.Secret) (*state.Secret, error) { ran = true; return nil, nil })
			tampered(t, "update", err)
			if ran {
				t.Fatal("fn ran on a tampered secret")
			}
			list, err := s.List(ctx)
			if err != nil || len(list) != 1 || list[0].Name != "other" {
				t.Fatalf("the list: %d secrets, %v", len(list), err)
			}
		})
	}
}

// a backup tool's labels and annotations are none of the store's business
func TestOthersLabels(t *testing.T) {
	ns := namespace(t)
	s := openIn(t, ns, kek(t, 1), "")
	put(t, s, "lake")
	edit(t, ns, kindSecret, secretName("lake"), func(u *unstructured.Unstructured) {
		u.SetLabels(map[string]string{"velero.io/restore-name": "r1"})
		u.SetAnnotations(map[string]string{"note": "x"})
	})
	if _, err := s.Get(ctx, "lake"); err != nil {
		t.Fatal(err)
	}
}

// a resource from another installation that shares the KEK (dev and prod) does not verify
func TestAnotherInstallation(t *testing.T) {
	ns := namespace(t)
	put(t, openIn(t, ns, kek(t, 1), "dev"), "lake")
	_, err := openIn(t, ns, kek(t, 1), "prod").Describe(ctx, "lake")
	tampered(t, "another installation", err)
	// another KEK: its data keys are not authentic
	if _, err := openIn(t, ns, kek(t, 2), "dev").Describe(ctx, "lake"); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("another KEK: %v", err)
	}
}

// a wrong KEK or instance is not ready: the installation's mark does not verify
func TestInstallationMark(t *testing.T) {
	ns := namespace(t)
	s := openIn(t, ns, kek(t, 1), "dev")
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := openIn(t, ns, kek(t, 1), "dev").Ping(ctx); err != nil {
		t.Fatalf("another replica: %v", err)
	}
	for what, other := range map[string]*Store{"another instance": openIn(t, ns, kek(t, 1), "prod"),
		"another KEK": openIn(t, ns, kek(t, 2), "dev")} {
		if err := other.Ping(ctx); err == nil || !strings.Contains(err.Error(), "another installation") {
			t.Fatalf("%s: %v", what, err)
		}
	}
	edit(t, ns, kindKeyring, installationName, func(u *unstructured.Unstructured) {
		unstructured.SetNestedField(u.Object, "prod", "spec", "instance")
	})
	if err := openIn(t, ns, kek(t, 1), "prod").Ping(ctx); err == nil {
		t.Fatal("a mark changed by hand passes")
	}
}

// the MAC does not stop a rollback - a whole older object put back: the admission policy is the guard
func TestRollbackPasses(t *testing.T) {
	ns := namespace(t)
	s := openIn(t, ns, kek(t, 1), "")
	put(t, s, "lake")
	ri := s.secrets.ri
	old, err := ri.Get(ctx, secretName("lake"), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	put(t, s, "lake")
	cur, _ := ri.Get(ctx, secretName("lake"), metav1.GetOptions{})
	old.SetResourceVersion(cur.GetResourceVersion())
	if _, err := ri.Update(ctx, old, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(ctx, "lake"); err != nil || got.Version != 1 {
		t.Fatalf("a rollback: %v %v (recorded: the MAC passes it)", got, err)
	}
}

// names that are no DNS subdomain are fine: resources are named by a hash
func TestAnyName(t *testing.T) {
	ns := namespace(t)
	s := openIn(t, ns, kek(t, 1), "")
	for _, name := range []string{"Lake", "a_b", "with space", "ü/../x", strings.Repeat("n", 200)} {
		put(t, s, name)
		if got, err := s.Get(ctx, name); err != nil || got.Name != name {
			t.Fatalf("%q: %v", name, err)
		}
	}
}

func TestLimits(t *testing.T) {
	ns := namespace(t)
	s := openIn(t, ns, kek(t, 1), "")
	_, err := s.Update(ctx, "big", func(*state.Secret) (*state.Secret, error) {
		return &state.Secret{Type: "s3", Version: 1,
			Params: map[string]json.RawMessage{"secret": json.RawMessage(`"` + strings.Repeat("x", 300<<10) + `"`)}}, nil
	})
	if !errors.Is(err, state.ErrTooLarge) {
		t.Fatalf("a secret over 256 KiB: %v", err)
	}
	_, err = s.Update(ctx, "many", func(*state.Secret) (*state.Secret, error) {
		sec := &state.Secret{Type: "s3", Version: 1}
		for i := range maxGrants + 1 {
			sec.Grants = append(sec.Grants, state.Grant{ID: strings.Repeat("g", 1+i%7) + string(rune('a'+i%26)), Principal: "role:r", Verbs: []string{"use"}})
		}
		return sec, nil
	})
	if !errors.Is(err, state.ErrTooLarge) {
		t.Fatalf("over %d grants: %v", maxGrants, err)
	}
	if list, _ := s.List(ctx); len(list) != 0 {
		t.Fatal("a refused secret was kept")
	}
}

// a delete carries its preconditions: a secret changed meanwhile is not deleted blind - fn runs again on it
func TestDeletePreconditions(t *testing.T) {
	ns := namespace(t)
	s := openIn(t, ns, kek(t, 1), "")
	other := openIn(t, ns, kek(t, 1), "")
	put(t, s, "lake")
	once := true
	s.beforeWrite = func() {
		if once {
			once = false
			put(t, other, "lake") // dropped and created anew, or changed: version 2
		}
	}
	var seen []int64
	if _, err := s.Update(ctx, "lake", func(cur *state.Secret) (*state.Secret, error) {
		seen = append(seen, cur.Version)
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[1] != 2 {
		t.Fatalf("fn saw versions %v: the delete did not see the change", seen)
	}
}

// a delegation grant changed behind the store - its user, its labels - is refused, and not counted
func TestGrantChangedBehind(t *testing.T) {
	ns := namespace(t)
	s := openIn(t, ns, kek(t, 1), "")
	d := s.Delegations()
	now := time.Now()
	g := state.Delegation{IDHash: []byte("hash-1"), ActorOwner: "subject:iss|node", ActorClient: "client:node",
		ActorIssuer: "iss", UserOwner: "subject:iss|alice", User: []byte(`{"Subject":"alice"}`), ExpiresAt: now.Add(time.Hour)}
	if err := d.Put(ctx, g, 10); err != nil {
		t.Fatal(err)
	}
	edit(t, ns, kindGrant, grantName(g.IDHash), func(u *unstructured.Unstructured) {
		unstructured.SetNestedField(u.Object, `{"Subject":"admin"}`, "spec", "user")
	})
	_, err := d.Get(ctx, g.IDHash, now)
	tampered(t, "a grant's user", err)
	if n, err := d.Count(ctx, g.ActorOwner, now); err != nil || n != 0 {
		t.Fatalf("a tampered grant counted: %d %v", n, err)
	}
	// a label stripped (to slip past a revocation): refused too
	g2 := g
	g2.IDHash = []byte("hash-2")
	if err := d.Put(ctx, g2, 10); err != nil {
		t.Fatal(err)
	}
	edit(t, ns, kindGrant, grantName(g2.IDHash), func(u *unstructured.Unstructured) {
		labels := u.GetLabels()
		delete(labels, labelUser)
		u.SetLabels(labels)
	})
	_, err = d.Get(ctx, g2.IDHash, now)
	tampered(t, "a label stripped", err)
	// the actor's counter: refused before it is moved
	edit(t, ns, kindActor, actorName(g.ActorOwner), func(u *unstructured.Unstructured) {
		unstructured.SetNestedField(u.Object, int64(0), "spec", "counter")
	})
	g3 := g
	g3.IDHash = []byte("hash-3")
	tampered(t, "a counter changed", d.Put(ctx, g3, 10))
	// a delete gives no one anything: tampered grants go with a revocation
	if n, err := d.DeleteWhere(ctx, "client:node", ""); err != nil || n != 2 {
		t.Fatalf("revoked %d: %v", n, err)
	}
}

// a minted token whose grant's label was stripped is swept by the purge
func TestPurgeOrphanTokens(t *testing.T) {
	ns := namespace(t)
	s := openIn(t, ns, kek(t, 1), "")
	d := s.Delegations()
	now := time.Now()
	g := state.Delegation{IDHash: []byte("hash-1"), ActorOwner: "subject:iss|node", ActorClient: "client:node",
		UserOwner: "subject:iss|alice", User: []byte(`{}`), ExpiresAt: now.Add(time.Hour)}
	if err := d.Put(ctx, g, 10); err != nil {
		t.Fatal(err)
	}
	if err := d.PutToken(ctx, g.IDHash, state.MintedToken{Key: "k", Version: 1, Token: []byte("t")}); err != nil {
		t.Fatal(err)
	}
	edit(t, ns, kindToken, tokenName(g.IDHash, "k"), func(u *unstructured.Unstructured) { u.SetLabels(nil) })
	if _, err := s.grants.remove(ctx, grantName(g.IDHash), nil); err != nil { // its label gone, Delete misses it
		t.Fatal(err)
	}
	if _, err := d.Purge(ctx, now); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.tokens.list(ctx, ""); len(left) != 0 {
		t.Fatalf("%d tokens outlive their grant", len(left))
	}
}

// an actor with no live grant left loses its counter at the purge; one with a live grant keeps it; a put after
// the purge makes a new one (spec 003's follow-up: no counter per actor ever seen)
func TestPurgeIdleActors(t *testing.T) {
	ns := namespace(t)
	s := openIn(t, ns, kek(t, 1), "")
	d := s.Delegations()
	now := time.Now()
	grant := func(id, actor string, expires time.Time) state.Delegation {
		return state.Delegation{IDHash: []byte(id), ActorOwner: actor, ActorClient: "client:node",
			UserOwner: "subject:iss|alice", User: []byte(`{}`), ExpiresAt: expires}
	}
	for _, g := range []state.Delegation{grant("h-1", "subject:iss|gone", now.Add(time.Minute)),
		grant("h-2", "subject:iss|busy", now.Add(time.Hour))} {
		if err := d.Put(ctx, g, 10); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Purge(ctx, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if a, _ := s.actors.get(ctx, actorName("subject:iss|gone")); a != nil {
		t.Fatal("an idle actor's counter outlives its grants")
	}
	if a, _ := s.actors.get(ctx, actorName("subject:iss|busy")); a == nil {
		t.Fatal("a busy actor's counter was dropped")
	}
	if err := d.Put(ctx, grant("h-3", "subject:iss|gone", now.Add(time.Hour)), 10); err != nil {
		t.Fatalf("a put after the purge: %v", err)
	}
	if n, err := d.Count(ctx, "subject:iss|gone", now); err != nil || n != 1 {
		t.Fatalf("counted: %d %v", n, err)
	}
}

// the zero time is kept as none: a grant with no subject token reads back with no subject expiry
func TestZeroTime(t *testing.T) {
	d := openIn(t, namespace(t), kek(t, 1), "").Delegations()
	now := time.Now()
	g := state.Delegation{IDHash: []byte("hash-1"), ActorOwner: "subject:iss|node", ActorClient: "client:node",
		UserOwner: "subject:iss|alice", User: []byte(`{}`), ExpiresAt: now.Add(time.Hour)}
	if err := d.Put(ctx, g, 10); err != nil {
		t.Fatal(err)
	}
	if got, err := d.Get(ctx, g.IDHash, now); err != nil || !got.SubjectExpiresAt.IsZero() {
		t.Fatalf("no subject expiry: %v %v", got.SubjectExpiresAt, err)
	}
	g.IDHash, g.ActorOwner = []byte("hash-2"), "subject:iss|\xff"
	if err := d.Put(ctx, g, 10); err == nil {
		t.Fatal("a value not UTF-8 was stored")
	}
}

// a variable's resource made into a secret's (or back) does not verify: the kind is in the MAC, and the name
func TestVariableNotASecret(t *testing.T) {
	ns := namespace(t)
	s := openIn(t, ns, kek(t, 1), "")
	put(t, s.Variables().(*Store), "lake")
	u, err := s.vars.secrets.ri.Get(ctx, variableName("lake"), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	u.SetResourceVersion("")
	u.SetUID("")
	u.SetKind(kindSecret.name)
	u.SetName(secretName("lake"))
	if _, err := s.secrets.ri.Create(ctx, u, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err = s.Describe(ctx, "lake")
	tampered(t, "a variable as a secret", err)
	if got, err := s.Variables().Get(ctx, "lake"); err != nil || string(got.Params["secret"]) != `"material"` {
		t.Fatalf("the variable itself: %v", err)
	}
}
