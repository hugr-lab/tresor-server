package policy

import (
	"slices"
	"testing"

	"github.com/hugr-lab/tresor-server/internal/auth"
	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/state"
)

// admins manage, roles use, a grant acts with the server's own rights (tresor specs/009)
func TestVerbs(t *testing.T) {
	p := New(config.Policy{Admins: []string{"role:secrets_admin"}, Actors: []config.ActorRule{
		{Principal: "client:node", Verbs: []string{"use", "update"}},
		{Principal: "client:creator", Verbs: []string{"use", "create"}, Issuer: "https://idp.example/"},
	}})
	sec := &state.Secret{Grants: []state.Grant{
		{Principal: "role:analysts", Verbs: []string{"use"}},
		{Principal: "subject:iss|alice", Verbs: []string{"use"}}, // before specs/009: gives nothing
		{Principal: "role:nodes", Verbs: []string{"use"}},
		{Principal: "group:lake", Verbs: []string{"use"}},
		{Principal: "role:editors", Verbs: []string{"update"}}, // a grant gives use only
	}}
	admin := &auth.Caller{Principals: []string{"role:secrets_admin"}}
	analyst := &auth.Caller{Principals: []string{"role:analysts", "subject:iss|bob"}}
	alice := &auth.Caller{Principals: []string{"subject:iss|alice"}}
	for name, c := range map[string]struct {
		caller *auth.Caller
		want   []string
	}{
		"an admin: management, no use":    {admin, ManageVerbs},
		"a role granted: use":             {analyst, []string{"use"}},
		"a subject grant: nothing":        {alice, []string{}},
		"an admin with the role too: all": {&auth.Caller{Principals: []string{"role:secrets_admin", "role:analysts"}}, append([]string{"use"}, ManageVerbs...)},
		// under a delegation grant: the actor's use; an admin user's management only as the actor policy passes it
		"a user through the node": {&auth.Caller{Principals: []string{"role:analysts"}, Actor: "client:node",
			ActorPrincipals: []string{"role:nodes"}}, []string{"use"}},
		"an admin through the node": {&auth.Caller{Principals: []string{"role:secrets_admin"}, Actor: "client:node",
			ActorPrincipals: []string{"role:nodes"}}, []string{"use", "update"}},
		"a group granted: use":    {&auth.Caller{Principals: []string{"group:lake"}}, []string{"use"}},
		"a grant of another verb": {&auth.Caller{Principals: []string{"role:editors"}}, []string{}},
		// use is the actor's: a user holding the granted role gets none through a node that does not
		"a user's role, not the node's": {&auth.Caller{Principals: []string{"role:analysts"}, Actor: "client:node",
			ActorPrincipals: []string{"role:other"}}, []string{}},
		"through a server from another issuer": {&auth.Caller{Principals: []string{"role:secrets_admin"}, Actor: "client:creator",
			ActorIssuer: "https://elsewhere.example", ActorPrincipals: []string{"role:nodes"}}, []string{}},
		"through a server not in the policy": {&auth.Caller{Principals: []string{"role:secrets_admin"}, Actor: "client:other",
			ActorPrincipals: []string{"role:nodes"}}, []string{}},
	} {
		if got := p.Verbs(c.caller, sec); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	if !p.MayCreate(admin) || p.MayCreate(analyst) {
		t.Error("only admins create")
	}
	if p.MayCreate(&auth.Caller{Principals: []string{"role:secrets_admin"}, Actor: "client:node"}) {
		t.Error("an admin through a server whose policy has no create")
	}
	if !p.MayCreate(&auth.Caller{Principals: []string{"role:secrets_admin"}, Actor: "client:creator", ActorIssuer: "https://idp.example"}) {
		t.Error("through a server whose policy has create, from its issuer")
	}
	if p.ActorAllowed("client:creator", "https://elsewhere.example") || !p.ActorAllowed("client:node", "any") || p.ActorAllowed("", "") {
		t.Error("actors: the issuer when named, a client always")
	}
}

func TestPrincipals(t *testing.T) {
	for p, want := range map[string][2]bool{
		"role:a": {true, true}, "group:g": {true, true}, "subject:iss|x": {false, true}, "client:c": {false, true},
		"role:": {false, false}, "user:x": {false, false}, "": {false, false},
	} {
		if RoleOrGroup(p) != want[0] {
			t.Errorf("%q: role or group %v", p, RoleOrGroup(p))
		}
	}
}
