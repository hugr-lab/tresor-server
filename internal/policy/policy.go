// Package policy is the permission model (tresor specs/009, spec 002): admins manage, roles use, a delegation
// grant acts with the server's own rights. It decides from the caller, the secret's grants and the configured
// policy (admins, actors) - no HTTP, no store: the API asks it, and so do the console's views.
package policy

import (
	"slices"
	"strings"

	"github.com/hugr-lab/tresor-server/internal/auth"
	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/state"
)

// ManageVerbs are the administrators' verbs on a secret; `use` comes from a grant only.
var ManageVerbs = []string{"update", "delete", "annotate", "grant"}

// Policy is the configured admins and actors.
type Policy struct {
	admins []string
	actors []config.ActorRule
}

// New is the policy configured.
func New(p config.Policy) *Policy {
	return &Policy{admins: p.Admins, actors: p.Actors}
}

// IsAdmin says whether one of the caller's principals is an administrator's.
func (p *Policy) IsAdmin(c *auth.Caller) bool {
	return slices.ContainsFunc(p.admins, c.Has)
}

// ActorVerbs is what the policy lets this server (its client: principal, from this issuer) do for users; nil
// when it may not act at all.
func (p *Policy) ActorVerbs(client, issuer string) []string {
	for _, a := range p.actors {
		if client != "" && a.Principal == client &&
			(a.Issuer == "" || config.IssuerKey(a.Issuer) == config.IssuerKey(issuer)) {
			return a.Verbs
		}
	}
	return nil
}

// ActorAllowed says whether this server may act for users at all.
func (p *Policy) ActorAllowed(client, issuer string) bool {
	return len(p.ActorVerbs(client, issuer)) > 0
}

// Verbs is what the caller may do with sec (specs/009): `use` when a grant names one of its roles or groups,
// and the management verbs for an admin (an admin role implies no `use`). Under a delegation grant `use` is
// the ACTOR's (a user gets nothing beyond what the server was granted), and a management verb passes only
// for a user who is an admin, when the actor policy lists it - administration through a duckdb-acl node.
func (p *Policy) Verbs(c *auth.Caller, sec *state.Secret) []string {
	out := []string{} // a list, never null
	if c.Actor != "" {
		allowed := p.ActorVerbs(c.Actor, c.ActorIssuer)
		if slices.Contains(allowed, "use") && Usable(sec, c.ActorPrincipals) {
			out = append(out, "use")
		}
		// administration through a server: the user's own admin role, and the verbs the policy lets it pass on
		if p.IsAdmin(c) {
			for _, v := range ManageVerbs {
				if slices.Contains(allowed, v) {
					out = append(out, v)
				}
			}
		}
		return out
	}
	if Usable(sec, c.Principals) {
		out = append(out, "use")
	}
	if p.IsAdmin(c) {
		out = append(out, ManageVerbs...)
	}
	return out
}

// MayCreate: only admins create - through a server too, when the actor policy lists `create`.
func (p *Policy) MayCreate(c *auth.Caller) bool {
	if !p.IsAdmin(c) {
		return false
	}
	return c.Actor == "" || slices.Contains(p.ActorVerbs(c.Actor, c.ActorIssuer), "create")
}

// Usable: a grant gives `use` to one of these principals - a role: or group: grant only. A grant a store kept
// from before specs/009 (to a subject: or a client:, or of other verbs) gives nothing: it is reported at
// start and ignored.
func Usable(sec *state.Secret, principals []string) bool {
	for _, g := range sec.Grants {
		if RoleOrGroup(g.Principal) && slices.Contains(g.Verbs, "use") && slices.Contains(principals, g.Principal) {
			return true
		}
	}
	return false
}

// RoleOrGroup says whether p is a role: or a group: principal - what a grant may name.
func RoleOrGroup(p string) bool {
	role, isRole := strings.CutPrefix(p, "role:")
	group, isGroup := strings.CutPrefix(p, "group:")
	return (isRole && role != "") || (isGroup && group != "")
}
