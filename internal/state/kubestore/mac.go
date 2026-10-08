package kubestore

import (
	"github.com/hugr-lab/tresor-server/internal/state/canon"
)

// The specs of the custom resources. What is not sealed is authenticated by a MAC (spec 003) under a data key:
// whoever can write the resources cannot change who may use what without the KEK.

type secretSpec struct {
	Name       string        `json:"name"`
	RowID      string        `json:"rowID"`
	Type       string        `json:"type"`
	Provider   string        `json:"provider"`
	Scope      []string      `json:"scope"`
	RedactKeys []string      `json:"redactKeys"`
	Comment    string        `json:"comment"`
	Owner      string        `json:"owner"`
	Version    int64         `json:"version"`
	CreatedAt  int64         `json:"createdAt"`
	UpdatedAt  int64         `json:"updatedAt"`
	Grants     []secretGrant `json:"grants"`
	DataKeyID  string        `json:"dataKeyID"`
	Sealed     []byte        `json:"sealed"`
	MAC        []byte        `json:"mac"`
}

type secretGrant struct {
	ID        string   `json:"id"`
	Principal string   `json:"principal"`
	Verbs     []string `json:"verbs"`
}

type grantSpec struct {
	IDHash           []byte `json:"idHash"`
	ActorOwner       string `json:"actorOwner"`
	ActorClient      string `json:"actorClient"`
	ActorIssuer      string `json:"actorIssuer"`
	UserOwner        string `json:"userOwner"`
	User             string `json:"user"`
	ExpiresAt        int64  `json:"expiresAt"`
	SubjectExpiresAt int64  `json:"subjectExpiresAt"`
	DataKeyID        string `json:"dataKeyID"`
	SubjectSealed    []byte `json:"subjectSealed"`
	MAC              []byte `json:"mac"`
}

type tokenSpec struct {
	IDHash    []byte `json:"idHash"`
	Key       []byte `json:"key"` // the audience and the scope, NUL between: bytes, not a JSON string
	Version   int64  `json:"version"`
	Failed    string `json:"failed"`
	DataKeyID string `json:"dataKeyID"`
	Sealed    []byte `json:"sealed"`
	MAC       []byte `json:"mac"`
}

type actorSpec struct {
	ActorOwner string `json:"actorOwner"`
	Counter    int64  `json:"counter"`
	DataKeyID  string `json:"dataKeyID"`
	MAC        []byte `json:"mac"`
}

type dataKeySpec struct {
	ID        string `json:"id"`
	KEKID     string `json:"kekID"`
	Wrapped   []byte `json:"wrapped"`
	Tag       []byte `json:"tag"`
	CreatedAt int64  `json:"createdAt"`
}

// keyringSpec is the active data key (named active), or the installation's mark (named installation: its
// instance, MACed).
type keyringSpec struct {
	DataKeyID string `json:"dataKeyID"`
	Slot      int64  `json:"slot"`
	Instance  string `json:"instance,omitempty"`
	MAC       []byte `json:"mac,omitempty"`
}

// newCanon starts a record's canonical encoding (the shared one: package canon).
func newCanon(k kind, instance string) *canon.Canon { return canon.New(k.name, instance) }

// canonical is a secret's (k: TresorSecret) or a variable's (TresorVariable): the kind keeps one from verifying
// as the other.
func (s *secretSpec) canonical(k kind, instance string) []byte {
	c := newCanon(k, instance)
	c.Str(s.Name)
	c.Str(s.RowID)
	c.Str(s.Type)
	c.Str(s.Provider)
	c.Strs(s.Scope)
	c.Strs(s.RedactKeys)
	c.Str(s.Comment)
	c.Str(s.Owner)
	c.I64(s.Version)
	c.I64(s.CreatedAt)
	c.I64(s.UpdatedAt)
	c.Count(s.Grants == nil, len(s.Grants))
	for _, g := range s.Grants {
		c.Str(g.ID)
		c.Str(g.Principal)
		c.Strs(g.Verbs)
	}
	c.Str(s.DataKeyID)
	c.Bytes(s.Sealed)
	return *c
}

func (g *grantSpec) canonical(instance string) []byte {
	c := newCanon(kindGrant, instance)
	c.Bytes(g.IDHash)
	c.Str(g.ActorOwner)
	c.Str(g.ActorClient)
	c.Str(g.ActorIssuer)
	c.Str(g.UserOwner)
	c.Str(g.User)
	c.I64(g.ExpiresAt)
	c.I64(g.SubjectExpiresAt)
	c.Str(g.DataKeyID)
	c.Bytes(g.SubjectSealed)
	return *c
}

func (t *tokenSpec) canonical(instance string) []byte {
	c := newCanon(kindToken, instance)
	c.Bytes(t.IDHash)
	c.Bytes(t.Key)
	c.I64(t.Version)
	c.Str(t.Failed)
	c.Str(t.DataKeyID)
	c.Bytes(t.Sealed)
	return *c
}

func (a *actorSpec) canonical(instance string) []byte {
	c := newCanon(kindActor, instance)
	c.Str(a.ActorOwner)
	c.I64(a.Counter)
	c.Str(a.DataKeyID)
	return *c
}

func (k *keyringSpec) canonical(instance string) []byte {
	c := newCanon(kindKeyring, instance)
	c.Str(installationName)
	c.Str(k.Instance)
	c.Str(k.DataKeyID)
	return *c
}
