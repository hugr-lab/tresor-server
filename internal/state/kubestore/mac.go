package kubestore

import (
	"encoding/binary"
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

// canon is the canonical encoding a MAC is over: the format and the kind first, the installation's id, then
// every field length-prefixed and every list count-prefixed, absent told from empty.
type canon []byte

func newCanon(k kind, instance string) *canon {
	c := canon("tresor-server/mac/1\x00")
	c.str(k.name)
	c.str(instance)
	return &c
}

func (c *canon) str(s string) { c.bytes([]byte(s)) }

func (c *canon) bytes(b []byte) {
	if b == nil {
		*c = append(*c, 0)
		return
	}
	*c = append(*c, 1)
	*c = binary.BigEndian.AppendUint64(*c, uint64(len(b)))
	*c = append(*c, b...)
}

func (c *canon) i64(n int64) { *c = binary.BigEndian.AppendUint64(*c, uint64(n)) }

// count opens a list: absent (nil) or n entries.
func (c *canon) count(isNil bool, n int) {
	if isNil {
		*c = append(*c, 0)
		return
	}
	*c = append(*c, 1)
	*c = binary.BigEndian.AppendUint64(*c, uint64(n))
}

func (c *canon) strs(ss []string) {
	c.count(ss == nil, len(ss))
	for _, s := range ss {
		c.str(s)
	}
}

// canonical is a secret's (k: TresorSecret) or a variable's (TresorVariable): the kind keeps one from verifying
// as the other.
func (s *secretSpec) canonical(k kind, instance string) []byte {
	c := newCanon(k, instance)
	c.str(s.Name)
	c.str(s.RowID)
	c.str(s.Type)
	c.str(s.Provider)
	c.strs(s.Scope)
	c.strs(s.RedactKeys)
	c.str(s.Comment)
	c.str(s.Owner)
	c.i64(s.Version)
	c.i64(s.CreatedAt)
	c.i64(s.UpdatedAt)
	c.count(s.Grants == nil, len(s.Grants))
	for _, g := range s.Grants {
		c.str(g.ID)
		c.str(g.Principal)
		c.strs(g.Verbs)
	}
	c.str(s.DataKeyID)
	c.bytes(s.Sealed)
	return *c
}

func (g *grantSpec) canonical(instance string) []byte {
	c := newCanon(kindGrant, instance)
	c.bytes(g.IDHash)
	c.str(g.ActorOwner)
	c.str(g.ActorClient)
	c.str(g.ActorIssuer)
	c.str(g.UserOwner)
	c.str(g.User)
	c.i64(g.ExpiresAt)
	c.i64(g.SubjectExpiresAt)
	c.str(g.DataKeyID)
	c.bytes(g.SubjectSealed)
	return *c
}

func (t *tokenSpec) canonical(instance string) []byte {
	c := newCanon(kindToken, instance)
	c.bytes(t.IDHash)
	c.bytes(t.Key)
	c.i64(t.Version)
	c.str(t.Failed)
	c.str(t.DataKeyID)
	c.bytes(t.Sealed)
	return *c
}

func (a *actorSpec) canonical(instance string) []byte {
	c := newCanon(kindActor, instance)
	c.str(a.ActorOwner)
	c.i64(a.Counter)
	c.str(a.DataKeyID)
	return *c
}

func (k *keyringSpec) canonical(instance string) []byte {
	c := newCanon(kindKeyring, instance)
	c.str(installationName)
	c.str(k.Instance)
	c.str(k.DataKeyID)
	return *c
}
