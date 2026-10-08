// Package canon is the canonical encoding a state store's MAC is over (specs 003, 014): the format and the kind
// first, the installation's id, then every field length-prefixed and every list count-prefixed, absent told from
// empty. The Kubernetes store and the SQL stores share it: one encoding, reviewed once.
package canon

import "encoding/binary"

// Canon is an encoding under way.
type Canon []byte

// New starts the encoding of one record of kind, in the installation instance.
func New(kind, instance string) *Canon {
	c := Canon("tresor-server/mac/1\x00")
	c.Str(kind)
	c.Str(instance)
	return &c
}

// Str adds a string.
func (c *Canon) Str(s string) { c.Bytes([]byte(s)) }

// Bytes adds bytes: absent (nil) told from empty.
func (c *Canon) Bytes(b []byte) {
	if b == nil {
		*c = append(*c, 0)
		return
	}
	*c = append(*c, 1)
	*c = binary.BigEndian.AppendUint64(*c, uint64(len(b)))
	*c = append(*c, b...)
}

// I64 adds a number.
func (c *Canon) I64(n int64) { *c = binary.BigEndian.AppendUint64(*c, uint64(n)) }

// Count opens a list: absent (nil) or n entries.
func (c *Canon) Count(isNil bool, n int) {
	if isNil {
		*c = append(*c, 0)
		return
	}
	*c = append(*c, 1)
	*c = binary.BigEndian.AppendUint64(*c, uint64(n))
}

// Strs adds a list of strings.
func (c *Canon) Strs(ss []string) {
	c.Count(ss == nil, len(ss))
	for _, s := range ss {
		c.Str(s)
	}
}
