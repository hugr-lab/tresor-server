package material

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// fake resolves ref+fake://<name>: values it holds; "down" does not answer
type fake struct{ values map[string]string }

func (fake) Scheme() string { return "fake" }
func (fake) Parse(text string) (Ref, error) {
	if text == "" || strings.Contains(text, "/") {
		return Ref{}, errors.New("ref+fake://<name>")
	}
	if text == "outside" {
		return Ref{}, errors.New("outside the allowlist")
	}
	return Ref{Scheme: "fake", Name: text}, nil
}
func (f fake) Resolve(_ context.Context, ref Ref) (string, string, error) {
	if v, ok := f.values[ref.Name]; ok {
		return v, "v1", nil
	}
	return "", "", errors.New("not there")
}

func params(t *testing.T, doc string) map[string]json.RawMessage {
	t.Helper()
	var p map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckWrite(t *testing.T) {
	r := New(fake{})
	redact, err := r.CheckWrite("config", params(t, `{"key_id":"ref+fake://id","secret":{"type":"VARCHAR","value":"ref+fake://s"},"region":"eu"}`),
		[]string{"secret"})
	if err != nil || !slices.Equal(redact, []string{"secret", "key_id"}) {
		t.Fatalf("a reference's parameter is redacted: %v %v", redact, err)
	}
	for name, doc := range map[string]string{
		"an unknown scheme":    `{"k":"ref+vault://x"}`,
		"malformed":            `{"k":"ref+fake://a/b"}`,
		"outside the list":     `{"k":"ref+fake://outside"}`,
		"no scheme":            `{"k":"ref+"}`,
		"not a VARCHAR":        `{"k":{"type":"BLOB","value":"ref+fake://x"}}`,
		"a token_exchange one": `{"k":"ref+fake://x"}`,
	} {
		provider := "config"
		if name == "a token_exchange one" {
			provider = "token_exchange"
		}
		if _, err := r.CheckWrite(provider, params(t, doc), nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// no source configured: every reference refused, nothing else touched
	var none *Resolver
	if _, err := none.CheckWrite("config", params(t, `{"k":"ref+fake://x"}`), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no sources: %v", err)
	}
	if _, err := none.CheckWrite("config", params(t, `{"k":"plain","n":{"type":"INTEGER","value":1}}`), nil); err != nil {
		t.Fatalf("no reference, no sources: %v", err)
	}
}

func TestResolve(t *testing.T) {
	r := New(fake{values: map[string]string{"id": "AKIA", "s": "hunter2"}})
	in := params(t, `{"key_id":"ref+fake://id","secret":{"type":"VARCHAR","value":"ref+fake://s"},"region":"eu"}`)
	out, done, err := r.Resolve(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if string(out["key_id"]) != `"AKIA"` || string(out["secret"]) != `{"type":"VARCHAR","value":"hunter2"}` ||
		string(out["region"]) != `"eu"` || len(done) != 2 {
		t.Fatalf("resolved: %s %v", out, done)
	}
	if string(in["key_id"]) != `"ref+fake://id"` {
		t.Fatal("the stored params were changed")
	}
	// one that does not resolve fails the whole fetch, and names no value
	_, _, err = r.Resolve(context.Background(), params(t, `{"a":"ref+fake://id","b":"ref+fake://gone"}`))
	if !errors.Is(err, ErrUnresolved) || strings.Contains(err.Error(), "AKIA") {
		t.Fatalf("unresolved: %v", err)
	}
	// a configuration without the source any more: the stored reference does not resolve
	var none *Resolver
	if _, _, err := none.Resolve(context.Background(), in); !errors.Is(err, ErrUnresolved) {
		t.Fatalf("no sources: %v", err)
	}
}
