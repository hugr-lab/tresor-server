package mint

import (
	"context"
	"net/url"
	"testing"
)

// a client assertion names the client; client_id goes with it unless omitted (Keycloak's federated client
// authentication refuses one that is not the assertion's sub)
func TestAssertionAuthOmitID(t *testing.T) {
	assertion := func(context.Context, string) (string, error) { return "a.b.c", nil }
	for omit, want := range map[bool]string{false: "duckdb-secrets", true: ""} {
		form := url.Values{}
		if err := (AssertionAuth{ID: "duckdb-secrets", Assertion: assertion, OmitID: omit}).Apply(context.Background(), form, ""); err != nil {
			t.Fatal(err)
		}
		if form.Get("client_id") != want || form.Get("client_assertion") != "a.b.c" ||
			form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			t.Fatalf("omit %v: %v", omit, form)
		}
	}
}
