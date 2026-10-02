// zitadelcheck is spec 006's ZITADEL helper (scripts/ci/zitadel.sh), not shipped:
//
//	zitadelcheck token <user key file> <issuer> <project id>[,<project id>...]
//	    a machine user's access token by the JWT profile grant, with the projects' audiences and the roles
//	zitadelcheck exchange <app key file> <issuer> <subject token> <audience>
//	    the service's exchange, as it logs in (key_file): a refresh refused as unsupported, an access token
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/hugr-lab/tresor-server/internal/clientauth"
	"github.com/hugr-lab/tresor-server/internal/mint"
)

func main() {
	log.SetFlags(0)
	switch {
	case len(os.Args) == 5 && os.Args[1] == "token":
		fmt.Print(token(os.Args[2], os.Args[3], os.Args[4]))
	case len(os.Args) == 6 && os.Args[1] == "exchange":
		exchange(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	default:
		log.Fatal("usage: zitadelcheck token <key> <issuer> <project> | exchange <key> <issuer> <subject> <audience>")
	}
}

func token(keyFile, issuer, project string) string {
	raw, err := os.ReadFile(keyFile)
	must(err)
	var k struct {
		UserID string `json:"userId"`
	}
	must(json.Unmarshal(raw, &k))
	signer, kid, _, err := clientauth.KeyFile(keyFile)
	must(err)
	assertion, err := clientauth.JWT(k.UserID, clientauth.Header{KID: kid}, clientauth.Audience{Issuer: issuer}, signer)(context.Background(), "")
	must(err)
	scope := "openid urn:zitadel:iam:org:projects:roles"
	for _, p := range strings.Split(project, ",") {
		scope += " urn:zitadel:iam:org:project:id:" + p + ":aud"
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}, "scope": {scope}}
	res, err := http.PostForm(strings.TrimSuffix(issuer, "/")+"/oauth/v2/token", form)
	must(err)
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Desc        string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &out)
	if out.AccessToken == "" {
		log.Fatalf("zitadelcheck: no token: %s %s", out.Error, out.Desc)
	}
	return out.AccessToken
}

func exchange(keyFile, issuer, subject, audience string) {
	signer, kid, clientID, err := clientauth.KeyFile(keyFile)
	must(err)
	c := &mint.Client{TokenURL: strings.TrimSuffix(issuer, "/") + "/oauth/v2/token", Auth: mint.AssertionAuth{ID: clientID,
		Assertion: clientauth.JWT(clientID, clientauth.Header{KID: kid}, clientauth.Audience{Issuer: issuer}, signer)}}
	ctx := context.Background()
	_, err = c.Exchange(ctx, subject, audience, "", true)
	fmt.Printf("zitadelcheck: a refresh by exchange: %v (unsupported: %v)\n", err, mint.IsUnsupported(err))
	if !mint.IsUnsupported(err) {
		os.Exit(1)
	}
	t, err := c.Exchange(ctx, subject, audience, "", false)
	if err != nil {
		log.Fatalf("zitadelcheck: the exchange: %v", err)
	}
	if t.Access == "" || t.Access == subject || t.Refresh != "" {
		log.Fatal("zitadelcheck: the exchange gave no new access token (or a refresh token)")
	}
	parts := strings.Split(t.Access, ".")
	if len(parts) == 3 {
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]any
		_ = json.Unmarshal(payload, &claims)
		fmt.Printf("zitadelcheck: exchanged: aud %v, act %v\n", claims["aud"], claims["act"] != nil)
	} else {
		fmt.Println("zitadelcheck: exchanged: an opaque token")
	}
}

func must(err error) {
	if err != nil {
		log.Fatalf("zitadelcheck: %v", err)
	}
}
