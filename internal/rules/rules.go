// Package rules are the workload identities a service login may use (spec 023, dynamic.identities): each makes
// a short-lived credential of its own kind - an Entra token, a GCP access token, an RDS IAM token, AWS STS
// credentials - or signs a client's assertion; each bounded by the operator to what it may be asked for. A
// credential made is never logged, nor put in an error.
package rules

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/oauth2"

	"github.com/hugr-lab/tresor-server/internal/login"
)

// rdsLife: an RDS IAM token is good for 15 minutes.
const rdsLife = 15 * time.Minute

// Azure makes Entra tokens of an identity (the service's own, or a user-assigned one), for listed scopes only.
type Azure struct {
	Cred   azcore.TokenCredential
	Scopes []string
	Dest   []string // where its tokens may go: a login's scope within these
}

func (a Azure) Destinations() []string { return a.Dest }

func (Azure) Kind() string { return "azure" }

func (a Azure) Check(s *login.Spec) error {
	if !slices.Contains(a.Scopes, s.OAuthScope) {
		return fmt.Errorf("the identity %q is not for the scope asked (its scopes are the operator's)", s.Identity)
	}
	return nil
}

func (a Azure) Make(ctx context.Context, s *login.Spec) (*login.Result, error) {
	tok, err := a.Cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{s.OAuthScope}})
	if err != nil {
		return nil, login.Outage("the identity %q gave no token: %v", s.Identity, err)
	}
	return &login.Result{Fields: map[string]string{"access_token": tok.Token}, Expiry: tok.ExpiresOn}, nil
}

// GCP makes access tokens of an identity (the service's own, or a service account impersonated), for listed
// scopes only. Source makes one token source per scope.
type GCP struct {
	Source func(ctx context.Context, scope string) (oauth2.TokenSource, error)
	Scopes []string
	Dest   []string
}

func (g GCP) Destinations() []string { return g.Dest }

func (GCP) Kind() string { return "gcp" }

func (g GCP) Check(s *login.Spec) error {
	if !slices.Contains(g.Scopes, s.OAuthScope) {
		return fmt.Errorf("the identity %q is not for the scope asked (its scopes are the operator's)", s.Identity)
	}
	return nil
}

func (g GCP) Make(ctx context.Context, s *login.Spec) (*login.Result, error) {
	type got struct {
		tok *oauth2.Token
		err error
	}
	ch := make(chan got, 1)
	go func() { // a token source takes no context: the request's deadline bounds the wait, not the call
		ts, err := g.Source(ctx, s.OAuthScope)
		if err != nil {
			ch <- got{nil, err}
			return
		}
		tok, err := ts.Token()
		ch <- got{tok, err}
	}()
	select {
	case <-ctx.Done():
		return nil, login.Outage("the identity %q gave no token in time", s.Identity)
	case r := <-ch:
		if r.err != nil {
			return nil, login.Outage("the identity %q gave no token: %v", s.Identity, r.err)
		}
		return &login.Result{Fields: map[string]string{"access_token": r.tok.AccessToken}, Expiry: r.tok.Expiry}, nil
	}
}

// RDS makes RDS IAM tokens (a database's password for 15 minutes) for listed endpoints and users only.
type RDS struct {
	Creds     aws.CredentialsProvider
	Region    string
	Endpoints []string // host:port
	Users     []string
	Dest      []string
	Now       func() time.Time
}

func (r RDS) Destinations() []string { return r.Dest }

func (RDS) Kind() string { return "aws_rds" }

func (r RDS) Check(s *login.Spec) error {
	if !slices.Contains(r.Endpoints, s.Endpoint) || !slices.Contains(r.Users, s.User) {
		return fmt.Errorf("the identity %q is not for the endpoint and user asked (the operator's)", s.Identity)
	}
	if s.Region != "" && s.Region != r.Region {
		return fmt.Errorf("the identity %q is for the region %s", s.Identity, r.Region)
	}
	return nil
}

func (r RDS) Make(ctx context.Context, s *login.Spec) (*login.Result, error) {
	token, err := auth.BuildAuthToken(ctx, s.Endpoint, r.Region, s.User, r.Creds)
	if err != nil {
		return nil, login.Outage("the identity %q made no RDS token: %v", s.Identity, err)
	}
	return &login.Result{Fields: map[string]string{"password": token, "user": s.User}, Expiry: r.Now().Add(rdsLife)}, nil
}

// Assumer is STS's AssumeRole.
type Assumer interface {
	AssumeRole(ctx context.Context, in *sts.AssumeRoleInput, opts ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// STS assumes one role, and serves its temporary credentials (an s3 secret's key_id, secret, session_token).
type STS struct {
	Client   Assumer
	RoleARN  string
	Duration time.Duration
	Dest     []string
}

func (t STS) Destinations() []string { return t.Dest }

func (STS) Kind() string { return "aws_sts" }

func (STS) Check(s *login.Spec) error {
	if s.Endpoint != "" || s.User != "" {
		return fmt.Errorf("the identity %q (aws_sts) takes no endpoint or user", s.Identity)
	}
	return nil
}

func (t STS) Make(ctx context.Context, s *login.Spec) (*login.Result, error) {
	out, err := t.Client.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: aws.String(t.RoleARN),
		RoleSessionName: aws.String(sessionName(s.Name)), DurationSeconds: aws.Int32(int32(t.Duration / time.Second))})
	if err != nil {
		return nil, login.Outage("the identity %q assumed no role: %v", s.Identity, err)
	}
	if out.Credentials == nil {
		return nil, login.Outage("the identity %q assumed no role", s.Identity)
	}
	c := out.Credentials
	return &login.Result{Fields: map[string]string{"access_key_id": aws.ToString(c.AccessKeyId),
		"secret_access_key": aws.ToString(c.SecretAccessKey), "session_token": aws.ToString(c.SessionToken)},
		Expiry: aws.ToTime(c.Expiration)}, nil
}

// sessionName names an STS session after its login (CloudTrail attributes it): AWS's characters, 64 at most.
func sessionName(login string) string {
	out := []rune("tresor-")
	for _, r := range login {
		if len(out) == 64 {
			break
		}
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("=,.@-_", r) {
			out = append(out, r)
		} else {
			out = append(out, '-')
		}
	}
	return string(out)
}

// JWT is a client's signing key: an assertion for a token endpoint (private_key_jwt, or the JWT bearer grant).
type JWT struct {
	ID        string
	Source    func(ctx context.Context, tokenURL string) (string, error)
	TokenURLs []string // where its assertions may go (the operator's): one is redeemable there
	// AsSecret: the assertion is the client's secret, with no client id (Snowflake's key pair, spec 032)
	AsSecret bool
}

func (j JWT) AssertionAsSecret() bool { return j.AsSecret }

func (j JWT) For(tokenURL string) bool { return slices.Contains(j.TokenURLs, tokenURL) }

func (JWT) Kind() string            { return "jwt" }
func (JWT) Check(*login.Spec) error { return nil }
func (j JWT) ClientID() string      { return j.ID }
func (j JWT) Assert(ctx context.Context, tokenURL string) (string, error) {
	return j.Source(ctx, tokenURL)
}
