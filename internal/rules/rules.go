// Package rules are the workload identities a service login may use (spec 023, dynamic.identities): each makes
// a short-lived credential of its own kind - an Entra token, a GCP access token, an RDS IAM token, AWS STS
// credentials - or signs a client's assertion; each bounded by the operator to what it may be asked for. A
// credential made is never logged, nor put in an error.
package rules

import (
	"context"
	"fmt"
	"slices"
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
}

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
		return nil, login.Outage("the identity %q gave no token", s.Identity)
	}
	return &login.Result{Fields: map[string]string{"access_token": tok.Token}, Expiry: tok.ExpiresOn}, nil
}

// GCP makes access tokens of an identity (the service's own, or a service account impersonated), for listed
// scopes only. Source makes one token source per scope.
type GCP struct {
	Source func(ctx context.Context, scope string) (oauth2.TokenSource, error)
	Scopes []string
}

func (GCP) Kind() string { return "gcp" }

func (g GCP) Check(s *login.Spec) error {
	if !slices.Contains(g.Scopes, s.OAuthScope) {
		return fmt.Errorf("the identity %q is not for the scope asked (its scopes are the operator's)", s.Identity)
	}
	return nil
}

func (g GCP) Make(ctx context.Context, s *login.Spec) (*login.Result, error) {
	ts, err := g.Source(ctx, s.OAuthScope)
	if err != nil {
		return nil, login.Outage("the identity %q gave no token", s.Identity)
	}
	tok, err := ts.Token()
	if err != nil {
		return nil, login.Outage("the identity %q gave no token", s.Identity)
	}
	return &login.Result{Fields: map[string]string{"access_token": tok.AccessToken}, Expiry: tok.Expiry}, nil
}

// RDS makes RDS IAM tokens (a database's password for 15 minutes) for listed endpoints and users only.
type RDS struct {
	Creds     aws.CredentialsProvider
	Region    string
	Endpoints []string // host:port
	Users     []string
	Now       func() time.Time
}

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
		return nil, login.Outage("the identity %q made no RDS token", s.Identity)
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
}

func (STS) Kind() string { return "aws_sts" }

func (STS) Check(s *login.Spec) error {
	if s.Endpoint != "" || s.User != "" {
		return fmt.Errorf("the identity %q (aws_sts) takes no endpoint or user", s.Identity)
	}
	return nil
}

func (t STS) Make(ctx context.Context, s *login.Spec) (*login.Result, error) {
	out, err := t.Client.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: aws.String(t.RoleARN),
		RoleSessionName: aws.String("tresor-server"), DurationSeconds: aws.Int32(int32(t.Duration / time.Second))})
	if err != nil || out.Credentials == nil {
		return nil, login.Outage("the identity %q assumed no role", s.Identity)
	}
	c := out.Credentials
	return &login.Result{Fields: map[string]string{"access_key_id": aws.ToString(c.AccessKeyId),
		"secret_access_key": aws.ToString(c.SecretAccessKey), "session_token": aws.ToString(c.SessionToken)},
		Expiry: aws.ToTime(c.Expiration)}, nil
}

// JWT is a client's signing key: an assertion for a token endpoint (private_key_jwt, or the JWT bearer grant).
type JWT struct {
	ID     string
	Source func(ctx context.Context, tokenURL string) (string, error)
}

func (JWT) Kind() string            { return "jwt" }
func (JWT) Check(*login.Spec) error { return nil }
func (j JWT) ClientID() string      { return j.ID }
func (j JWT) Assert(ctx context.Context, tokenURL string) (string, error) {
	return j.Source(ctx, tokenURL)
}
