package rules

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"golang.org/x/oauth2"

	"github.com/hugr-lab/tresor-server/internal/login"
)

type fakeCred struct{ scopes []string }

func (f *fakeCred) GetToken(_ context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.scopes = o.Scopes
	return azcore.AccessToken{Token: "entra", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type fakeSTS struct{ in *sts.AssumeRoleInput }

func (f *fakeSTS) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.in = in
	exp := time.Now().Add(time.Hour)
	return &sts.AssumeRoleOutput{Credentials: &types.Credentials{AccessKeyId: aws.String("ASIA"),
		SecretAccessKey: aws.String("s"), SessionToken: aws.String("t"), Expiration: &exp}}, nil
}

func TestIdentities(t *testing.T) {
	ctx := context.Background()
	cred := &fakeCred{}
	az := Azure{Cred: cred, Scopes: []string{"https://database.windows.net/.default"}}
	ok := &login.Spec{Identity: "db", OAuthScope: "https://database.windows.net/.default"}
	if err := az.Check(ok); err != nil {
		t.Fatal(err)
	}
	if err := az.Check(&login.Spec{Identity: "db", OAuthScope: "https://vault.azure.net/.default"}); err == nil {
		t.Fatal("a scope the operator did not list")
	}
	if res, err := az.Make(ctx, ok); err != nil || res.Fields["access_token"] != "entra" || cred.scopes[0] != ok.OAuthScope {
		t.Fatalf("azure: %+v %v", res, err)
	}
	g := GCP{Scopes: []string{"https://www.googleapis.com/auth/sqlservice.login"},
		Source: func(context.Context, string) (oauth2.TokenSource, error) {
			return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "gcp", Expiry: time.Now().Add(time.Hour)}), nil
		}}
	if res, err := g.Make(ctx, &login.Spec{OAuthScope: g.Scopes[0]}); err != nil || res.Fields["access_token"] != "gcp" {
		t.Fatalf("gcp: %+v %v", res, err)
	}
	rds := RDS{Creds: credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""), Region: "eu-west-1",
		Endpoints: []string{"db.example:5432"}, Users: []string{"catalog"}, Now: time.Now}
	spec := &login.Spec{Identity: "rds", Endpoint: "db.example:5432", User: "catalog"}
	if err := rds.Check(spec); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []*login.Spec{{Endpoint: "other:5432", User: "catalog"}, {Endpoint: "db.example:5432", User: "admin"},
		{Endpoint: "db.example:5432", User: "catalog", Region: "us-east-1"}} {
		if rds.Check(bad) == nil {
			t.Errorf("%+v: allowed", bad)
		}
	}
	res, err := rds.Make(ctx, spec)
	if err != nil || !strings.Contains(res.Fields["password"], "X-Amz-Signature") || res.Fields["user"] != "catalog" {
		t.Fatalf("rds: %+v %v", res, err)
	}
	fs := &fakeSTS{}
	st := STS{Client: fs, RoleARN: "arn:aws:iam::1:role/lake", Duration: time.Hour}
	res, err = st.Make(ctx, &login.Spec{Identity: "lake"})
	if err != nil || res.Fields["access_key_id"] != "ASIA" || res.Fields["session_token"] != "t" ||
		aws.ToString(fs.in.RoleArn) != st.RoleARN || aws.ToInt32(fs.in.DurationSeconds) != 3600 {
		t.Fatalf("sts: %+v %v", res, err)
	}
}
