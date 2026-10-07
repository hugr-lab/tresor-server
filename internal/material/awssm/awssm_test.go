package awssm

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/hugr-lab/tresor-server/internal/material"
)

type fake struct {
	secrets map[string]*secretsmanager.GetSecretValueOutput
	reads   int
	last    *secretsmanager.GetSecretValueInput
}

func (f *fake) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.reads++
	f.last = in
	if out, ok := f.secrets[aws.ToString(in.SecretId)]; ok {
		return out, nil
	}
	return nil, &types.ResourceNotFoundException{Message: aws.String("the name quoted back")}
}

func text(s, v string) *secretsmanager.GetSecretValueOutput {
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(s), VersionId: aws.String(v)}
}

func TestParse(t *testing.T) {
	s := New(&fake{}, []string{"duckdb/", "lake-"}, false, 0)
	for text, want := range map[string]string{
		"duckdb/lake":          "ref+aws://duckdb/lake",
		"duckdb/lake#password": "ref+aws://duckdb/lake#password",
		"lake-key?version=" + strings.Repeat("a", 32):       "ref+aws://lake-key?version=" + strings.Repeat("a", 32),
		"duckdb/pg#user?version=" + strings.Repeat("0", 36): "ref+aws://duckdb/pg#user?version=" + strings.Repeat("0", 36),
	} {
		ref, err := s.Parse(text)
		if err != nil || ref.String() != want {
			t.Errorf("%s: %s %v", text, ref, err)
		}
	}
	for _, text := range []string{
		"", "other/lake", "Duckdb/lake", "duckdb//lake", "/duckdb/lake", "duckdb/lake/",
		"arn:aws:secretsmanager:eu-central-1:123456789012:secret:duckdb/lake",
		"duckdb/lake#", "duckdb/lake#a b", "duckdb/lake?stage=AWSPREVIOUS", "duckdb/lake?version=short",
		"duckdb/la ke", "duckdb/lake#f#g",
	} {
		if ref, err := s.Parse(text); err == nil {
			t.Errorf("%q accepted: %s", text, ref)
		}
	}
	if _, err := New(&fake{}, nil, false, 0).Parse("duckdb/lake"); err == nil {
		t.Error("an empty allowlist reads something")
	}
	if _, err := New(&fake{}, nil, true, 0).Parse("anything/at-all"); err != nil {
		t.Errorf("the whole account: %v", err)
	}
}

func TestResolve(t *testing.T) {
	f := &fake{secrets: map[string]*secretsmanager.GetSecretValueOutput{
		"duckdb/lake": text("s3cr3t", "v-1"),
		"duckdb/pg":   text(`{"user":"etl","password":"pw","port":5432,"tls":true,"nested":{"a":1}}`, "v-2"),
		"duckdb/bin":  {SecretBinary: []byte{1, 2}, VersionId: aws.String("v-3")},
		"duckdb/text": text("not json", "v-4"),
	}}
	s := New(f, []string{"duckdb/"}, false, time.Minute)
	ctx := context.Background()
	read := func(text string) (string, string, error) {
		ref, err := s.Parse(text)
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		return s.Resolve(ctx, ref)
	}
	if v, ver, err := read("duckdb/lake"); err != nil || v != "s3cr3t" || ver != "v-1" {
		t.Fatalf("a string: %q %q %v", v, ver, err)
	}
	for field, want := range map[string]string{"user": "etl", "port": "5432", "tls": "true"} {
		if v, _, err := read("duckdb/pg#" + field); err != nil || v != want {
			t.Errorf("#%s: %q %v", field, v, err)
		}
	}
	for _, text := range []string{"duckdb/pg#nested", "duckdb/pg#missing", "duckdb/bin", "duckdb/text#x", "duckdb/gone"} {
		if _, _, err := read(text); err == nil {
			t.Errorf("%s: resolved", text)
		} else if strings.Contains(err.Error(), "quoted back") {
			t.Errorf("%s: the API's message reached the error: %v", text, err)
		}
	}
	// the version pinned in the request; the cache serves a second read
	pinned := "duckdb/lake?version=" + strings.Repeat("b", 32)
	if _, _, err := read(pinned); err != nil || aws.ToString(f.last.VersionId) != strings.Repeat("b", 32) {
		t.Fatalf("a pinned version: %v %+v", err, f.last)
	}
	n := f.reads
	if _, _, err := read("duckdb/lake"); err != nil || f.reads != n {
		t.Fatalf("the cache: %d reads, want %d", f.reads, n)
	}
	// the allowlist again at the resolve
	if _, _, err := s.Resolve(ctx, refOf("other/x")); err == nil {
		t.Fatal("resolved outside the allowlist")
	}
}

func refOf(name string) material.Ref { return material.Ref{Scheme: "aws", Kind: "aws", Name: name} }
