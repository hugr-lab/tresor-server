package awsid

import (
	"context"
	"strings"
	"testing"
)

// static keys from the environment: refused, unless allowed (tests); a region is required
func TestStaticCredentials(t *testing.T) {
	ctx := context.Background()
	if _, err := Config(ctx, Identity{}, nil); err == nil {
		t.Fatal("no region: accepted")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "never-in-an-error")
	_, err := Config(ctx, Identity{Region: "eu-central-1"}, nil)
	if err == nil || !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID is set") || strings.Contains(err.Error(), "never-in-an-error") ||
		strings.Contains(err.Error(), "AKIAEXAMPLE") {
		t.Fatalf("static keys: %v", err)
	}
	cfg, err := Config(ctx, Identity{Region: "eu-central-1", StaticCredentials: true, EndpointURL: "http://127.0.0.1:1"}, nil)
	if err != nil || cfg.Region != "eu-central-1" || cfg.BaseEndpoint == nil || *cfg.BaseEndpoint != "http://127.0.0.1:1" {
		t.Fatalf("allowed: %v", err)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	// the SDK's legacy names are static keys too
	t.Setenv("AWS_ACCESS_KEY", "AKIAALIAS")
	t.Setenv("AWS_SECRET_KEY", "x")
	if _, err := Config(ctx, Identity{Region: "eu-central-1"}, nil); err == nil || !strings.Contains(err.Error(), "AWS_ACCESS_KEY is set") {
		t.Fatalf("the legacy names: %v", err)
	}
	t.Setenv("AWS_ACCESS_KEY", "")
	t.Setenv("AWS_SECRET_KEY", "")
	// an endpoint from the environment: refused
	t.Setenv("AWS_ENDPOINT_URL_KMS", "https://elsewhere.example")
	if _, err := Config(ctx, Identity{Region: "eu-central-1"}, nil); err == nil || !strings.Contains(err.Error(), "AWS_ENDPOINT_URL_KMS") {
		t.Fatalf("an endpoint from the environment: %v", err)
	}
	t.Setenv("AWS_ENDPOINT_URL_KMS", "")
	if _, err := Config(ctx, Identity{Region: "eu-central-1", RoleARN: "arn:aws:iam::123456789012:role/tresor-reader"}, nil); err != nil {
		t.Fatalf("an assumed role: %v", err)
	}
}
