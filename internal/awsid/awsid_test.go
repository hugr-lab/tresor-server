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
	if _, err := Config(ctx, Identity{Region: "eu-central-1", RoleARN: "arn:aws:iam::123456789012:role/tresor-reader"}, nil); err != nil {
		t.Fatalf("an assumed role: %v", err)
	}
}
