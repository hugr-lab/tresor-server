package gcpsm

import (
	"context"
	"hash/crc32"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fake struct {
	versions map[string]string // name -> data; "<secret>/versions/latest" resolves to the highest
	reads    int
	badCRC   bool
}

func (f *fake) AccessSecretVersion(_ context.Context, r *secretmanagerpb.AccessSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	f.reads++
	name := r.Name
	if strings.HasSuffix(name, "/versions/latest") {
		name = strings.TrimSuffix(name, "latest") + "2"
	}
	data, ok := f.versions[name]
	if !ok {
		return nil, status.Error(codes.NotFound, "the name quoted back")
	}
	c := int64(crc32.Checksum([]byte(data), castagnoli))
	if f.badCRC {
		c++
	}
	return &secretmanagerpb.AccessSecretVersionResponse{Name: name, Payload: &secretmanagerpb.SecretPayload{Data: []byte(data), DataCrc32C: &c}}, nil
}

func TestParseResolve(t *testing.T) {
	f := &fake{versions: map[string]string{
		"projects/corp-data/secrets/duckdb-lake/versions/1": "old",
		"projects/corp-data/secrets/duckdb-lake/versions/2": "current",
		"projects/corp-data/secrets/duckdb-bin/versions/2":  "\xff\xfe",
	}}
	s := New(f, []Allow{{Project: "corp-data", Prefixes: []string{"duckdb-"}}, {Project: "123456789012"}}, time.Minute)
	ctx := context.Background()
	for text, want := range map[string]string{"corp-data/duckdb-lake": "current", "corp-data/duckdb-lake/1": "old"} {
		ref, err := s.Parse(text)
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		if v, _, err := s.Resolve(ctx, ref); err != nil || v != want {
			t.Errorf("%s: %q %v", text, v, err)
		}
	}
	for _, text := range []string{"", "corp-data", "corp-data/other", "other-proj/duckdb-lake", "corp-data/duckdb-lake/latest",
		"corp-data/duckdb-lake/0", "corp-data/duckdb.lake", "corp-data/duckdb-lake/1/x", "Corp-Data/duckdb-lake", "corp-data/../x"} {
		if ref, err := s.Parse(text); err == nil {
			t.Errorf("%q accepted: %s", text, ref)
		}
	}
	if _, err := s.Parse("123456789012/anything"); err != nil {
		t.Errorf("a project by number, every secret: %v", err)
	}
	for _, text := range []string{"corp-data/duckdb-bin", "corp-data/duckdb-gone"} {
		ref, _ := s.Parse(text)
		if _, _, err := s.Resolve(ctx, ref); err == nil || strings.Contains(err.Error(), "quoted back") {
			t.Errorf("%s: %v", text, err)
		}
	}
	f.badCRC = true
	ref, _ := s.Parse("corp-data/duckdb-lake/1")
	s.cache = map[string]cached{}
	if _, _, err := s.Resolve(ctx, ref); err == nil {
		t.Error("a bad CRC accepted")
	}
}
