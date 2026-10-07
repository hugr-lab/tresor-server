package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/keys/awskms"
)

// AWS against an emulator (spec 012; moto in CI: TRESOR_TEST_AWS_ENDPOINT): the awskms KEK on SQLite, ref+aws as
// a string and a JSON field, a move from a local KEK to awskms (spec 011), signing with a KMS key - through the
// service's own wiring (kekOf, materialResolver, rewrap).
func TestAWS(t *testing.T) {
	endpoint := os.Getenv("TRESOR_TEST_AWS_ENDPOINT")
	if endpoint == "" {
		t.Skip("TRESOR_TEST_AWS_ENDPOINT is not set (an AWS emulator: scripts/ci/aws.sh)")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	ctx := context.Background()
	id := config.AWS{Region: "eu-central-1", EndpointURL: endpoint, StaticCredentials: "allow"}
	ac, err := awsOf(id)
	if err != nil {
		t.Fatal(err)
	}
	k := kms.NewFromConfig(ac)
	key := func(spec kmstypes.KeySpec, usage kmstypes.KeyUsageType) string {
		out, err := k.CreateKey(ctx, &kms.CreateKeyInput{KeySpec: spec, KeyUsage: usage})
		if err != nil {
			t.Fatal(err)
		}
		return aws.ToString(out.KeyMetadata.Arn)
	}
	enc := key(kmstypes.KeySpecSymmetricDefault, kmstypes.KeyUsageTypeEncryptDecrypt)
	mac := key(kmstypes.KeySpecHmac256, kmstypes.KeyUsageTypeGenerateVerifyMac)
	sign := key(kmstypes.KeySpecEccNistP256, kmstypes.KeyUsageTypeSignVerify)
	sm := secretsmanager.NewFromConfig(ac)
	run := strconv.FormatInt(time.Now().UnixNano(), 36) // names of this run's: the emulator may hold another's
	for name, value := range map[string]string{"duckdb/lake-" + run: "from-secrets-manager", "duckdb/pg-" + run: `{"password":"from-a-json-field"}`,
		"other/x-" + run: "outside"} {
		if _, err := sm.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String(name), SecretString: aws.String(value)}); err != nil {
			t.Fatal(err)
		}
	}

	// a store under a local KEK first, then moved to awskms with the local one previous
	dir := t.TempDir()
	local := filepath.Join(dir, "kek")
	if err := os.WriteFile(local, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "server.yaml")
	write := func(keysDoc string) *config.Config {
		t.Helper()
		doc := "listen: 127.0.0.1:8443\npublic_url: http://127.0.0.1:8443\nstate: {kind: sqlite, path: " + filepath.Join(dir, "t.db") + "}\n" +
			keysDoc + "aws: {region: eu-central-1, endpoint_url: '" + endpoint + "', static_credentials: allow}\n" +
			"material: {aws: {allow: [{prefixes: [duckdb/]}]}}\n" +
			"issuers: [{issuer: 'http://127.0.0.1:18080/realms/t', audience: duckdb-secrets}]\npolicy: {admins: [role:secrets_admin]}\n"
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, _, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := write("keys: {kind: local, key_file: " + local + "}\n")
	st, _, err := openState(ctx, cfg, log, false)
	if err != nil {
		t.Fatal(err)
	}
	put(t, st, "pg", `{"password":"under-the-local-kek"}`)
	st.Close()

	awsKeys := "keys: {kind: awskms, key: '" + enc + "', mac_key: '" + mac + "'"
	cfg = write(awsKeys + ", previous: [{kind: local, key_file: " + local + "}]}\n")
	st, checks, err := openState(ctx, cfg, log, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if err := c.Run(ctx); err != nil {
			t.Fatalf("readiness %s: %v", c.Name, err)
		}
	}
	put(t, st, "lake", `{"secret":"written-under-awskms"}`)
	st.Close()
	if err := rewrap(path, false, log); err != nil {
		t.Fatal(err)
	}
	cfg = write(awsKeys + "}\n")
	st, _, err = openState(ctx, cfg, log, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for name, want := range map[string]string{"pg": "under-the-local-kek", "lake": "written-under-awskms"} {
		sec, err := st.Get(ctx, name)
		if err != nil || !strings.Contains(string(sec.Params["password"])+string(sec.Params["secret"]), want) {
			t.Fatalf("%s under awskms alone: %v", name, err)
		}
	}

	// references
	r, err := materialResolver(cfg)
	if err != nil || r == nil {
		t.Fatalf("the resolver: %v", err)
	}
	for ref, want := range map[string]string{"ref+aws://duckdb/lake-" + run: "from-secrets-manager", "ref+aws://duckdb/pg-" + run + "#password": "from-a-json-field"} {
		if v, err := r.ResolveOne(ctx, ref); err != nil || v != want {
			t.Errorf("%s: %q %v", ref, v, err)
		}
	}
	if r.Admits("ref+aws://other/x-" + run) {
		t.Error("a secret outside the allowlist admitted")
	}

	// signing the exchange's assertion
	s, err := awskms.NewSigner(ctx, k, sign)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("h.p"))
	if sig, err := s.Sign(ctx, d[:]); err != nil || len(sig) != 64 || s.Alg() != "ES256" {
		t.Fatalf("sign: %d %v", len(sig), err)
	}
}
