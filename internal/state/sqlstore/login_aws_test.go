package sqlstore

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"
)

// an RDS IAM token is a presigned URL for connect, signed offline: the server, the user, never the secret key
func TestAWSLogin(t *testing.T) {
	l := AWSLogin{Endpoint: "db.abc.eu-central-1.rds.amazonaws.com:5432", Region: "eu-central-1", User: "tresor",
		Credentials: credentials.NewStaticCredentialsProvider("AKIAEXAMPLE", "never-in-a-token", "")}
	token, err := l.Password(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse("https://" + token)
	if err != nil || u.Host != "db.abc.eu-central-1.rds.amazonaws.com:5432" || u.Query().Get("Action") != "connect" ||
		u.Query().Get("DBUser") != "tresor" || strings.Contains(token, "never-in-a-token") {
		t.Fatalf("token: %v %s", err, u.Redacted())
	}
}
