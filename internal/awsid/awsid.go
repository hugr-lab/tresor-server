// Package awsid is the service's own identity on AWS (spec 012): the SDK's default chain - EKS Pod Identity,
// IRSA (a projected web identity token), an instance's or a task's role. Static keys from the environment are
// refused unless allowed (development, tests); another account is reached by a role assumed with that identity.
// No secret of the service's own.
package awsid

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Identity says where and how the service calls AWS.
type Identity struct {
	Region string
	// EndpointURL replaces every AWS API's endpoint (LocalStack, a VPC endpoint); "": the SDK's.
	EndpointURL string
	// StaticCredentials allows keys from the environment (AWS_ACCESS_KEY_ID): development and tests only.
	StaticCredentials bool
	// RoleARN is a role assumed with the service's identity (another account: a named source's).
	RoleARN string
}

// staticVariables are the environment's static keys: the SDK would prefer them to the platform's identity.
var staticVariables = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}

// Config returns the SDK's configuration for the identity.
func Config(ctx context.Context, id Identity, log *slog.Logger) (aws.Config, error) {
	if id.Region == "" {
		return aws.Config{}, errors.New("aws.region is required")
	}
	for _, v := range staticVariables {
		if os.Getenv(v) == "" {
			continue
		}
		if !id.StaticCredentials {
			return aws.Config{}, fmt.Errorf("%s is set: static AWS keys are refused - the service uses the platform's "+
				"identity (EKS Pod Identity, IRSA, an instance role); aws.static_credentials: allow is for tests", v)
		}
		if log != nil {
			log.Warn("static AWS keys from the environment (aws.static_credentials: allow): for development and tests only")
		}
		break
	}
	opts := []func(*config.LoadOptions) error{config.WithRegion(id.Region),
		// the shared files (~/.aws) are a developer's, never the service's
		config.WithSharedConfigFiles([]string{}), config.WithSharedCredentialsFiles([]string{})}
	if id.EndpointURL != "" {
		opts = append(opts, config.WithBaseEndpoint(id.EndpointURL))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("the AWS configuration: %w", err)
	}
	if id.RoleARN != "" {
		cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), id.RoleARN,
			func(o *stscreds.AssumeRoleOptions) { o.RoleSessionName = "tresor-server" }))
	}
	return cfg, nil
}
