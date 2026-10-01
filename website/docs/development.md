---
title: Development
---

# Development

Go 1.27, one module, no cgo.

```bash
go build ./cmd/tresor-server
go test -race ./...           # GOWORK=off inside a go.work tree
```

## The tests

- **Every package's own tests**: the API (every route, permission and precondition), token verification,
  the configuration, the envelope, the stores.
- **The state store suite** (`internal/state/statetest`): one suite every store passes - compare-and-set
  under concurrent writers, two handles as two replicas, exact names, delegation grants and their limit,
  minted tokens.
  - Memory and SQLite always run.
  - Kubernetes runs when envtest's API server is installed (no cluster):

    ```bash
    export KUBEBUILDER_ASSETS="$(go run sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.25.1 use 1.37.0 -p path)"
    ```
  - PostgreSQL and SQL Server run when a server is given; each test gets a database of its own:

    ```bash
    TRESOR_TEST_POSTGRES='postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable' \
    TRESOR_TEST_POSTGRES_PASSWORD=... \
    TRESOR_TEST_SQLSERVER='sqlserver://sa@127.0.0.1:51433?encrypt=disable' \
    TRESOR_TEST_SQLSERVER_PASSWORD=... \
      go test -race ./...
    ```

## tresor's conformance suite

The protocol's conformance suite, and tresor's reference-server tests, run against this service through
tresor's own `scripts/ci/test_keycloak.sh`: Keycloak in docker, DuckDB with the tresor extension, this service
in the reference server's place.

```bash
scripts/ci/tresor_checkout.sh ../tresor-pin --submodules   # tresor at the pinned commit; build it (make)
scripts/ci/conformance.sh ../tresor-pin sqlite             # memory | sqlite | postgres | sqlserver | kubernetes
TRESOR_CONFORMANCE_REPLICAS=2 scripts/ci/conformance.sh ../tresor-pin postgres   # two replicas, a proxy
```

On SQLite, PostgreSQL, SQL Server and Kubernetes (envtest's API server) the run then checks the store for the
seeded material in the clear.

CI runs it on every store, two replicas on PostgreSQL, SQL Server and Kubernetes, with tresor at the commit
`scripts/ci/tresor_checkout.sh` pins.

## The chart

```bash
helm lint --strict deploy/helm/tresor-server
scripts/ci/kind.sh     # kind, the image built here, the Kubernetes store and PostgreSQL, through the protocol
```

`kind.sh` makes a CA, an OIDC issuer and a PostgreSQL with TLS in the cluster, installs the chart twice and
checks each install through the protocol. On the Kubernetes store it also checks the admission policy: a hand
write is refused, and the garbage collector may delete. CI runs it on every PR.

## Live on Azure

By hand, with the owner's tenant and subscription; nothing secret is printed:

- `scripts/dev/azure_live.sh up`: a Key Vault KEK (seal, open, a rotation, rewrap) and a reference, against
  a real vault;
- `scripts/dev/aca_live.sh up sqlserver`: the Container Apps recipe, checked from DuckDB with an Entra
  application;
- `scripts/dev/aks_live.sh up`: the chart on AKS - the Kubernetes store, the KEK in Key Vault by workload
  identity, `ref+azkv` - checked through the protocol; `down` deletes it all.

## The process

One lightweight spec per change under `specs/`, a branch, a PR, an independent review, then a merge on green
CI. A protocol change lands in tresor's `protocol.md` first.
