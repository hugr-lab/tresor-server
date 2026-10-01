// Package kubestore is the state.Store in the Kubernetes API (spec 003): custom resources in the service's
// namespace, compare-and-set through their resourceVersion. Params and tokens are sealed (keys.Envelope); what is
// not sealed is authenticated by a MAC under a data key, checked on every read and before every write, so a
// resource changed behind the store is refused, never served and never written over.
package kubestore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/state"
)

const (
	// maxAttempts bounds Update's compare-and-set retries.
	maxAttempts = 8
	// maxPutAttempts bounds a delegation grant's put: all of one actor's racing puts share one counter.
	maxPutAttempts = 16
	// maxObject is the most a secret's object may weigh: etcd holds ~1.5 MiB, and a store is no blob store.
	maxObject = 256 << 10
	// maxGrants is the most grants one secret holds.
	maxGrants = 1000
)

// ErrTampered: a resource was changed behind the store - its MAC, name or labels do not match, or someone else
// set its finalizers or owners. Never served, never written over: an operator looks.
var ErrTampered = fmt.Errorf("%w: a resource was changed behind the store", keys.ErrSealed)

// Store is safe for concurrent use, by several replicas at once.
type Store struct {
	ns       string
	instance string
	envelope *keys.Envelope
	log      *slog.Logger

	secrets  client[secretSpec] // this namespace's entries: TresorSecret, or TresorVariable (spec 004)
	space    entries
	vars     *Store
	grants   client[grantSpec]
	tokens   client[tokenSpec]
	actors   client[actorSpec]
	dataKeys client[dataKeySpec]
	keyrings client[keyringSpec]

	// beforeWrite, in tests, runs between fn and the compare-and-set: another writer's moment.
	beforeWrite func()
}

// Options tune a store.
type Options struct {
	// Namespace is where the resources are: the service's own.
	Namespace string
	// Instance names the installation, in every MAC: a resource moved from another installation that shares
	// the KEK does not verify. The namespace when empty; kept stable, so a restore still verifies.
	Instance string
	Keys     keys.Options
	Log      *slog.Logger
}

// Open reaches the API server through cfg, checks that it serves the store's resources, and opens the store.
func Open(ctx context.Context, cfg *rest.Config, wrapper keys.KeyWrapper, opts Options) (*Store, error) {
	if opts.Namespace == "" {
		return nil, errors.New("the Kubernetes store needs a namespace")
	}
	if opts.Instance == "" {
		opts.Instance = opts.Namespace
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.QPS == 0 { // client-go's own (5 a second) would throttle a service; kube.Config sets it too
		cfg = rest.CopyConfig(cfg)
		cfg.QPS, cfg.Burst = 100, 200
	}
	if err := checkSchema(ctx, cfg); err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	s := &Store{ns: opts.Namespace, instance: opts.Instance, log: opts.Log,
		secrets:  newClient[secretSpec](dyn, opts.Namespace, kindSecret),
		grants:   newClient[grantSpec](dyn, opts.Namespace, kindGrant),
		tokens:   newClient[tokenSpec](dyn, opts.Namespace, kindToken),
		actors:   newClient[actorSpec](dyn, opts.Namespace, kindActor),
		dataKeys: newClient[dataKeySpec](dyn, opts.Namespace, kindDataKey),
		keyrings: newClient[keyringSpec](dyn, opts.Namespace, kindKeyring)}
	s.space = entries{kind: kindSecret, name: secretName, aad: "tresor-server/params/1"}
	s.envelope = keys.NewEnvelope(wrapper, dataKeys{s}, opts.Keys)
	v := *s
	v.secrets = newClient[secretSpec](dyn, opts.Namespace, kindVar)
	v.space = entries{kind: kindVar, name: variableName, aad: "tresor-server/variable/1"}
	v.vars = &v
	s.vars = &v
	return s, nil
}

// checkSchema: the API server serves every resource of the version the store knows - by discovery, which needs
// no cluster-scope right. Otherwise the service does not start.
func checkSchema(ctx context.Context, cfg *rest.Config) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	hc, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return err
	}
	host := cfg.Host
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	url := strings.TrimSuffix(host, "/") + "/apis/" + Group + "/" + Version
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("the Kubernetes API: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("the API server does not serve %s/%s (%s): install the chart's CRDs", Group, Version, res.Status)
	}
	var list metav1.APIResourceList
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&list); err != nil {
		return fmt.Errorf("the API server's discovery of %s/%s: %w", Group, Version, err)
	}
	var missing []string
	for _, k := range allKinds {
		if !slices.ContainsFunc(list.APIResources, func(r metav1.APIResource) bool { return r.Name == k.resource && r.Kind == k.name }) {
			missing = append(missing, k.resource)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the API server does not serve %s in %s/%s: install the chart's CRDs", strings.Join(missing, ", "), Group, Version)
	}
	return nil
}

// Envelope is the store's envelope: its Check is the KEK's readiness.
func (s *Store) Envelope() *keys.Envelope { return s.envelope }

// entries are what one store keeps (spec 004): the secrets, or the variables - their own kind, names and AAD.
type entries struct {
	kind kind
	name func(string) string
	aad  string
}

// Variables is the variables' namespace (spec 004).
func (s *Store) Variables() state.Store { return s.vars }

// paramsAAD binds sealed params to their namespace, resource, name and version, as on the SQL stores.
func (s *Store) paramsAAD(rowID, name string, version int64) []byte {
	return []byte(s.space.aad + "\x00" + rowID + "\x00" + name + "\x00" + strconv.FormatInt(version, 10))
}

// verified is a TresorSecret checked: its name, its metadata, its MAC. A KEK that does not answer is no
// verdict (not ErrTampered).
func (s *Store) verified(ctx context.Context, o *object[secretSpec]) (*state.Secret, error) {
	sp := &o.Spec
	if o.Metadata.Name != s.space.name(sp.Name) || !sameLabels(o.Metadata.Labels, nil) || !untouched(o.Metadata, "") {
		return nil, fmt.Errorf("%w: %s", ErrTampered, o.Metadata.Name)
	}
	if err := s.envelope.Verify(ctx, sp.DataKeyID, sp.canonical(s.space.kind, s.instance), sp.MAC); err != nil {
		if errors.Is(err, keys.ErrSealed) {
			return nil, fmt.Errorf("%w: %s: %w", ErrTampered, o.Metadata.Name, err)
		}
		return nil, err
	}
	sec := &state.Secret{Name: sp.Name, Type: sp.Type, Provider: sp.Provider, Scope: sp.Scope, RedactKeys: sp.RedactKeys,
		Comment: sp.Comment, Owner: sp.Owner, Version: sp.Version,
		CreatedAt: fromNanos(sp.CreatedAt), UpdatedAt: fromNanos(sp.UpdatedAt)}
	if sp.Grants != nil {
		sec.Grants = make([]state.Grant, len(sp.Grants))
		for i, g := range sp.Grants {
			sec.Grants[i] = state.Grant{ID: g.ID, Principal: g.Principal, Verbs: g.Verbs}
		}
	}
	return sec, nil
}

// read reads one secret, checked; nil when there is none.
func (s *Store) read(ctx context.Context, name string) (*object[secretSpec], *state.Secret, error) {
	o, err := s.secrets.get(ctx, s.space.name(name))
	if err != nil || o == nil {
		return nil, nil, err
	}
	if o.Spec.Name != name {
		return nil, nil, fmt.Errorf("%w: %s holds another name", ErrTampered, o.Metadata.Name)
	}
	sec, err := s.verified(ctx, o)
	return o, sec, err
}

// opened is a secret with its params open.
func (s *Store) opened(ctx context.Context, o *object[secretSpec], sec *state.Secret) (*state.Secret, error) {
	plain, err := s.envelope.Open(ctx, o.Spec.DataKeyID, s.paramsAAD(o.Spec.RowID, sec.Name, sec.Version), o.Spec.Sealed)
	if err != nil {
		return nil, fmt.Errorf("secret %s: its params: %w", sec.Name, err)
	}
	err = json.Unmarshal(plain, &sec.Params)
	clear(plain)
	if err != nil {
		return nil, fmt.Errorf("secret %s: its params: %w", sec.Name, keys.ErrSealed)
	}
	return sec, nil
}

func (s *Store) List(ctx context.Context) ([]*state.Secret, error) {
	all, err := s.secrets.list(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make([]*state.Secret, 0, len(all))
	for _, o := range all {
		sec, err := s.verified(ctx, o)
		if errors.Is(err, keys.ErrSealed) {
			// one bad resource never fails a list (spec 002): left out, and logged
			s.log.Error("a secret's resource was changed behind the store: left out", "resource", o.Metadata.Name,
				"error", err.Error())
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, sec)
	}
	slices.SortFunc(out, func(a, b *state.Secret) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (s *Store) Describe(ctx context.Context, name string) (*state.Secret, error) {
	o, sec, err := s.read(ctx, name)
	if err != nil {
		return nil, err
	}
	if o == nil {
		return nil, state.ErrNotFound
	}
	return sec, nil
}

func (s *Store) Get(ctx context.Context, name string) (*state.Secret, error) {
	o, sec, err := s.read(ctx, name)
	if err != nil {
		return nil, err
	}
	if o == nil {
		return nil, state.ErrNotFound
	}
	return s.opened(ctx, o, sec)
}

func (s *Store) Update(ctx context.Context, name string,
	fn func(current *state.Secret) (*state.Secret, error)) (*state.Secret, error) {
	for range maxAttempts {
		// checked before fn runs: a tampered resource is never re-MACed by the next honest write
		o, current, err := s.read(ctx, name)
		if err != nil {
			return nil, err
		}
		var broken error // the params do not open: only a delete may pass
		if o != nil {
			opened, err := s.opened(ctx, o, state.Clone(current))
			switch {
			case errors.Is(err, keys.ErrSealed):
				broken = err // fn gets the descriptor, verified, without params
			case err != nil:
				return nil, err // the KEK may be unreachable: nothing is decided on a guess
			default:
				current = opened
			}
		}
		next, err := fn(state.Clone(current))
		if err != nil {
			return nil, err
		}
		if broken != nil && next != nil {
			return nil, broken // never rewritten blind; an admin may delete it
		}
		if err := state.CheckVersion(current, next); err != nil {
			return nil, err
		}
		if s.beforeWrite != nil {
			s.beforeWrite()
		}
		var done bool
		switch {
		case next == nil && current == nil:
			return nil, state.ErrNotFound
		case next == nil:
			done, err = s.secrets.remove(ctx, o.Metadata.Name, o)
			if apierrors.IsConflict(err) {
				done, err = false, nil
			}
		default:
			next = state.Clone(next)
			next.Name = name
			done, err = s.write(ctx, o, next)
		}
		if err != nil {
			return nil, err
		}
		if done {
			return next, nil
		}
		// another writer came first: run fn again on what is there
	}
	return nil, state.ErrConflict
}

// write creates next (o nil) or replaces o by it, compare-and-set on o's resourceVersion; false when another
// writer came first.
func (s *Store) write(ctx context.Context, o *object[secretSpec], next *state.Secret) (bool, error) {
	strs := append([]string{next.Name, next.Type, next.Provider, next.Comment, next.Owner}, next.Scope...)
	strs = append(strs, next.RedactKeys...)
	for _, g := range next.Grants {
		strs = append(append(strs, g.ID, g.Principal), g.Verbs...)
	}
	if err := validUTF8(strs...); err != nil {
		return false, err
	}
	if len(next.Grants) > maxGrants {
		return false, fmt.Errorf("%w: secret %s: more than %d grants", state.ErrTooLarge, next.Name, maxGrants)
	}
	out := &object[secretSpec]{}
	if o != nil {
		out.Metadata = o.Metadata
		out.Spec.RowID = o.Spec.RowID
	} else {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return false, err
		}
		out.Metadata.Name, out.Spec.RowID = s.space.name(next.Name), hex.EncodeToString(raw)
	}
	plain, err := json.Marshal(next.Params)
	if err != nil {
		return false, err
	}
	sp := &out.Spec
	sp.DataKeyID, sp.Sealed, err = s.envelope.Seal(ctx, s.paramsAAD(sp.RowID, next.Name, next.Version), plain)
	clear(plain)
	if err != nil {
		return false, err
	}
	sp.Name, sp.Type, sp.Provider, sp.Scope, sp.RedactKeys = next.Name, next.Type, next.Provider, next.Scope, next.RedactKeys
	sp.Comment, sp.Owner, sp.Version = next.Comment, next.Owner, next.Version
	sp.CreatedAt, sp.UpdatedAt = nanos(next.CreatedAt), nanos(next.UpdatedAt)
	if next.Grants != nil {
		sp.Grants = make([]secretGrant, len(next.Grants))
		for i, g := range next.Grants {
			sp.Grants[i] = secretGrant{ID: g.ID, Principal: g.Principal, Verbs: g.Verbs}
		}
	}
	if sp.MAC, err = s.envelope.MAC(ctx, sp.DataKeyID, sp.canonical(s.space.kind, s.instance)); err != nil {
		return false, err
	}
	if n, err := s.secrets.size(out); err != nil {
		return false, err
	} else if n > maxObject {
		return false, fmt.Errorf("%w: secret %s: %d KiB, over %d KiB", state.ErrTooLarge, next.Name, n>>10, maxObject>>10)
	}
	if o == nil {
		_, err = s.secrets.create(ctx, out)
		if apierrors.IsAlreadyExists(err) {
			return false, nil // created by another writer meanwhile
		}
	} else {
		_, err = s.secrets.update(ctx, out)
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			return false, nil
		}
	}
	return err == nil, err
}

// Ping says whether the API server answers, and whether the namespace is this installation's: its mark
// verifies under the KEK and state.instance. A wrong KEK or instance is not ready, rather than serving an empty
// list with every resource refused.
func (s *Store) Ping(ctx context.Context) error {
	if _, err := s.secrets.ri.List(ctx, metav1.ListOptions{Limit: 1}); err != nil {
		return err
	}
	return s.checkInstallation(ctx)
}

// checkInstallation verifies the installation's mark, made by the first replica to look.
func (s *Store) checkInstallation(ctx context.Context) error {
	for range maxAttempts {
		o, err := s.keyrings.get(ctx, installationName)
		if err != nil {
			return err
		}
		if o == nil {
			spec := keyringSpec{Instance: s.instance}
			if spec.DataKeyID, err = s.envelope.ActiveID(ctx); err != nil {
				return err
			}
			if spec.MAC, err = s.envelope.MAC(ctx, spec.DataKeyID, spec.canonical(s.instance)); err != nil {
				return err
			}
			_, err = s.keyrings.create(ctx, &object[keyringSpec]{Metadata: meta(installationName), Spec: spec})
			if apierrors.IsAlreadyExists(err) {
				continue
			}
			return err
		}
		sp := &o.Spec
		err = s.check(ctx, installationName, sp.Instance == s.instance && untouched(o.Metadata, ""), sp.DataKeyID,
			sp.canonical(s.instance), sp.MAC)
		if errors.Is(err, keys.ErrSealed) {
			return fmt.Errorf("namespace %s was written by another installation, or under another KEK: state.instance "+
				"and keys must be the ones that wrote it (%w)", s.ns, err)
		}
		return err
	}
	return state.ErrConflict
}

func (s *Store) Close() error { return nil }

var _ state.Store = (*Store)(nil)

// nanos is a time as stored: int64 nanoseconds, 0 for none (the zero time is no int64 of nanoseconds).
func nanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func fromNanos(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

// validUTF8: JSON - and so the API server - would replace what is not UTF-8, and the resource would then not
// verify: refused before it is written.
func validUTF8(ss ...string) error {
	for _, s := range ss {
		if !utf8.ValidString(s) {
			return errors.New("a value to store is not UTF-8")
		}
	}
	return nil
}
