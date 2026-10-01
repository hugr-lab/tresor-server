package kubestore

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

// Group and Version are the custom resources' (spec 003): the CRDs are the chart's.
const (
	Group   = "tresor.hugr-lab.io"
	Version = "v1alpha1"
)

// kind is one custom resource the store keeps.
type kind struct {
	name     string // TresorSecret
	resource string // tresorsecrets
}

var (
	kindSecret   = kind{"TresorSecret", "tresorsecrets"}
	kindGrant    = kind{"TresorGrant", "tresorgrants"}
	kindToken    = kind{"TresorMintedToken", "tresormintedtokens"}
	kindActor    = kind{"TresorActor", "tresoractors"}
	kindDataKey  = kind{"TresorDataKey", "tresordatakeys"}
	kindKeyring  = kind{"TresorKeyring", "tresorkeyrings"}
	allKinds     = []kind{kindSecret, kindGrant, kindToken, kindActor, kindDataKey, kindKeyring}
	labelPrefix  = Group + "/"
	labelActor   = labelPrefix + "actor-owner"
	labelClient  = labelPrefix + "actor-client"
	labelUser    = labelPrefix + "user"
	labelGrant   = labelPrefix + "grant"
	keyringName  = "active"
	listPageSize = int64(500)
)

// object is a custom resource as the store reads and writes it: everything it keeps is in its spec.
type object[T any] struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   metav1.ObjectMeta `json:"metadata"`
	Spec       T                 `json:"spec"`
}

// client reaches one kind in the store's namespace. Every read goes to the API server: no informer cache, so a
// replica sees another's write at once (spec 003).
type client[T any] struct {
	k  kind
	ri dynamic.ResourceInterface
}

func newClient[T any](dyn dynamic.Interface, namespace string, k kind) client[T] {
	gvr := schema.GroupVersionResource{Group: Group, Version: Version, Resource: k.resource}
	return client[T]{k: k, ri: dyn.Resource(gvr).Namespace(namespace)}
}

func fromUnstructured[T any](u *unstructured.Unstructured) (*object[T], error) {
	data, err := u.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var o object[T]
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("a %s does not read: %w", u.GetKind(), err)
	}
	return &o, nil
}

func (c client[T]) toUnstructured(o *object[T]) (*unstructured.Unstructured, int, error) {
	o.APIVersion, o.Kind = Group+"/"+Version, c.k.name
	data, err := json.Marshal(o)
	if err != nil {
		return nil, 0, err
	}
	u := &unstructured.Unstructured{}
	if err := u.UnmarshalJSON(data); err != nil { // integers stay int64
		return nil, 0, err
	}
	return u, len(data), nil
}

// get reads one resource; nil when there is none.
func (c client[T]) get(ctx context.Context, name string) (*object[T], error) {
	u, err := c.ri.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return fromUnstructured[T](u)
}

// list reads every resource the selector matches, page by page; a continue token that expired starts it over.
func (c client[T]) list(ctx context.Context, selector string) ([]*object[T], error) {
	for attempt := 0; ; attempt++ {
		out, err := c.listOnce(ctx, selector)
		if apierrors.IsResourceExpired(err) && attempt < 2 {
			continue
		}
		return out, err
	}
}

func (c client[T]) listOnce(ctx context.Context, selector string) ([]*object[T], error) {
	var out []*object[T]
	opts := metav1.ListOptions{LabelSelector: selector, Limit: listPageSize}
	for {
		page, err := c.ri.List(ctx, opts)
		if err != nil {
			return nil, err
		}
		for i := range page.Items {
			o, err := fromUnstructured[T](&page.Items[i])
			if err != nil {
				return nil, err
			}
			out = append(out, o)
		}
		if opts.Continue = page.GetContinue(); opts.Continue == "" {
			return out, nil
		}
	}
}

// create creates o; an apierrors AlreadyExists when the name is taken.
func (c client[T]) create(ctx context.Context, o *object[T]) (*object[T], error) {
	u, _, err := c.toUnstructured(o)
	if err != nil {
		return nil, err
	}
	u, err = c.ri.Create(ctx, u, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	return fromUnstructured[T](u)
}

// update replaces o, compare-and-set on the resourceVersion it carries: an apierrors Conflict when another
// write came first.
func (c client[T]) update(ctx context.Context, o *object[T]) (*object[T], error) {
	u, _, err := c.toUnstructured(o)
	if err != nil {
		return nil, err
	}
	u, err = c.ri.Update(ctx, u, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	return fromUnstructured[T](u)
}

// remove deletes a resource; with o's UID and resourceVersion as preconditions when o is given (a Conflict
// when it changed, or was dropped and created again). false when there was none.
func (c client[T]) remove(ctx context.Context, name string, o *object[T]) (bool, error) {
	opts := metav1.DeleteOptions{}
	if o != nil {
		uid, rv := o.Metadata.UID, o.Metadata.ResourceVersion
		opts.Preconditions = &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}
	}
	err := c.ri.Delete(ctx, name, opts)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

// size is o's size as written: what the store holds a secret to.
func (c client[T]) size(o *object[T]) (int, error) {
	_, n, err := c.toUnstructured(o)
	return n, err
}

// hashName names a resource by a hash of what identifies it: any name, of any length or case, makes a valid
// one, and none can take another's.
func hashName(prefix string, parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	return prefix + hex.EncodeToString(h.Sum(nil))[:40]
}

func secretName(name string) string  { return hashName("s-", []byte(name)) }
func grantName(idHash []byte) string { return hashName("g-", idHash) }
func actorName(owner string) string  { return hashName("a-", []byte(owner)) }
func tokenName(idHash []byte, key string) string {
	return hashName("t-", idHash, []byte(key))
}

// dataKeyName names a data key by its id, when the id makes a valid name: the envelope's are hex.
func dataKeyName(id string) (string, bool) {
	if id == "" || len(id) > 64 || strings.Trim(id, "0123456789abcdef") != "" {
		return "", false
	}
	return "k-" + id, true
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// labelValue is a label's value for v: its SHA-256 in base32 (52 characters; a label value holds 63).
func labelValue(v []byte) string {
	sum := sha256.Sum256(v)
	return strings.ToLower(b32.EncodeToString(sum[:]))
}

// selector selects by one of the store's labels.
func selector(label string, v []byte) string { return label + "=" + labelValue(v) }

// sameLabels: the store's own labels on a resource are exactly want. Labels of others (a backup tool's) are
// left alone.
func sameLabels(got, want map[string]string) bool {
	n := 0
	for k, v := range got {
		if !strings.HasPrefix(k, labelPrefix) {
			continue
		}
		if want[k] != v {
			return false
		}
		n++
	}
	return n == len(want)
}

// untouched: no one but the store has set what would change a resource's fate - it is not being deleted, has
// no finalizer, and no owner but the one the store may set (owner, kind TresorGrant).
func untouched(m metav1.ObjectMeta, owner string) bool {
	if m.DeletionTimestamp != nil || len(m.Finalizers) > 0 {
		return false
	}
	for _, ref := range m.OwnerReferences {
		if owner == "" || ref.Kind != kindGrant.name || ref.Name != owner || ref.APIVersion != Group+"/"+Version {
			return false
		}
	}
	return true
}

// ownedBy is the owner reference to a grant: a backstop, for the garbage collector, to the store's own deletes.
func ownedBy(name string, uid types.UID) []metav1.OwnerReference {
	return []metav1.OwnerReference{{APIVersion: Group + "/" + Version, Kind: kindGrant.name, Name: name, UID: uid}}
}

func meta(name string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name} }

// removeAll deletes every resource the selector matches.
func (c client[T]) removeAll(ctx context.Context, selector string) error {
	return c.ri.DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: selector})
}

func metaLabelled(name string, labels map[string]string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Labels: labels}
}
