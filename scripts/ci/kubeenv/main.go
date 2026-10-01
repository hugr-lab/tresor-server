// kubeenv is conformance's Kubernetes helper (scripts/ci/conformance.sh), not shipped: an API server with no
// cluster - envtest's kube-apiserver and etcd, from KUBEBUILDER_ASSETS (setup-envtest) - with the chart's CRDs.
//
//	kubeenv up <crds> <kubeconfig> <namespace>   starts it with the CRDs of a directory, makes the namespace,
//	                                              writes the kubeconfig once ready; stops on SIGTERM or SIGINT
//	kubeenv clear <kubeconfig> <namespace> <text>   fails when any of the store's resources holds text in the clear
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func main() {
	log.SetFlags(0)
	switch {
	case len(os.Args) == 5 && os.Args[1] == "up":
		up(os.Args[2], os.Args[3], os.Args[4])
	case len(os.Args) == 5 && os.Args[1] == "clear":
		clear(os.Args[2], os.Args[3], os.Args[4])
	default:
		log.Fatal("usage: kubeenv up <crds> <kubeconfig> <namespace> | kubeenv clear <kubeconfig> <namespace> <text>")
	}
}

func up(crds, kubeconfig, namespace string) {
	env := &envtest.Environment{CRDDirectoryPaths: []string{crds}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		env.Stop() // whatever of it started
		log.Fatalf("kubeenv: %v", err)
	}
	// from here, a failure stops the API server first: it must not outlive this process
	fatal := func(err error) {
		env.Stop()
		log.Fatalf("kubeenv: %v", err)
	}
	ctx := context.Background()
	cs := kubernetes.NewForConfigOrDie(cfg)
	if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}},
		metav1.CreateOptions{}); err != nil {
		fatal(err)
	}
	user, err := env.AddUser(envtest.User{Name: "tresor-server", Groups: []string{"system:masters"}}, nil)
	if err != nil {
		fatal(err)
	}
	raw, err := user.KubeConfig()
	if err != nil {
		fatal(err)
	}
	// written whole, then renamed: the kubeconfig's existence says the API server is ready
	if err := os.WriteFile(kubeconfig+".tmp", raw, 0o600); err != nil {
		fatal(err)
	}
	if err := os.Rename(kubeconfig+".tmp", kubeconfig); err != nil {
		fatal(err)
	}
	log.Printf("kubeenv: an API server at %s, namespace %s", cfg.Host, namespace)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	env.Stop()
}

func clear(kubeconfig, namespace, text string) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("kubeenv: %v", err)
	}
	dyn := dynamic.NewForConfigOrDie(cfg)
	ctx := context.Background()
	total := 0
	for _, resource := range []string{"tresorsecrets", "tresorvariables", "tresorgrants", "tresormintedtokens", "tresoractors",
		"tresordatakeys", "tresorkeyrings"} {
		list, err := dyn.Resource(schema.GroupVersionResource{Group: "tresor.hugr-lab.io", Version: "v1alpha1",
			Resource: resource}).Namespace(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Fatalf("kubeenv: %s: %v", resource, err)
		}
		for _, item := range list.Items {
			if holds(item.Object, text) {
				log.Fatalf("kubeenv: %s %s holds the text in the clear", resource, item.GetName())
			}
		}
		total += len(list.Items)
	}
	if total == 0 {
		log.Fatal("kubeenv: the store holds no resources")
	}
	fmt.Printf("kubeenv: %d resources, none holds the text in the clear\n", total)
}

// holds: a string of v holds text - as it is, or base64-decoded (the byte fields: sealed values, keys).
func holds(v any, text string) bool {
	switch v := v.(type) {
	case string:
		if strings.Contains(v, text) {
			return true
		}
		raw, err := base64.StdEncoding.DecodeString(v)
		return err == nil && strings.Contains(string(raw), text)
	case map[string]any:
		for _, e := range v {
			if holds(e, text) {
				return true
			}
		}
	case []any:
		for _, e := range v {
			if holds(e, text) {
				return true
			}
		}
	}
	return false
}
