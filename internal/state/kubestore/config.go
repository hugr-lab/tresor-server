package kubestore

import (
	"errors"
	"os"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// podNamespace is where a pod's ServiceAccount mounts its namespace's name.
const podNamespace = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// RESTConfig is how the service reaches the API server - in a pod, by its ServiceAccount; outside one, by
// KUBECONFIG - and the namespace of its resources: namespace when set, else the pod's own.
func RESTConfig(namespace string) (*rest.Config, string, error) {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, "", err
		}
		if namespace == "" {
			raw, err := os.ReadFile(podNamespace)
			if err != nil {
				return nil, "", errors.New("state.namespace: the pod's namespace does not read: " + err.Error())
			}
			namespace = strings.TrimSpace(string(raw))
		}
		return cfg, namespace, nil
	}
	if namespace == "" {
		return nil, "", errors.New("state.namespace is required outside a pod")
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, "", errors.New("the Kubernetes API (KUBECONFIG): " + err.Error())
	}
	return cfg, namespace, nil
}
