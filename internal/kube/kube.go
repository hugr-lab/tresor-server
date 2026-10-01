// Package kube is how the service reaches the Kubernetes API (spec 003): in a pod, by its ServiceAccount;
// outside one, by KUBECONFIG. Its store and its ref+k8s source share it.
package kube

import (
	"errors"
	"os"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// podNamespace is where a pod's ServiceAccount mounts its namespace's name.
const podNamespace = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

func inPod() bool { return os.Getenv("KUBERNETES_SERVICE_HOST") != "" }

// Config is how the service reaches the API server: in a pod, by its ServiceAccount; outside one, by
// KUBECONFIG. Its rate is a service's, not client-go's default (5 a second).
func Config() (*rest.Config, error) {
	var cfg *rest.Config
	var err error
	if inPod() {
		cfg, err = rest.InClusterConfig()
	} else {
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			err = errors.New("the Kubernetes API (KUBECONFIG): " + err.Error())
		}
	}
	if err != nil {
		return nil, err
	}
	if cfg.QPS == 0 {
		cfg.QPS, cfg.Burst = 100, 200
	}
	cfg.UserAgent = "tresor-server"
	return cfg, nil
}

// Namespace is namespace when set, else the pod's own; outside a pod, required.
func Namespace(namespace string) (string, error) {
	if namespace != "" {
		return namespace, nil
	}
	if !inPod() {
		return "", errors.New("state.namespace is required outside a pod")
	}
	raw, err := os.ReadFile(podNamespace)
	if err != nil {
		return "", errors.New("state.namespace: the pod's namespace does not read: " + err.Error())
	}
	return strings.TrimSpace(string(raw)), nil
}
